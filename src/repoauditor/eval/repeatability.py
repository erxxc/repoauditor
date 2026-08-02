"""Fail-closed, non-mutating OPT-004 identical-input repeatability execution."""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path

from pydantic import BaseModel, Field

from ..analyze.provider_cost import calculate_provider_cost
from ..config import Config, get_config
from ..detect.retrieval import RetrievalIndex
from ..falsify import challenge_finding
from ..ingest import latest_snapshot
from ..llm import LLMClient, get_llm_client, model_usage_scope
from ..map import load_architecture
from ..store import db
from ..store.models import FalsificationStatus, RunStatus
from .convergence import DEFAULT_PROFILES
from .regression import STAGE_PROMPT_VERSIONS

_CITATION_RE = re.compile(r"^# [^:\n]+: .* \(([^()]+:\d+-\d+)\)$", re.MULTILINE)


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class RepeatabilityObservation(BaseModel):
    finding_id: int
    repetition: int
    pipeline_run_id: int
    verdict: FalsificationStatus
    confidence: float
    citations: list[str] = Field(default_factory=list)
    evidence_characters: int
    calls: int
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    known_tokens: int
    unknown_usage_calls: int
    latency_ms: int
    calculated_cost_usd: float


class RepeatabilityResult(BaseModel):
    schema_version: int = 1
    optimization: str = "OPT-004"
    status: str
    receipt_digest: str
    provider: str
    model: str
    prompt_versions: dict[str, str]
    observations: list[RepeatabilityObservation]
    aggregate_usage: dict[str, int | float]
    subject_metrics: list[dict]
    descriptive_only: bool = True
    production_verdicts_persisted: bool = False


def _jaccard(left: set[str], right: set[str]) -> float | None:
    union = left | right
    return len(left & right) / len(union) if union else None


def _subject_metrics(observations: list[RepeatabilityObservation]) -> list[dict]:
    result = []
    for finding_id in sorted({item.finding_id for item in observations}):
        rows = [item for item in observations if item.finding_id == finding_id]
        confidences = [item.confidence for item in rows]
        overlaps = [
            _jaccard(set(left.citations), set(right.citations))
            for index, left in enumerate(rows)
            for right in rows[index + 1:]
        ]
        result.append({
            "finding_id": finding_id,
            "observations": len(rows),
            "verdict_sequence": [item.verdict.value for item in rows],
            "verdict_agreement": len({item.verdict for item in rows}) == 1,
            "all_pairs_citation_jaccard": overlaps,
            "confidence_range": (
                max(confidences) - min(confidences) if confidences else None
            ),
            "confidence_standard_deviation": (
                math.sqrt(sum((value - sum(confidences) / len(confidences)) ** 2
                              for value in confidences) / len(confidences))
                if confidences else None
            ),
            "evidence_character_range": (
                [min(item.evidence_characters for item in rows),
                 max(item.evidence_characters for item in rows)] if rows else None
            ),
        })
    return result


def _verify_inputs(receipt: dict, config: Config):
    subjects = receipt["subjects"]
    findings = []
    for subject in subjects:
        finding = db.get_finding(subject["finding_id"], config)
        if finding is None:
            raise ValueError(f"finding #{subject['finding_id']} does not exist")
        actual = _digest(finding.model_dump(mode="json"))
        if actual != subject["finding_row_digest"]:
            raise ValueError(f"finding #{finding.id} digest changed: {actual}")
        findings.append(finding)
    if len({finding.repo_id for finding in findings}) != 1:
        raise ValueError("repeatability subjects must share one frozen repository")
    snapshot_path, commit = latest_snapshot(config, findings[0].repo_id)
    if commit != receipt["repository"]["snapshot_commit"]:
        raise ValueError(f"snapshot commit changed: {commit}")
    architecture = load_architecture(findings[0].repo_id, commit, config)
    actual_arch = _digest(architecture.model_dump(mode="json"))
    expected_arch = receipt["held_constant_digests"]["architecture_artifact"]
    if actual_arch != expected_arch:
        raise ValueError(f"architecture digest changed: {actual_arch}")
    index = RetrievalIndex().build(snapshot_path)
    actual_index = index.content_digest()
    expected_index = receipt["held_constant_digests"]["retrieval_index"]
    if actual_index != expected_index:
        raise ValueError(f"retrieval index digest changed: {actual_index}")
    return findings, snapshot_path, commit, architecture, index


def _retained_observation(
    source: str, repo_id: str, config: Config
) -> RepeatabilityObservation | None:
    """Reuse a completed exact observation and refuse ambiguous/failed prior attempts."""
    matches = [
        run for run in db.list_pipeline_runs(config, repo_id=repo_id)
        if run.source == source
    ]
    if not matches:
        return None
    latest = matches[0]
    if latest.status is not RunStatus.COMPLETED:
        raise RuntimeError(
            f"prior observation run #{latest.id} is {latest.status}; refusing to rebill it"
        )
    stages = db.list_stage_runs(latest.id, config)
    stage = next((item for item in stages if item.stage == "opt-004-repeatability"), None)
    if stage is None or stage.status is not RunStatus.COMPLETED:
        raise RuntimeError(f"completed run #{latest.id} lacks a completed observation summary")
    return RepeatabilityObservation.model_validate(stage.summary)


def run_repeatability(
    receipt_path: Path,
    *,
    approved_receipt_digest: str,
    config: Config | None = None,
    llm: LLMClient | None = None,
) -> RepeatabilityResult:
    """Execute six fresh, metered observations only for an explicitly approved receipt."""
    config = config or get_config()
    receipt = json.loads(Path(receipt_path).read_text(encoding="utf-8"))
    receipt_digest = _digest(receipt)
    if receipt_digest != approved_receipt_digest:
        raise ValueError("approved receipt digest does not match the execution receipt")
    budget = receipt["proposed_aggregate_budget"]
    expected_instrument = receipt["instrument"]
    if (config.llm.provider, config.model.name) != (
        expected_instrument["provider"], expected_instrument["model"]
    ):
        raise ValueError("configured provider/model differs from the frozen receipt")
    findings, snapshot_path, commit, architecture, index = _verify_inputs(receipt, config)
    profile = next(item for item in DEFAULT_PROFILES if item.name == "standard")
    observations: list[RepeatabilityObservation] = []
    aggregate_calls = aggregate_tokens = 0
    aggregate_cost = 0.0
    client = llm or get_llm_client(config)

    for finding in findings:
        for repetition in range(1, expected_instrument["repetitions_per_subject"] + 1):
            _verify_inputs(receipt, config)
            source = (
                f"opt-004:{receipt_digest}:finding-{finding.id}:repetition-{repetition}"
            )
            retained = _retained_observation(source, finding.repo_id, config)
            if retained is not None:
                observations.append(retained)
                aggregate_calls += retained.calls
                aggregate_tokens += retained.known_tokens
                aggregate_cost += retained.calculated_cost_usd
                continue
            if aggregate_calls + 4 > budget["maximum_provider_calls"]:
                raise RuntimeError("aggregate provider-call ceiling cannot admit next observation")
            if aggregate_tokens >= budget["maximum_provider_reported_tokens"]:
                raise RuntimeError("aggregate provider-token ceiling exhausted")
            pipeline = db.start_pipeline_run(
                source, config
            )
            db.update_pipeline_run_identity(pipeline.id, finding.repo_id, commit, config)
            db.start_stage_run(pipeline.id, "opt-004-repeatability", config)
            evidence: list[str] = []
            try:
                with model_usage_scope(pipeline.id):
                    outcome = challenge_finding(
                        finding, architecture, client, index=index, config=config,
                        self_critique=True, snapshot_commit=commit,
                        resolution=profile.challenger_resolution(),
                        evidence_observer=lambda _iteration, block: evidence.append(block),
                        minimum_iterations=2, persist_artifacts=False,
                    )
                rows = db.list_model_usage(config, pipeline_run_id=pipeline.id)
                usage = db.summarize_model_usage(pipeline.id, config)
                cost = calculate_provider_cost(rows)
                if usage["unknown_usage_calls"] or cost.usd is None:
                    raise RuntimeError("observation lacks authoritative priced provider usage")
                known_tokens = sum(usage[key] for key in (
                    "input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens"
                ))
                observation = RepeatabilityObservation(
                    finding_id=finding.id, repetition=repetition,
                    pipeline_run_id=pipeline.id, verdict=outcome.status,
                    confidence=outcome.confidence,
                    citations=sorted({citation for block in evidence
                                      for citation in _CITATION_RE.findall(block)}),
                    evidence_characters=sum(len(block) for block in evidence),
                    calls=usage["calls"], input_tokens=usage["input_tokens"],
                    output_tokens=usage["output_tokens"],
                    cache_read_tokens=usage["cache_read_tokens"],
                    cache_write_tokens=usage["cache_write_tokens"],
                    known_tokens=known_tokens,
                    unknown_usage_calls=usage["unknown_usage_calls"],
                    latency_ms=usage["latency_ms"], calculated_cost_usd=float(cost.usd),
                )
                observations.append(observation)
                aggregate_calls += observation.calls
                aggregate_tokens += observation.known_tokens
                aggregate_cost += observation.calculated_cost_usd
                if aggregate_calls > budget["maximum_provider_calls"]:
                    raise RuntimeError("aggregate provider-call ceiling exceeded")
                if aggregate_tokens > budget["maximum_provider_reported_tokens"]:
                    raise RuntimeError("aggregate provider-token ceiling exceeded")
                if aggregate_cost > budget["maximum_usd"]:
                    raise RuntimeError("aggregate provider-cost ceiling exceeded")
            except BaseException as exc:
                db.finish_stage_run(
                    pipeline.id, "opt-004-repeatability", RunStatus.FAILED,
                    failure_detail=f"{type(exc).__name__}: {exc}"[:4000], config=config,
                )
                db.finish_pipeline_run(
                    pipeline.id, RunStatus.FAILED, failed_stage="opt-004-repeatability",
                    failure_detail=f"{type(exc).__name__}: {exc}"[:4000], config=config,
                )
                raise
            db.finish_stage_run(
                pipeline.id, "opt-004-repeatability", RunStatus.COMPLETED,
                summary=observation.model_dump(mode="json"), config=config,
            )
            db.finish_pipeline_run(pipeline.id, RunStatus.COMPLETED, config=config)

    return RepeatabilityResult(
        status="complete", receipt_digest=receipt_digest,
        provider=config.llm.provider, model=config.model.name,
        prompt_versions={"falsify": STAGE_PROMPT_VERSIONS["falsify"]},
        observations=observations,
        aggregate_usage={
            "calls": aggregate_calls, "known_tokens": aggregate_tokens,
            "calculated_cost_usd": round(aggregate_cost, 6),
        },
        subject_metrics=_subject_metrics(observations),
    )

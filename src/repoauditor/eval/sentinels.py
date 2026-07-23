"""Method-of-manufactured-solutions controls for the falsification instrument.

The answer key lives outside the scanned snapshot. These fixed positive and negative cases
qualify whether the configured falsification path can recover known answers at run time;
they are not training data and are not evidence of performance on real repositories.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, Field, model_validator

from ..config import Config, get_config
from ..detect.retrieval import RetrievalIndex
from ..falsify import challenge_finding
from ..llm import LLMClient, get_llm_client
from ..map import ArchitectureMap, EntryPoint, TrustBoundary
from ..store.models import FalsificationStatus, Finding
from .regression import STAGE_PROMPT_VERSIONS


class SentinelCase(BaseModel):
    id: str
    title: str
    file: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    citation_snippet: str
    severity: str
    expected: FalsificationStatus
    ground_truth_basis: str = Field(min_length=1)

    @model_validator(mode="after")
    def _terminal_answer(self) -> "SentinelCase":
        if self.expected not in {
            FalsificationStatus.CONFIRMED,
            FalsificationStatus.KILLED,
        }:
            raise ValueError("manufactured sentinel answers must be confirmed or killed")
        if self.line_end < self.line_start:
            raise ValueError("sentinel line_end must be >= line_start")
        return self


class SentinelManifest(BaseModel):
    schema_version: str
    kind: str
    purpose: str
    cases: list[SentinelCase] = Field(min_length=2)

    @model_validator(mode="after")
    def _balanced_and_unique(self) -> "SentinelManifest":
        if len({case.id for case in self.cases}) != len(self.cases):
            raise ValueError("manufactured sentinel ids must be unique")
        answers = {case.expected for case in self.cases}
        if answers != {
            FalsificationStatus.CONFIRMED,
            FalsificationStatus.KILLED,
        }:
            raise ValueError("sentinel cohort requires positive and negative controls")
        return self


class SentinelObservation(BaseModel):
    sentinel_id: str
    expected: FalsificationStatus
    observed: FalsificationStatus
    passed: bool
    confidence: float
    rationale: str


class SentinelQualification(BaseModel):
    schema_version: str
    snapshot_digest: str
    provider: str
    model: str
    prompt_version: str
    sampling_seed: int | None
    observations: list[SentinelObservation]
    positive_recovery: float
    negative_recovery: float
    overall_recovery: float
    qualified: bool
    evidence_scope: str = (
        "manufactured controls only; not real-world precision or recall"
    )


def _snapshot_digest(snapshot: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in snapshot.rglob("*") if item.is_file()):
        digest.update(path.relative_to(snapshot).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def load_sentinel_fixture(fixture_root: Path) -> tuple[SentinelManifest, Path, str]:
    """Load and validate a fixture without exposing its answer key to retrieval."""
    fixture_root = Path(fixture_root)
    snapshot = fixture_root / "snapshot"
    manifest_path = fixture_root / "manifest.json"
    if not snapshot.is_dir() or not manifest_path.is_file():
        raise ValueError(
            f"manufactured sentinel fixture is incomplete: {fixture_root}"
        )
    manifest = SentinelManifest.model_validate_json(
        manifest_path.read_text(encoding="utf-8")
    )
    if manifest.kind != "manufactured_solution":
        raise ValueError("sentinel manifest kind must be manufactured_solution")
    for case in manifest.cases:
        source_path = (snapshot / case.file).resolve()
        try:
            source_path.relative_to(snapshot.resolve())
        except ValueError as exc:
            raise ValueError(f"sentinel {case.id} escapes the snapshot") from exc
        if not source_path.is_file():
            raise ValueError(f"sentinel {case.id} source file is missing")
        lines = source_path.read_text(encoding="utf-8").splitlines()
        cited = "\n".join(lines[case.line_start - 1:case.line_end])
        if case.citation_snippet not in cited:
            raise ValueError(
                f"sentinel {case.id} citation is not present in its declared range"
            )
    return manifest, snapshot, _snapshot_digest(snapshot)


def evaluate_manufactured_sentinels(
    fixture_root: Path,
    *,
    config: Config | None = None,
    llm: LLMClient | None = None,
) -> SentinelQualification:
    """Judge fixed knowns without persisting any finding or falsification artifact."""
    config = config or get_config()
    llm = llm or get_llm_client(config)
    manifest, snapshot, digest = load_sentinel_fixture(fixture_root)
    index = RetrievalIndex().build(snapshot)
    boundary = TrustBoundary(
        id=1,
        name="manufactured public edge",
        description="Fixed external-input boundary for instrument qualification.",
    )
    architecture = ArchitectureMap(
        repo_id="manufactured_sentinels",
        commit=digest,
        trust_boundaries=[boundary],
        entry_points=[
            EntryPoint(
                name="manufactured HTTP handlers",
                location="app.py",
                trust_boundary=boundary.name,
            )
        ],
    )

    observations: list[SentinelObservation] = []
    for ordinal, case in enumerate(manifest.cases, 1):
        finding = Finding(
            id=ordinal,
            repo_id="manufactured_sentinels",
            title=case.title,
            file=case.file,
            line_start=case.line_start,
            line_end=case.line_end,
            citation_snippet=case.citation_snippet,
            source_tool="manufactured-sentinel",
            confidence=1.0,
            severity=case.severity,
            trust_boundary_id=boundary.id,
        )
        outcome = challenge_finding(
            finding,
            architecture,
            llm,
            index=index,
            config=config,
            snapshot_commit=digest,
            persist_artifacts=False,
        )
        observations.append(SentinelObservation(
            sentinel_id=case.id,
            expected=case.expected,
            observed=outcome.status,
            passed=outcome.status is case.expected,
            confidence=outcome.confidence,
            rationale=outcome.rationale,
        ))

    positives = [
        item for item in observations
        if item.expected is FalsificationStatus.CONFIRMED
    ]
    negatives = [
        item for item in observations
        if item.expected is FalsificationStatus.KILLED
    ]
    positive_recovery = sum(item.passed for item in positives) / len(positives)
    negative_recovery = sum(item.passed for item in negatives) / len(negatives)
    overall = sum(item.passed for item in observations) / len(observations)
    return SentinelQualification(
        schema_version=manifest.schema_version,
        snapshot_digest=digest,
        provider=config.llm.provider,
        model=config.model.name,
        prompt_version=STAGE_PROMPT_VERSIONS["falsify"],
        sampling_seed=llm.sampling_seed,
        observations=observations,
        positive_recovery=positive_recovery,
        negative_recovery=negative_recovery,
        overall_recovery=overall,
        qualified=all(item.passed for item in observations),
    )


def render_sentinel_qualification(result: SentinelQualification) -> str:
    rows = [
        (
            f"{'PASS' if item.passed else 'MISS'} {item.sentinel_id}: "
            f"expected={item.expected.value} observed={item.observed.value} "
            f"confidence={item.confidence:.3f}"
        )
        for item in result.observations
    ]
    seed = (
        str(result.sampling_seed)
        if result.sampling_seed is not None
        else "unavailable (repeatability not isolated)"
    )
    return "\n".join([
        "Manufactured-sentinel instrument qualification",
        *rows,
        (
            f"positive_recovery={result.positive_recovery:.3f}; "
            f"negative_recovery={result.negative_recovery:.3f}; "
            f"overall={result.overall_recovery:.3f}; "
            f"qualified={'yes' if result.qualified else 'no'}"
        ),
        (
            f"instrument={result.provider}/{result.model}; sampling_seed={seed}; "
            f"scope={result.evidence_scope}"
        ),
    ])

"""Bounded, isolated instrument qualification for OPT-009.

This module is intentionally separate from prospective collection.  It reproduces
aggregate wave-one accounting, exercises the frozen parser/citation boundary locally,
and can run exactly one positive/negative semantic canary pair against an upstream
benchmark.  Canary findings are never persisted to the production store or cohort.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

from ..analyze.provider_cost import calculate_provider_cost
from ..config import Config, PathsConfig, get_config
from ..detect.ensemble import (
    DETECTION_REQUEST_CONTENT_MAX_BYTES,
    DETECTION_REGION_MAX_BYTES,
    LENS_PROMPT_VERSIONS,
    LensCandidate,
    LensFindings,
    _LENS_PROMPTS,
    _assert_provider_content_bound,
    _call_lens,
    _canonicalize_citation,
)
from ..detect.retrieval import RetrievalIndex
from ..llm import AnthropicBackend
from ..llm.prompt_security import delimit_repository_evidence, secure_system_prompt
from ..sourcefiles import read_numbered_bounded
from ..store import db
from ..store.models import ModelUsage, Severity, ValidationFailure
from ..triage.acquisition_funnel import classify_review_path


ROOT = Path(__file__).resolve().parents[3]
RECEIPT = ROOT / "docs/optimizations/opt-009-instrument-qualification-receipt-2026-08-13.json"
ARTIFACT_DIR = ROOT / "data/artifacts/opt009-instrument-qualification"
OFFLINE_RESULT = ARTIFACT_DIR / "offline-audit.json"
SCRATCH_DB = ARTIFACT_DIR / "scratch.sqlite"
POSITIVE_REL = "testcode/BenchmarkTest00099.py"
NEGATIVE_REL = "testcode/BenchmarkTest00011.py"
FIXTURE_ROOT = ROOT / "tests/fixtures/owasp_benchmark_py/snapshot"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _record_path(record: dict) -> Path:
    return (RECEIPT.parent / record["path"]).resolve()


def _bound_records(receipt: dict) -> list[tuple[str, dict]]:
    records: list[tuple[str, dict]] = []
    records.extend((f"retained_evidence.{key}", value) for key, value in receipt["retained_evidence"].items())
    records.extend(
        (f"frozen_instrument.{key}", receipt["frozen_instrument"][key])
        for key in ("owasp_prompt", "prompt_security", "ensemble", "planner", "source_bounds")
    )
    benchmark = receipt["semantic_canary"]["benchmark"]
    records.extend((f"semantic_canary.benchmark.{key}", benchmark[key]) for key in ("ground_truth", "positive", "negative"))
    records.append(("pricing", receipt["pricing"]))
    return records


def _scratch_config() -> Config:
    config = get_config().model_copy(deep=True)
    config.paths = PathsConfig(
        data_dir=ARTIFACT_DIR,
        raw_dir=ARTIFACT_DIR / "raw-unused",
        db_path=SCRATCH_DB,
    )
    config.llm.max_retries = 0
    config.llm.max_calls_per_pipeline_run = 2
    config.llm.max_tokens_per_pipeline_run = 30_000
    return config


def _region(relative_path: str) -> tuple[str, dict]:
    numbered, evidence = read_numbered_bounded(FIXTURE_ROOT / relative_path, 160_000)
    region = f"# FILE: {relative_path}\n{numbered}"
    region_bytes = len(region.encode("utf-8"))
    system = secure_system_prompt(_LENS_PROMPTS["owasp"])
    user = delimit_repository_evidence(region)
    request_bytes = _assert_provider_content_bound(system, user, LensFindings)
    if region_bytes > DETECTION_REGION_MAX_BYTES:
        raise RuntimeError("qualification region exceeded the frozen byte bound")
    return region, {
        "region_utf8_bytes": region_bytes,
        "request_content_utf8_bytes": request_bytes,
        "source_truncated": bool(evidence["truncated"]),
    }


def run_offline_audit() -> dict:
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    digest_checks = []
    for name, record in _bound_records(receipt):
        actual = _sha256(_record_path(record))
        digest_checks.append({"name": name, "passed": actual == record["sha256"]})

    config = get_config()
    store_before = _sha256(config.db_path)
    region_runs = []
    stage_summaries = []
    for pipeline_id, repo_id, commit in (
        (115, "opt009-wave1-vikunja", "9403ed15264e"),
        (116, "opt009-wave1-miniflux", "106cdd09e155"),
    ):
        region_runs.extend(
            item for item in db.list_detection_regions(repo_id, commit, config)
            if item.lens == "owasp"
        )
        stage = next(item for item in db.list_stage_runs(pipeline_id, config) if item.stage == "detect")
        stage_summaries.append(stage.summary)

    llm_findings = sum(
        finding.source_lens is not None
        for repo_id in ("opt009-wave1-vikunja", "opt009-wave1-miniflux")
        for finding in db.list_findings(repo_id, config)
    )
    selection_bases: Counter[str] = Counter()
    path_classes: Counter[str] = Counter()
    primary_bytes = retrieval_bytes = 0
    retrieval_larger = primary_truncated = retrieval_truncated = 0
    for summary in stage_summaries:
        basis_by_file = {
            item["file"]: item["basis"]
            for item in summary.get("selected_regions", [])
        }
        for item in summary["context_expansions"]:
            path = item["primary_file"]
            selection_bases[basis_by_file.get(path, "not-persisted-in-stage-summary").split(":", 1)[0]] += 1
            path_classes[str(classify_review_path(path))] += 1
            bound = item["evidence_bound"]
            primary_bytes += int(bound["primary_sent_bytes"])
            retrieval_bytes += int(bound["retrieval_sent_bytes"])
            retrieval_larger += int(bound["retrieval_sent_bytes"] > bound["primary_sent_bytes"])
            primary_truncated += int(bool(bound["primary_truncated"]))
            retrieval_truncated += int(bool(bound["retrieval_truncated"]))

    index = RetrievalIndex().build(FIXTURE_ROOT)
    scripted = LensFindings.model_validate({
        "findings": [{
            "title": "scripted parser qualification",
            "file": POSITIVE_REL,
            "line_start": 49,
            "line_end": 49,
            "citation_snippet": "cur.execute(sql)",
            "severity": "critical",
            "confidence": 0.9,
        }]
    })
    scratch_config = _scratch_config()
    anchored = _canonicalize_citation(
        scripted.findings[0], index, POSITIVE_REL, "owasp", scratch_config
    )
    empty = LensFindings.model_validate({"findings": []})
    _, positive_bound = _region(POSITIVE_REL)
    _, negative_bound = _region(NEGATIVE_REL)
    store_after = _sha256(config.db_path)

    checks = {
        "all_bound_digests_match": all(item["passed"] for item in digest_checks),
        "completed_owasp_regions": sum(str(item.status) == "completed" for item in region_runs) == 12,
        "region_finding_count_zero": sum(item.finding_count for item in region_runs) == 0,
        "persisted_llm_findings_zero": llm_findings == 0,
        "scripted_positive_parses_and_anchors": anchored is not None and "cur.execute(sql)" in anchored.citation_snippet,
        "scripted_negative_parses_empty": len(empty.findings) == 0,
        "canary_requests_within_bounds": all(
            item["region_utf8_bytes"] <= DETECTION_REGION_MAX_BYTES
            and item["request_content_utf8_bytes"] <= DETECTION_REQUEST_CONTENT_MAX_BYTES
            for item in (positive_bound, negative_bound)
        ),
        "production_store_unchanged": store_before == store_after,
    }
    result = {
        "schema_version": 1,
        "optimization": "OPT-009",
        "stage": "offline-instrument-audit",
        "status": "passed" if all(checks.values()) else "failed",
        "digest_checks": digest_checks,
        "checks": checks,
        "retained_accounting": {
            "completed_owasp_regions": sum(str(item.status) == "completed" for item in region_runs),
            "region_finding_count": sum(item.finding_count for item in region_runs),
            "persisted_llm_origin_findings": llm_findings,
        },
        "aggregate_region_diagnostics": {
            "selection_basis_counts": dict(sorted(selection_bases.items())),
            "path_class_counts": dict(sorted(path_classes.items())),
            "primary_sent_utf8_bytes": primary_bytes,
            "retrieval_sent_utf8_bytes": retrieval_bytes,
            "regions_where_retrieval_exceeded_primary": retrieval_larger,
            "primary_truncations": primary_truncated,
            "retrieval_truncations": retrieval_truncated,
        },
        "canary_request_bounds": {"positive": positive_bound, "negative": negative_bound},
        "production_store": {"before_sha256": store_before, "after_sha256": store_after},
        "candidate_identities_disclosed": 0,
        "source_excerpts_persisted": 0,
    }
    _canonical_write(OFFLINE_RESULT, result)
    return result


def _usage_row(config: Config, *, started: float, available: bool, usage) -> None:
    db.insert_model_usage(
        ModelUsage(
            stage="qualification",
            module="detect",
            prompt_version=LENS_PROMPT_VERSIONS["owasp"],
            provider="anthropic",
            model="claude-opus-4-8",
            usage_available=available,
            input_tokens=usage.input_tokens if available else None,
            output_tokens=usage.output_tokens if available else None,
            cache_read_tokens=usage.cache_read_tokens if available else None,
            cache_write_tokens=usage.cache_write_tokens if available else None,
            latency_ms=max(0, round((time.monotonic() - started) * 1000)),
        ),
        config,
    )


class _QualificationClient:
    """One-attempt client with authoritative usage and sanitized failure chronology."""

    def __init__(self, config: Config):
        self._config = config
        self._backend = AnthropicBackend(config)

    def call(self, *, module, prompt_version, system, user, schema, context=None):
        started = time.monotonic()
        try:
            raw = self._backend.complete(
                system=system, user=user, schema=schema, context=context or {}
            )
            value = schema.model_validate_json(raw)
        except BaseException as exc:
            usage = self._backend.last_usage
            _usage_row(
                self._config,
                started=started,
                available=usage is not None,
                usage=usage,
            )
            db.insert_validation_failure(
                ValidationFailure(
                    module=module,
                    prompt_version=prompt_version,
                    raw_response="",
                    validation_error=f"sanitized qualification failure: {type(exc).__name__}",
                ),
                self._config,
            )
            raise
        usage = self._backend.last_usage
        _usage_row(
            self._config,
            started=started,
            available=usage is not None,
            usage=usage,
        )
        return SimpleNamespace(value=value, confidence=None, low_confidence=False)


def _validated_counts(completion: LensFindings, relative_path: str, anchor: str | None) -> dict:
    index = RetrievalIndex().build(FIXTURE_ROOT)
    valid = invalid = anchor_matches = 0
    for candidate in completion.findings:
        locations = index.locate_citation(candidate.citation_snippet)
        if len(locations) != 1:
            invalid += 1
            continue
        location = locations[0]
        if location.file != relative_path:
            invalid += 1
            continue
        valid += 1
        anchor_matches += int(anchor is not None and anchor in candidate.citation_snippet)
    return {
        "schema_valid_findings": len(completion.findings),
        "citation_valid_findings": valid,
        "citation_invalid_findings": invalid,
        "expected_anchor_matches": anchor_matches,
    }


def run_qualification(output: Path) -> dict:
    started = time.monotonic()
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    offline = run_offline_audit()
    if offline["status"] != "passed":
        result = {
            "schema_version": 1,
            "optimization": "OPT-009",
            "status": "stopped-offline-gate-failed",
            "offline_audit_sha256": _sha256(OFFLINE_RESULT),
            "provider_attempts": 0,
            "disposition": "instrument-not-qualified",
        }
        _canonical_write(output, result)
        return result

    if SCRATCH_DB.exists():
        raise RuntimeError("qualification scratch database existed before semantic gate")
    config = _scratch_config()
    db.init_db(config)
    llm = _QualificationClient(config)
    cases = (("positive", POSITIVE_REL, "cur.execute(sql)"), ("negative", NEGATIVE_REL, None))
    case_results: list[dict] = []
    for case, relative_path, anchor in cases:
        region, bounds = _region(relative_path)
        before = len(db.list_model_usage(config))
        call_started = time.monotonic()
        try:
            completion = _call_lens(
                llm,
                "owasp",
                region,
                context={"stage": "qualification", "case": case},
            )
        except BaseException as exc:
            after = db.list_model_usage(config)
            if len(after) == before:
                backend = getattr(llm, "_backend")
                usage = getattr(backend, "last_usage", None)
                _usage_row(config, started=call_started, available=usage is not None, usage=usage)
                after = db.list_model_usage(config)
            case_results.append({
                "case": case,
                "status": "provider-or-validation-failure",
                "error_type": type(exc).__name__,
                "authoritative_usage": bool(after[-1].usage_available),
                "request_bounds": bounds,
            })
            break
        usage_rows = db.list_model_usage(config)
        usage = usage_rows[-1]
        validated = _validated_counts(completion.value, relative_path, anchor)
        case_results.append({
            "case": case,
            "status": "completed",
            "authoritative_usage": bool(usage.usage_available),
            "request_bounds": bounds,
            **validated,
        })
        if not usage.usage_available:
            break

    usage_rows = db.list_model_usage(config)
    cost = calculate_provider_cost(usage_rows)
    tokens = sum(
        (row.input_tokens or 0) + (row.output_tokens or 0)
        + (row.cache_read_tokens or 0) + (row.cache_write_tokens or 0)
        for row in usage_rows if row.usage_available
    )
    positive = next((item for item in case_results if item["case"] == "positive"), {})
    negative = next((item for item in case_results if item["case"] == "negative"), {})
    semantic_passed = (
        len(case_results) == 2
        and positive.get("expected_anchor_matches", 0) >= 1
        and positive.get("citation_valid_findings", 0) >= 1
        and negative.get("citation_valid_findings") == 0
        and all(item.get("authoritative_usage") for item in case_results)
        and len(usage_rows) <= 2
        and tokens <= 30_000
        and cost.status == "priced"
        and float(cost.usd or 0) <= 0.5
    )
    store_after = _sha256(get_config().db_path)
    result = {
        "schema_version": 1,
        "optimization": "OPT-009",
        "status": "qualification-passed" if semantic_passed else "qualification-failed",
        "offline_audit": {"status": offline["status"], "sha256": _sha256(OFFLINE_RESULT)},
        "semantic_canary": {
            "cases": case_results,
            "provider_attempts": len(usage_rows),
            "provider_reported_tokens": tokens,
            "known_dated_price_cost_status": cost.status,
            "known_dated_price_cost_usd": float(cost.usd) if cost.usd is not None else None,
            "unknown_usage_attempts": sum(not row.usage_available for row in usage_rows),
        },
        "production_store": {
            "expected_sha256": json.loads(RECEIPT.read_text())["retained_evidence"]["production_store"]["sha256"],
            "after_sha256": store_after,
            "unchanged": store_after == json.loads(RECEIPT.read_text())["retained_evidence"]["production_store"]["sha256"],
        },
        "resource_accounting": {
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "new_data_bytes": sum(path.stat().st_size for path in ARTIFACT_DIR.rglob("*") if path.is_file()),
            "ceiling_breaches": [],
        },
        "exclusions": {
            "production_candidates_persisted": 0,
            "source_excerpts_persisted": 0,
            "human_reviews": 0,
            "assessments": 0,
            "labels": 0,
            "models_trained": 0,
            "planner_or_prompt_changes": 0,
            "source_activations": 0,
        },
        "disposition": "instrument-qualified-stop" if semantic_passed else "instrument-not-qualified-stop",
    }
    if result["resource_accounting"]["new_data_bytes"] > 10_485_760:
        result["resource_accounting"]["ceiling_breaches"].append("new-data")
    if result["resource_accounting"]["elapsed_seconds"] > 1800:
        result["resource_accounting"]["ceiling_breaches"].append("elapsed-time")
    if not result["production_store"]["unchanged"]:
        result["resource_accounting"]["ceiling_breaches"].append("production-store-mutation")
    _canonical_write(output, result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ARTIFACT_DIR / "result.json")
    args = parser.parse_args()
    result = run_qualification(args.output)
    print(json.dumps({
        "status": result["status"],
        "provider_attempts": result.get("semantic_canary", {}).get("provider_attempts", result.get("provider_attempts", 0)),
        "provider_reported_tokens": result.get("semantic_canary", {}).get("provider_reported_tokens", 0),
        "known_dated_price_cost_usd": result.get("semantic_canary", {}).get("known_dated_price_cost_usd"),
    }, sort_keys=True))


if __name__ == "__main__":
    main()

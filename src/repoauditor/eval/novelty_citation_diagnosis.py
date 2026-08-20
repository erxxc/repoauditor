"""Final aggregate-only citation diagnosis for OPT-009."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
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
)
from ..detect.retrieval import RetrievalIndex
from ..llm import AnthropicBackend
from ..llm.prompt_security import delimit_repository_evidence, secure_system_prompt
from ..sourcefiles import read_numbered_bounded
from ..store import db
from ..store.models import ModelUsage, ValidationFailure


ROOT = Path(__file__).resolve().parents[3]
RECEIPT = ROOT / "docs/optimizations/opt-009-citation-diagnosis-receipt-2026-08-13.json"
ARTIFACT_DIR = ROOT / "data/artifacts/opt009-citation-diagnosis"
OFFLINE_RESULT = ARTIFACT_DIR / "offline-diagnosis.json"
SCRATCH_DB = ARTIFACT_DIR / "scratch.sqlite"
FIXTURE_ROOT = ROOT / "tests/fixtures/owasp_benchmark_py/snapshot"
POSITIVE_REL = "testcode/BenchmarkTest00099.py"
ANCHOR = "cur.execute(sql)"
CLARIFICATION = ROOT / "docs/optimizations/opt-009-citation-diagnostic-clarification-2026-08-13.md"
_DISPLAY_PREFIX = re.compile(r"(?m)^[ \t]*\d+\t")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _record_path(record: dict) -> Path:
    return (RECEIPT.parent / record["path"]).resolve()


def _bound_records(receipt: dict) -> list[tuple[str, dict]]:
    records = [
        (f"retained_evidence.{key}", value)
        for key, value in receipt["retained_evidence"].items()
    ]
    records.extend(
        (f"frozen_inputs.{key}", receipt["frozen_inputs"][key])
        for key in (
            "owasp_prompt",
            "ensemble",
            "source_rendering",
            "benchmark_ground_truth",
            "benchmark_positive",
            "diagnostic_clarification",
        )
    )
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


def _region_and_requests() -> tuple[str, dict[str, int | bool]]:
    numbered, evidence = read_numbered_bounded(
        FIXTURE_ROOT / POSITIVE_REL, 160_000
    )
    region = f"# FILE: {POSITIVE_REL}\n{numbered}"
    region_bytes = len(region.encode("utf-8"))
    user = delimit_repository_evidence(region)
    exact_system = secure_system_prompt(_LENS_PROMPTS["owasp"])
    clarified_system = secure_system_prompt(
        _LENS_PROMPTS["owasp"] + "\n\n" + CLARIFICATION.read_text(encoding="utf-8")
    )
    exact_bytes = _assert_provider_content_bound(exact_system, user, LensFindings)
    clarified_bytes = _assert_provider_content_bound(
        clarified_system, user, LensFindings
    )
    if region_bytes > DETECTION_REGION_MAX_BYTES:
        raise RuntimeError("diagnostic region exceeds the frozen byte bound")
    return region, {
        "region_utf8_bytes": region_bytes,
        "exact_request_content_utf8_bytes": exact_bytes,
        "clarified_request_content_utf8_bytes": clarified_bytes,
        "source_truncated": bool(evidence["truncated"]),
    }


def _canonical_status(candidate: LensCandidate, index: RetrievalIndex) -> str:
    locations = index.locate_citation(candidate.citation_snippet)
    if not locations:
        return "absent"
    declared = [item for item in locations if item.file == candidate.file]
    overlapping = [
        item
        for item in declared
        if item.line_start <= candidate.line_end
        and candidate.line_start <= item.line_end
    ]
    if len(overlapping) == 1 or len(declared) == 1 or len(locations) == 1:
        return "exact"
    return "ambiguous"


def _remove_display_prefixes(value: str) -> str:
    return _DISPLAY_PREFIX.sub("", value)


def _classify_candidate(candidate: LensCandidate, index: RetrievalIndex) -> tuple[str, bool]:
    if not candidate.citation_snippet.strip():
        return "absent", False
    status = _canonical_status(candidate, index)
    if status == "exact":
        return "exact", ANCHOR in candidate.citation_snippet
    if status == "ambiguous":
        return "ambiguous", False
    recovered = _remove_display_prefixes(candidate.citation_snippet)
    if recovered != candidate.citation_snippet:
        repaired = candidate.model_copy(update={"citation_snippet": recovered})
        recovered_status = _canonical_status(repaired, index)
        if recovered_status == "exact":
            return "display-prefix-recoverable", ANCHOR in recovered
        if recovered_status == "ambiguous":
            return "ambiguous", False
    return "other-nonverbatim", False


def run_offline_diagnosis() -> dict:
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    digest_checks = []
    for name, record in _bound_records(receipt):
        digest_checks.append({
            "name": name,
            "passed": _sha256(_record_path(record)) == record["sha256"],
        })

    production_store = get_config().db_path
    store_before = _sha256(production_store)
    index = RetrievalIndex().build(FIXTURE_ROOT)
    source_lines = (FIXTURE_ROOT / POSITIVE_REL).read_text(errors="replace").splitlines()
    anchor_line = next(i for i, line in enumerate(source_lines, 1) if ANCHOR in line)
    exact_candidate = LensCandidate(
        title="offline canonicalization probe",
        file=POSITIVE_REL,
        line_start=anchor_line,
        line_end=anchor_line,
        citation_snippet=ANCHOR,
        severity="critical",
        confidence=0.9,
    )
    numbered_candidate = exact_candidate.model_copy(
        update={"citation_snippet": f"{anchor_line}\t{ANCHOR}"}
    )
    exact_status = _canonical_status(exact_candidate, index)
    numbered_status = _canonical_status(numbered_candidate, index)
    recovered = _remove_display_prefixes(numbered_candidate.citation_snippet)
    recovered_candidate = numbered_candidate.model_copy(
        update={"citation_snippet": recovered}
    )
    recovered_status = _canonical_status(recovered_candidate, index)
    _, bounds = _region_and_requests()
    store_after = _sha256(production_store)
    checks = {
        "all_bound_digests_match": all(item["passed"] for item in digest_checks),
        "exact_unnumbered_citation_canonicalizes": exact_status == "exact",
        "display_prefixed_citation_fails_exact_canonicalization": numbered_status == "absent",
        "prefix_only_removal_recovers_exact_citation": (
            recovered_status == "exact" and recovered == ANCHOR
        ),
        "requests_within_frozen_bounds": (
            bounds["region_utf8_bytes"] <= DETECTION_REGION_MAX_BYTES
            and bounds["exact_request_content_utf8_bytes"]
            <= DETECTION_REQUEST_CONTENT_MAX_BYTES
            and bounds["clarified_request_content_utf8_bytes"]
            <= DETECTION_REQUEST_CONTENT_MAX_BYTES
        ),
        "production_store_unchanged": store_before == store_after,
    }
    result = {
        "schema_version": 1,
        "optimization": "OPT-009",
        "stage": "offline-citation-diagnosis",
        "status": "passed" if all(checks.values()) else "failed",
        "digest_checks": digest_checks,
        "checks": checks,
        "classification_counts": {
            "exact": int(exact_status == "exact") + int(recovered_status == "exact"),
            "display_prefix_rejected_before_recovery": int(numbered_status == "absent"),
            "display_prefix_recovered": int(recovered_status == "exact"),
        },
        "request_bounds": bounds,
        "production_store": {
            "before_sha256": store_before,
            "after_sha256": store_after,
        },
        "source_excerpts_persisted": 0,
        "candidate_identities_disclosed": 0,
    }
    _canonical_write(OFFLINE_RESULT, result)
    return result


def _insert_usage(config: Config, backend: AnthropicBackend, started: float) -> bool:
    usage = backend.last_usage
    db.insert_model_usage(
        ModelUsage(
            stage="citation-diagnosis",
            module="detect",
            prompt_version=LENS_PROMPT_VERSIONS["owasp"],
            provider="anthropic",
            model="claude-opus-4-8",
            usage_available=usage is not None,
            input_tokens=usage.input_tokens if usage else None,
            output_tokens=usage.output_tokens if usage else None,
            cache_read_tokens=usage.cache_read_tokens if usage else None,
            cache_write_tokens=usage.cache_write_tokens if usage else None,
            latency_ms=max(0, round((time.monotonic() - started) * 1000)),
        ),
        config,
    )
    return usage is not None


class _DiagnosticClient:
    """No-retry client retaining usage and sanitized failure type only."""

    def __init__(self, config: Config):
        self.config = config
        self.backend = AnthropicBackend(config)

    def call(self, *, module, prompt_version, system, user, schema, context=None):
        started = time.monotonic()
        try:
            raw = self.backend.complete(
                system=system, user=user, schema=schema, context=context or {}
            )
            value = schema.model_validate_json(raw)
        except BaseException as exc:
            _insert_usage(self.config, self.backend, started)
            db.insert_validation_failure(
                ValidationFailure(
                    module=module,
                    prompt_version=prompt_version,
                    raw_response="",
                    validation_error=f"sanitized citation diagnosis failure: {type(exc).__name__}",
                ),
                self.config,
            )
            raise
        _insert_usage(self.config, self.backend, started)
        return SimpleNamespace(value=value, confidence=None, low_confidence=False)


def _aggregate_completion(value: LensFindings) -> dict:
    index = RetrievalIndex().build(FIXTURE_ROOT)
    counts: Counter[str] = Counter()
    anchor_matches: Counter[str] = Counter()
    for candidate in value.findings:
        category, anchor_match = _classify_candidate(candidate, index)
        counts[category] += 1
        if anchor_match:
            anchor_matches[category] += 1
    return {
        "schema_valid_findings": len(value.findings),
        "citation_categories": {
            key: counts[key]
            for key in (
                "exact",
                "display-prefix-recoverable",
                "other-nonverbatim",
                "ambiguous",
                "absent",
            )
        },
        "anchor_matches": {
            "exact": anchor_matches["exact"],
            "display-prefix-recoverable": anchor_matches[
                "display-prefix-recoverable"
            ],
        },
    }


def _case_failure(case: str, exc: BaseException, usage_available: bool, bounds: dict) -> dict:
    return {
        "case": case,
        "status": "provider-or-validation-failure",
        "error_type": type(exc).__name__,
        "authoritative_usage": usage_available,
        "request_content_utf8_bytes": bounds[
            f"{case}_request_content_utf8_bytes"
        ],
    }


def _write_with_final_size(output: Path, result: dict) -> None:
    for _ in range(4):
        _canonical_write(output, result)
        size = sum(path.stat().st_size for path in ARTIFACT_DIR.rglob("*") if path.is_file())
        if result["resource_accounting"].get("new_data_bytes") == size:
            return
        result["resource_accounting"]["new_data_bytes"] = size
    _canonical_write(output, result)


def run_diagnosis(output: Path) -> dict:
    started = time.monotonic()
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=False)
    offline = run_offline_diagnosis()
    if offline["status"] != "passed":
        result = {
            "schema_version": 1,
            "optimization": "OPT-009",
            "status": "offline-diagnosis-failed",
            "offline_diagnosis_sha256": _sha256(OFFLINE_RESULT),
            "provider_attempts": 0,
            "recommendation": "close-opt009-at-current-scope",
        }
        _canonical_write(output, result)
        return result

    config = _scratch_config()
    db.init_db(config)
    client = _DiagnosticClient(config)
    region, bounds = _region_and_requests()
    cases: list[dict] = []

    try:
        exact = _call_lens(
            client,
            "owasp",
            region,
            context={"stage": "citation-diagnosis", "case": "exact"},
        )
    except BaseException as exc:
        rows = db.list_model_usage(config)
        cases.append(_case_failure("exact", exc, bool(rows[-1].usage_available), bounds))
    else:
        rows = db.list_model_usage(config)
        cases.append({
            "case": "exact",
            "status": "completed",
            "authoritative_usage": bool(rows[-1].usage_available),
            "request_content_utf8_bytes": bounds[
                "exact_request_content_utf8_bytes"
            ],
            **_aggregate_completion(exact.value),
        })

    if cases[-1]["authoritative_usage"]:
        clarified_system = secure_system_prompt(
            _LENS_PROMPTS["owasp"]
            + "\n\n"
            + CLARIFICATION.read_text(encoding="utf-8")
        )
        user = delimit_repository_evidence(region)
        try:
            clarified = client.call(
                module="detect",
                prompt_version=(
                    LENS_PROMPT_VERSIONS["owasp"]
                    + "+opt009-citation-format-diagnostic-v1"
                ),
                system=clarified_system,
                user=user,
                schema=LensFindings,
                context={"stage": "citation-diagnosis", "case": "clarified"},
            )
        except BaseException as exc:
            rows = db.list_model_usage(config)
            cases.append(
                _case_failure(
                    "clarified", exc, bool(rows[-1].usage_available), bounds
                )
            )
        else:
            rows = db.list_model_usage(config)
            cases.append({
                "case": "clarified",
                "status": "completed",
                "authoritative_usage": bool(rows[-1].usage_available),
                "request_content_utf8_bytes": bounds[
                    "clarified_request_content_utf8_bytes"
                ],
                **_aggregate_completion(clarified.value),
            })

    usage_rows = db.list_model_usage(config)
    cost = calculate_provider_cost(usage_rows)
    tokens = sum(
        (row.input_tokens or 0)
        + (row.output_tokens or 0)
        + (row.cache_read_tokens or 0)
        + (row.cache_write_tokens or 0)
        for row in usage_rows
        if row.usage_available
    )
    exact_case = next((item for item in cases if item["case"] == "exact"), {})
    clarified_case = next(
        (item for item in cases if item["case"] == "clarified"), {}
    )
    exact_categories = exact_case.get("citation_categories", {})
    clarified_categories = clarified_case.get("citation_categories", {})
    clarified_anchors = clarified_case.get("anchor_matches", {})
    success = (
        len(cases) == 2
        and all(item.get("authoritative_usage") for item in cases)
        and exact_categories.get("exact", 0) == 0
        and exact_categories.get("display-prefix-recoverable", 0) >= 1
        and clarified_categories.get("exact", 0) >= 1
        and clarified_anchors.get("exact", 0) >= 1
        and len(usage_rows) <= 2
        and tokens <= 30_000
        and cost.status == "priced"
        and float(cost.usd or 0) <= 0.5
    )
    expected_store = json.loads(RECEIPT.read_text(encoding="utf-8"))[
        "retained_evidence"
    ]["production_store"]["sha256"]
    store_after = _sha256(get_config().db_path)
    result = {
        "schema_version": 1,
        "optimization": "OPT-009",
        "status": (
            "bounded-citation-correction-supported"
            if success
            else "citation-diagnosis-inconclusive"
        ),
        "offline_diagnosis": {
            "status": offline["status"],
            "sha256": _sha256(OFFLINE_RESULT),
        },
        "provider_diagnosis": {
            "cases": cases,
            "provider_attempts": len(usage_rows),
            "attempts_with_authoritative_usage": sum(
                row.usage_available for row in usage_rows
            ),
            "unknown_usage_attempts": sum(
                not row.usage_available for row in usage_rows
            ),
            "provider_reported_tokens": tokens,
            "known_dated_price_cost_status": cost.status,
            "known_dated_price_cost_usd": (
                float(cost.usd) if cost.usd is not None else None
            ),
        },
        "production_store": {
            "expected_sha256": expected_store,
            "after_sha256": store_after,
            "unchanged": store_after == expected_store,
        },
        "resource_accounting": {
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "new_data_bytes": 0,
            "ceiling_breaches": [],
        },
        "exclusions": {
            "raw_provider_outputs_persisted": 0,
            "source_excerpts_persisted": 0,
            "findings_persisted": 0,
            "production_store_mutations": 0,
            "human_reviews": 0,
            "assessments": 0,
            "labels": 0,
            "models_trained": 0,
            "production_prompt_or_rendering_changes": 0,
            "source_activations": 0,
            "optimization_status_changes": 0,
        },
        "recommendation": (
            "separately-authorize-versioned-citation-correction-and-requalification"
            if success
            else "close-opt009-at-current-scope"
        ),
        "required_stop": True,
    }
    _write_with_final_size(output, result)
    if result["resource_accounting"]["new_data_bytes"] > 10_485_760:
        result["resource_accounting"]["ceiling_breaches"].append("new-data")
    if result["resource_accounting"]["elapsed_seconds"] > 1200:
        result["resource_accounting"]["ceiling_breaches"].append("elapsed-time")
    if not result["production_store"]["unchanged"]:
        result["resource_accounting"]["ceiling_breaches"].append(
            "production-store-mutation"
        )
    _write_with_final_size(output, result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline-only", action="store_true")
    parser.add_argument("--output", type=Path, default=ARTIFACT_DIR / "result.json")
    args = parser.parse_args()
    if args.offline_only:
        ARTIFACT_DIR.mkdir(parents=True, exist_ok=False)
        result = run_offline_diagnosis()
    else:
        result = run_diagnosis(args.output)
    print(json.dumps({
        "status": result["status"],
        "provider_attempts": result.get("provider_diagnosis", {}).get(
            "provider_attempts", result.get("provider_attempts", 0)
        ),
        "provider_reported_tokens": result.get("provider_diagnosis", {}).get(
            "provider_reported_tokens", 0
        ),
        "known_dated_price_cost_usd": result.get("provider_diagnosis", {}).get(
            "known_dated_price_cost_usd"
        ),
        "recommendation": result.get("recommendation"),
    }, sort_keys=True))


if __name__ == "__main__":
    main()

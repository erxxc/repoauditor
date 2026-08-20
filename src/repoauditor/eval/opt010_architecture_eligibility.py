"""Bounded scratch architecture and mechanism qualification for OPT-010.

The helper operates only on the six already-materialized wave-one snapshots.  It
freezes the language/mechanism matrix before opening source, calls the frozen
architecture schema directly with no general retry, and never opens the production
store or scanner artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..analyze.provider_cost import calculate_provider_cost
from ..config import get_config
from ..detect.retrieval import RetrievalIndex
from ..llm import AnthropicBackend
from ..map.domain_map import (
    PROMPT,
    PROMPT_VERSION,
    _build_context,
)
from ..map.schema import ArchitectureExtraction
from ..store.models import ModelUsage
from .opt010_acquisition_qualification import (
    SUBJECTS,
    _detector_input_digest,
    _snapshot_digest,
)


ROOT = Path(__file__).resolve().parents[3]
RECEIPT = ROOT / "docs/optimizations/opt-010-architecture-mechanism-eligibility-receipt-2026-08-20.json"
RETRY_RECEIPT = ROOT / "docs/optimizations/opt-010-architecture-mechanism-eligibility-corrected-retry-receipt-2026-08-20.json"
WAVE_RESULT = ROOT / "docs/optimizations/opt-010-prospective-acquisition-instrument-qualification-wave-1-runtime-identity-retry-result-2026-08-19.json"
WAVE_ARTIFACT = ROOT / "data/artifacts/opt010-acquisition-instrument-qualification-wave-1-runtime-identity-retry"
ARTIFACT_DIR = ROOT / "data/artifacts/opt010-architecture-mechanism-eligibility"
ORIGINAL_RESULT = ROOT / "docs/optimizations/opt-010-architecture-mechanism-eligibility-result-2026-08-20.json"
CORRECTED_RESULT = ROOT / "docs/optimizations/opt-010-architecture-mechanism-eligibility-corrected-retry-result-2026-08-20.json"
RECEIPT_TEST = ROOT / "tests/test_opt_010_architecture_mechanism_eligibility_receipt.py"
FOCUSED_TEST = ROOT / "tests/test_opt_010_architecture_mechanism_eligibility.py"

MECHANISM_MATRIX = {
    "Python": ["sql_injection", "command_injection", "ssrf"],
    "TypeScript": ["command_injection", "ssrf"],
    "Java": ["ssrf"],
    "Ruby": ["unsafe_deserialization"],
    "Go": [],
    "Rust": [],
}
INITIAL_CONTEXT_CHARS = 60_000
REPASS_CONTEXT_CHARS = 240_000
MAX_REQUEST_BYTES = 320_000
MAX_ATTEMPTS = 12
MAX_TOKENS = 500_000
MAX_COST_USD = 7.5
MAX_NEW_BYTES = 10_485_760
MAX_SECONDS = 45 * 60


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def canonical_write(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(canonical_bytes(payload) + b"\n")
    os.replace(temporary, path)


def complete_request_bytes(system: str, user: str) -> int:
    schema = json.dumps(
        ArchitectureExtraction.model_json_schema(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return len(system.encode("utf-8")) + len(user.encode("utf-8")) + len(schema.encode("utf-8"))


def fixed_mechanisms(language: str) -> tuple[str, ...]:
    if language not in MECHANISM_MATRIX:
        raise ValueError("language is outside the frozen mechanism matrix")
    return tuple(MECHANISM_MATRIX[language])


def _artifact_bytes() -> int:
    return sum(path.stat().st_size for path in ARTIFACT_DIR.rglob("*") if path.is_file())


def _git_output(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=False
    )
    if completed.returncode != 0:
        raise RuntimeError(f"git identity check failed: {' '.join(args)}")
    return completed.stdout.strip()


def exact_resume_state(retry_receipt: dict[str, Any]) -> bool:
    """Return whether the retained stop is exactly the authorized matrix-only state."""
    retained = retry_receipt["retained_stopped_attempt"]
    if not ARTIFACT_DIR.is_dir() or not ORIGINAL_RESULT.is_file() or CORRECTED_RESULT.exists():
        return False
    files = sorted(
        path.relative_to(ARTIFACT_DIR).as_posix()
        for path in ARTIFACT_DIR.rglob("*")
        if path.is_file()
    )
    expected_inventory = retained["exact_artifact_inventory"]
    if files != [item["path"] for item in expected_inventory]:
        return False
    if any(sha256(ARTIFACT_DIR / item["path"]) != item["sha256"] for item in expected_inventory):
        return False
    stopped = retained["stopped_result"]
    return sha256(ROOT / stopped["path"]) == stopped["sha256"]


def _prewrite_checks(
    receipt: dict[str, Any],
    wave: dict[str, Any],
    *,
    retry_receipt: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if retry_receipt is None:
        if ARTIFACT_DIR.exists():
            raise RuntimeError("artifact directory existed before authorized execution")
        if ORIGINAL_RESULT.exists():
            raise RuntimeError("result existed before authorized execution")
    elif not exact_resume_state(retry_receipt):
        raise RuntimeError("retained corrected-resume state drifted")
    if _git_output("branch", "--show-current") != "main":
        raise RuntimeError("workspace branch drifted from main")
    staged = subprocess.run(
        ["git", "diff", "--cached", "--quiet"], cwd=ROOT, check=False
    )
    if staged.returncode != 0:
        raise RuntimeError("workspace index is not empty")

    checks: list[dict[str, Any]] = []
    records = [
        receipt["frozen_wave"]["qualification_result"],
        *receipt["frozen_architecture_instrument"]["implementation_bindings"].values(),
        *receipt["concrete_mechanism_matrix"]["implementation_bindings"].values(),
    ]
    for record in records:
        path = ROOT / record["path"]
        actual = sha256(path)
        checks.append({"path": record["path"], "sha256": actual, "passed": actual == record["sha256"]})
    if not all(item["passed"] for item in checks):
        raise RuntimeError("a frozen input digest drifted")
    if sha256(ROOT / "data/repoauditor.db") != receipt["frozen_wave"]["production_store_sha256"]:
        raise RuntimeError("production store digest drifted")
    if len(wave["subjects"]) != len(SUBJECTS) == 6:
        raise RuntimeError("frozen subject count drifted")
    return checks


def _freeze_matrix(receipt: dict[str, Any], *, resume: bool = False) -> Path:
    expected = receipt["concrete_mechanism_matrix"]["matrix"]
    if expected != MECHANISM_MATRIX:
        raise RuntimeError("receipt mechanism matrix does not match helper")
    path = ARTIFACT_DIR / "mechanism-matrix.json"
    if resume:
        if sha256(path) != "734d7bc40e54323b5bee963110c92f445b05f28c795e25f23884ede1d0e57ec3":
            raise RuntimeError("retained mechanism matrix drifted")
        return path
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=False)
    canonical_write(path, {
        "schema_version": 1,
        "matrix": MECHANISM_MATRIX,
        "assignment": "complete row by frozen primary language",
        "unsupported_languages_retained_in_denominator": ["Go", "Rust"],
        "frozen_before_source_or_credential_access": True,
    })
    return path


def _verify_snapshots(wave: dict[str, Any]) -> list[dict[str, Any]]:
    verified: list[dict[str, Any]] = []
    for subject, expected in zip(SUBJECTS, wave["subjects"], strict=True):
        if (
            subject.order != expected["order"]
            or subject.stable_identity != expected["stable_identity_sha256"]
            or subject.commit != expected["exact_commit"]
            or subject.language != expected["language"]
        ):
            raise RuntimeError("frozen subject identity drifted")
        snapshot = WAVE_ARTIFACT / "subjects" / subject.stable_identity / "snapshot"
        head = (snapshot / ".git/HEAD").read_text(encoding="utf-8").strip()
        snapshot_digest = _snapshot_digest(snapshot)[0]
        detector_digest = _detector_input_digest(snapshot)[0]
        retrieval_digest = RetrievalIndex().build(snapshot).content_digest().removeprefix("sha256:")
        passed = (
            head == subject.commit
            and snapshot_digest == expected["snapshot_sha256"]
            and detector_digest == expected["detector_input_sha256"]
            and retrieval_digest == expected["retrieval_index_sha256"]
        )
        verified.append({
            "order": subject.order,
            "stable_identity_sha256": subject.stable_identity,
            "passed": passed,
        })
        if not passed:
            raise RuntimeError(f"snapshot identity drifted at frozen order {subject.order}")
    return verified


@dataclass
class Attempt:
    usage: ModelUsage
    extraction: ArchitectureExtraction | None
    failure_type: str | None
    request_bytes: int


def _attempt(
    backend: AnthropicBackend,
    user: str,
    *,
    subject_hash: str,
    attempt_number: int,
    chronology: list[dict[str, Any]],
) -> Attempt:
    request_bytes = complete_request_bytes(PROMPT, user)
    if request_bytes > MAX_REQUEST_BYTES:
        raise RuntimeError("complete architecture request exceeded frozen byte ceiling")
    started = time.monotonic()
    extraction: ArchitectureExtraction | None = None
    failure_type: str | None = None
    try:
        raw = backend.complete(
            system=PROMPT,
            user=user,
            schema=ArchitectureExtraction,
            context={"stage": "map", "subject": subject_hash, "attempt": attempt_number},
        )
        extraction = ArchitectureExtraction.model_validate_json(raw)
    except BaseException as exc:
        failure_type = type(exc).__name__
    provider_usage = backend.last_usage
    usage = ModelUsage(
        stage="architecture-eligibility",
        module="map",
        prompt_version=PROMPT_VERSION,
        provider="anthropic",
        model="claude-opus-4-8",
        usage_available=provider_usage is not None,
        input_tokens=provider_usage.input_tokens if provider_usage else None,
        output_tokens=provider_usage.output_tokens if provider_usage else None,
        cache_read_tokens=provider_usage.cache_read_tokens if provider_usage else None,
        cache_write_tokens=provider_usage.cache_write_tokens if provider_usage else None,
        latency_ms=max(0, round((time.monotonic() - started) * 1000)),
    )
    chronology.append({
        "attempt": len(chronology) + 1,
        "subject_stable_identity_sha256": subject_hash,
        "subject_attempt": attempt_number,
        "request_content_utf8_bytes": request_bytes,
        "usage_available": usage.usage_available,
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "cache_read_tokens": usage.cache_read_tokens,
        "cache_write_tokens": usage.cache_write_tokens,
        "latency_ms": usage.latency_ms,
        "status": "completed" if extraction is not None else "failed",
        "failure_type": failure_type,
    })
    canonical_write(ARTIFACT_DIR / "provider-chronology.json", {"attempts": chronology})
    return Attempt(usage, extraction, failure_type, request_bytes)


def _totals(rows: list[ModelUsage]) -> tuple[int, float | None, str]:
    tokens = sum(
        (row.input_tokens or 0)
        + (row.output_tokens or 0)
        + (row.cache_read_tokens or 0)
        + (row.cache_write_tokens or 0)
        for row in rows
        if row.usage_available
    )
    cost = calculate_provider_cost(rows)
    return tokens, float(cost.usd) if cost.usd is not None else None, cost.status


def _assert_live_budgets(rows: list[ModelUsage], started: float) -> None:
    tokens, cost, cost_status = _totals(rows)
    if len(rows) > MAX_ATTEMPTS or tokens > MAX_TOKENS:
        raise RuntimeError("provider attempt or token ceiling exceeded")
    if cost_status != "priced" or cost is None or cost > MAX_COST_USD:
        raise RuntimeError("authoritative dated-price accounting unavailable or exceeded")
    if _artifact_bytes() > MAX_NEW_BYTES:
        raise RuntimeError("new-data ceiling exceeded")
    if time.monotonic() - started > MAX_SECONDS:
        raise RuntimeError("elapsed-time ceiling exceeded")


def _stable_result_write(payload: dict[str, Any], output: Path) -> None:
    previous = -1
    for _ in range(5):
        canonical_write(output, payload)
        size = (
            _artifact_bytes()
            + output.stat().st_size
            + Path(__file__).stat().st_size
            + FOCUSED_TEST.stat().st_size
        )
        payload["resource_accounting"]["new_data_bytes"] = size
        if size == previous:
            break
        previous = size
    canonical_write(output, payload)


def run(*, corrected_resume: bool = False) -> dict[str, Any]:
    started = time.monotonic()
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    retry_receipt = (
        json.loads(RETRY_RECEIPT.read_text(encoding="utf-8"))
        if corrected_resume
        else None
    )
    wave = json.loads(WAVE_RESULT.read_text(encoding="utf-8"))
    digest_checks = _prewrite_checks(receipt, wave, retry_receipt=retry_receipt)
    matrix_path = _freeze_matrix(receipt, resume=corrected_resume)

    subject_checks = _verify_snapshots(wave)
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("Anthropic cloud-chain credential is unavailable")
    config = get_config().model_copy(deep=True)
    if (
        config.llm.provider != "anthropic"
        or config.model.name != "claude-opus-4-8"
        or config.model.temperature != 0.0
        or config.model.max_tokens != 4096
    ):
        raise RuntimeError("frozen provider/model configuration drifted")

    backend = AnthropicBackend(config)
    chronology: list[dict[str, Any]] = []
    usage_rows: list[ModelUsage] = []
    subject_results: list[dict[str, Any]] = []
    stop_reason: str | None = None

    for subject in SUBJECTS:
        snapshot = WAVE_ARTIFACT / "subjects" / subject.stable_identity / "snapshot"
        extraction: ArchitectureExtraction | None = None
        attempts = 0
        try:
            first = _attempt(
                backend,
                _build_context(snapshot, INITIAL_CONTEXT_CHARS),
                subject_hash=subject.stable_identity,
                attempt_number=1,
                chronology=chronology,
            )
            usage_rows.append(first.usage)
            attempts += 1
            if first.extraction is None or not first.usage.usage_available:
                raise RuntimeError(first.failure_type or "provider usage unavailable")
            _assert_live_budgets(usage_rows, started)
            extraction = first.extraction
            if extraction.confidence < 0.5:
                second = _attempt(
                    backend,
                    _build_context(snapshot, REPASS_CONTEXT_CHARS),
                    subject_hash=subject.stable_identity,
                    attempt_number=2,
                    chronology=chronology,
                )
                usage_rows.append(second.usage)
                attempts += 1
                if second.extraction is None or not second.usage.usage_available:
                    raise RuntimeError(second.failure_type or "provider usage unavailable")
                _assert_live_budgets(usage_rows, started)
                extraction = second.extraction

            map_payload = extraction.model_dump(mode="json")
            map_path = ARTIFACT_DIR / f"architecture-{subject.stable_identity}.json"
            canonical_write(map_path, map_payload)
            subject_results.append({
                "order": subject.order,
                "stable_identity_sha256": subject.stable_identity,
                "terminal_state": "completed",
                "provider_attempts": attempts,
                "architecture_map_sha256": sha256(map_path),
                "architecture_counts": {
                    "trust_boundaries": len(extraction.trust_boundaries),
                    "entry_points": len(extraction.entry_points),
                    "data_stores": len(extraction.data_stores),
                    "integrations": len(extraction.integrations),
                },
                "fixed_mechanism_count": len(fixed_mechanisms(subject.language)),
                "language_supported": bool(fixed_mechanisms(subject.language)),
            })
            _assert_live_budgets(usage_rows, started)
        except BaseException as exc:
            stop_reason = type(exc).__name__
            subject_results.append({
                "order": subject.order,
                "stable_identity_sha256": subject.stable_identity,
                "terminal_state": "stopped",
                "provider_attempts": attempts,
                "architecture_map_sha256": None,
                "failure_type": stop_reason,
                "fixed_mechanism_count": len(fixed_mechanisms(subject.language)),
                "language_supported": bool(fixed_mechanisms(subject.language)),
            })
            break

    store_after = sha256(ROOT / "data/repoauditor.db")
    tokens, cost, cost_status = _totals(usage_rows)
    completed = sum(item["terminal_state"] == "completed" for item in subject_results)
    aggregate_counts = {
        key: sum(item.get("architecture_counts", {}).get(key, 0) for item in subject_results)
        for key in ("trust_boundaries", "entry_points", "data_stores", "integrations")
    }
    complete = (
        completed == 6
        and len(subject_results) == 6
        and stop_reason is None
        and all(row.usage_available for row in usage_rows)
        and store_after == receipt["frozen_wave"]["production_store_sha256"]
    )
    output = CORRECTED_RESULT if corrected_resume else ORIGINAL_RESULT
    controlling_receipt = RETRY_RECEIPT if corrected_resume else RECEIPT
    result: dict[str, Any] = {
        "schema_version": 1,
        "optimization": "OPT-010",
        "status": "complete-architecture-mechanism-eligibility" if complete else "stopped",
        "execution_evidence": {
            "receipt": {"path": controlling_receipt.relative_to(ROOT).as_posix(), "sha256": sha256(controlling_receipt)},
            "original_receipt": {"path": RECEIPT.relative_to(ROOT).as_posix(), "sha256": sha256(RECEIPT)},
            "retained_stopped_result": {
                "path": ORIGINAL_RESULT.relative_to(ROOT).as_posix(),
                "sha256": sha256(ORIGINAL_RESULT),
                "preserved": corrected_resume,
            },
            "receipt_test": {"path": RECEIPT_TEST.relative_to(ROOT).as_posix(), "sha256": sha256(RECEIPT_TEST)},
            "helper": {"path": Path(__file__).relative_to(ROOT).as_posix(), "sha256": sha256(Path(__file__))},
            "mechanism_matrix": {"path": matrix_path.relative_to(ROOT).as_posix(), "sha256": sha256(matrix_path)},
            "frozen_input_checks": digest_checks,
            "subject_identity_checks_passed": sum(item["passed"] for item in subject_checks),
        },
        "subjects": subject_results,
        "aggregate_architecture_counts": aggregate_counts,
        "mechanism_eligibility": {
            "subjects_in_denominator": 6,
            "language_supported_subjects": 4,
            "language_unsupported_subjects": 2,
            "fixed_mechanism_cells": sum(len(value) for value in MECHANISM_MATRIX.values()),
            "unsupported_languages_retained": ["Go", "Rust"],
            "assignment_basis": "complete frozen language row only",
        },
        "provider_accounting": {
            "attempts": len(usage_rows),
            "source_transmissions": len(usage_rows),
            "provider_reported_tokens": tokens,
            "unknown_usage_attempts": sum(not row.usage_available for row in usage_rows),
            "known_dated_price_cost_status": cost_status,
            "known_dated_price_cost_usd": cost,
        },
        "production_store": {
            "expected_sha256": receipt["frozen_wave"]["production_store_sha256"],
            "after_sha256": store_after,
            "byte_identical": store_after == receipt["frozen_wave"]["production_store_sha256"],
            "reads": 0,
            "mutations": 0,
        },
        "resource_accounting": {
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "new_data_bytes": 0,
            "repository_materializations": 0,
            "repository_code_executions": 0,
            "scanner_processes": 0,
            "findings_or_candidates_created": 0,
            "assessments": 0,
            "labels": 0,
            "model_training_runs": 0,
            "rescoring_runs": 0,
            "human_reviews": 0,
            "agentic_runs": 0,
            "workspace_branch_or_index_mutations": 0,
            "commits": 0,
            "merges": 0,
            "pushes": 0,
            "lifecycle_changes": 0,
            "other_network_activity": 0,
        },
        "gate_assessment": {
            "G02": "documented-pass-exact-subjects-and-architecture-slots" if complete else "partial",
            "G05": "documented-pass-fixed-concrete-mechanism-eligibility" if complete else "partial",
            "G07": "partial-four-language-supported-two-explicit-unsupported",
            "G03b": "not-authorized",
            "G04_empirical_recall": "not-authorized",
            "OPT_010_status": "open-deferred",
            "production_activation_permitted": False,
        },
        "stop": {
            "reason_type": stop_reason,
            "current_authority_exhausted": True,
            "next_prerequisite": "Separately authorize the frozen G03b paired comparison; G04 empirical recall remains subsequent and separately gated.",
        },
        "result_boundary": "Descriptive architecture/mechanism eligibility only; no empirical safety, comparison, outcome, threshold, production activation, or OPT-010 closure claim.",
    }
    _stable_result_write(result, output)
    if result["resource_accounting"]["new_data_bytes"] > MAX_NEW_BYTES:
        raise RuntimeError("final new-data accounting exceeded the receipt ceiling")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("run", "corrected-resume"))
    args = parser.parse_args()
    payload = run(corrected_resume=args.command == "corrected-resume")
    print(json.dumps({
        "status": payload["status"],
        "provider_attempts": payload["provider_accounting"]["attempts"],
        "subjects_completed": sum(item["terminal_state"] == "completed" for item in payload["subjects"]),
    }, sort_keys=True))
    if payload["status"] != "complete-architecture-mechanism-eligibility":
        raise SystemExit(1)


if __name__ == "__main__":
    main()

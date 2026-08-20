"""Bounded supported-primary acquisition and metadata feasibility screen for OPT-010."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .opt010_acquisition_qualification import (
    _acquire,
    _detector_input_digest,
    _retrieval_summary,
    _semgrep_scan,
    _snapshot_digest,
    _supplemental_scan,
)
from .opt010_paired_foundation import SUPPORTED_CELLS
from .opt010_paired_wave import candidates_from_sarif, deduplicate


ROOT = Path(__file__).resolve().parents[3]
RECEIPT = ROOT / "docs/optimizations/opt-010-supported-primary-augmentation-receipt-2026-08-20.json"
WAVE_RESULT = ROOT / "docs/optimizations/opt-010-prospective-acquisition-instrument-qualification-wave-1-runtime-identity-retry-result-2026-08-19.json"
RETAINED_ROOT = ROOT / "data/artifacts/opt010-acquisition-instrument-qualification-wave-1-runtime-identity-retry"
ARTIFACT_ROOT = ROOT / "data/artifacts/opt010-supported-primary-augmentation"
MAPPING = ARTIFACT_ROOT / "mechanism-mapping.json"
SUMMARY = ARTIFACT_ROOT / "augmentation-summary.json"
RESULT = ROOT / "docs/optimizations/opt-010-supported-primary-augmentation-result-2026-08-20.json"
FOCUSED_TEST = ROOT / "tests/test_opt_010_supported_primary_augmentation.py"
EXPECTED_MAPPING_SHA256 = "5a954ed23a788d34dce0b36bda1b98ad3f8fe322915552f7d237fe57627218b0"
EXPECTED_STORE_SHA256 = "468c8de903f6c4c0ed23304e59db150a1d5d0b6cf350247fba3bc3d2699caf5a"
MAX_NEW_BYTES = 16_106_127_360
MAX_SECONDS = 780 * 60
SCANNERS = ("semgrep", "semgrep-supplemental")


@dataclass(frozen=True)
class Subject:
    order: int
    repository: str
    commit: str
    stable_identity: str
    language: str


SUBJECTS = (
    Subject(7, "alexta69/metube", "86954784fd7d284b4397020207d8a33908780e53", "86e056d03ce11434bfcb7c0fdfb62ba3dca418fd39dc736b142db71325175ef1", "Python"),
    Subject(8, "TriliumNext/Trilium", "02835932b88b1ebcf9f9981b005716aacfd18513", "5058c9f30326d4ced50529fc24fc91c7d30ffd1e4579891ffa2894a08af987ab", "TypeScript"),
    Subject(10, "Athou/commafeed", "41fc77322cdc02ebe685a1cc1a81e7a5910e5174", "8041f1999440423b3315895e91e58a253f04e7a60ecec3b5e73e9328d33a4ddd", "Java"),
    Subject(11, "solectrus/solectrus", "f62cef2f2ce4bc48b51d2d07b8871ae7522e5b63", "ac8e82b257e2ba90c415241aa204f7198e9b92ac97bf4980efe692173b4ca8f4", "Ruby"),
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(_canonical_bytes(payload) + b"\n")
    os.replace(temporary, path)


def provisional_feasibility(counts: dict[str, int]) -> bool:
    """Apply only the frozen four-family floor and 20-per-family capacity ceiling."""
    return (
        set(counts) == set(SUPPORTED_CELLS)
        and all(counts[family] > 0 for family in SUPPORTED_CELLS)
        and sum(min(counts[family], 20) for family in SUPPORTED_CELLS) >= 40
    )


def _preflight() -> tuple[dict[str, Any], dict[str, Any]]:
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    if not ARTIFACT_ROOT.is_dir() or RESULT.exists() or SUMMARY.exists():
        raise RuntimeError("augmentation artifact state is not the authorized post-canary state")
    if sha256(MAPPING) != EXPECTED_MAPPING_SHA256:
        raise RuntimeError("frozen mechanism mapping drifted")
    for record in receipt["frozen_inputs"].values():
        if isinstance(record, dict) and sha256(ROOT / record["path"]) != record["sha256"]:
            raise RuntimeError("frozen input digest drifted")
    for record in receipt["frozen_instruments"].values():
        if sha256(ROOT / record["path"]) != record["sha256"]:
            raise RuntimeError("frozen instrument digest drifted")
    if sha256(ROOT / "data/repoauditor.db") != EXPECTED_STORE_SHA256:
        raise RuntimeError("production store digest drifted")
    branch = subprocess.run(
        ["git", "branch", "--show-current"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    staged = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT, check=False)
    if branch != "main" or staged.returncode != 0:
        raise RuntimeError("workspace branch or index drifted")
    for name in SCANNERS:
        canary = json.loads((ARTIFACT_ROOT / f"canary-{name}.json").read_text(encoding="utf-8"))
        if canary.get("passed") is not True or len(canary.get("results", [])) != 1:
            raise RuntimeError(f"{name} canary did not pass")
        execution = canary["results"][0]
        if execution.get("scanner") != name or execution.get("provenance_passed") is not True:
            raise RuntimeError(f"{name} canary provenance failed")
        versions = {
            execution[probe]["execution"].get("version") for probe in ("positive", "clean")
        }
        if versions != {"1.170.0"}:
            raise RuntimeError(f"{name} canary version drifted")
    selected = receipt["protected_augmentation_wave"]["subjects"]
    if [
        (item["order"], item["repository"], item["exact_commit"], item["stable_identity_sha256"], item["language"])
        for item in selected
    ] != [
        (item.order, item.repository, item.commit, item.stable_identity, item.language)
        for item in SUBJECTS
    ]:
        raise RuntimeError("protected augmentation identities drifted")
    return receipt, json.loads(WAVE_RESULT.read_text(encoding="utf-8"))


def _artifact_bytes() -> int:
    paths = [Path(__file__), FOCUSED_TEST, RESULT]
    paths.extend(path for path in ARTIFACT_ROOT.rglob("*") if path.is_file())
    return sum(path.stat().st_size for path in paths if path.is_file())


def _scanner_record(snapshot: Path, output: Path) -> list[dict[str, Any]]:
    output.mkdir(parents=True, exist_ok=False)
    return [
        _semgrep_scan(snapshot, output, timeout=180 * 60),
        _supplemental_scan(snapshot, output, timeout=180 * 60),
    ]


def _aggregate_metadata(wave: dict[str, Any]) -> dict[str, Any]:
    retained = {
        item["stable_identity_sha256"]: item["language"]
        for item in wave["subjects"]
        if item["language"] in SUPPORTED_CELLS
    }
    combined = [
        (RETAINED_ROOT, identity, language) for identity, language in sorted(retained.items())
    ] + [
        (ARTIFACT_ROOT, item.stable_identity, item.language) for item in SUBJECTS
    ]
    candidates = []
    scanner_hashes = []
    for root, identity, language in combined:
        for scanner in SCANNERS:
            path = root / "subjects" / identity / "scanners" / f"{scanner}.sarif"
            scanner_hashes.append(sha256(path))
            candidates.extend(candidates_from_sarif(
                json.loads(path.read_text(encoding="utf-8")),
                subject=identity,
                language=language,
                scanner=scanner,
            ))
    groups = deduplicate(candidates)
    family = Counter(item.language for item in groups)
    mechanism = Counter(item.mechanism for item in groups)
    counts = {name: family[name] for name in sorted(SUPPORTED_CELLS)}
    return {
        "metadata_compatible_results": len(candidates),
        "metadata_deduplicated_issue_groups": len(groups),
        "by_supported_family": counts,
        "by_mechanism": {name: mechanism[name] for name in sorted({m for row in SUPPORTED_CELLS.values() for m in row})},
        "supported_families_contributing": sum(counts[name] > 0 for name in counts),
        "capped_packet_capacity": sum(min(counts[name], 20) for name in counts),
        "provisionally_feasible": provisional_feasibility(counts),
        "scanner_artifact_set_sha256": hashlib.sha256("".join(sorted(scanner_hashes)).encode()).hexdigest(),
    }


def _stable_result(payload: dict[str, Any]) -> None:
    for _ in range(5):
        write_json(RESULT, payload)
        size = _artifact_bytes()
        if payload["resource_accounting"]["new_data_bytes"] == size:
            break
        payload["resource_accounting"]["new_data_bytes"] = size
    write_json(RESULT, payload)


def run() -> dict[str, Any]:
    started = time.monotonic()
    _, wave = _preflight()
    summary: dict[str, Any] = {
        "schema_version": 1,
        "status": "running",
        "subjects": [],
        "logical_scanner_processes": 4,
        "retrieval_indexes": 0,
        "repositories_materialized": 0,
    }
    write_json(SUMMARY, summary)
    stop_reason: str | None = None
    for subject in SUBJECTS:
        subject_started = time.monotonic()
        record: dict[str, Any] = {
            "order": subject.order,
            "stable_identity_sha256": subject.stable_identity,
            "language": subject.language,
            "exact_commit": subject.commit,
            "terminal_state": "failed",
        }
        summary["subjects"].append(record)
        subject_root = ARTIFACT_ROOT / "subjects" / subject.stable_identity
        snapshot = subject_root / "snapshot"
        try:
            _acquire(subject, snapshot)
            summary["repositories_materialized"] += 1
            snapshot_digest, file_count, snapshot_bytes = _snapshot_digest(snapshot)
            detector_digest, detector_files, detector_bytes = _detector_input_digest(snapshot)
            retrieval = _retrieval_summary(snapshot)
            summary["retrieval_indexes"] += 1
            scanners = _scanner_record(snapshot, subject_root / "scanners")
            summary["logical_scanner_processes"] += 2
            if any(item["status"] not in {"complete", "empty", "not-applicable"} for item in scanners):
                raise RuntimeError("Semgrep qualification failed closed")
            record.update({
                "snapshot_sha256": snapshot_digest,
                "snapshot_file_count": file_count,
                "snapshot_bytes": snapshot_bytes,
                "detector_input_sha256": detector_digest,
                "detector_input_file_count": detector_files,
                "detector_input_bytes": detector_bytes,
                "retrieval": retrieval,
                "scanner_executions": scanners,
                "terminal_state": "completed",
            })
        except BaseException as exc:
            record["failure_type"] = type(exc).__name__
            record["failure_detail"] = str(exc)[:300]
            stop_reason = f"subject-{subject.order}-failed"
        record["elapsed_seconds"] = round(time.monotonic() - subject_started, 3)
        summary["new_data_bytes"] = _artifact_bytes()
        if record["elapsed_seconds"] > 180 * 60:
            record["terminal_state"] = "timed_out"
            stop_reason = f"subject-{subject.order}-timed-out"
        if summary["new_data_bytes"] > MAX_NEW_BYTES or time.monotonic() - started > MAX_SECONDS:
            record["terminal_state"] = "budget_exhausted"
            stop_reason = "resource-ceiling"
        write_json(SUMMARY, summary)
        if stop_reason:
            break

    aggregate = None
    if stop_reason is None and len(summary["subjects"]) == len(SUBJECTS):
        aggregate = _aggregate_metadata(wave)
        summary["status"] = "completed"
    else:
        summary["status"] = "stopped"
    summary["stop_reason"] = stop_reason
    write_json(SUMMARY, summary)

    result: dict[str, Any] = {
        "schema_version": 1,
        "optimization": "OPT-010",
        "status": "completed-aggregate-metadata-feasibility" if aggregate is not None else "stopped-before-aggregate-screen",
        "interpretation": (
            "This outcome-blind metadata screen only determines whether a later architecture and verifier gate is justified. "
            "It does not establish candidate-specific eligibility, packet completeness, G03b, G04, or production readiness."
        ),
        "augmentation": {
            "subjects_frozen": 4,
            "subjects_completed": sum(item["terminal_state"] == "completed" for item in summary["subjects"]),
            "supported_language_families": sorted(SUPPORTED_CELLS),
            "go_rust_or_reserve_sources_activated": 0,
        },
        "aggregate_metadata_feasibility": aggregate,
        "decision": {
            "architecture_and_verifier_gate_justified": bool(aggregate and aggregate["provisionally_feasible"]),
            "packet_frozen": False,
            "paired_execution_started": False,
            "g03b_decided": False,
            "g04_decided": False,
            "opt010_status_changed": False,
        },
        "resource_accounting": {
            "repositories_materialized": summary["repositories_materialized"],
            "retrieval_index_builds": summary["retrieval_indexes"],
            "logical_scanner_processes": summary["logical_scanner_processes"],
            "network_hosts_used": ["github.com"] if summary["repositories_materialized"] else [],
            "network_uploads": 0,
            "provider_calls": 0,
            "provider_reported_tokens": 0,
            "provider_cost_usd": 0.0,
            "keychain_or_credential_reads": 0,
            "repository_code_executions": 0,
            "dependency_resolutions_or_installations": 0,
            "other_scanner_processes": 0,
            "production_store_reads": 0,
            "production_store_mutations": 0,
            "human_reviews": 0,
            "outcomes_read": 0,
            "assessments": 0,
            "labels": 0,
            "model_training_runs": 0,
            "rescoring_runs": 0,
            "agentic_or_baseline_runs": 0,
            "workspace_branch_or_index_mutations": 0,
            "commits": 0,
            "merges": 0,
            "pushes": 0,
            "lifecycle_changes": 0,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "new_data_bytes": 0,
        },
        "production_store": {
            "expected_sha256": EXPECTED_STORE_SHA256,
            "after_sha256": sha256(ROOT / "data/repoauditor.db"),
            "byte_identical": sha256(ROOT / "data/repoauditor.db") == EXPECTED_STORE_SHA256,
        },
        "stop_reason": stop_reason,
    }
    _stable_result(result)
    if result["resource_accounting"]["logical_scanner_processes"] > 12:
        raise RuntimeError("scanner-process ceiling exceeded")
    if result["resource_accounting"]["new_data_bytes"] > MAX_NEW_BYTES:
        raise RuntimeError("new-data ceiling exceeded")
    if not result["production_store"]["byte_identical"]:
        raise RuntimeError("production store changed")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("--run is required")
    print(json.dumps(run(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

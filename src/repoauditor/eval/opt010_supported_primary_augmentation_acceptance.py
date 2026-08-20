"""Offline acceptance of retained OPT-010 augmentation aggregate evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any

from .opt010_paired_foundation import SUPPORTED_CELLS
from .opt010_paired_wave import candidates_from_sarif, deduplicate


ROOT = Path(__file__).resolve().parents[3]
RECEIPT = ROOT / "docs/optimizations/opt-010-supported-primary-augmentation-corrected-acceptance-receipt-2026-08-20.json"
ORIGINAL_RECEIPT = ROOT / "docs/optimizations/opt-010-supported-primary-augmentation-receipt-2026-08-20.json"
SUMMARY = ROOT / "data/artifacts/opt010-supported-primary-augmentation/augmentation-summary.json"
RETAINED_ROOT = ROOT / "data/artifacts/opt010-acquisition-instrument-qualification-wave-1-runtime-identity-retry"
AUGMENTATION_ROOT = ROOT / "data/artifacts/opt010-supported-primary-augmentation"
ARTIFACT = AUGMENTATION_ROOT / "acceptance-artifact.json"
RESULT = ROOT / "docs/optimizations/opt-010-supported-primary-augmentation-corrected-acceptance-result-2026-08-20.json"
FOCUSED_TEST = ROOT / "tests/test_opt_010_supported_primary_augmentation_acceptance.py"
STORE_SHA256 = "468c8de903f6c4c0ed23304e59db150a1d5d0b6cf350247fba3bc3d2699caf5a"
MAX_NEW_BYTES = 2_097_152
MAX_SECONDS = 10 * 60
SCANNERS = ("semgrep", "semgrep-supplemental")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def write_json(path: Path, payload: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(_canonical_bytes(payload) + b"\n")
    os.replace(temporary, path)


def _git_head(snapshot: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=snapshot,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("retained exact HEAD could not be resolved")
    return completed.stdout.strip()


def _preflight() -> tuple[dict[str, Any], list[tuple[Path, str, str]]]:
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    if ARTIFACT.exists() or RESULT.exists():
        raise RuntimeError("corrected acceptance output already exists")
    for record in receipt["retained_attempt"].values():
        if isinstance(record, dict) and "path" in record:
            if sha256(ROOT / record["path"]) != record["sha256"]:
                raise RuntimeError("retained evidence digest drifted")
    for record in receipt["frozen_instruments"].values():
        if sha256(ROOT / record["path"]) != record["sha256"]:
            raise RuntimeError("frozen instrument digest drifted")
    if sha256(ROOT / "data/repoauditor.db") != STORE_SHA256:
        raise RuntimeError("production store digest drifted")
    branch = subprocess.run(
        ["git", "branch", "--show-current"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    staged = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT, check=False)
    if branch != "main" or staged.returncode != 0:
        raise RuntimeError("workspace branch or index drifted")

    original = json.loads(ORIGINAL_RECEIPT.read_text(encoding="utf-8"))
    wave_record = original["frozen_inputs"]["wave_one_result"]
    wave_path = ROOT / wave_record["path"]
    if sha256(wave_path) != wave_record["sha256"]:
        raise RuntimeError("original wave result drifted")
    wave = json.loads(wave_path.read_text(encoding="utf-8"))
    subjects = [
        (
            RETAINED_ROOT,
            item["stable_identity_sha256"],
            item["language"],
            item["exact_commit"],
        )
        for item in wave["subjects"]
        if item["language"] in SUPPORTED_CELLS
    ]
    summary = json.loads(SUMMARY.read_text(encoding="utf-8"))
    subjects.extend(
        (
            AUGMENTATION_ROOT,
            item["stable_identity_sha256"],
            item["language"],
            item["exact_commit"],
        )
        for item in summary["subjects"]
    )
    if len(subjects) != 8:
        raise RuntimeError("retained supported-subject denominator drifted")
    for root, identity, _, commit in subjects:
        snapshot = root / "subjects" / identity / "snapshot"
        if _git_head(snapshot) != commit:
            raise RuntimeError("retained exact HEAD drifted")
    return receipt, [(root, identity, language) for root, identity, language, _ in subjects]


def reproduce(subjects: list[tuple[Path, str, str]]) -> dict[str, Any]:
    """Reproduce only aggregate metadata counts from the retained SARIF set."""
    candidates = []
    scanner_hashes = []
    for root, identity, language in subjects:
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
    family_counts = {name: family[name] for name in sorted(SUPPORTED_CELLS)}
    return {
        "metadata_compatible_results": len(candidates),
        "metadata_deduplicated_issue_groups": len(groups),
        "by_supported_family": family_counts,
        "by_mechanism": {
            name: mechanism[name]
            for name in sorted({value for row in SUPPORTED_CELLS.values() for value in row})
        },
        "supported_families_contributing": sum(family_counts[name] > 0 for name in family_counts),
        "capped_packet_capacity": sum(min(family_counts[name], 20) for name in family_counts),
        "provisionally_feasible": (
            all(family_counts[name] > 0 for name in family_counts)
            and sum(min(family_counts[name], 20) for name in family_counts) >= 40
        ),
        "scanner_artifact_set_sha256": hashlib.sha256("".join(sorted(scanner_hashes)).encode()).hexdigest(),
    }


def _new_bytes() -> int:
    return sum(
        path.stat().st_size
        for path in (Path(__file__), FOCUSED_TEST, ARTIFACT, RESULT)
        if path.is_file()
    )


def _stable_result(payload: dict[str, Any]) -> None:
    for _ in range(5):
        write_json(RESULT, payload)
        size = _new_bytes()
        if payload["resource_accounting"]["new_data_bytes"] == size:
            break
        payload["resource_accounting"]["new_data_bytes"] = size
    write_json(RESULT, payload)


def run() -> dict[str, Any]:
    started = time.monotonic()
    receipt, subjects = _preflight()
    aggregate = reproduce(subjects)
    expected = receipt["offline_acceptance_contract"]["expected_result"]
    exact = aggregate == expected
    artifact_payload = {
        "schema_version": 1,
        "status": "exact-negative-reproduction" if exact else "aggregate-drift",
        "retained_bindings_verified": True,
        "supported_subjects_verified": len(subjects),
        "aggregate": aggregate,
        "expected": expected,
        "exact_reproduction": exact,
        "original_result_edited_or_requalified": False,
        "snapshot_source_files_opened": 0,
        "candidate_identities_persisted_or_disclosed": 0,
    }
    write_json(ARTIFACT, artifact_payload)
    result: dict[str, Any] = {
        "schema_version": 1,
        "optimization": "OPT-010",
        "status": "completed-negative-corrected-offline-acceptance" if exact else "stopped-aggregate-reproduction-drift",
        "interpretation": (
            "The retained supported-primary augmentation reproducibly fails the frozen metadata-capacity screen. "
            "This bounded negative result does not establish verifier eligibility, packet completeness, paired performance, empirical recall, or broad infeasibility."
        ),
        "original_evidence": {
            "immutable": True,
            "original_result_remains_nonqualifying": True,
            "historical_preflight_deviation_preserved": True,
        },
        "acceptance": {
            "retained_bindings_verified": True,
            "exact_aggregate_reproduction": exact,
            "completed_negative": exact and aggregate["provisionally_feasible"] is False,
            "architecture_and_verifier_gate_justified": False,
        },
        "aggregate_metadata_feasibility": aggregate,
        "gates": {
            "packet_frozen": False,
            "paired_execution_started": False,
            "g03b_decided": False,
            "g04_decided": False,
            "opt010_status_changed": False,
        },
        "resource_accounting": {
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "new_data_bytes": 0,
            "network_reads_or_uploads": 0,
            "provider_calls": 0,
            "provider_reported_tokens": 0,
            "provider_cost_usd": 0.0,
            "keychain_or_credential_reads": 0,
            "repository_materializations": 0,
            "repository_code_executions": 0,
            "snapshot_source_file_reads": 0,
            "scanner_processes": 0,
            "retrieval_index_builds": 0,
            "production_store_database_reads": 0,
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
        },
        "production_store": {
            "expected_sha256": STORE_SHA256,
            "after_sha256": sha256(ROOT / "data/repoauditor.db"),
            "byte_identical": sha256(ROOT / "data/repoauditor.db") == STORE_SHA256,
        },
    }
    _stable_result(result)
    if not exact:
        raise RuntimeError("retained aggregate did not reproduce exactly")
    if time.monotonic() - started > MAX_SECONDS:
        raise RuntimeError("elapsed-time ceiling exceeded")
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

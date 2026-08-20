"""Offline acceptance of retained OPT-010 Java/Ruby scanner-cell evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from .opt010_paired_foundation import SUPPORTED_CELLS
from .opt010_paired_wave import CWE_MAPPING, candidates_from_sarif


ROOT = Path(__file__).resolve().parents[3]
RECEIPT = ROOT / "docs/optimizations/opt-010-java-ruby-scanner-cell-coverage-corrected-acceptance-receipt-2026-08-20.json"
ORIGINAL_RESULT = ROOT / "docs/optimizations/opt-010-java-ruby-scanner-cell-coverage-result-2026-08-20.json"
ARTIFACT_ROOT = ROOT / "data/artifacts/opt010-java-ruby-scanner-cell-coverage"
ORIGINAL_ARTIFACT = ARTIFACT_ROOT / "coverage-artifact.json"
ARTIFACT = ARTIFACT_ROOT / "acceptance-artifact.json"
RESULT = ROOT / "docs/optimizations/opt-010-java-ruby-scanner-cell-coverage-corrected-acceptance-result-2026-08-20.json"
ORIGINAL_HELPER = ROOT / "src/repoauditor/eval/opt010_scanner_cell_coverage.py"
ORIGINAL_TEST = ROOT / "tests/test_opt_010_scanner_cell_coverage.py"
FOCUSED_TEST = ROOT / "tests/test_opt_010_scanner_cell_coverage_acceptance.py"
STORE = ROOT / "data/repoauditor.db"
STORE_SHA256 = "468c8de903f6c4c0ed23304e59db150a1d5d0b6cf350247fba3bc3d2699caf5a"
SEMGREP_VERSION = "1.170.0"
PINNED_CONFIGURATION_SHA256 = "e1fb774d43b23f8265ae07566a5e325763244df9ba6eb8cbefe51e3ce05540c4"
EXPECTED_RETAINED_BYTES = 7_841_236
MAX_RETAINED_BYTES = 8 * 1024**2
MAX_NEW_BYTES = 1 * 1024**2
MAX_SECONDS = 10 * 60


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def write_json(path: Path, payload: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(_canonical_bytes(payload) + b"\n")
    os.replace(temporary, path)


def classify_cell(
    *, positive_valid: bool, clean_valid: bool, positive_mapped: int, clean_mapped: int
) -> str:
    """Apply the frozen fail-closed synthetic scanner-cell classification."""
    if not positive_valid or not clean_valid:
        return "scanner-or-provenance-failure"
    if clean_mapped > 0:
        return "clean-control-failure"
    if positive_mapped == 0:
        return "coverage-gap"
    return "qualified-detectable"


def supported_cells_match(frozen: Any, current: Any) -> bool:
    """Compare exact language/cell membership without assigning list order meaning."""
    if not isinstance(frozen, dict) or not isinstance(current, dict):
        return False
    if set(frozen) != set(current):
        return False
    return all(
        isinstance(frozen[language], list)
        and sorted(frozen[language]) == sorted(current[language])
        for language in frozen
    )


def _execution_valid(execution: dict[str, Any], target_report: dict[str, Any]) -> bool:
    return (
        execution.get("status") in {"complete", "empty"}
        and execution.get("output_valid") is True
        and execution.get("target_count") == 1
        and execution.get("version") == SEMGREP_VERSION
        and execution.get("configuration_resolution") == "pinned-verified"
        and execution.get("configuration_digest") == PINNED_CONFIGURATION_SHA256
        and isinstance(execution.get("rule_count"), int)
        and execution["rule_count"] > 0
        and target_report.get("version") == SEMGREP_VERSION
        and target_report.get("errors") == []
        and len(target_report.get("paths", {}).get("scanned", [])) == 1
    )


def _retained_bytes() -> int:
    paths = [ORIGINAL_HELPER, ORIGINAL_TEST, ORIGINAL_RESULT]
    paths.extend(path for path in ARTIFACT_ROOT.rglob("*") if path.is_file() and path != ARTIFACT)
    return sum(path.stat().st_size for path in paths)


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


def _verify_digest_records(receipt: dict[str, Any]) -> None:
    for record in receipt["retained_attempt"].values():
        if isinstance(record, dict) and "path" in record:
            if sha256(ROOT / record["path"]) != record["sha256"]:
                raise RuntimeError("retained attempt digest drifted")
    for scan in receipt["retained_scan_evidence"]:
        for name in ("sarif", "target_report"):
            record = scan[name]
            if sha256(ROOT / record["path"]) != record["sha256"]:
                raise RuntimeError("retained scan evidence digest drifted")
    for record in receipt["frozen_instruments"].values():
        if sha256(ROOT / record["path"]) != record["sha256"]:
            raise RuntimeError("frozen instrument digest drifted")


def _preflight() -> tuple[dict[str, Any], dict[str, Any]]:
    if ARTIFACT.exists() or RESULT.exists():
        raise RuntimeError("corrected acceptance output already exists")
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    _verify_digest_records(receipt)
    original_result = json.loads(ORIGINAL_RESULT.read_text(encoding="utf-8"))
    if (
        original_result.get("status") != "stopped-nonqualifying-new-data-ceiling-exceeded"
        or original_result.get("boundary", {}).get("receipt_qualified") is not False
        or original_result.get("boundary", {}).get("observed_bytes") != EXPECTED_RETAINED_BYTES
    ):
        raise RuntimeError("original nonqualifying boundary drifted")
    retained_bytes = _retained_bytes()
    if retained_bytes != EXPECTED_RETAINED_BYTES or retained_bytes > MAX_RETAINED_BYTES:
        raise RuntimeError("retained evidence byte boundary drifted")
    if sha256(STORE) != STORE_SHA256:
        raise RuntimeError("production store digest drifted")
    branch = subprocess.run(
        ["git", "branch", "--show-current"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    staged = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT, check=False)
    if branch != "main" or staged.returncode != 0:
        raise RuntimeError("workspace branch or index drifted")

    runtime = json.loads((ROOT / receipt["retained_attempt"]["runtime_import_check"]["path"]).read_text())
    if (
        runtime.get("passed") is not True
        or runtime.get("expected_version") != SEMGREP_VERSION
        or runtime.get("semgrep_cli_started") is not False
    ):
        raise RuntimeError("retained runtime report drifted")
    for name in ("retained_semgrep_canary", "retained_supplemental_canary"):
        canary = json.loads((ROOT / receipt["retained_attempt"][name]["path"]).read_text())
        if canary.get("passed") is not True or canary.get("persisted_findings") != 0:
            raise RuntimeError("retained canary report drifted")
    manifest = json.loads((ROOT / receipt["retained_attempt"]["fixture_manifest"]["path"]).read_text())
    if manifest.get("frozen_before_runtime_import_or_scanner_activity") is not True or len(manifest.get("fixtures", [])) != 4:
        raise RuntimeError("fixture manifest boundary drifted")
    mapping = json.loads((ROOT / receipt["retained_attempt"]["mechanism_mapping"]["path"]).read_text())
    current_cells = {name: list(values) for name, values in SUPPORTED_CELLS.items()}
    if mapping.get("cwe_mapping") != CWE_MAPPING or not supported_cells_match(
        mapping.get("supported_cells"), current_cells
    ):
        raise RuntimeError("frozen mechanism mapping drifted")
    coverage = json.loads(ORIGINAL_ARTIFACT.read_text(encoding="utf-8"))
    if coverage.get("retained_canaries_verified_without_rerun") is not True:
        raise RuntimeError("retained coverage chronology drifted")
    return receipt, coverage


def reproduce(receipt: dict[str, Any], coverage: dict[str, Any]) -> dict[str, Any]:
    """Reproduce only aggregate scan validity, cell counts, and routing."""
    coverage_by_order = {item["order"]: item for item in coverage["scans"]}
    observations: list[dict[str, Any]] = []
    digest_records: list[dict[str, Any]] = []
    for frozen in receipt["retained_scan_evidence"]:
        recorded = coverage_by_order.get(frozen["order"])
        if recorded is None or (recorded["cell"], recorded["expectation"]) != (
            frozen["cell"],
            frozen["expectation"],
        ):
            raise RuntimeError("retained scan chronology drifted")
        sarif = json.loads((ROOT / frozen["sarif"]["path"]).read_text(encoding="utf-8"))
        target_report = json.loads((ROOT / frozen["target_report"]["path"]).read_text(encoding="utf-8"))
        language, mechanism = frozen["cell"].split(":", 1)
        candidates = candidates_from_sarif(
            sarif,
            subject=f"synthetic-{language.lower()}-{frozen['expectation']}",
            language=language,
            scanner="semgrep",
        )
        mapped = sum(candidate.mechanism == mechanism for candidate in candidates)
        valid = _execution_valid(recorded["execution"], target_report)
        if recorded.get("sarif_sha256") != frozen["sarif"]["sha256"]:
            raise RuntimeError("coverage artifact SARIF binding drifted")
        observations.append(
            {
                "order": frozen["order"],
                "cell": frozen["cell"],
                "expectation": frozen["expectation"],
                "execution_valid": valid,
                "mapped_cell_results": mapped,
            }
        )
        digest_records.append(
            {
                "order": frozen["order"],
                "cell": frozen["cell"],
                "expectation": frozen["expectation"],
                "sarif_sha256": frozen["sarif"]["sha256"],
                "target_report_sha256": frozen["target_report"]["sha256"],
            }
        )

    cells = []
    for cell in ("Java:ssrf", "Ruby:unsafe_deserialization"):
        positive = next(item for item in observations if item["cell"] == cell and item["expectation"] == "positive")
        clean = next(item for item in observations if item["cell"] == cell and item["expectation"] == "clean")
        cells.append(
            {
                "cell": cell,
                "positive_execution_valid": positive["execution_valid"],
                "positive_mapped_results": positive["mapped_cell_results"],
                "clean_execution_valid": clean["execution_valid"],
                "clean_mapped_results": clean["mapped_cell_results"],
                "classification": classify_cell(
                    positive_valid=positive["execution_valid"],
                    clean_valid=clean["execution_valid"],
                    positive_mapped=positive["mapped_cell_results"],
                    clean_mapped=clean["mapped_cell_results"],
                ),
            }
        )
    classifications = [item["classification"] for item in cells]
    if any(item in {"clean-control-failure", "scanner-or-provenance-failure"} for item in classifications):
        routing = "stop-instrument-audit-failure"
    elif "coverage-gap" in classifications:
        routing = "supplemental-rule-qualification-prerequisite"
    else:
        routing = "source-scarcity-diagnosis"
    return {
        "cells": cells,
        "supplemental_applicability": {
            "java": coverage["supplemental_applicability"]["java"],
            "ruby": coverage["supplemental_applicability"]["ruby"],
        },
        "routing": routing,
        "retained_scan_set_sha256": hashlib.sha256(_canonical_bytes(digest_records)).hexdigest(),
    }


def run() -> dict[str, Any]:
    started = time.monotonic()
    receipt, coverage = _preflight()
    reproduced = reproduce(receipt, coverage)
    expected = receipt["offline_acceptance_contract"]["expected_result"]
    exact = (
        reproduced["cells"] == expected["cells"]
        and reproduced["supplemental_applicability"] == expected["supplemental_applicability"]
        and reproduced["routing"] == expected["routing"]
    )
    retained_bytes = _retained_bytes()
    artifact_payload = {
        "schema_version": 1,
        "status": "exact-completed-negative-reproduction" if exact else "classification-drift",
        "retained_bindings_verified": True,
        "retained_evidence_bytes": retained_bytes,
        "retained_evidence_ceiling_bytes": MAX_RETAINED_BYTES,
        "reproduced": reproduced,
        "expected": expected,
        "exact_reproduction": exact,
        "original_result_edited_or_requalified": False,
        "runtime_import_checks": 0,
        "scanner_or_canary_processes": 0,
        "repository_or_source_reads": 0,
        "finding_identities_persisted_or_disclosed": 0,
    }
    write_json(ARTIFACT, artifact_payload)
    result: dict[str, Any] = {
        "schema_version": 1,
        "optimization": "OPT-010",
        "status": "completed-negative-corrected-offline-acceptance" if exact else "stopped-classification-reproduction-drift",
        "interpretation": (
            "The retained synthetic evidence reproducibly shows a pinned-default Java SSRF coverage gap and detectable Ruby unsafe deserialization. "
            "The supported next prerequisite is separately authorized Java SSRF supplemental-rule qualification; this does not establish production recall, source prevalence, finding validity, packet feasibility, or OPT-010 completion."
        ),
        "original_evidence": {
            "immutable": True,
            "original_result_remains_nonqualifying": True,
            "historical_new_data_ceiling_failure_preserved": True,
        },
        "acceptance": {
            "retained_bindings_verified": True,
            "exact_classification_reproduction": exact,
            "completed_negative": exact and reproduced["routing"] == "supplemental-rule-qualification-prerequisite",
            "next_prerequisite": reproduced["routing"] if exact else None,
        },
        "cells": reproduced["cells"],
        "supplemental_semgrep": {
            **reproduced["supplemental_applicability"],
            "processes": 0,
        },
        "routing": reproduced["routing"],
        "gates": {
            "packet_frozen": False,
            "paired_execution_started": False,
            "g03b_decided": False,
            "g04_decided": False,
            "opt010_status_changed": False,
        },
        "resource_accounting": {
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "retained_evidence_bytes": retained_bytes,
            "new_data_bytes": 0,
            "network_reads_or_uploads": 0,
            "runtime_import_checks": 0,
            "scanner_or_canary_processes": 0,
            "provider_calls": 0,
            "provider_reported_tokens": 0,
            "provider_cost_usd": 0.0,
            "keychain_or_credential_reads": 0,
            "repository_materializations": 0,
            "repository_or_source_reads": 0,
            "repository_code_executions": 0,
            "production_store_database_reads": 0,
            "production_store_mutations": 0,
            "assessments": 0,
            "labels": 0,
            "model_training_runs": 0,
            "rescoring_runs": 0,
            "agentic_or_baseline_runs": 0,
            "human_reviews": 0,
            "outcomes_read": 0,
            "workspace_branch_or_index_mutations": 0,
            "commits": 0,
            "merges": 0,
            "pushes": 0,
            "lifecycle_changes": 0,
        },
        "production_store": {
            "expected_sha256": STORE_SHA256,
            "after_sha256": sha256(STORE),
            "byte_identical": sha256(STORE) == STORE_SHA256,
        },
    }
    _stable_result(result)
    if not exact:
        raise RuntimeError("retained scanner-cell classifications did not reproduce exactly")
    if time.monotonic() - started > MAX_SECONDS:
        raise RuntimeError("elapsed-time ceiling exceeded")
    if retained_bytes > MAX_RETAINED_BYTES:
        raise RuntimeError("retained-evidence ceiling exceeded")
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

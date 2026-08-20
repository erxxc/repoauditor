"""Offline synthetic scanner-cell coverage audit for OPT-010 Java and Ruby cells."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import yaml

from ..detect.deterministic.provenance import (
    SEMGREP_RULESET_SHA256,
    supplemental_semgrep_provenance,
)
from ..detect.deterministic.sast_adapter import SastAdapter
from .opt010_paired_wave import candidates_from_sarif
from .semgrep_runtime import seed_version_cache


ROOT = Path(__file__).resolve().parents[3]
RECEIPT = ROOT / "docs/optimizations/opt-010-java-ruby-scanner-cell-coverage-receipt-2026-08-20.json"
ARTIFACT_ROOT = ROOT / "data/artifacts/opt010-java-ruby-scanner-cell-coverage"
MANIFEST = ARTIFACT_ROOT / "fixture-manifest.json"
MAPPING = ARTIFACT_ROOT / "mechanism-mapping.json"
RUNTIME_CHECK = ARTIFACT_ROOT / "runtime-import-check.json"
ARTIFACT = ARTIFACT_ROOT / "coverage-artifact.json"
RESULT = ROOT / "docs/optimizations/opt-010-java-ruby-scanner-cell-coverage-result-2026-08-20.json"
FOCUSED_TEST = ROOT / "tests/test_opt_010_scanner_cell_coverage.py"
STORE_SHA256 = "468c8de903f6c4c0ed23304e59db150a1d5d0b6cf350247fba3bc3d2699caf5a"
MAPPING_SHA256 = "5a954ed23a788d34dce0b36bda1b98ad3f8fe322915552f7d237fe57627218b0"
FIXTURE_SET_SHA256 = "3b9b12d566e0592ab37b97c63f7f1b21146280bcd913052c1dc544b1e8d95881"
SEMGREP_VERSION = "1.170.0"
SEMGREP_INTERPRETER = Path("/opt/homebrew/Cellar/semgrep/1.170.0/libexec/bin/python")
SEMGREP_BINARY = Path("/opt/homebrew/bin/semgrep")
MAX_SECONDS = 10 * 60
MAX_NEW_BYTES = 2_097_152


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(_canonical_bytes(payload) + b"\n")
    os.replace(temporary, path)


def fixture_set_digest(rows: list[dict[str, Any]]) -> str:
    canonical = [
        {
            "cell": item["cell"],
            "expectation": item["expectation"],
            "path": item["path"],
            "sha256": item["sha256"],
        }
        for item in rows
    ]
    return hashlib.sha256(_canonical_bytes(canonical)).hexdigest()


def classify_cell(
    *, positive_valid: bool, clean_valid: bool, positive_mapped: int, clean_mapped: int
) -> str:
    if not positive_valid or not clean_valid:
        return "scanner-or-provenance-failure"
    if clean_mapped > 0:
        return "clean-control-failure"
    if positive_mapped == 0:
        return "coverage-gap"
    return "qualified-detectable"


def route(classifications: list[str]) -> str:
    if any(item in {"clean-control-failure", "scanner-or-provenance-failure"} for item in classifications):
        return "stop-instrument-audit-failure"
    if any(item == "coverage-gap" for item in classifications):
        return "supplemental-rule-qualification-prerequisite"
    return "source-scarcity-diagnosis"


def _preflight() -> tuple[dict[str, Any], dict[str, Any]]:
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    if RUNTIME_CHECK.exists() or ARTIFACT.exists() or RESULT.exists():
        raise RuntimeError("coverage output already exists")
    for record in receipt["frozen_inputs"].values():
        if isinstance(record, dict) and sha256(ROOT / record["path"]) != record["sha256"]:
            raise RuntimeError("frozen input digest drifted")
    for record in receipt["frozen_instruments"].values():
        if sha256(ROOT / record["path"]) != record["sha256"]:
            raise RuntimeError("frozen scanner instrument drifted")
    if sha256(ROOT / "data/repoauditor.db") != STORE_SHA256:
        raise RuntimeError("production store digest drifted")
    if sha256(MAPPING) != MAPPING_SHA256:
        raise RuntimeError("copied mechanism mapping drifted")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if (
        manifest.get("frozen_before_runtime_import_or_scanner_activity") is not True
        or manifest.get("fixture_set_sha256") != FIXTURE_SET_SHA256
        or fixture_set_digest(manifest["fixtures"]) != FIXTURE_SET_SHA256
    ):
        raise RuntimeError("fixture manifest drifted")
    receipt_fixtures = receipt["frozen_fixture_contract"]["fixtures"]
    if len(receipt_fixtures) != len(manifest["fixtures"]) == 4:
        raise RuntimeError("fixture denominator drifted")
    for expected, recorded in zip(receipt_fixtures, manifest["fixtures"], strict=True):
        path = ARTIFACT_ROOT / recorded["path"]
        rendered = "\n".join(expected["source_lines"]) + "\n"
        if (
            expected["cell"] != recorded["cell"]
            or expected["expectation"] != recorded["expectation"]
            or expected["path"] != recorded["path"]
            or path.read_text(encoding="utf-8") != rendered
            or sha256(path) != recorded["sha256"]
        ):
            raise RuntimeError("frozen fixture drifted")
    if not SEMGREP_INTERPRETER.is_file() or not SEMGREP_BINARY.exists():
        raise RuntimeError("frozen installed Semgrep path is unavailable")
    resolved = shutil.which("semgrep")
    if resolved is None or Path(resolved).resolve() != SEMGREP_BINARY.resolve():
        raise RuntimeError("PATH Semgrep identity drifted")
    branch = subprocess.run(
        ["git", "branch", "--show-current"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    staged = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT, check=False)
    if branch != "main" or staged.returncode != 0:
        raise RuntimeError("workspace branch or index drifted")
    for name in ("retained_semgrep_canary", "retained_supplemental_canary"):
        canary = json.loads((ROOT / receipt["frozen_inputs"][name]["path"]).read_text())
        if canary.get("passed") is not True or canary.get("persisted_findings") != 0:
            raise RuntimeError("retained scanner canary did not pass")
    rules_path, rules_digest, _ = supplemental_semgrep_provenance()
    document = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    supplemental_languages = sorted({
        str(language).lower()
        for rule in document.get("rules", [])
        for language in rule.get("languages", [])
    })
    if rules_digest != receipt["frozen_instruments"]["supplemental_rules"]["sha256"]:
        raise RuntimeError("supplemental rule digest drifted")
    if "java" in supplemental_languages or "ruby" in supplemental_languages:
        raise RuntimeError("supplemental applicability drifted")
    return receipt, {"languages": supplemental_languages, "java": "not-applicable", "ruby": "not-applicable"}


def _runtime_import() -> None:
    cache = Path(os.environ.get("SEMGREP_VERSION_CACHE_PATH", ""))
    log = Path(os.environ.get("SEMGREP_LOG_FILE", ""))
    if cache != ARTIFACT_ROOT / "semgrep-version-cache" or log != ARTIFACT_ROOT / "semgrep.log":
        raise RuntimeError("Semgrep runtime binding drifted")
    seed_version_cache(cache)
    command = [
        str(SEMGREP_INTERPRETER),
        "-c",
        (
            "import importlib.metadata, semgrep; "
            "version=importlib.metadata.version('semgrep'); "
            "assert version == '1.170.0', version"
        ),
    ]
    completed = subprocess.run(
        command,
        env={**os.environ, "SEMGREP_LOG_FILE": str(log), "SEMGREP_VERSION_CACHE_PATH": str(cache)},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    payload = {
        "schema_version": 1,
        "interpreter": str(SEMGREP_INTERPRETER),
        "expected_version": SEMGREP_VERSION,
        "semgrep_cli_started": False,
        "passed": completed.returncode == 0,
        "failure_type": None if completed.returncode == 0 else "import-or-version-failure",
    }
    write_json(RUNTIME_CHECK, payload)
    if completed.returncode != 0:
        raise RuntimeError("exact installed Semgrep import check failed")


def _execution_valid(execution: dict[str, Any]) -> bool:
    return (
        execution.get("status") in {"complete", "empty"}
        and execution.get("output_valid") is True
        and execution.get("target_count") == 1
        and execution.get("version") == SEMGREP_VERSION
        and execution.get("configuration_resolution") == "pinned-verified"
        and execution.get("configuration_digest") == SEMGREP_RULESET_SHA256
        and isinstance(execution.get("rule_count"), int)
        and execution["rule_count"] > 0
    )


def _scan_fixture(
    *, order: int, path: Path, language: str, mechanism: str, expectation: str
) -> dict[str, Any]:
    output = ARTIFACT_ROOT / "scans" / f"{order:02d}-{language.lower()}-{expectation}"
    output.mkdir(parents=True, exist_ok=False)
    adapter = SastAdapter(
        120,
        sarif_output_path=output / "semgrep.sarif",
        target_report_output_path=output / "semgrep-targets.json",
    )
    adapter.run(path.parent)
    execution = adapter.execution().model_dump(mode="json")
    sarif_path = output / "semgrep.sarif"
    mapped = 0
    if sarif_path.is_file():
        mapped = len(candidates_from_sarif(
            json.loads(sarif_path.read_text(encoding="utf-8")),
            subject=f"synthetic-{language.lower()}-{expectation}",
            language=language,
            scanner="semgrep",
        ))
    return {
        "order": order,
        "cell": f"{language}:{mechanism}",
        "expectation": expectation,
        "execution_valid": _execution_valid(execution),
        "mapped_cell_results": mapped,
        "execution": execution,
        "sarif_sha256": sha256(sarif_path) if sarif_path.is_file() else None,
    }


def _new_bytes() -> int:
    paths = [Path(__file__), FOCUSED_TEST, RESULT]
    paths.extend(path for path in ARTIFACT_ROOT.rglob("*") if path.is_file())
    return sum(path.stat().st_size for path in paths if path.is_file())


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
    _, supplemental = _preflight()
    _runtime_import()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    scans = []
    for order, item in enumerate(manifest["fixtures"], start=1):
        language, mechanism = item["cell"].split(":", 1)
        scans.append(_scan_fixture(
            order=order,
            path=ARTIFACT_ROOT / item["path"],
            language=language,
            mechanism=mechanism,
            expectation=item["expectation"],
        ))
    cells = []
    for cell in ("Java:ssrf", "Ruby:unsafe_deserialization"):
        positive = next(item for item in scans if item["cell"] == cell and item["expectation"] == "positive")
        clean = next(item for item in scans if item["cell"] == cell and item["expectation"] == "clean")
        classification = classify_cell(
            positive_valid=positive["execution_valid"],
            clean_valid=clean["execution_valid"],
            positive_mapped=positive["mapped_cell_results"],
            clean_mapped=clean["mapped_cell_results"],
        )
        cells.append({
            "cell": cell,
            "classification": classification,
            "positive_mapped_results": positive["mapped_cell_results"],
            "clean_mapped_results": clean["mapped_cell_results"],
            "positive_execution_valid": positive["execution_valid"],
            "clean_execution_valid": clean["execution_valid"],
        })
    routing = route([item["classification"] for item in cells])
    artifact_payload = {
        "schema_version": 1,
        "status": "completed-offline-cell-coverage",
        "fixture_set_sha256": FIXTURE_SET_SHA256,
        "mapping_sha256": MAPPING_SHA256,
        "runtime_import": json.loads(RUNTIME_CHECK.read_text()),
        "retained_canaries_verified_without_rerun": True,
        "supplemental_applicability": supplemental,
        "scans": scans,
        "cells": cells,
        "routing": routing,
        "production_or_repository_source_access": 0,
    }
    write_json(ARTIFACT, artifact_payload)
    result: dict[str, Any] = {
        "schema_version": 1,
        "optimization": "OPT-010",
        "status": "completed-offline-java-ruby-scanner-cell-coverage",
        "interpretation": (
            "This synthetic audit classifies only frozen scanner-cell recognition. "
            "It does not estimate production recall, source prevalence, finding validity, or packet feasibility."
        ),
        "cells": cells,
        "routing": routing,
        "supplemental_semgrep": {
            "java": "not-applicable",
            "ruby": "not-applicable",
            "processes": 0,
        },
        "gates": {
            "packet_frozen": False,
            "architecture_recovery_started": False,
            "g03b_decided": False,
            "g04_decided": False,
            "opt010_status_changed": False,
        },
        "resource_accounting": {
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "new_data_bytes": 0,
            "logical_scanner_processes": 4,
            "network_reads_or_uploads": 0,
            "provider_calls": 0,
            "provider_reported_tokens": 0,
            "provider_cost_usd": 0.0,
            "keychain_or_credential_reads": 0,
            "repository_materializations": 0,
            "repository_code_executions": 0,
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
    if time.monotonic() - started > MAX_SECONDS:
        raise RuntimeError("elapsed-time ceiling exceeded")
    if result["resource_accounting"]["new_data_bytes"] > MAX_NEW_BYTES:
        result["status"] = "stopped-nonqualifying-new-data-ceiling-exceeded"
        result["interpretation"] = (
            "The retained synthetic observations are descriptive only because full "
            "pinned-default SARIF retention exceeded the authorized new-data ceiling."
        )
        result["boundary"] = {
            "ceiling_bytes": MAX_NEW_BYTES,
            "observed_bytes": result["resource_accounting"]["new_data_bytes"],
            "receipt_qualified": False,
            "retained_evidence_use": "descriptive-non-qualifying-only",
            "stop_reason": "new-data-ceiling-exceeded",
        }
        _stable_result(result)
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

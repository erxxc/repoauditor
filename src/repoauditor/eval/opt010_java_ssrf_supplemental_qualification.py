"""Scratch-only Java SSRF supplemental Semgrep qualification for OPT-010."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path, PurePosixPath
from typing import Any

from ..detect.deterministic.sast_adapter import SastAdapter
from .opt010_paired_wave import mechanism_from_rule_properties
from .semgrep_runtime import seed_version_cache


ROOT = Path(__file__).resolve().parents[3]
RECEIPT = ROOT / "docs/optimizations/opt-010-java-ssrf-supplemental-rule-qualification-receipt-2026-08-20.json"
ARTIFACT_ROOT = ROOT / "data/artifacts/opt010-java-ssrf-supplemental-qualification"
CANDIDATE_RULE = ARTIFACT_ROOT / "candidate-rule.json"
MANIFEST = ARTIFACT_ROOT / "control-manifest.json"
RUNTIME_CHECK = ARTIFACT_ROOT / "runtime-import-check.json"
ARTIFACT = ARTIFACT_ROOT / "qualification-artifact.json"
RESULT = ROOT / "docs/optimizations/opt-010-java-ssrf-supplemental-rule-qualification-result-2026-08-20.json"
FOCUSED_TEST = ROOT / "tests/test_opt_010_java_ssrf_supplemental_qualification.py"
STORE = ROOT / "data/repoauditor.db"
STORE_SHA256 = "468c8de903f6c4c0ed23304e59db150a1d5d0b6cf350247fba3bc3d2699caf5a"
PRODUCTION_RULESET = ROOT / "src/repoauditor/detect/deterministic/semgrep-supplemental.yml"
PRODUCTION_RULESET_SHA256 = "e3b5ce91d91dcf194eff6fd1a0cdb9b6214a31a71b661075534d919143017963"
RULE_ID = "repoauditor.java.spring.security.tainted-resttemplate-url"
RULE_DIGEST = "03aa9e47ca6e38efa7970a24a8f682ebc2f98029285b11014e50b6cb46636210"
SEMGREP_VERSION = "1.170.0"
SEMGREP_INTERPRETER = Path("/opt/homebrew/Cellar/semgrep/1.170.0/libexec/bin/python")
SEMGREP_BINARY = Path("/opt/homebrew/bin/semgrep")
MAX_SECONDS = 10 * 60
MAX_NEW_BYTES = 5 * 1024**2


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(_canonical_bytes(payload) + b"\n")
    os.replace(temporary, path)


def canonical_scratch_rule_id(rule_id: str) -> str:
    if rule_id == RULE_ID or rule_id.endswith(f".{RULE_ID}"):
        return RULE_ID
    return rule_id


def control_set_digest(rows: list[dict[str, Any]]) -> str:
    canonical = [
        {
            "order": item["order"],
            "id": item["id"],
            "expectation": item["expectation"],
            "path": item["path"],
            "sha256": item["sha256"],
        }
        for item in rows
    ]
    return hashlib.sha256(_canonical_bytes(canonical)).hexdigest()


def expectation_passed(expectation: str, exact_rule_results: int) -> bool:
    if expectation == "raised-exactly-once":
        return exact_rule_results == 1
    if expectation == "absent":
        return exact_rule_results == 0
    return False


def _preflight() -> dict[str, Any]:
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    if ARTIFACT_ROOT.exists() or RESULT.exists():
        raise RuntimeError("qualification output already exists")
    for record in receipt["frozen_inputs"].values():
        if isinstance(record, dict) and sha256(ROOT / record["path"]) != record["sha256"]:
            raise RuntimeError("frozen input digest drifted")
    for record in receipt["frozen_instruments"].values():
        if sha256(ROOT / record["path"]) != record["sha256"]:
            raise RuntimeError("frozen instrument digest drifted")
    if sha256(PRODUCTION_RULESET) != PRODUCTION_RULESET_SHA256:
        raise RuntimeError("production supplemental ruleset drifted")
    if sha256(STORE) != STORE_SHA256:
        raise RuntimeError("production store digest drifted")
    if not SEMGREP_INTERPRETER.is_file() or SEMGREP_BINARY.resolve() != Path("/opt/homebrew/bin/semgrep").resolve():
        raise RuntimeError("exact Semgrep runtime path drifted")
    branch = subprocess.run(
        ["git", "branch", "--show-current"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    staged = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT, check=False)
    if branch != "main" or staged.returncode != 0:
        raise RuntimeError("workspace branch or index drifted")
    controls = receipt["frozen_control_contract"]["ordered_controls"]
    retained = (
        ROOT / receipt["frozen_inputs"]["retained_java_positive_fixture"]["path"],
        ROOT / receipt["frozen_inputs"]["retained_java_clean_fixture"]["path"],
    )
    for source, control in zip(retained, controls[:2], strict=True):
        rendered = "\n".join(control["source_lines"]) + "\n"
        if source.read_text(encoding="utf-8") != rendered:
            raise RuntimeError("retained synthetic control drifted")
    return receipt


def _freeze_inputs(receipt: dict[str, Any]) -> dict[str, Any]:
    ARTIFACT_ROOT.mkdir(parents=False, exist_ok=False)
    rule_payload = {"rules": [receipt["candidate_rule_contract"]["rule"]]}
    write_json(CANDIDATE_RULE, rule_payload)
    if sha256(CANDIDATE_RULE) != RULE_DIGEST:
        raise RuntimeError("scratch candidate digest drifted")
    rows = []
    for control in receipt["frozen_control_contract"]["ordered_controls"]:
        path = ARTIFACT_ROOT / control["path"]
        path.parent.mkdir(parents=True, exist_ok=False)
        path.write_text("\n".join(control["source_lines"]) + "\n", encoding="utf-8")
        rows.append(
            {
                "order": control["order"],
                "id": control["id"],
                "expectation": control["expectation"],
                "path": control["path"],
                "sha256": sha256(path),
            }
        )
    manifest = {
        "schema_version": 1,
        "frozen_before_runtime_or_scanner_activity": True,
        "candidate_rule_sha256": RULE_DIGEST,
        "controls": rows,
        "control_set_sha256": control_set_digest(rows),
    }
    write_json(MANIFEST, manifest)
    return manifest


def _runtime_import() -> None:
    cache = ARTIFACT_ROOT / "semgrep-version-cache"
    log = ARTIFACT_ROOT / "semgrep.log"
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
    completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
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


def _sarif_rule_evidence(payload: dict[str, Any], expected_file: str) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for run in payload.get("runs", []):
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            raw_id = rule.get("id")
            if isinstance(raw_id, str):
                rules[canonical_scratch_rule_id(raw_id)] = rule
        results.extend(run.get("results", []))
    exact_rule = rules.get(RULE_ID)
    exact_cwe = exact_rule is not None and mechanism_from_rule_properties(
        exact_rule.get("properties", {})
    ) == "ssrf"
    exact_results = 0
    locations_valid = True
    unexpected_rule_results = 0
    for result in results:
        canonical = canonical_scratch_rule_id(str(result.get("ruleId", "")))
        if canonical != RULE_ID:
            unexpected_rule_results += 1
            continue
        exact_results += 1
        locations = result.get("locations") or []
        if len(locations) != 1:
            locations_valid = False
            continue
        uri = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
        if not isinstance(uri, str) or PurePosixPath(uri).as_posix() != expected_file:
            locations_valid = False
    return {
        "driver_exact_rule_count": int(exact_rule is not None),
        "driver_exact_cwe918": exact_cwe,
        "exact_rule_results": exact_results,
        "unexpected_rule_results": unexpected_rule_results,
        "locations_valid": locations_valid,
    }


def _scan_control(control: dict[str, Any]) -> dict[str, Any]:
    output = ARTIFACT_ROOT / "scans" / f"{control['order']:02d}"
    output.mkdir(parents=True, exist_ok=False)
    adapter = SastAdapter(
        120,
        sarif_output_path=output / "semgrep.sarif",
        target_report_output_path=output / "semgrep-targets.json",
        configuration=str(CANDIDATE_RULE),
        configuration_label=f"repoauditor-java-ssrf-qualification@sha256:{RULE_DIGEST}",
        scanner_name="semgrep-supplemental",
        producer="semgrep-supplemental",
        applicable_extensions=frozenset({".java"}),
    )
    adapter.version = SEMGREP_VERSION
    adapter.run((ARTIFACT_ROOT / control["path"]).parent)
    execution = adapter.execution().model_dump(mode="json")
    sarif_path = output / "semgrep.sarif"
    target_path = output / "semgrep-targets.json"
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    target = json.loads(target_path.read_text(encoding="utf-8"))
    evidence = _sarif_rule_evidence(sarif, Path(control["path"]).name)
    execution_valid = (
        execution["status"] in {"complete", "empty"}
        and execution["output_valid"] is True
        and execution["target_count"] == 1
        and execution["version"] == SEMGREP_VERSION
        and execution["configuration_resolution"] == "pinned-verified"
        and execution["configuration_digest"] == RULE_DIGEST
        and target.get("version") == SEMGREP_VERSION
        and target.get("errors") == []
        and len(target.get("paths", {}).get("scanned", [])) == 1
        and evidence["driver_exact_rule_count"] == 1
        and evidence["driver_exact_cwe918"] is True
        and evidence["unexpected_rule_results"] == 0
        and evidence["locations_valid"] is True
    )
    passed = execution_valid and expectation_passed(
        control["expectation"], evidence["exact_rule_results"]
    )
    return {
        "order": control["order"],
        "id": control["id"],
        "expectation": control["expectation"],
        "execution_valid": execution_valid,
        "exact_rule_results": evidence["exact_rule_results"],
        "driver_exact_rule_count": evidence["driver_exact_rule_count"],
        "driver_exact_cwe918": evidence["driver_exact_cwe918"],
        "unexpected_rule_results": evidence["unexpected_rule_results"],
        "locations_valid": evidence["locations_valid"],
        "passed": passed,
        "execution": execution,
        "sarif_sha256": sha256(sarif_path),
        "target_report_sha256": sha256(target_path),
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
    receipt = _preflight()
    manifest = _freeze_inputs(receipt)
    original_env = {
        "SEMGREP_LOG_FILE": os.environ.get("SEMGREP_LOG_FILE"),
        "SEMGREP_VERSION_CACHE_PATH": os.environ.get("SEMGREP_VERSION_CACHE_PATH"),
    }
    os.environ["SEMGREP_LOG_FILE"] = str(ARTIFACT_ROOT / "semgrep.log")
    os.environ["SEMGREP_VERSION_CACHE_PATH"] = str(ARTIFACT_ROOT / "semgrep-version-cache")
    try:
        _runtime_import()
        scans = [_scan_control(control) for control in manifest["controls"]]
    finally:
        for name, value in original_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    qualified = len(scans) == 6 and all(item["passed"] for item in scans)
    artifact_payload = {
        "schema_version": 1,
        "status": "qualified-synthetic-scratch-rule" if qualified else "completed-negative-synthetic-qualification",
        "candidate_rule_sha256": RULE_DIGEST,
        "control_set_sha256": manifest["control_set_sha256"],
        "controls": [
            {
                key: item[key]
                for key in (
                    "order",
                    "id",
                    "expectation",
                    "execution_valid",
                    "exact_rule_results",
                    "driver_exact_rule_count",
                    "driver_exact_cwe918",
                    "unexpected_rule_results",
                    "locations_valid",
                    "passed",
                    "sarif_sha256",
                    "target_report_sha256",
                )
            }
            for item in scans
        ],
        "qualified": qualified,
        "production_rule_edited_or_promoted": False,
        "repository_or_production_source_reads": 0,
        "finding_or_candidate_identities_persisted_or_disclosed": 0,
    }
    write_json(ARTIFACT, artifact_payload)
    result: dict[str, Any] = {
        "schema_version": 1,
        "optimization": "OPT-010",
        "status": "qualified-synthetic-scratch-rule" if qualified else "completed-negative-synthetic-qualification",
        "interpretation": (
            "The exact scratch Java RestTemplate rule passed all frozen synthetic controls and may proceed only to a separately authorized retained-source rescan."
            if qualified
            else "The exact scratch Java RestTemplate rule did not pass every frozen synthetic control and cannot proceed to retained-source rescanning or production promotion."
        ),
        "qualification": {
            "candidate_rule_sha256": RULE_DIGEST,
            "controls_total": len(scans),
            "controls_passed": sum(item["passed"] for item in scans),
            "positive_controls": sum(item["expectation"] == "raised-exactly-once" for item in scans),
            "clean_controls": sum(item["expectation"] == "absent" for item in scans),
            "qualified": qualified,
            "next_prerequisite": "separately-authorized-retained-java-source-rescan" if qualified else None,
        },
        "boundaries": {
            "production_rule_edited_or_promoted": False,
            "retained_source_rescan_started": False,
            "packet_frozen": False,
            "g03b_decided": False,
            "g04_decided": False,
            "opt010_status_changed": False,
        },
        "resource_accounting": {
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "new_data_bytes": 0,
            "runtime_import_checks": 1,
            "logical_scanner_processes": len(scans),
            "network_reads_or_uploads": 0,
            "provider_calls": 0,
            "provider_reported_tokens": 0,
            "provider_cost_usd": 0.0,
            "keychain_or_credential_reads": 0,
            "repository_materializations": 0,
            "repository_or_production_source_reads": 0,
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
        "production_supplemental_ruleset": {
            "expected_sha256": PRODUCTION_RULESET_SHA256,
            "after_sha256": sha256(PRODUCTION_RULESET),
            "byte_identical": sha256(PRODUCTION_RULESET) == PRODUCTION_RULESET_SHA256,
        },
        "production_store": {
            "expected_sha256": STORE_SHA256,
            "after_sha256": sha256(STORE),
            "byte_identical": sha256(STORE) == STORE_SHA256,
        },
    }
    _stable_result(result)
    if time.monotonic() - started > MAX_SECONDS:
        raise RuntimeError("elapsed-time ceiling exceeded")
    if result["resource_accounting"]["new_data_bytes"] > MAX_NEW_BYTES:
        raise RuntimeError("new-data ceiling exceeded")
    if not result["production_supplemental_ruleset"]["byte_identical"]:
        raise RuntimeError("production supplemental ruleset changed")
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

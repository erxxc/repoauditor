"""Outcome-blind retained Java SSRF source screen for OPT-010."""

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

from ..detect.deterministic.sast_adapter import SastAdapter
from .opt010_acquisition_qualification import _snapshot_digest
from .opt010_paired_wave import candidates_from_sarif, deduplicate
from .semgrep_runtime import seed_version_cache


ROOT = Path(__file__).resolve().parents[3]
RECEIPT = ROOT / "docs/optimizations/opt-010-java-ssrf-retained-source-screen-receipt-2026-08-20.json"
ARTIFACT_ROOT = ROOT / "data/artifacts/opt010-java-ssrf-retained-source-screen"
SCRATCH_RULE = ARTIFACT_ROOT / "candidate-rule.json"
RUNTIME_CHECK = ARTIFACT_ROOT / "runtime-import-check.json"
ARTIFACT = ARTIFACT_ROOT / "screen-artifact.json"
RESULT = ROOT / "docs/optimizations/opt-010-java-ssrf-retained-source-screen-result-2026-08-20.json"
FOCUSED_TEST = ROOT / "tests/test_opt_010_java_ssrf_retained_source_screen.py"
STORE = ROOT / "data/repoauditor.db"
STORE_SHA256 = "468c8de903f6c4c0ed23304e59db150a1d5d0b6cf350247fba3bc3d2699caf5a"
PRODUCTION_RULESET = ROOT / "src/repoauditor/detect/deterministic/semgrep-supplemental.yml"
PRODUCTION_RULESET_SHA256 = "e3b5ce91d91dcf194eff6fd1a0cdb9b6214a31a71b661075534d919143017963"
RULE_ID = "repoauditor.java.spring.security.tainted-resttemplate-url"
RULE_DIGEST = "03aa9e47ca6e38efa7970a24a8f682ebc2f98029285b11014e50b6cb46636210"
SEMGREP_VERSION = "1.170.0"
SEMGREP_INTERPRETER = Path("/opt/homebrew/Cellar/semgrep/1.170.0/libexec/bin/python")
SEMGREP_BINARY = Path("/opt/homebrew/bin/semgrep")
MAX_SECONDS = 30 * 60
MAX_NEW_BYTES = 10 * 1024**2


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


def combined_capacity(java_results: int, java_groups: int) -> dict[str, Any]:
    family = {"Java": java_groups, "Python": 29, "Ruby": 0, "TypeScript": 19}
    mechanism = {
        "command_injection": 30,
        "sql_injection": 18,
        "ssrf": java_groups,
        "unsafe_deserialization": 0,
    }
    capped = sum(min(value, 20) for value in family.values())
    return {
        "metadata_compatible_results": 57 + java_results,
        "metadata_deduplicated_issue_groups": 48 + java_groups,
        "by_supported_family": family,
        "by_mechanism": mechanism,
        "supported_families_contributing": sum(value > 0 for value in family.values()),
        "capped_packet_capacity": capped,
        "provisionally_feasible": capped >= 40 and all(value > 0 for value in family.values()),
    }


def _git_head(snapshot: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=snapshot, capture_output=True, text=True, check=False
    )
    if completed.returncode != 0:
        raise RuntimeError("retained snapshot HEAD unavailable")
    return completed.stdout.strip()


def _preflight() -> dict[str, Any]:
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    if ARTIFACT_ROOT.exists() or RESULT.exists():
        raise RuntimeError("retained-source screen output already exists")
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
    if not SEMGREP_INTERPRETER.is_file() or not SEMGREP_BINARY.is_file():
        raise RuntimeError("exact Semgrep runtime unavailable")
    branch = subprocess.run(
        ["git", "branch", "--show-current"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    staged = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT, check=False)
    if branch != "main" or staged.returncode != 0:
        raise RuntimeError("workspace branch or index drifted")
    qualification = json.loads(
        (ROOT / receipt["frozen_inputs"]["scratch_rule_qualification_result"]["path"]).read_text()
    )
    if qualification.get("qualification", {}).get("qualified") is not True:
        raise RuntimeError("scratch rule is not qualified")
    base = json.loads((ROOT / receipt["frozen_inputs"]["base_capacity_result"]["path"]).read_text())
    expected_base = receipt["screen_contract"]["base_aggregate"]
    if base.get("aggregate_metadata_feasibility") != {
        **expected_base,
        "scanner_artifact_set_sha256": base["aggregate_metadata_feasibility"]["scanner_artifact_set_sha256"],
    }:
        raise RuntimeError("frozen base aggregate drifted")
    for subject in receipt["frozen_subjects"]:
        snapshot = ROOT / subject["snapshot"]
        if _git_head(snapshot) != subject["exact_commit"]:
            raise RuntimeError("retained snapshot commit drifted")
        digest, _, _ = _snapshot_digest(snapshot)
        if digest != subject["snapshot_sha256"]:
            raise RuntimeError("retained snapshot digest drifted")
    return receipt


def _freeze_rule(receipt: dict[str, Any]) -> None:
    ARTIFACT_ROOT.mkdir(parents=False, exist_ok=False)
    source = ROOT / receipt["frozen_inputs"]["qualified_scratch_rule"]["path"]
    shutil.copyfile(source, SCRATCH_RULE)
    if sha256(SCRATCH_RULE) != RULE_DIGEST:
        raise RuntimeError("copied scratch rule digest drifted")


def _runtime_import() -> None:
    cache = ARTIFACT_ROOT / "semgrep-version-cache"
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


def _validate_raw_rules(sarif: dict[str, Any]) -> tuple[int, int]:
    driver_rules: set[str] = set()
    result_rules: list[str] = []
    for run in sarif.get("runs", []):
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            raw = rule.get("id")
            if isinstance(raw, str):
                driver_rules.add(canonical_scratch_rule_id(raw))
        for result in run.get("results", []):
            result_rules.append(canonical_scratch_rule_id(str(result.get("ruleId", ""))))
    return sum(item == RULE_ID for item in driver_rules), sum(item != RULE_ID for item in result_rules)


def _scan_subject(subject: dict[str, Any]) -> tuple[dict[str, Any], list[Any]]:
    output = ARTIFACT_ROOT / "scans" / f"{subject['order']:02d}"
    output.mkdir(parents=True, exist_ok=False)
    adapter = SastAdapter(
        900,
        sarif_output_path=output / "semgrep.sarif",
        target_report_output_path=output / "semgrep-targets.json",
        configuration=str(SCRATCH_RULE),
        configuration_label=f"repoauditor-java-ssrf-screen@sha256:{RULE_DIGEST}",
        scanner_name="semgrep-supplemental",
        producer="semgrep-supplemental",
        applicable_extensions=frozenset({".java"}),
    )
    adapter.version = SEMGREP_VERSION
    snapshot = ROOT / subject["snapshot"]
    adapter.run(snapshot)
    execution = adapter.execution().model_dump(mode="json")
    sarif_path = output / "semgrep.sarif"
    target_path = output / "semgrep-targets.json"
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    target = json.loads(target_path.read_text(encoding="utf-8"))
    driver_rule_count, unexpected_rule_results = _validate_raw_rules(sarif)
    candidates = candidates_from_sarif(
        sarif,
        subject=subject["stable_identity_sha256"],
        language="Java",
        scanner="semgrep-supplemental",
    )
    raw_results = sum(len(run.get("results", [])) for run in sarif.get("runs", []))
    valid = (
        execution["status"] in {"complete", "empty"}
        and execution["output_valid"] is True
        and execution["target_count"] > 0
        and execution["version"] == SEMGREP_VERSION
        and execution["configuration_resolution"] == "pinned-verified"
        and execution["configuration_digest"] == RULE_DIGEST
        and target.get("version") == SEMGREP_VERSION
        and target.get("errors") == []
        and len(target.get("paths", {}).get("scanned", [])) == execution["target_count"]
        and driver_rule_count == 1
        and unexpected_rule_results == 0
        and len(candidates) == raw_results
    )
    if not valid:
        raise RuntimeError("retained Java scratch scan or provenance failed")
    return (
        {
            "execution_valid": True,
            "target_count": execution["target_count"],
            "compatible_results": len(candidates),
            "sarif_sha256": sha256(sarif_path),
            "target_report_sha256": sha256(target_path),
        },
        candidates,
    )


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
    _freeze_rule(receipt)
    original_env = {
        "SEMGREP_LOG_FILE": os.environ.get("SEMGREP_LOG_FILE"),
        "SEMGREP_VERSION_CACHE_PATH": os.environ.get("SEMGREP_VERSION_CACHE_PATH"),
    }
    os.environ["SEMGREP_LOG_FILE"] = str(ARTIFACT_ROOT / "semgrep.log")
    os.environ["SEMGREP_VERSION_CACHE_PATH"] = str(ARTIFACT_ROOT / "semgrep-version-cache")
    try:
        _runtime_import()
        scan_records = []
        candidates = []
        for subject in receipt["frozen_subjects"]:
            record, subject_candidates = _scan_subject(subject)
            scan_records.append(record)
            candidates.extend(subject_candidates)
    finally:
        for name, value in original_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    groups = deduplicate(candidates)
    aggregate = combined_capacity(len(candidates), len(groups))
    if aggregate["provisionally_feasible"] is not False:
        raise RuntimeError("Ruby-zero packet boundary drifted")
    routing = (
        "ruby-source-scarcity"
        if len(groups) > 0
        else "java-and-ruby-source-scarcity"
    )
    raw_hashes = sorted(
        value
        for record in scan_records
        for key, value in record.items()
        if key in {"sarif_sha256", "target_report_sha256"}
    )
    artifact_payload = {
        "schema_version": 1,
        "status": "completed-outcome-blind-retained-java-screen",
        "qualified_scratch_rule_sha256": RULE_DIGEST,
        "frozen_subjects_verified": 2,
        "scanner_executions_valid": sum(record["execution_valid"] for record in scan_records),
        "aggregate_scanner_targets": sum(record["target_count"] for record in scan_records),
        "java_compatible_results": len(candidates),
        "java_deduplicated_issue_groups": len(groups),
        "combined_capacity": aggregate,
        "routing": routing,
        "raw_artifact_set_sha256": hashlib.sha256("".join(raw_hashes).encode()).hexdigest(),
        "normalized_candidate_or_issue_group_identities_persisted_or_disclosed": 0,
        "subject_level_counts_persisted_or_disclosed": 0,
        "packet_constructed": False,
    }
    write_json(ARTIFACT, artifact_payload)
    result: dict[str, Any] = {
        "schema_version": 1,
        "optimization": "OPT-010",
        "status": "completed-outcome-blind-java-cell-recovered" if len(groups) > 0 else "completed-negative-java-and-ruby-source-scarcity",
        "interpretation": (
            "The qualified scratch rule recovered aggregate Java SSRF groups in the retained sources; Ruby source scarcity remains the next prerequisite and the four-family packet remains infeasible."
            if len(groups) > 0
            else "The qualified scratch rule recovered no Java SSRF groups in the retained sources; Java and Ruby source scarcity remain and the four-family packet remains infeasible."
        ),
        "aggregate_java_screen": {
            "compatible_results": len(candidates),
            "deduplicated_issue_groups": len(groups),
            "raw_artifact_set_sha256": artifact_payload["raw_artifact_set_sha256"],
        },
        "combined_capacity": aggregate,
        "routing": routing,
        "boundaries": {
            "production_rule_edited_or_promoted": False,
            "normalized_candidate_or_issue_group_identities_persisted_or_disclosed": 0,
            "subject_level_counts_persisted_or_disclosed": 0,
            "packet_constructed": False,
            "g03b_decided": False,
            "g04_decided": False,
            "opt010_status_changed": False,
        },
        "resource_accounting": {
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "new_data_bytes": 0,
            "frozen_snapshot_subjects": 2,
            "runtime_import_checks": 1,
            "logical_scanner_processes": 2,
            "network_reads_or_uploads": 0,
            "provider_calls": 0,
            "provider_reported_tokens": 0,
            "provider_cost_usd": 0.0,
            "keychain_or_credential_reads": 0,
            "repository_materializations": 0,
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

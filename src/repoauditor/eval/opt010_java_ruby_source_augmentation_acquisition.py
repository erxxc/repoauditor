"""Corrected outcome-blind Java/Ruby source augmentation screen for OPT-010."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..detect.deterministic.provenance import SEMGREP_RULESET_SHA256
from ..detect.deterministic.sast_adapter import SastAdapter
from .opt010_acquisition_qualification import (
    _acquire,
    _detector_input_digest,
    _retrieval_summary,
    _snapshot_digest,
)
from .opt010_paired_wave import (
    candidates_from_sarif,
    deduplicate,
    mechanism_from_rule_properties,
)
from .semgrep_runtime import seed_version_cache


ROOT = Path(__file__).resolve().parents[3]
ORIGINAL_RECEIPT = ROOT / "docs/optimizations/opt-010-java-ruby-source-augmentation-acquisition-screen-receipt-2026-08-20.json"
CORRECTED_RECEIPT = ROOT / "docs/optimizations/opt-010-java-ruby-source-augmentation-acquisition-screen-corrected-retry-receipt-2026-08-20.json"
FINAL_RECEIPT = ROOT / "docs/optimizations/opt-010-java-ruby-source-augmentation-acquisition-screen-final-retry-receipt-2026-08-20.json"
STOPPED_RESULT = ROOT / "docs/optimizations/opt-010-java-ruby-source-augmentation-acquisition-screen-result-2026-08-20.json"
CORRECTED_STOPPED_RESULT = ROOT / "docs/optimizations/opt-010-java-ruby-source-augmentation-acquisition-screen-corrected-retry-result-2026-08-20.json"
RESULT = ROOT / "docs/optimizations/opt-010-java-ruby-source-augmentation-acquisition-screen-final-retry-result-2026-08-20.json"
ARTIFACT_ROOT = ROOT / "data/artifacts/opt010-java-ruby-source-augmentation-acquisition-screen-final-retry"
ARTIFACT = ARTIFACT_ROOT / "aggregate-artifact.json"
MAPPING = ARTIFACT_ROOT / "mechanism-mapping.json"
SCRATCH_RULE = ARTIFACT_ROOT / "candidate-rule.json"
RUNTIME_CHECK = ARTIFACT_ROOT / "runtime-import-check.json"
FOCUSED_TEST = ROOT / "tests/test_opt_010_java_ruby_source_augmentation_acquisition.py"
STORE = ROOT / "data/repoauditor.db"
PRODUCTION_RULES = ROOT / "src/repoauditor/detect/deterministic/semgrep-supplemental.yml"
STORE_SHA256 = "468c8de903f6c4c0ed23304e59db150a1d5d0b6cf350247fba3bc3d2699caf5a"
PRODUCTION_RULES_SHA256 = "e3b5ce91d91dcf194eff6fd1a0cdb9b6214a31a71b661075534d919143017963"
MAPPING_SHA256 = "5a954ed23a788d34dce0b36bda1b98ad3f8fe322915552f7d237fe57627218b0"
JAVA_RULE_SHA256 = "03aa9e47ca6e38efa7970a24a8f682ebc2f98029285b11014e50b6cb46636210"
JAVA_RULE_ID = "repoauditor.java.spring.security.tainted-resttemplate-url"
SEMGREP_VERSION = "1.170.0"
SEMGREP_INTERPRETER = Path("/opt/homebrew/Cellar/semgrep/1.170.0/libexec/bin/python")
SEMGREP_BINARY = Path("/opt/homebrew/bin/semgrep")
MAX_SECONDS = 780 * 60
MAX_REPOSITORY_SECONDS = 180 * 60
MAX_NEW_BYTES = 15 * 1024**3
RETAINED_NEW_BYTES = 38_929


@dataclass(frozen=True)
class Subject:
    order: int
    repository: str
    commit: str
    stable_identity: str
    language: str
    mechanism: str


SUBJECTS = (
    Subject(1, "Suwayomi/Suwayomi-Server", "4b2c19abbc637dfd2c26b9b5eafd326ba92f91ee", "32a6c35ce90f7818d69da1ac87c5b672e969daba50ecfaf81f720f1213bc796c", "Java", "ssrf"),
    Subject(2, "codelibs/fess", "41f138b5b91af26413ae6cab05bb6acffa6611df", "9f6e322f1bb116d30ef5c417dbe99bf3aaa1ef3ba5ec296a9476c7d3236bd17e", "Java", "ssrf"),
    Subject(3, "Multiwoven/multiwoven", "0a68d209009f9009664e96ef1e5d1f23843781b2", "067c9c94d76c421ccb540eae192cc1cdfe70d89a5121258905359b405c4275f8", "Ruby", "unsafe_deserialization"),
    Subject(4, "docusealco/docuseal", "004a22c1c88109c7ba0b567df011a8cb13894001", "1ac9ce7c055dc18077aa032f4c44fd4edcffe008963b24d4134736703854d51e", "Ruby", "unsafe_deserialization"),
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


def combined_capacity(java_results: int, java_groups: int, ruby_results: int, ruby_groups: int) -> dict[str, Any]:
    family = {"Java": java_groups, "Python": 29, "Ruby": ruby_groups, "TypeScript": 19}
    mechanism = {
        "command_injection": 30,
        "sql_injection": 18,
        "ssrf": java_groups,
        "unsafe_deserialization": ruby_groups,
    }
    capped = sum(min(value, 20) for value in family.values())
    return {
        "metadata_compatible_results": 57 + java_results + ruby_results,
        "metadata_deduplicated_issue_groups": 48 + java_groups + ruby_groups,
        "by_supported_family": family,
        "by_mechanism": mechanism,
        "supported_families_contributing": sum(value > 0 for value in family.values()),
        "capped_packet_capacity": capped,
        "provisionally_feasible": capped >= 40 and all(value > 0 for value in family.values()),
    }


def _verify_records(records: dict[str, Any]) -> None:
    for record in records.values():
        if isinstance(record, dict) and "path" in record:
            if sha256(ROOT / record["path"]) != record["sha256"]:
                raise RuntimeError("frozen file digest drifted")


def _preflight() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    original = json.loads(ORIGINAL_RECEIPT.read_text(encoding="utf-8"))
    corrected = json.loads(CORRECTED_RECEIPT.read_text(encoding="utf-8"))
    final = json.loads(FINAL_RECEIPT.read_text(encoding="utf-8"))
    if ARTIFACT_ROOT.exists() or RESULT.exists():
        raise RuntimeError("corrected-retry output already exists")
    _verify_records(original["frozen_inputs"])
    _verify_records(original["frozen_instruments"])
    _verify_records(corrected["retained_authority"])
    _verify_records(corrected["added_frozen_inputs"])
    _verify_records(corrected["added_frozen_instruments"])
    _verify_records({
        key: value
        for key, value in final["retained_authority"].items()
        if key not in {"pre_correction_helper", "pre_correction_focused_test"}
    })
    _verify_records(final["retained_corrected_attempt_evidence"])
    stopped = json.loads(STOPPED_RESULT.read_text(encoding="utf-8"))
    accepted = corrected["retained_authority"]["accepted_state"]
    if (
        stopped.get("status") != accepted["status"]
        or stopped.get("preflight", {}).get("artifact_directory_created") is not False
        or stopped.get("resource_accounting", {}).get("logical_scanner_processes") != 0
        or stopped.get("resource_accounting", {}).get("network_reads") != 0
    ):
        raise RuntimeError("retained stopped state drifted")
    corrected_stopped = json.loads(CORRECTED_STOPPED_RESULT.read_text(encoding="utf-8"))
    accepted_final = final["accepted_stopped_state"]
    accounting = corrected_stopped.get("resource_accounting", {})
    if (
        corrected_stopped.get("status") != accepted_final["status"]
        or corrected_stopped.get("stop_reason") != accepted_final["stop_reason"]
        or accounting.get("runtime_import_checks") != accepted_final["runtime_import_checks"]
        or accounting.get("logical_scanner_processes") != accepted_final["logical_scanner_processes"]
        or accounting.get("repositories_materialized") != 0
        or accounting.get("network_hosts_used") != []
    ):
        raise RuntimeError("retained corrected-retry state drifted")
    if sha256(STORE) != STORE_SHA256 or sha256(PRODUCTION_RULES) != PRODUCTION_RULES_SHA256:
        raise RuntimeError("production store or supplemental rules drifted")
    if not SEMGREP_INTERPRETER.is_file() or not SEMGREP_BINARY.is_file():
        raise RuntimeError("exact Semgrep runtime unavailable")
    branch = subprocess.run(
        ["git", "branch", "--show-current"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    staged = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT, check=False)
    workspace = original["workspace_preflight"]
    if branch != workspace["branch"] or head != workspace["committed_main"] or staged.returncode != 0:
        raise RuntimeError("workspace branch, HEAD, or index drifted")
    frozen = original["frozen_subjects"]
    actual = [
        (item.order, item.repository, item.commit, item.stable_identity, item.language, item.mechanism)
        for item in SUBJECTS
    ]
    expected = [
        (item["order"], item["repository"], item["exact_commit"], item["stable_identity_sha256"], item["language"], item["mechanism"])
        for item in frozen
    ]
    if actual != expected:
        raise RuntimeError("frozen subject identity drifted")
    java = json.loads(
        (ROOT / original["frozen_inputs"]["java_scratch_rule_qualification_result"]["path"]).read_text()
    )
    ruby = json.loads(
        (ROOT / corrected["added_frozen_inputs"]["ruby_scanner_cell_corrected_acceptance_result"]["path"]).read_text()
    )
    ruby_cell = next(item for item in ruby["cells"] if item["cell"] == "Ruby:unsafe_deserialization")
    if java.get("qualification", {}).get("qualified") is not True or ruby_cell.get("classification") != "qualified-detectable":
        raise RuntimeError("scanner-cell qualification drifted")
    return original, corrected, final


def validate_java_scratch_configuration(payload: Any) -> bool:
    """Validate the frozen JSON rule structurally, never through a YAML text counter."""
    if not isinstance(payload, dict) or not isinstance(payload.get("rules"), list):
        return False
    rules = payload["rules"]
    if len(rules) != 1 or not isinstance(rules[0], dict):
        return False
    rule = rules[0]
    return (
        rule.get("id") == JAVA_RULE_ID
        and rule.get("languages") == ["java"]
        and mechanism_from_rule_properties(rule.get("metadata", {})) == "ssrf"
    )


def validate_java_sarif(payload: Any) -> bool:
    """Bind the SARIF driver and every result to the exact canonical Java rule."""
    if not isinstance(payload, dict):
        return False
    exact_rules = 0
    for run in payload.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            rule_id = str(rule.get("id", ""))
            canonical = JAVA_RULE_ID if rule_id == JAVA_RULE_ID or rule_id.endswith(f".{JAVA_RULE_ID}") else rule_id
            if canonical == JAVA_RULE_ID:
                if mechanism_from_rule_properties(rule.get("properties", {})) != "ssrf":
                    return False
                exact_rules += 1
        for result in run.get("results", []):
            rule_id = str(result.get("ruleId", ""))
            canonical = JAVA_RULE_ID if rule_id == JAVA_RULE_ID or rule_id.endswith(f".{JAVA_RULE_ID}") else rule_id
            if canonical != JAVA_RULE_ID:
                return False
    return exact_rules == 1


def _freeze_inputs(original: dict[str, Any], corrected: dict[str, Any]) -> list[dict[str, Any]]:
    ARTIFACT_ROOT.mkdir(parents=False, exist_ok=False)
    shutil.copyfile(ROOT / original["frozen_inputs"]["mechanism_mapping"]["path"], MAPPING)
    shutil.copyfile(ROOT / original["frozen_inputs"]["qualified_java_scratch_rule"]["path"], SCRATCH_RULE)
    if sha256(MAPPING) != MAPPING_SHA256 or sha256(SCRATCH_RULE) != JAVA_RULE_SHA256:
        raise RuntimeError("copied mapping or Java scratch rule drifted")
    controls = []
    specifications = (
        (1, "Java", "positive", "java_positive_control"),
        (2, "Java", "clean", "java_clean_control"),
        (3, "Ruby", "positive", "ruby_positive_control"),
        (4, "Ruby", "clean", "ruby_clean_control"),
    )
    for order, language, expectation, key in specifications:
        source = ROOT / corrected["added_frozen_inputs"][key]["path"]
        destination = ARTIFACT_ROOT / "canary-controls" / f"{order:02d}-{language.lower()}-{expectation}" / source.name
        destination.parent.mkdir(parents=True, exist_ok=False)
        shutil.copyfile(source, destination)
        expected = corrected["added_frozen_inputs"][key]["sha256"]
        if sha256(destination) != expected:
            raise RuntimeError("copied canary control drifted")
        controls.append({
            "order": order,
            "language": language,
            "expectation": expectation,
            "path": destination.relative_to(ARTIFACT_ROOT).as_posix(),
            "sha256": expected,
        })
    write_json(
        ARTIFACT_ROOT / "canary-manifest.json",
        {"schema_version": 1, "frozen_before_runtime_or_scanner_activity": True, "controls": controls},
    )
    return controls


def _runtime_import() -> None:
    cache = ARTIFACT_ROOT / "semgrep-version-cache"
    log = ARTIFACT_ROOT / "semgrep.log"
    seed_version_cache(cache)
    completed = subprocess.run(
        [
            str(SEMGREP_INTERPRETER),
            "-c",
            "import importlib.metadata, semgrep; version=importlib.metadata.version('semgrep'); assert version == '1.170.0', version",
        ],
        env={**os.environ, "SEMGREP_LOG_FILE": str(log), "SEMGREP_VERSION_CACHE_PATH": str(cache), "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"},
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


def _scan(
    path: Path, output: Path, language: str, activity: dict[str, int]
) -> tuple[dict[str, Any], list[Any]]:
    output.mkdir(parents=True, exist_ok=False)
    if language == "Java":
        adapter = SastAdapter(
            MAX_REPOSITORY_SECONDS,
            sarif_output_path=output / "semgrep.sarif",
            target_report_output_path=output / "semgrep-targets.json",
            configuration=str(SCRATCH_RULE),
            configuration_label=f"repoauditor-java-ssrf-screen@sha256:{JAVA_RULE_SHA256}",
            scanner_name="semgrep-supplemental",
            producer="semgrep-supplemental",
            applicable_extensions=frozenset({".java"}),
        )
        scanner = "semgrep-supplemental"
        expected_digest = JAVA_RULE_SHA256
    elif language == "Ruby":
        adapter = SastAdapter(
            MAX_REPOSITORY_SECONDS,
            sarif_output_path=output / "semgrep.sarif",
            target_report_output_path=output / "semgrep-targets.json",
            applicable_extensions=frozenset({".rb"}),
        )
        scanner = "semgrep"
        expected_digest = SEMGREP_RULESET_SHA256
    else:
        raise RuntimeError("unsupported source language")
    adapter.version = SEMGREP_VERSION
    activity["logical_scanner_processes"] += 1
    adapter.run(path)
    execution = adapter.execution().model_dump(mode="json")
    sarif_path = output / "semgrep.sarif"
    target_path = output / "semgrep-targets.json"
    if not sarif_path.is_file() or not target_path.is_file():
        raise RuntimeError("scanner raw evidence missing")
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    target = json.loads(target_path.read_text(encoding="utf-8"))
    candidates = candidates_from_sarif(sarif, subject="canary-or-frozen-subject", language=language, scanner=scanner)
    raw_results = sum(len(run.get("results", [])) for run in sarif.get("runs", []))
    java_structure_valid = language != "Java" or validate_java_scratch_configuration(
        json.loads(SCRATCH_RULE.read_text(encoding="utf-8"))
    )
    java_sarif_valid = language != "Java" or validate_java_sarif(sarif)
    rule_count_valid = (
        java_structure_valid
        if language == "Java"
        else isinstance(execution.get("rule_count"), int) and execution["rule_count"] > 0
    )
    valid = (
        execution.get("status") in {"complete", "empty"}
        and execution.get("output_valid") is True
        and execution.get("target_count", 0) > 0
        and execution.get("version") == SEMGREP_VERSION
        and execution.get("configuration_resolution") == "pinned-verified"
        and execution.get("configuration_digest") == expected_digest
        and rule_count_valid
        and target.get("version") == SEMGREP_VERSION
        and target.get("errors") == []
        and len(target.get("paths", {}).get("scanned", [])) == execution["target_count"]
        and java_sarif_valid
        and (language != "Java" or len(candidates) == raw_results)
    )
    if not valid:
        raise RuntimeError(f"{language} scan or provenance failed")
    record = {
        "status": execution["status"],
        "version": execution["version"],
        "configuration_digest": execution["configuration_digest"],
        "configuration_resolution": execution["configuration_resolution"],
        "rule_count": 1 if language == "Java" else execution["rule_count"],
        "adapter_text_rule_count": execution["rule_count"],
        "target_count": execution["target_count"],
        "sarif_sha256": sha256(sarif_path),
        "target_report_sha256": sha256(target_path),
    }
    return record, candidates


def _run_canaries(
    controls: list[dict[str, Any]], activity: dict[str, int]
) -> list[dict[str, Any]]:
    records = []
    for control in controls:
        path = ARTIFACT_ROOT / control["path"]
        scan, candidates = _scan(
            path.parent,
            ARTIFACT_ROOT / "canary-scans" / f"{control['order']:02d}",
            control["language"],
            activity,
        )
        count = len(candidates)
        passed = count > 0 if control["expectation"] == "positive" else count == 0
        if control["language"] == "Java" and control["expectation"] == "positive":
            passed = count == 1
        record = {
            "order": control["order"],
            "language": control["language"],
            "expectation": control["expectation"],
            "compatible_results": count,
            "passed": passed,
            **scan,
        }
        records.append(record)
        if not passed:
            raise RuntimeError(f"{control['language']} {control['expectation']} canary failed")
    write_json(ARTIFACT_ROOT / "canary-results.json", {"schema_version": 1, "passed": True, "results": records})
    return records


def _artifact_bytes() -> int:
    paths = [Path(__file__), FOCUSED_TEST, RESULT]
    paths.extend(path for path in ARTIFACT_ROOT.rglob("*") if path.is_file())
    return RETAINED_NEW_BYTES + sum(
        path.stat().st_size for path in paths if path.is_file()
    )


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
    original, corrected, _ = _preflight()
    controls = _freeze_inputs(original, corrected)
    original_env = {name: os.environ.get(name) for name in (
        "SEMGREP_LOG_FILE", "SEMGREP_VERSION_CACHE_PATH", "SEMGREP_SEND_METRICS", "SEMGREP_ENABLE_VERSION_CHECK"
    )}
    os.environ.update({
        "SEMGREP_LOG_FILE": str(ARTIFACT_ROOT / "semgrep.log"),
        "SEMGREP_VERSION_CACHE_PATH": str(ARTIFACT_ROOT / "semgrep-version-cache"),
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
    })
    repositories_materialized = 0
    retrieval_indexes = 0
    acquisition_started = False
    source_scan_records = []
    candidates = []
    completed_subjects = 0
    stop_reason = None
    activity = {"logical_scanner_processes": 0}
    try:
        _runtime_import()
        _run_canaries(controls, activity)
        for subject in SUBJECTS:
            subject_started = time.monotonic()
            subject_root = ARTIFACT_ROOT / "subjects" / subject.stable_identity
            snapshot = subject_root / "snapshot"
            acquisition_started = True
            _acquire(subject, snapshot)
            repositories_materialized += 1
            snapshot_sha, snapshot_files, snapshot_bytes = _snapshot_digest(snapshot)
            detector_sha, detector_files, detector_bytes = _detector_input_digest(snapshot)
            retrieval = _retrieval_summary(snapshot)
            retrieval_indexes += 1
            scan, _ = _scan(
                snapshot, subject_root / "scanner", subject.language, activity
            )
            candidates.extend(
                candidates_from_sarif(
                    json.loads((subject_root / "scanner/semgrep.sarif").read_text(encoding="utf-8")),
                    subject=subject.stable_identity,
                    language=subject.language,
                    scanner="semgrep-supplemental" if subject.language == "Java" else "semgrep",
                )
            )
            source_scan_records.append({
                "language": subject.language,
                "snapshot_sha256": snapshot_sha,
                "snapshot_file_count": snapshot_files,
                "snapshot_bytes": snapshot_bytes,
                "detector_input_sha256": detector_sha,
                "detector_input_file_count": detector_files,
                "detector_input_bytes": detector_bytes,
                "retrieval": retrieval,
                "scanner": scan,
            })
            completed_subjects += 1
            if time.monotonic() - subject_started > MAX_REPOSITORY_SECONDS:
                raise RuntimeError("per-repository elapsed-time ceiling exceeded")
            if _artifact_bytes() > MAX_NEW_BYTES or time.monotonic() - started > MAX_SECONDS:
                raise RuntimeError("resource ceiling exceeded")
    except BaseException as exc:
        stop_reason = f"{type(exc).__name__}: {str(exc)[:300]}"
    finally:
        for name, value in original_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    aggregate = None
    if stop_reason is None and completed_subjects == len(SUBJECTS):
        groups = deduplicate(candidates)
        candidate_family = Counter(item.language for item in candidates)
        group_family = Counter(item.language for item in groups)
        aggregate = combined_capacity(
            candidate_family["Java"], group_family["Java"],
            candidate_family["Ruby"], group_family["Ruby"],
        )
        raw_hashes = sorted(
            value
            for record in source_scan_records
            for value in (record["scanner"]["sarif_sha256"], record["scanner"]["target_report_sha256"])
        )
        write_json(ARTIFACT, {
            "schema_version": 1,
            "status": "completed-outcome-blind-aggregate-capacity-screen",
            "subjects_completed": completed_subjects,
            "scanner_executions_valid": len(source_scan_records),
            "aggregate_new_compatible_results": len(candidates),
            "aggregate_new_deduplicated_issue_groups": len(groups),
            "new_by_supported_family": {"Java": group_family["Java"], "Ruby": group_family["Ruby"]},
            "combined_capacity": aggregate,
            "raw_artifact_set_sha256": hashlib.sha256("".join(raw_hashes).encode()).hexdigest(),
            "candidate_or_issue_group_identities_persisted_or_disclosed": 0,
            "subject_level_finding_counts_persisted_or_disclosed": 0,
            "packet_constructed": False,
        })

    store_after = sha256(STORE)
    rules_after = sha256(PRODUCTION_RULES)
    result: dict[str, Any] = {
        "schema_version": 1,
        "optimization": "OPT-010",
        "status": (
            "completed-aggregate-capacity-feasible"
            if aggregate and aggregate["provisionally_feasible"]
            else "completed-negative-java-ruby-source-scarcity"
            if aggregate is not None
            else "stopped-before-aggregate-capacity-screen"
        ),
        "interpretation": (
            "The approved Java/Ruby augmentation sources clear only the frozen aggregate four-family capacity prerequisite; architecture and candidate-specific verifier eligibility remain separately gated."
            if aggregate and aggregate["provisionally_feasible"]
            else "The approved Java/Ruby augmentation sources do not clear the frozen aggregate four-family capacity prerequisite."
            if aggregate is not None
            else "The corrected retry stopped before aggregate capacity could be computed."
        ),
        "augmentation": {
            "subjects_frozen": 4,
            "subjects_completed": completed_subjects,
            "source_scanner_executions": len(source_scan_records),
            "aggregate_capacity": aggregate,
        },
        "decision": {
            "architecture_and_verifier_gate_justified": bool(aggregate and aggregate["provisionally_feasible"]),
            "candidate_or_issue_group_identities_persisted_or_disclosed": 0,
            "subject_level_finding_counts_persisted_or_disclosed": 0,
            "packet_constructed": False,
            "paired_execution_started": False,
            "g03b_decided": False,
            "g04_decided": False,
            "opt010_status_changed": False,
        },
        "resource_accounting": {
            "elapsed_seconds": round(2.265 + time.monotonic() - started, 3),
            "new_data_bytes": 0,
            "runtime_import_checks": 1 + int(RUNTIME_CHECK.is_file()),
            "logical_scanner_processes": 1 + activity["logical_scanner_processes"],
            "repositories_materialized": repositories_materialized,
            "retrieval_index_builds": retrieval_indexes,
            "network_hosts_used": ["github.com"] if acquisition_started else [],
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
            "assessments": 0,
            "labels": 0,
            "model_training_runs": 0,
            "rescoring_runs": 0,
            "agentic_or_baseline_runs": 0,
            "human_finding_reviews": 0,
            "outcomes_read": 0,
            "workspace_branch_or_index_mutations": 0,
            "commits": 0,
            "merges": 0,
            "pushes": 0,
            "lifecycle_changes": 0,
        },
        "production_store": {"expected_sha256": STORE_SHA256, "after_sha256": store_after, "byte_identical": store_after == STORE_SHA256},
        "production_supplemental_ruleset": {"expected_sha256": PRODUCTION_RULES_SHA256, "after_sha256": rules_after, "byte_identical": rules_after == PRODUCTION_RULES_SHA256},
        "stop_reason": stop_reason,
    }
    _stable_result(result)
    if result["resource_accounting"]["logical_scanner_processes"] > 9:
        raise RuntimeError("scanner-process ceiling exceeded")
    if result["resource_accounting"]["new_data_bytes"] > MAX_NEW_BYTES:
        raise RuntimeError("new-data ceiling exceeded")
    if not result["production_store"]["byte_identical"] or not result["production_supplemental_ruleset"]["byte_identical"]:
        raise RuntimeError("production store or rules changed")
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

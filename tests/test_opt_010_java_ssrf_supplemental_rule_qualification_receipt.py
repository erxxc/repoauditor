from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-java-ssrf-supplemental-rule-qualification-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_rule_bytes(payload: dict) -> bytes:
    return json.dumps(
        {"rules": [payload["candidate_rule_contract"]["rule"]]},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode() + b"\n"


def test_receipt_binds_current_acceptance_evidence_and_scanner_instruments():
    payload = _payload()
    for record in payload["frozen_inputs"].values():
        if isinstance(record, dict):
            assert _sha256(ROOT / record["path"]) == record["sha256"]
    for record in payload["frozen_instruments"].values():
        assert _sha256(ROOT / record["path"]) == record["sha256"]


def test_candidate_rule_is_exact_scratch_only_java_cwe918_taint():
    contract = _payload()["candidate_rule_contract"]
    rule = contract["rule"]
    assert contract["scratch_only"] is True
    assert contract["production_ruleset_edited"] is False
    assert rule["id"] == "repoauditor.java.spring.security.tainted-resttemplate-url"
    assert rule["languages"] == ["java"]
    assert rule["mode"] == "taint"
    assert rule["metadata"]["cwe"] == ["CWE-918: Server-Side Request Forgery (SSRF)"]
    assert hashlib.sha256(_canonical_rule_bytes(_payload())).hexdigest() == contract["canonical_json_sha256"]


def test_controls_are_frozen_three_positive_three_clean_before_scanning():
    contract = _payload()["frozen_control_contract"]
    controls = contract["ordered_controls"]
    assert contract["freeze_before_runtime_or_scanner_activity"] is True
    assert [item["order"] for item in controls] == list(range(1, 7))
    assert sum(item["expectation"] == "raised-exactly-once" for item in controls) == 3
    assert sum(item["expectation"] == "absent" for item in controls) == 3
    assert all(item["source_lines"] for item in controls)
    assert "Do not edit" in contract["failure_policy"]
    assert "do not retry" in contract["failure_policy"]


def test_runtime_is_exact_isolated_and_has_no_general_canary_or_retry():
    runtime = _payload()["runtime_contract"]
    assert runtime["semgrep_version"] == "1.170.0"
    assert runtime["installed_import_interpreter"] == "/opt/homebrew/Cellar/semgrep/1.170.0/libexec/bin/python"
    requirements = " ".join(runtime["requirements"])
    assert "SEMGREP_LOG_FILE" in requirements
    assert "SEMGREP_VERSION_CACHE_PATH" in requirements
    assert "run a general canary" in requirements
    assert "retry" in requirements


def test_resource_boundary_is_six_scans_and_zero_external_activity():
    ceilings = _payload()["resource_ceilings"]
    assert ceilings["maximum_elapsed_minutes"] == 10
    assert ceilings["maximum_new_data_bytes"] == 5 * 1024**2
    assert ceilings["runtime_import_checks"] == 1
    assert ceilings["logical_scanner_processes"] == 6
    for field, value in ceilings.items():
        if field not in {
            "maximum_elapsed_minutes",
            "maximum_new_data_bytes",
            "runtime_import_checks",
            "logical_scanner_processes",
        }:
            assert value in {0, 0.0}


def test_receipt_is_pending_and_cannot_promote_rule_or_opt010():
    payload = _payload()
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "Production-rule editing or promotion" in statement
    assert "retained-source rescanning" in statement
    assert "OPT-010 promotion or closure" in statement

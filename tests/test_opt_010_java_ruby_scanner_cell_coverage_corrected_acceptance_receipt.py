from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-java-ruby-scanner-cell-coverage-corrected-acceptance-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_retained_attempt_scan_evidence_and_instruments_are_digest_frozen():
    payload = _payload()
    for record in payload["retained_attempt"].values():
        if isinstance(record, dict) and "path" in record:
            assert _sha256(ROOT / record["path"]) == record["sha256"]
    for scan in payload["retained_scan_evidence"]:
        assert _sha256(ROOT / scan["sarif"]["path"]) == scan["sarif"]["sha256"]
        assert _sha256(ROOT / scan["target_report"]["path"]) == scan["target_report"]["sha256"]
    for record in payload["frozen_instruments"].values():
        assert _sha256(ROOT / record["path"]) == record["sha256"]


def test_original_result_remains_historical_and_nonqualifying():
    retained = _payload()["retained_attempt"]
    assert "does not erase" in retained["interpretation"]
    assert "retroactively qualify" in retained["interpretation"]
    result = json.loads((ROOT / retained["nonqualifying_result"]["path"]).read_text())
    assert result["status"] == "stopped-nonqualifying-new-data-ceiling-exceeded"
    assert result["boundary"] == {
        "ceiling_bytes": 2 * 1024**2,
        "observed_bytes": 7_841_236,
        "receipt_qualified": False,
        "retained_evidence_use": "descriptive-non-qualifying-only",
        "stop_reason": "new-data-ceiling-exceeded",
    }


def test_acceptance_requires_exact_cell_classification_reproduction():
    expected = _payload()["offline_acceptance_contract"]["expected_result"]
    assert expected["cells"] == [
        {
            "cell": "Java:ssrf",
            "positive_execution_valid": True,
            "positive_mapped_results": 0,
            "clean_execution_valid": True,
            "clean_mapped_results": 0,
            "classification": "coverage-gap",
        },
        {
            "cell": "Ruby:unsafe_deserialization",
            "positive_execution_valid": True,
            "positive_mapped_results": 1,
            "clean_execution_valid": True,
            "clean_mapped_results": 0,
            "classification": "qualified-detectable",
        },
    ]
    assert expected["supplemental_applicability"] == {
        "java": "not-applicable",
        "ruby": "not-applicable",
    }
    assert expected["routing"] == "supplemental-rule-qualification-prerequisite"


def test_acceptance_access_is_no_rescan_and_source_blind():
    contract = _payload()["offline_acceptance_contract"]
    assert "four Semgrep SARIF files" in contract["artifact_access"]
    assert "four target reports" in contract["artifact_access"]
    assert "Do not open fixture source" in contract["artifact_access"]
    assert "independently reproduce" in contract["reproduction"]
    assert "corrected completed-negative" in contract["acceptance_rule"]


def test_resource_boundaries_separate_retained_evidence_from_new_data():
    ceilings = _payload()["resource_ceilings"]
    assert ceilings["maximum_elapsed_minutes"] == 10
    assert ceilings["retained_evidence_bytes_maximum"] == 8 * 1024**2
    assert ceilings["maximum_new_data_bytes"] == 1 * 1024**2
    for field, value in ceilings.items():
        if field not in {
            "maximum_elapsed_minutes",
            "retained_evidence_bytes_maximum",
            "maximum_new_data_bytes",
        }:
            assert value in {0, 0.0}


def test_receipt_is_pending_and_cannot_change_rules_or_opt010_status():
    payload = _payload()
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "without editing or retroactively qualifying the original result" in statement
    assert "new or edited scanner rules" in statement
    assert "OPT-010 promotion or closure" in statement
    assert "8 MiB retained evidence, 1 MiB new data" in statement

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-supported-primary-augmentation-corrected-acceptance-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_retained_attempt_and_instruments_are_digest_frozen():
    payload = _payload()
    for record in payload["retained_attempt"].values():
        if isinstance(record, dict) and "path" in record:
            assert _sha256(ROOT / record["path"]) == record["sha256"]
    for record in payload["frozen_instruments"].values():
        assert _sha256(ROOT / record["path"]) == record["sha256"]


def test_original_deviation_remains_historical_and_nonqualifying():
    retained = _payload()["retained_attempt"]
    assert "does not erase" in retained["interpretation"]
    assert "retroactively cure" in retained["interpretation"]
    result = json.loads((ROOT / retained["nonqualifying_result"]["path"]).read_text())
    assert result["decision"]["receipt_qualified"] is False
    assert result["preflight_chronology"]["receipt_stop_condition_triggered"] is True


def test_acceptance_requires_exact_negative_aggregate_reproduction():
    contract = _payload()["offline_acceptance_contract"]
    expected = contract["expected_result"]
    assert expected["metadata_compatible_results"] == 57
    assert expected["metadata_deduplicated_issue_groups"] == 48
    assert expected["by_supported_family"] == {
        "Java": 0,
        "Python": 29,
        "Ruby": 0,
        "TypeScript": 19,
    }
    assert expected["capped_packet_capacity"] == 39
    assert expected["supported_families_contributing"] == 2
    assert expected["provisionally_feasible"] is False
    assert "completed-negative" in contract["acceptance_rule"]


def test_acceptance_reads_only_retained_sarif_json_and_git_identity():
    contract = _payload()["offline_acceptance_contract"]
    assert "Semgrep and supplemental Semgrep SARIF" in contract["artifact_access"]
    assert "exact .git HEAD/object identity" in contract["artifact_access"]
    assert "Do not open snapshot source files" in contract["artifact_access"]
    assert "inclusive-transitive issue-group deduplication" in contract["reproduction"]


def test_resource_boundaries_are_offline_and_zero_live_activity():
    ceilings = _payload()["resource_ceilings"]
    assert ceilings["maximum_elapsed_minutes"] == 10
    assert ceilings["maximum_new_data_bytes"] == 2 * 1024**2
    for field, value in ceilings.items():
        if field not in {"maximum_elapsed_minutes", "maximum_new_data_bytes"}:
            assert value in {0, 0.0}


def test_receipt_remains_pending_and_cannot_advance_opt010():
    payload = _payload()
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "without retroactively qualifying or editing the original result" in statement
    assert "OPT-010 promotion or closure" in statement
    assert "architecture recovery" in statement

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-java-ruby-source-augmentation-acquisition-screen-final-retry-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_final_receipt_binds_prior_authority_results_helper_and_test():
    authority = _payload()["retained_authority"]
    historical_current_files = {
        "pre_correction_helper": "00208ab4f17597e7cf9dbc3cd50f839d9b64f39774c06d69e19d900f753c004f",
        "pre_correction_focused_test": "807a44cd348834193cb517be751f92486ab95946683958d1858619683ad58b36",
    }
    for name, record in authority.items():
        if name in historical_current_files:
            assert record["sha256"] == historical_current_files[name]
            assert len(_sha256(ROOT / record["path"])) == 64
        else:
            assert _sha256(ROOT / record["path"]) == record["sha256"]


def test_final_receipt_binds_retained_successful_scanner_evidence():
    for record in _payload()["retained_corrected_attempt_evidence"].values():
        assert _sha256(ROOT / record["path"]) == record["sha256"]
    state = _payload()["accepted_stopped_state"]
    assert state["runtime_import_checks"] == 1
    assert state["logical_scanner_processes"] == 1
    assert state["repositories_materialized"] == 0
    assert state["network_hosts_used"] == []


def test_correction_is_validation_only_and_requires_fresh_canaries():
    payload = _payload()
    diagnosis = payload["diagnosis"]
    assert diagnosis["not_a_rule_change"] is True
    assert diagnosis["not_a_scanner_change"] is True
    assert diagnosis["not_a_source_change"] is True
    assert "JSON" in diagnosis["authorized_correction"]
    assert "do not reuse the prior canary output as a pass" in payload["final_retry_contract"]["fresh_execution"]


def test_cumulative_accounting_adds_one_import_and_eight_scans():
    ceilings = _payload()["cumulative_resource_ceilings"]
    assert ceilings["runtime_import_checks"] == 2
    assert ceilings["logical_scanner_processes"] == 9
    assert ceilings["repositories"] == 4
    assert ceilings["retrieval_index_builds"] == 4
    assert ceilings["allowed_network_hosts"] == ["github.com"]
    assert ceilings["maximum_new_data_bytes"] == 15 * 1024**3


def test_final_retry_is_pending_and_forbids_any_further_retry():
    payload = _payload()
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "one final aggregate artifact and result" in statement
    assert "Any other helper or test change" in statement
    assert "OPT-010 promotion or closure" in statement

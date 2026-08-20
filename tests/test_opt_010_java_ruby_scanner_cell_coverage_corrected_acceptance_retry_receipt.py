from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-java-ruby-scanner-cell-coverage-corrected-acceptance-retry-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_retained_authority_and_corrected_instruments_are_digest_frozen():
    payload = _payload()
    for record in payload["retained_authority"].values():
        if isinstance(record, dict):
            assert _sha256(ROOT / record["path"]) == record["sha256"]
    for record in payload["corrected_instruments"].values():
        assert _sha256(ROOT / record["path"]) == record["sha256"]


def test_stopped_attempt_is_preserved_as_pre_output_and_zero_live_activity():
    stopped = _payload()["retained_stopped_attempt"]
    assert stopped["status"] == "stopped-pre-output-supported-cell-order-comparison-mismatch"
    assert stopped["pre_correction_helper_sha256"] == "d8987d4051228307bd0d10ea4a0aab28fdfb289d389c679233c6a14cc3c68dcd"
    assert stopped["pre_correction_focused_test_sha256"] == "6fe56d226dc3b7c258e8b10eafede16eed13120c57ff7be323215dc0c5349b4f"
    observed = stopped["observed_difference"]
    assert observed["exact_language_membership_equal"] is True
    assert observed["exact_mechanism_membership_equal"] is True
    assert observed["cwe_mapping_equal"] is True
    assert "Zero runtime imports" in stopped["facts"]["activity"]


def test_only_exact_membership_order_comparison_is_corrected():
    contract = _payload()["correction_contract"]
    assert "exact language-key equality" in contract["only_change"]
    assert "sorted exact mechanism membership" in contract["only_change"]
    assert set(contract["must_reject"]) == {
        "any added or removed language",
        "any added, removed, or changed mechanism membership",
        "any changed CWE mapping",
        "any malformed non-list frozen membership",
    }
    assert "execute exactly once" in contract["resume_rule"]


def test_historical_pre_output_state_is_distinguished_from_authorized_outputs():
    execution = _payload()["execution"]
    artifact = json.loads((ROOT / execution["artifact"]).read_text(encoding="utf-8"))
    result = json.loads((ROOT / execution["result"]).read_text(encoding="utf-8"))

    assert artifact["status"] == "exact-completed-negative-reproduction"
    assert result["status"] == "completed-negative-corrected-offline-acceptance"
    assert result["acceptance"]["retained_bindings_verified"] is True
    assert result["acceptance"]["exact_classification_reproduction"] is True


def test_cumulative_boundaries_remain_offline_and_zero_live_activity():
    ceilings = _payload()["cumulative_resource_ceilings"]
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


def test_receipt_is_pending_and_cannot_advance_opt010():
    payload = _payload()
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "stopped pre-output attempt" in statement
    assert "sorted exact mechanism memberships" in statement
    assert "OPT-010 status" in statement

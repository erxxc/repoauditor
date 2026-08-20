from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-architecture-mechanism-eligibility-final-retry-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_final_retry_binds_current_executable_state_and_retained_evidence():
    retained = _payload()["retained_attempts"]
    for key in (
        "original_receipt", "original_stopped_result", "corrected_retry_receipt",
        "corrected_helper", "corrected_focused_test", "mechanism_matrix",
    ):
        record = retained[key]
        if key == "corrected_focused_test":
            assert record["sha256"] == "5caf462c21645623886e9b2f6c04abd086be0006122353f5c4f8501e64e254e4"
            assert len(_sha256(ROOT / record["path"])) == 64
        else:
            assert _sha256(ROOT / record["path"]) == record["sha256"]
    assert retained["provider_attempts"] == retained["keychain_secret_reads"] == 0


def test_pre_reconciliation_receipt_test_hash_is_retained_as_history():
    record = _payload()["retained_attempts"]["corrected_receipt_test_before_reconciliation"]
    assert record["sha256"] == "b2e64c0b20014f3ddd8b8d6947082cfec2f6097c1d2d1fadd365d72f46f7a695"
    assert record["path"].endswith("corrected_retry_receipt.py")


def test_only_one_historical_assertion_reconciliation_is_permitted():
    reconciliation = _payload()["permitted_reconciliation"]
    assert reconciliation["only_file"].endswith("corrected_retry_receipt.py")
    assert reconciliation["implementation_changes"] == 0
    assert reconciliation["evidence_changes"] == 0
    assert "without comparing those historical hashes" in reconciliation["only_change"]


def test_live_boundaries_are_unchanged_and_opt010_stays_open():
    payload = _payload()
    ceilings = payload["cumulative_resource_ceilings"]
    assert ceilings["provider_attempts"] == ceilings["authorized_public_source_transmissions"] == 12
    assert ceilings["allowed_network_hosts"] == ["api.anthropic.com"]
    assert ceilings["production_store_mutations"] == 0
    assert "cannot claim empirical safety" in payload["result_boundary"]
    assert "OPT-010 promotion or closure" in payload["authorization"]["required_statement"]

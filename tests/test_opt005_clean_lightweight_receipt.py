"""The replacement lightweight observation is isolated, bounded, and separately gated."""

import json
from pathlib import Path


RECEIPT = (
    Path(__file__).resolve().parents[1]
    / "docs/optimizations/opt-005-clean-lightweight-receipt-2026-08-07.json"
)


def test_clean_lightweight_receipt_requires_new_same_store_identity():
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    subject = receipt["frozen_subject"]
    isolation = receipt["isolation_contract"]
    budget = receipt["proposed_budget"]

    assert receipt["status"] == "clean-lightweight-authorization-pending"
    assert subject["tree_digest"].startswith("sha256:")
    assert "uat_lightweight_app" in subject["execution_source"]
    assert "current persistent" in isolation["same_store"]
    assert "not used" in isolation["new_identity"]
    assert "parent_run_id=null" in isolation["new_root"]
    assert "zero reused" in isolation["no_reuse"]
    assert budget == {
        "maximum_linked_batches": 50,
        "maximum_provider_calls": 400,
        "maximum_provider_reported_tokens": 1200000,
        "maximum_usd": 8.0,
        "authorization_granted": False,
    }
    assert receipt["data_transfer"]["authorized"] is False
    assert "protected snapshot execution" in receipt["excluded"]

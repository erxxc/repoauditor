"""The protected pre-fix run is independently frozen and authorization gated."""

import json
from pathlib import Path


RECEIPT = (
    Path(__file__).resolve().parents[1]
    / "docs/optimizations/opt-005-protected-pre-receipt-2026-08-07.json"
)


def test_protected_pre_receipt_is_frozen_bounded_and_pre_only():
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    subject = receipt["protected_subject"]
    budget = receipt["proposed_budget"]

    assert receipt["status"] == "protected-pre-authorization-pending"
    assert subject["fixture_id"] == "independent_serialize_javascript_pre"
    assert subject["variant"] == "pre_fix"
    assert subject["pinned_commit"] == "3bab6dee8db7317310a97af5d28f0f0479d21930"
    assert subject["tree_digest"].startswith("sha256:")
    assert subject["manifest_digest"].startswith("sha256:")
    assert budget == {
        "maximum_linked_batches": 3,
        "maximum_provider_calls": 225,
        "maximum_provider_reported_tokens": 750000,
        "maximum_usd": 5.0,
        "authorization_granted": False,
    }
    assert receipt["data_transfer"]["authorized"] is False
    assert "post-fix" in receipt["excluded"]
    assert "Do not inspect" in receipt["execution_policy"]["isolation"]
    assert receipt["readiness"]["network_accessed_during_audit"] is False

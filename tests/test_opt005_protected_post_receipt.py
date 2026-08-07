"""The protected post-fix run is independently frozen and authorization gated."""

import json
from pathlib import Path


RECEIPT = (
    Path(__file__).resolve().parents[1]
    / "docs/optimizations/opt-005-protected-post-receipt-2026-08-07.json"
)


def test_protected_post_receipt_is_frozen_bounded_and_no_tuning():
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    subject = receipt["protected_subject"]
    budget = receipt["proposed_budget"]

    assert receipt["status"] == "protected-post-authorization-pending"
    assert subject["fixture_id"] == "independent_serialize_javascript_post"
    assert subject["variant"] == "post_fix"
    assert subject["pinned_commit"] == "16a68ab53d9626fc7c942b48a1163108fcd184c8"
    assert subject["tree_digest"].startswith("sha256:")
    assert subject["manifest_digest"].startswith("sha256:")
    assert budget == {
        "maximum_linked_batches": 14,
        "maximum_provider_calls": 350,
        "maximum_provider_reported_tokens": 1000000,
        "maximum_usd": 7.0,
        "authorization_granted": False,
    }
    assert receipt["data_transfer"]["authorized"] is False
    assert receipt["readiness"]["network_accessed_during_audit"] is False
    assert "Do not change" in receipt["execution_policy"]["no_tuning"]
    assert "pre-fix execution" in receipt["excluded"]

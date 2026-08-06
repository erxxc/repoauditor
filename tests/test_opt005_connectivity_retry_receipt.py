"""The post-timeout OPT-005 retry is small, frozen, and separately authorized."""

import json
from pathlib import Path


RECEIPT = (
    Path(__file__).resolve().parents[1]
    / "docs/optimizations/opt-005-connectivity-retry-receipt-2026-08-06.json"
)


def test_connectivity_retry_receipt_is_separate_bounded_and_protected_pair_excluded():
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    budget = receipt["proposed_retry_budget"]

    assert receipt["status"] == "connectivity-retry-authorization-pending"
    assert receipt["frozen_queue"]["deferred_findings"] == 60
    assert receipt["frozen_queue"]["conservative_issue_groups"] == 52
    assert budget["maximum_continuation_batches"] == 2
    assert budget["maximum_provider_calls"] == 36
    assert budget["maximum_provider_reported_tokens"] == 120000
    assert budget["maximum_usd"] == 1.0
    assert budget["authorization_granted"] is False
    assert "not reused" in receipt["claim_boundary"]["prior_authorization"]
    assert "Neither protected" in receipt["claim_boundary"]["protected_pair"]

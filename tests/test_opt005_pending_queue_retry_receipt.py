"""The corrected OPT-005 retry freezes the exact production pending queue."""

import json
from pathlib import Path


RECEIPT = (
    Path(__file__).resolve().parents[1]
    / "docs/optimizations/opt-005-pending-queue-retry-receipt-2026-08-07.json"
)


def test_pending_queue_retry_receipt_covers_both_pending_statuses_and_is_bounded():
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    queue = receipt["frozen_queue"]
    budget = receipt["proposed_retry_budget"]

    assert receipt["status"] == "pending-queue-retry-authorization-pending"
    assert queue["pending_findings"] == 55
    assert queue["status_counts"] == {"deferred": 53, "unresolved": 2}
    assert queue["conservative_issue_groups"] == 51
    assert "unresolved,deferred" in queue["predicate"]
    assert budget["maximum_continuation_batches"] == 2
    assert budget["maximum_provider_calls"] == 36
    assert budget["maximum_provider_reported_tokens"] == 120000
    assert budget["maximum_usd"] == 1.0
    assert budget["authorization_granted"] is False
    assert "Neither protected" in receipt["claim_boundary"]["protected_pair"]

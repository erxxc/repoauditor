"""OPT-005 proceeds one fully scoped batch at a time."""

import json
from pathlib import Path


RECEIPT = (
    Path(__file__).resolve().parents[1]
    / "docs/optimizations/opt-005-single-batch-receipt-2026-08-07.json"
)


def test_single_batch_receipt_is_frozen_bounded_and_transfer_pending():
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    budget = receipt["proposed_budget"]

    assert receipt["status"] == "single-batch-authorization-pending"
    assert receipt["frozen_queue"]["pending_findings"] == 51
    assert receipt["frozen_queue"]["conservative_issue_groups"] == 47
    assert budget["maximum_continuation_batches"] == 1
    assert budget["maximum_provider_calls"] == 26
    assert budget["maximum_provider_reported_tokens"] == 75000
    assert budget["maximum_usd"] == 0.55
    assert budget["authorization_granted"] is False
    assert receipt["data_transfer"]["destination"] == "Anthropic"
    assert receipt["data_transfer"]["authorized"] is False
    assert "Neither protected" in receipt["claim_boundary"]["protected_pair"]

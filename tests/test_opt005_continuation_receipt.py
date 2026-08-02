"""OPT-005 continuation stays lightweight-only and explicitly budget gated."""

import json
from pathlib import Path


RECEIPT = (
    Path(__file__).resolve().parents[1]
    / "docs/optimizations/opt-005-lightweight-continuation-receipt-2026-08-02.json"
)


def test_lightweight_continuation_receipt_is_frozen_bounded_and_not_authorized():
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))

    assert receipt["optimization"] == "OPT-005"
    assert receipt["status"] == "lightweight-continuation-authorization-pending"
    assert receipt["parent_run"]["pipeline_run_id"] == 6
    assert receipt["frozen_queue"]["deferred_findings"] == 111
    assert receipt["frozen_queue"]["conservative_issue_groups"] == 60
    assert all(
        receipt["frozen_queue"][key].startswith("sha256:")
        for key in ("finding_rows_digest", "ordered_groups_digest")
    )
    budget = receipt["proposed_aggregate_budget"]
    assert budget["maximum_continuation_batches"] == 16
    assert budget["maximum_provider_calls"] == 180
    assert budget["maximum_provider_reported_tokens"] == 600000
    assert budget["maximum_usd"] == 5.0
    assert budget["authorization_granted"] is False
    assert "does not authorize" in receipt["claim_boundary"]["protected_pair"]

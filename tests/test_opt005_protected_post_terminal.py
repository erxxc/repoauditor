"""Post-fix result and one-row terminal continuation remain separately gated."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "docs/optimizations"


def test_post_result_stops_at_authorized_cap():
    result = json.loads((ROOT / "opt-005-protected-post-result-2026-08-07.json").read_text())
    execution = result["execution"]
    ceilings = result["authorized_ceilings"]

    assert result["status"] == "protected-post-batch-cap-reached"
    assert execution["completed_batches"] == ceilings["linked_batches"] == 14
    assert execution["provider_calls"] <= ceilings["provider_calls"]
    assert execution["provider_reported_tokens"] <= ceilings["provider_reported_tokens"]
    assert execution["calculated_cost_usd"] <= ceilings["usd"]
    assert execution["unknown_usage_calls"] == 0
    assert execution["pending_after"] == 1
    assert result["outcome"]["terminal"] is False


def test_terminal_receipt_is_one_row_bounded_and_pending():
    receipt = json.loads(
        (ROOT / "opt-005-protected-post-terminal-receipt-2026-08-07.json").read_text()
    )
    queue = receipt["frozen_queue"]
    budget = receipt["proposed_budget"]

    assert receipt["status"] == "protected-post-terminal-authorization-pending"
    assert queue["pending_findings"] == queue["conservative_issue_groups"] == 1
    assert budget["maximum_continuation_batches"] == 1
    assert budget["maximum_provider_calls"] == 26
    assert budget["maximum_provider_reported_tokens"] == 75000
    assert budget["maximum_usd"] == 0.55
    assert budget["authorization_granted"] is False
    assert receipt["data_transfer"]["authorized"] is False
    assert "pre-fix execution" in receipt["excluded"]

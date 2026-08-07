"""The protected pre-fix continuation is digest-pinned and separately gated."""

import json
from pathlib import Path


RECEIPT = (
    Path(__file__).resolve().parents[1]
    / "docs/optimizations/opt-005-protected-pre-continuation-receipt-2026-08-07.json"
)


def test_protected_pre_continuation_is_frozen_bounded_and_post_excluded():
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    queue = receipt["frozen_queue"]
    budget = receipt["proposed_budget"]

    assert receipt["status"] == "protected-pre-continuation-authorization-pending"
    assert receipt["parent_chain"]["latest_completed_pipeline_run_id"] == 64
    assert receipt["parent_chain"]["variant"] == "pre_fix"
    assert queue["pending_findings"] == queue["conservative_issue_groups"] == 44
    assert all(queue[key].startswith("sha256:") for key in (
        "finding_ids_digest", "ordered_group_ids_digest"
    ))
    assert budget == {
        "maximum_continuation_batches": 11,
        "maximum_provider_calls": 275,
        "maximum_provider_reported_tokens": 750000,
        "maximum_usd": 5.5,
        "authorization_granted": False,
    }
    assert receipt["data_transfer"]["authorized"] is False
    assert "post-fix" in receipt["excluded"]
    assert "do not repeat ingest" in receipt["execution_policy"]["continuation_only"]

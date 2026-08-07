"""The pre-execution checkpoint separates accepted DoD from remaining OPT work."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_outstanding_checkpoint_closes_poc_dod_and_lists_every_open_opt():
    checkpoint = json.loads((
        ROOT / "docs/optimizations/outstanding-work-checkpoint-2026-08-07.json"
    ).read_text(encoding="utf-8"))
    status = json.loads((
        ROOT / "docs/optimizations/optimization-status.json"
    ).read_text(encoding="utf-8"))

    expected = {item["id"] for item in status["items"] if item["status"] == "open"}
    recorded = {item["id"] for item in checkpoint["open_optimizations_in_priority_order"]}
    assert checkpoint["poc_definition_of_done"]["status"] == "complete"
    assert checkpoint["poc_definition_of_done"]["outstanding_acceptance_items"] == []
    assert recorded == expected
    assert checkpoint["optimization_summary"] == status["summary"]
    assert checkpoint["tuning_hold"]["active"] is True


def test_next_batch_receipt_links_checkpoint_and_keeps_transfer_pending():
    receipt = json.loads((
        ROOT / "docs/optimizations/opt-005-single-batch-2-receipt-2026-08-07.json"
    ).read_text(encoding="utf-8"))
    assert receipt["outstanding_work_checkpoint"] == "outstanding-work-checkpoint-2026-08-07.json"
    assert receipt["frozen_queue"]["pending_findings"] == 47
    assert receipt["frozen_queue"]["conservative_issue_groups"] == 43
    assert receipt["proposed_budget"]["maximum_provider_calls"] == 26
    assert receipt["proposed_budget"]["authorization_granted"] is False
    assert receipt["data_transfer"]["authorized"] is False
    assert "Neither protected" in receipt["protected_pair"]

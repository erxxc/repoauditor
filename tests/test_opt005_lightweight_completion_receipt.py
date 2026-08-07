"""OPT-005 lightweight completion remains frozen, bounded, and authorization gated."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-005-lightweight-completion-receipt-2026-08-07.json"
REASSESSMENT = ROOT / "docs/optimizations/opt-closeout-reassessment-2026-08-07.json"


def test_lightweight_completion_receipt_is_frozen_and_authorization_pending():
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    queue = receipt["frozen_queue"]
    budget = receipt["proposed_budget"]
    batch = receipt["per_batch_breakers"]

    assert receipt["status"] == "lightweight-completion-authorization-pending"
    assert queue["pending_findings"] == 46
    assert queue["conservative_issue_groups"] == 42
    assert all(queue[key].startswith("sha256:") for key in (
        "finding_ids_digest", "ordered_group_ids_digest"
    ))
    assert budget == {
        "maximum_continuation_batches": 42,
        "maximum_provider_calls": 270,
        "maximum_provider_reported_tokens": 750000,
        "maximum_usd": 5.5,
        "authorization_granted": False,
    }
    assert batch["maximum_provider_calls"] == 26
    assert batch["maximum_provider_reported_tokens"] == 75000
    assert batch["maximum_usd"] == 0.55
    assert receipt["data_transfer"]["authorized"] is False
    assert "Neither protected" in receipt["protected_pair"]


def test_closeout_reassessment_matches_canonical_ledger():
    reassessment = json.loads(REASSESSMENT.read_text(encoding="utf-8"))
    ledger = json.loads(
        (ROOT / "docs/optimizations/optimization-status.json").read_text(encoding="utf-8")
    )

    assert reassessment["optimization_summary"] == ledger["summary"]
    assert reassessment["current_execution_gate"]["authorization_pending"] is True
    assert reassessment["poc_definition_of_done"]["outstanding_acceptance_items"] == []

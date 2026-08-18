from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ATTEMPT = ROOT / "docs/optimizations/opt-009-closure-merge-attempt-2026-08-18.json"


def _payload() -> dict:
    return json.loads(ATTEMPT.read_text(encoding="utf-8"))


def test_opt009_closure_attempt_binds_receipt_checkpoint_test_and_store():
    payload = _payload()
    receipt = ATTEMPT.parent / payload["execution_receipt"]["path"]
    checkpoint = ATTEMPT.parent / "outstanding-work-checkpoint-2026-08-07.json"
    corrected_receipt = json.loads((
        ATTEMPT.parent
        / "opt-009-closure-merge-corrected-retry-receipt-2026-08-18.json"
    ).read_text(encoding="utf-8"))
    store = ROOT / "data/repoauditor.db"

    assert hashlib.sha256(receipt.read_bytes()).hexdigest() == payload[
        "execution_receipt"
    ]["sha256"]
    assert hashlib.sha256(checkpoint.read_bytes()).hexdigest() == payload["restoration"][
        "historical_checkpoint_sha256"
    ]
    assert corrected_receipt["allowed_test_reconciliation"][
        "pre_change_sha256"
    ] == payload["validation"]["failed_test_file_sha256"]
    assert hashlib.sha256(store.read_bytes()).hexdigest() == payload["store"][
        "after_sha256"
    ]


def test_opt009_closure_attempt_stopped_before_commit_or_merge_and_restored_open():
    payload = _payload()

    assert payload["validation"]["full_suite_passed"] == 862
    assert payload["validation"]["full_suite_failed"] == 1
    assert payload["validation"]["full_suite_deselected"] == 27
    assert payload["branch_state"]["source_branch_commits_created"] == 0
    assert payload["branch_state"]["merge_commits_created"] == 0
    assert payload["restoration"]["optimization_status"] == "open"
    assert payload["restoration"]["summary"] == {
        "closed": 32, "open": 3, "total": 35
    }
    assert payload["disposition"]["required_stop_observed"] is True
    assert payload["disposition"]["opt_009_closed"] is False


def test_opt009_closure_attempt_has_zero_live_or_store_activity():
    accounting = _payload()["accounting"]

    assert accounting["network_reads"] == accounting["network_uploads"] == 0
    assert accounting["provider_calls"] == accounting["provider_reported_tokens"] == 0
    assert accounting["production_store_mutations"] == 0
    assert accounting["assessments_written"] == accounting["labels_written"] == 0
    assert accounting["rescored_findings"] == accounting["model_training_runs"] == 0

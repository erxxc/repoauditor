from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / (
    "docs/optimizations/opt-009-closure-merge-corrected-retry-receipt-2026-08-18.json"
)


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _assert_bound(record: dict) -> None:
    path = (RECEIPT.parent / record["path"]).resolve()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]


def test_corrected_opt009_receipt_binds_original_attempt_checkpoint_and_store():
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    _assert_bound(payload["original_receipt"])
    _assert_bound(payload["stopped_attempt"])
    _assert_bound(payload["retained_closure_contract"]["historical_checkpoint"])
    _assert_bound(payload["retained_closure_contract"]["production_store"])


def test_corrected_opt009_receipt_adds_exactly_one_stale_test_reconciliation():
    payload = _payload()
    reconciliation = payload["allowed_test_reconciliation"]

    assert reconciliation["path"] == "../../tests/test_outstanding_work_checkpoint.py"
    assert payload["commit_allowlist_extension"] == [
        "tests/test_outstanding_work_checkpoint.py"
    ]
    assert reconciliation["historical_checkpoint_edit_permitted"] is False
    assert reconciliation["other_test_semantics_permitted"] is False
    assert "historical 32-closed/3-open snapshot" in reconciliation["permitted_change"]
    assert "33 closed and two open" in reconciliation["permitted_change"]


def test_corrected_opt009_receipt_retains_lifecycle_and_git_contract():
    payload = _payload()
    closure = payload["retained_closure_contract"]
    branch = payload["branch_preconditions"]

    assert closure["optimization_status"] == {"closed": 33, "open": 2, "total": 35}
    assert closure["opt_009"] == {
        "status": "closed", "gate": "none", "next_priority": None
    }
    assert closure["remaining_priority_order"] == ["OPT-014", "OPT-010"]
    assert branch["current_branch"] == closure["source_branch"]
    assert branch["current_head"] == branch["local_main"]
    assert branch["source_commits_since_base"] == 0
    assert closure["merge_strategy"].startswith("one conflict-free local non-fast-forward")
    assert closure["remote_push"] is False
    assert closure["branch_deletion"] is False


def test_corrected_opt009_receipt_retains_zero_live_and_scope_expansion():
    payload = _payload()
    ceilings = payload["resource_ceilings"]
    required = payload["authorization"]["required_statement"]

    assert ceilings["network_reads"] == ceilings["network_uploads"] == 0
    assert ceilings["provider_calls"] == ceilings["provider_reported_tokens"] == 0
    assert ceilings["provider_cost_usd"] == 0.0
    assert ceilings["production_store_mutations"] == 0
    assert ceilings["assessments_written"] == ceilings["labels_written"] == 0
    assert ceilings["rescored_findings"] == ceilings["model_training_runs"] == 0
    assert "without a universal impossibility claim" in required
    assert "Any other test or historical-evidence change" in required
    assert "OPT-014 or OPT-010 execution" in required

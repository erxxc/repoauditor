from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-009-closure-merge-receipt-2026-08-18.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _assert_bound(record: dict) -> None:
    assert _sha256((RECEIPT.parent / record["path"]).resolve()) == record["sha256"]


def test_opt009_closure_receipt_binds_every_terminal_result_and_store():
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    for record in payload["bound_evidence"].values():
        _assert_bound(record)
    assert "not a universal claim" in payload["terminal_interpretation"]


def test_opt009_closure_reconciles_to_two_remaining_open_items():
    lifecycle = _payload()["authorized_lifecycle_changes"]
    status = lifecycle["optimization_status"]

    assert status["summary"] == {"closed": 33, "open": 2, "total": 35}
    assert status["opt_009"] == {
        "status": "closed", "gate": "none", "next_priority": None
    }
    assert status["remaining_priority_order"] == ["OPT-014", "OPT-010"]
    assert "remains byte-identical historical evidence" in lifecycle[
        "historical_checkpoint_policy"
    ]


def test_opt009_closure_uses_one_local_branch_commit_and_one_merge():
    payload = _payload()
    git = payload["git_preconditions"]
    contract = payload["commit_and_merge_contract"]

    assert git["initial_working_branch"] == "main"
    assert git["initial_head"] == git["initial_local_main"]
    assert git["new_source_branch"] == "codex/opt-009-closure"
    assert git["network_fetch"] is False
    assert contract["source_branch_commits"] == 1
    assert contract["merge_strategy"].startswith("one local non-fast-forward")
    assert contract["remote_push"] is False
    assert contract["branch_deletion"] is False
    assert "data/" not in contract["allowed_commit_paths"]


def test_opt009_closure_has_zero_live_or_policy_expansion():
    payload = _payload()
    ceilings = payload["resource_ceilings"]

    assert ceilings["network_reads"] == ceilings["network_uploads"] == 0
    assert ceilings["provider_calls"] == ceilings["provider_reported_tokens"] == 0
    assert ceilings["provider_cost_usd"] == 0.0
    assert ceilings["store_mutations"] == ceilings["assessments_written"] == 0
    assert ceilings["labels_written"] == ceilings["rescored_findings"] == 0
    assert ceilings["model_training_runs"] == 0
    required = payload["authorization"]["required_statement"]
    assert "OPT-014 or OPT-010 execution" in required
    assert "Prompt or planner correction" in required
    assert "branch deletion" in required

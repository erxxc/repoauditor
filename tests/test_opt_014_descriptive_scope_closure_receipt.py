from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-014-descriptive-scope-closure-receipt-2026-08-18.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_frozen_evidence_checkpoint_and_store_are_digest_bound():
    mutable_lifecycle = {"optimization_status"}
    for name, binding in _payload()["frozen_evidence"].items():
        if name in mutable_lifecycle:
            assert len(binding["sha256"]) == 64
        else:
            assert _sha256(ROOT / binding["path"]) == binding["sha256"]


def test_closure_is_bounded_and_preserves_sec_as_inactive_reserve():
    contract = _payload()["closure_contract"]

    assert "not a universal claim" in contract["bounded_negative_claim"]
    assert contract["sec_edgar"]["state"] == "inactive-reserve-preserved"
    assert contract["sec_edgar"]["activation_authorized"] is False
    assert "not a zero-incident" in contract["sec_edgar"]["prohibited_interpretation"]


def test_lifecycle_closes_only_opt_014_and_prioritizes_opt_010():
    lifecycle = _payload()["closure_contract"]["lifecycle_after_closure"]

    assert lifecycle == {
        "closed": 34,
        "open": 1,
        "total": 35,
        "sole_open_item": "OPT-010",
        "OPT_010_next_priority": 1,
        "OPT_014_status": "closed",
        "OPT_014_gate": "none",
        "OPT_014_next_priority": None,
    }


def test_changes_are_lifecycle_only_and_integration_is_deferred():
    payload = _payload()

    assert set(payload["allowed_file_changes_after_authorization"]) == {
        "docs/optimizations/optimization-status.json",
        "docs/optimizations/optimization-register.md",
        "docs/documentation-status.md",
        "docs/project-priorities.md",
        "docs/triage-accuracy-roadmap.md",
        "tests/test_documentation_current_state.py",
        "tests/test_outstanding_work_checkpoint.py",
        "docs/optimizations/opt-014-descriptive-scope-closure-result-2026-08-18.json",
    }
    assert payload["validation_contract"]["full_offline_non_live_suite"] == (
        "deferred-to-separate-branch-integration-receipt"
    )


def test_receipt_allows_no_live_mutating_or_branch_activity():
    ceilings = _payload()["resource_ceilings"]
    zero_fields = (
        "network_reads", "network_uploads", "provider_calls",
        "provider_reported_tokens", "provider_cost_usd", "production_store_reads",
        "production_store_mutations", "schema_migrations", "assessments_written",
        "labels_written", "simulation_runs", "model_training_runs", "rescoring_runs",
        "source_commits", "merge_commits", "remote_pushes",
    )

    assert all(ceilings[field] == 0 for field in zero_fields)
    assert any("branch creation" in item for item in _payload()["excluded"])


def test_receipt_requires_exact_separate_authorization():
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "bounded descriptive-scope closure" in statement
    assert "34 closed and one open item" in statement
    assert "inactive material-disclosure-context reserve" in statement
    assert "shared OPT-036 worktree" in statement

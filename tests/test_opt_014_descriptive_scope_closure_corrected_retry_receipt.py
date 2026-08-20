from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / (
    "docs/optimizations/opt-014-descriptive-scope-closure-corrected-retry-receipt-2026-08-18.json"
)


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_retry_binds_original_receipt_and_accepts_zero_activity_preflight_stop():
    payload = _payload()
    original = payload["original_receipt"]
    stopped = payload["stopped_preflight"]

    assert _sha256(ROOT / original["path"]) == original["sha256"]
    assert stopped["status"] == "stopped-before-lifecycle-change-validation-file-not-allowlisted"
    assert stopped["lifecycle_files_changed"] == stopped["OPT_010_files_changed"] == 0
    assert stopped["source_commits"] == stopped["merge_commits"] == 0
    assert stopped["network_reads"] == stopped["provider_calls"] == 0


def test_only_correction_adds_exact_focused_result_test():
    payload = _payload()
    correction = payload["only_correction"]

    assert correction["add_to_allowed_file_changes"] == "tests/test_opt_014_descriptive_scope_closure.py"
    assert correction["other_original_allowlist_or_semantic_change"] is False
    original = json.loads((ROOT / payload["original_receipt"]["path"]).read_text(encoding="utf-8"))
    assert set(payload["corrected_allowed_file_changes_after_authorization"]) == (
        set(original["allowed_file_changes_after_authorization"])
        | {"tests/test_opt_014_descriptive_scope_closure.py"}
    )


def test_retry_retains_lifecycle_sec_and_deferred_integration_boundaries():
    retained = _payload()["retained_contract"]

    assert retained["lifecycle_after_closure"] == {
        "closed": 34,
        "open": 1,
        "total": 35,
        "sole_open_item": "OPT-010",
        "OPT_010_next_priority": 1,
    }
    assert retained["SEC_EDGAR_state"] == "inactive-material-disclosure-context-reserve"
    assert retained["full_offline_non_live_suite"] == "deferred-to-separate-branch-integration-receipt"
    assert retained["branch_or_commit_activity_authorized"] is False


def test_retry_keeps_all_live_mutating_and_branch_activity_at_zero():
    ceilings = _payload()["resource_ceilings"]
    zero_fields = (
        "network_reads", "network_uploads", "provider_calls", "provider_reported_tokens",
        "provider_cost_usd", "production_store_reads", "production_store_mutations",
        "schema_migrations", "assessments_written", "labels_written", "simulation_runs",
        "model_training_runs", "rescoring_runs", "source_commits", "merge_commits",
        "remote_pushes", "branch_operations",
    )

    assert all(ceilings[field] == 0 for field in zero_fields)


def test_retry_requires_exact_fresh_authorization():
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "accepting the stopped preflight" in statement
    assert "only addition of tests/test_opt_014_descriptive_scope_closure.py" in statement
    assert "34-closed/1-open" in statement
    assert "Any other allowlist" in statement

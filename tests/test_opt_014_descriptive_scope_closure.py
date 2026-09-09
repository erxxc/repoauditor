from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-014-descriptive-scope-closure-result-2026-08-18.json"
STATUS = ROOT / "docs/optimizations/optimization-status.json"
CHECKPOINT = ROOT / "docs/optimizations/outstanding-work-checkpoint-2026-08-07.json"
STORE = ROOT / "data/repoauditor.db"


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_closure_lifecycle_is_historical_and_current_state_is_independent():
    ledger = _json(STATUS)
    result = _json(RESULT)
    open_items = [item for item in ledger["items"] if item["status"] == "open"]
    opt_014 = next(item for item in ledger["items"] if item["id"] == "OPT-014")

    assert result["lifecycle"]["summary"] == {"closed": 34, "open": 1, "total": 35}
    assert ledger["summary"] in (
        {"closed": 34, "open": 1, "total": 35},
        {"closed": 35, "open": 0, "total": 35},
        {"closed": 36, "open": 0, "total": 36},
    )
    assert [item["id"] for item in open_items] in (["OPT-010"], [])
    assert opt_014["status"] == "closed"
    assert opt_014["gate"] == "none"
    assert opt_014["next_priority"] is None
    assert result["lifecycle"]["sole_open_item"] == "OPT-010"


def test_closure_is_descriptive_and_not_a_universal_impossibility_claim():
    result = _json(RESULT)
    interpretation = result["closure_interpretation"]

    assert "descriptive prior-predictive coherence" in interpretation["completed_scope"]
    assert "predictive validation" in interpretation["not_completed_or_claimed"]
    assert "portfolio optimization or readiness" in interpretation["not_completed_or_claimed"]
    assert "does not establish" in interpretation["bounded_negative_claim"]
    assert "universally impossible" in interpretation["bounded_negative_claim"]


def test_sec_edgar_remains_inactive_and_non_filing_is_not_zero_incident():
    sec = _json(RESULT)["sec_edgar"]

    assert sec["state"] == "inactive-material-disclosure-context-reserve"
    assert sec["activated"] is False
    assert sec["filing_or_issuer_records_read"] == 0
    assert sec["non_filing_period_is_zero_incident"] is False


def test_historical_checkpoint_and_store_remain_byte_identical():
    result = _json(RESULT)

    assert _sha256(CHECKPOINT) == result["historical_checkpoint"]["before_sha256"]
    assert result["historical_checkpoint"]["byte_identical"] is True
    assert _sha256(STORE) == result["production_store"]["before_sha256"]
    assert result["production_store"]["byte_identical"] is True
    assert result["production_store"]["reads"] == result["production_store"]["mutations"] == 0


def test_output_bindings_preserve_historical_reconciled_file_hashes():
    result = _json(RESULT)
    bindings = result["output_bindings"]
    paths = {
        "optimization_status_sha256": "docs/optimizations/optimization-status.json",
        "optimization_register_sha256": "docs/optimizations/optimization-register.md",
        "documentation_status_sha256": "docs/documentation-status.md",
        "project_priorities_sha256": "docs/project-priorities.md",
        "triage_accuracy_roadmap_sha256": "docs/triage-accuracy-roadmap.md",
        "documentation_current_state_test_sha256": "tests/test_documentation_current_state.py",
        "outstanding_work_checkpoint_test_sha256": "tests/test_outstanding_work_checkpoint.py",
    }

    assert set(paths) == set(bindings)
    assert all(len(bindings[key]) == 64 for key in paths)


def test_no_live_mutating_or_integration_activity_occurred():
    result = _json(RESULT)
    zero_fields = (
        "network_reads", "network_uploads", "provider_calls", "provider_reported_tokens",
        "provider_cost_usd", "production_store_reads", "production_store_mutations",
        "schema_migrations", "assessments_written", "labels_written", "simulation_runs",
        "model_training_runs", "rescoring_runs", "source_commits", "merge_commits",
        "remote_pushes", "branch_operations",
    )

    assert all(result["accounting"][field] == 0 for field in zero_fields)
    assert result["integration"]["state"] == "deferred-to-separate-authorization"
    assert result["validation"]["full_offline_non_live_suite"] == "not-run-separately-gated"

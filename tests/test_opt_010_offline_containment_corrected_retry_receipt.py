from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / (
    "docs/optimizations/opt-010-offline-containment-foundation-corrected-retry-receipt-2026-08-18.json"
)


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def test_retry_accepts_exact_retained_failure_and_zero_activity():
    attempt = _payload()["retained_attempt"]

    assert attempt["implementation_security_tests_passed"] == 19
    assert attempt["focused_non_live_compatibility_tests_passed"] == 134
    assert attempt["final_boundary_tests_passed"] == 26
    assert attempt["final_boundary_tests_failed"] == 1
    assert attempt["provider_calls"] == attempt["agentic_runs"] == 0
    assert attempt["production_store_reads"] == attempt["production_store_mutations"] == 0


def test_retry_allows_only_exact_historical_test_and_final_evidence_files():
    assert set(_payload()["allowed_file_changes"]) == {
        "tests/test_opt_010_offline_containment_foundation_receipt.py",
        "docs/agentic-escalation-gate.md",
        "tests/test_opt_010_gate_decomposition.py",
        "docs/optimizations/opt-010-offline-containment-foundation-artifact-2026-08-18.json",
        "docs/optimizations/opt-010-offline-containment-foundation-result-2026-08-18.json",
    }


def test_reconciliation_preserves_immutable_inputs_and_names_only_three_outputs():
    reconciliation = _payload()["exact_test_reconciliation"]

    assert reconciliation["authorized_mutable_outputs"] == [
        "agentic_gate",
        "configuration",
        "config_schema",
    ]
    assert "production_store" in reconciliation["immutable_receipt_inputs"]
    assert "must continue comparing immutable inputs" in reconciliation["rule"]
    assert "may not update, replace, or weaken" in reconciliation["rule"]


def test_retry_has_zero_live_mutating_commit_and_merge_activity():
    ceilings = _payload()["resource_ceilings"]
    zero_fields = (
        "network_reads", "network_uploads", "provider_calls",
        "provider_reported_tokens", "provider_cost_usd", "production_store_reads",
        "production_store_mutations", "schema_migrations",
        "repository_materializations", "repository_code_executions",
        "scanner_processes", "agentic_falsification_runs", "assessments_written",
        "labels_written", "model_training_runs", "rescoring_runs", "source_commits",
        "merge_commits",
    )

    assert all(ceilings[field] == 0 for field in zero_fields)
    assert ceilings["maximum_test_reconciliations"] == 1


def test_retry_requires_fresh_exact_authorization():
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "one historical receipt-test reconciliation" in statement
    assert "only the explicitly authorized" in statement
    assert "Any implementation, protocol, original receipt" in statement

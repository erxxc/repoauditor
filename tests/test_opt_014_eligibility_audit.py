from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STORE = ROOT / "data/repoauditor.db"
ARTIFACT = ROOT / "data/artifacts/opt014-eligibility-audit.json"
RESULT = ROOT / (
    "docs/optimizations/opt-014-offline-eligibility-audit-result-2026-08-18.json"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _artifact() -> dict:
    return json.loads(ARTIFACT.read_text(encoding="utf-8"))


def test_opt014_audit_reads_store_without_mutation_and_emits_only_aggregates():
    before = _sha256(STORE)
    payload = _artifact()
    after = _sha256(STORE)

    assert before == after == payload["store"]["sha256_before"]
    assert payload["store"]["sha256_after"] == before
    assert payload["store"]["byte_identical"] is True
    assert payload["accounting"]["row_identities_emitted"] == 0
    assert payload["accounting"]["raw_outcome_values_emitted"] == 0


def test_opt014_audit_classifies_model_and_finding_rows_as_ineligible_outcomes():
    payload = _artifact()
    inventory = payload["aggregate_inventory"]
    classification = payload["evidence_classification"]

    assert inventory["ingested_repositories"] > 0
    assert inventory["findings"] > 0
    assert inventory["assessments"] > 0
    assert inventory["labels"] > 0
    assert inventory["risk_scenarios"] > 0
    assert inventory["simulation_runs"] > 0
    assert classification["eligible_observed_outcome_records"] == 0
    assert classification["finding_rows_are_outcomes"] is False
    assert classification["assessment_or_label_rows_are_outcomes"] is False
    assert classification["simulation_or_scenario_rows_are_outcomes"] is False


def test_opt014_audit_reports_only_descriptive_plumbing_as_structurally_present():
    payload = _artifact()
    states = {name: item["state"] for name, item in payload["capacity"].items()}

    assert states == {
        "descriptive_prior_predictive_plumbing": "structurally-present",
        "independent_held_out_validation_and_backtesting": "structurally-absent",
        "hierarchical_cohorts": "structurally-absent",
        "remediation_effect_analysis": "structurally-absent",
        "portfolio_modeling": "structurally-absent",
    }
    assert payload["decision"]["opt_014_data_gate_cleared"] is False
    assert payload["decision"]["adequacy_threshold_selected"] is False
    assert payload["decision"]["holdout_or_cohort_selected"] is False


def test_opt014_audit_has_zero_live_model_or_store_activity():
    accounting = _artifact()["accounting"]

    assert accounting["network_reads"] == accounting["network_uploads"] == 0
    assert accounting["provider_calls"] == accounting["provider_reported_tokens"] == 0
    assert accounting["production_store_mutations"] == accounting["schema_migrations"] == 0
    assert accounting["assessments_written"] == accounting["labels_written"] == 0
    assert accounting["simulation_runs"] == accounting["model_training_runs"] == 0
    assert accounting["rescoring_runs"] == 0


def test_opt014_persisted_artifact_retains_frozen_input_digests():
    persisted = _artifact()
    assert persisted["status"] == "complete-observed-outcome-capacity-absent"
    assert set(persisted["input_digests"]) == {
        "configuration", "optimization_status", "organization_frequency_methodology",
        "prior_scope_roadmap", "priors", "production_store",
    }
    assert all(len(digest) == 64 for digest in persisted["input_digests"].values())


def test_opt014_result_binds_aggregate_artifact_helper_and_store():
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    artifact = (RESULT.parent / result["execution_evidence"]["artifact"]["path"]).resolve()
    helper = (RESULT.parent / result["execution_evidence"]["helper"]["path"]).resolve()

    assert _sha256(artifact) == result["execution_evidence"]["artifact"]["sha256"]
    assert _sha256(helper) == result["execution_evidence"]["helper"]["sha256"]
    assert _sha256(STORE) == result["store"]["after_sha256"]
    assert result["store"]["before_sha256"] == result["store"]["after_sha256"]
    assert result["store"]["byte_identical"] is True


def test_opt014_result_retains_data_gate_and_hybrid_decision_boundary():
    result = json.loads(RESULT.read_text(encoding="utf-8"))

    assert result["observed_outcome_capacity"][
        "eligible_observed_organization_period_records"
    ] == 0
    assert result["decision"]["opt_014_status"] == "open-data-gated"
    assert result["decision"]["data_gate_cleared"] is False
    assert result["capacity"] == {
        "descriptive_prior_predictive_plumbing": "structurally-present",
        "independent_held_out_validation_and_backtesting": "structurally-absent",
        "hierarchical_cohorts": "structurally-absent",
        "remediation_effect_analysis": "structurally-absent",
        "portfolio_modeling": "structurally-absent",
    }
    assert "does not claim validation" in result["decision"]["hybrid_recommendation"]


def test_opt014_result_records_zero_excluded_activity():
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    accounting = result["accounting"]

    assert accounting["audit_runs"] == 1
    assert accounting["network_reads"] == accounting["network_uploads"] == 0
    assert accounting["provider_calls"] == accounting["provider_reported_tokens"] == 0
    assert accounting["production_store_mutations"] == accounting["schema_migrations"] == 0
    assert accounting["assessments_written"] == accounting["labels_written"] == 0
    assert accounting["simulation_runs"] == accounting["model_training_runs"] == 0
    assert accounting["rescoring_runs"] == 0

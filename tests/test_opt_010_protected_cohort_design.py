from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "docs/optimizations/opt-010-protected-cohort-design-2026-08-18.json"
ARTIFACT = ROOT / "docs/optimizations/opt-010-protected-cohort-eligibility-artifact-2026-08-18.json"
RESULT = ROOT / "docs/optimizations/opt-010-protected-cohort-design-result-2026-08-18.json"


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_design_binds_authorized_receipt_and_freezes_subject_before_execution():
    design = _read(DESIGN)
    receipt = ROOT / "docs/optimizations/opt-010-protected-cohort-design-receipt-2026-08-18.json"

    assert design["authorization_receipt"]["sha256"] == _sha256(receipt)
    assert "selection_digest" in design["subject_identity"]["required_fields"]
    assert design["decision_boundary"]["selected_source_or_cohort"] is False
    assert design["decision_boundary"]["outcome_accessed"] is False


def test_missing_subgroup_metadata_is_unavailable_and_never_inferred():
    subgroup = _read(DESIGN)["subgroup_metadata"]

    assert all(subgroup[name]["missing_rule"] == "unavailable" for name in (
        "family", "mechanism", "language", "detector_provenance"
    ))
    assert "file extension" in subgroup["language"]["prohibited_inference"]
    assert "outcomes" in subgroup["mechanism"]["prohibited_inference"]


def test_terminal_contract_retains_failures_and_unknown_usage():
    terminal = _read(DESIGN)["terminal_observation"]

    assert {"failed", "timed_out", "budget_exhausted", "parser_failed", "verifier_failed"} <= set(
        terminal["required_states"]
    )
    assert "never assigned zero" in terminal["usage_rule"]
    assert "may not be silently removed" in terminal["denominator_rule"]


def test_sufficiency_examples_are_arithmetic_not_thresholds():
    design = _read(DESIGN)
    arithmetic = design["sufficiency_arithmetic"]

    assert arithmetic["frozen_historical_reference"]["overall_decided_identities"] == 40
    assert arithmetic["frozen_historical_reference"]["evaluation_families"] == 8
    assert arithmetic["illustrative_non_selected_scenarios"][1]["marginal_reference_count"] == 160
    assert arithmetic["illustrative_non_selected_scenarios"][1]["intersectional_reference_count"] == 640
    assert design["decision_boundary"]["selected_threshold"] is None
    assert design["decision_boundary"]["recommended_threshold"] is None


def test_aggregate_inventory_closes_and_has_zero_eligible_capacity():
    artifact = _read(ARTIFACT)
    counts = artifact["aggregate_classification"]

    assert counts["bounded_documented_units"] == sum(
        value for key, value in counts.items() if key != "bounded_documented_units"
    )
    assert counts["eligible-unexposed-independent"] == 0
    assert artifact["capacity"]["fully_specified_untouched_source_families"] == 0
    assert artifact["sufficiency_summary"]["threshold_selected_or_recommended"] is False


def test_result_keeps_gates_open_and_recommends_only_metadata_discovery():
    result = _read(RESULT)

    assert result["decision"]["result_state"] == "prospective-metadata-source-discovery-required"
    assert result["decision"]["OPT_010_status"] == "open-deferred"
    assert result["decision"]["agentic_experiment_permitted"] is False
    assert result["decision"]["source_ceiling_recommended"] is None
    assert result["decision"]["adequacy_threshold_recommended"] is None
    assert all(result["gate_state"][gate].startswith("partial") for gate in ("G02", "G04", "G05", "G07"))


def test_opt_036_and_all_live_or_mutating_activity_remain_excluded():
    design = _read(DESIGN)
    artifact = _read(ARTIFACT)
    result = _read(RESULT)

    assert design["decision_boundary"]["OPT_036_admitted"] is False
    assert artifact["boundaries"]["OPT_036_used"] is False
    assert result["findings"]["OPT_036_admitted"] is False
    zero_fields = (
        "network_reads", "network_uploads", "provider_calls",
        "provider_reported_tokens", "provider_cost_usd", "production_store_reads",
        "production_store_mutations", "schema_migrations", "repository_materializations",
        "repository_code_executions", "scanner_processes", "agentic_falsification_runs",
        "assessments_written", "labels_written", "model_training_runs", "rescoring_runs",
        "source_commits", "merge_commits",
    )
    assert all(result["accounting"][field] == 0 for field in zero_fields)

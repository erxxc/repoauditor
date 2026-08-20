from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

import numpy as np

from repoauditor.eval.prior_predictive import (
    EXCEEDANCE_POINTS_USD,
    summarize_losses,
)


ROOT = Path(__file__).resolve().parents[1]
STORE = ROOT / "data/repoauditor.db"
ARTIFACT = ROOT / "data/artifacts/opt014-prior-predictive-coherence.json"
RESULT = ROOT / (
    "docs/optimizations/opt-014-prior-predictive-coherence-result-2026-08-18.json"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_opt014_frozen_parameters_reproduce_configured_frequency_and_magnitude():
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    reproduction = result["source_reproduction"]
    p = float(reproduction["annual_probability_at_least_one"])
    lam = float(reproduction["poisson_lambda"])

    assert abs((1.0 - math.exp(-lam)) - p) <= 1e-12
    assert abs(reproduction["reconstructed_magnitude_median_usd"] / reproduction["configured_magnitude_median_usd"] - 1.0) <= 1e-12
    assert abs(reproduction["reconstructed_magnitude_p95_usd"] / reproduction["configured_magnitude_p95_usd"] - 1.0) <= 1e-12
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert artifact["model"]["modeling_unit"] == "anonymous-neutral-organization-year"


def test_opt014_aggregate_summary_uses_only_fixed_nonidentifying_metrics():
    losses = np.array([0.0, 0.0, 100_000.0, 1_000_000.0, 10_000_000.0])
    summary = summarize_losses(losses)

    assert summary["anonymous_organization_years"] == 5
    assert summary["positive_loss_years"] == 3
    assert summary["zero_loss_fraction"] == 0.4
    assert list(summary["fixed_exceedance_probability"]) == [
        str(point) for point in EXCEEDANCE_POINTS_USD
    ]
    assert summary["batch_summaries"] == []


def test_opt014_persisted_coherence_artifact_is_bounded_and_store_is_unchanged():
    if not ARTIFACT.exists():
        return
    payload = json.loads(ARTIFACT.read_text(encoding="utf-8"))

    assert payload["coherence_checks_passed"] == 7
    assert all(check["passed"] for check in payload["coherence_checks"])
    assert payload["model"]["trials"] == 200000
    assert payload["model"]["seed"] == 2014
    assert len(payload["simulated_implications"]["batch_summaries"]) == 20
    assert payload["interpretation"]["predictive_validation"] is False
    assert payload["interpretation"]["decision_grade"] is False
    assert payload["interpretation"]["opt_014_data_gate_cleared"] is False
    assert payload["accounting"]["raw_draws_persisted"] == 0
    assert payload["accounting"]["production_store_rows_read"] == 0
    assert payload["accounting"]["production_store_mutations"] == 0
    assert _sha256(STORE) == payload["store"]["sha256_after"]


def test_opt014_coherence_result_binds_artifact_helper_and_store():
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    artifact = (RESULT.parent / result["execution_evidence"]["artifact"]["path"]).resolve()
    helper = (RESULT.parent / result["execution_evidence"]["helper"]["path"]).resolve()

    assert _sha256(artifact) == result["execution_evidence"]["artifact"]["sha256"]
    assert _sha256(helper) == result["execution_evidence"]["helper"]["sha256"]
    assert _sha256(STORE) == result["store"]["after_sha256"]
    assert result["store"]["before_sha256"] == result["store"]["after_sha256"]
    assert result["store"]["byte_identical"] is True


def test_opt014_coherence_result_is_descriptive_tail_evidence_not_validation():
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    interpretation = result["interpretation"]

    assert result["coherence"]["checks_passed"] == 7
    assert result["simulated_implications"]["annual_loss_usd"]["p50"] == 0.0
    assert result["simulated_implications"]["annual_loss_usd"]["p75"] == 0.0
    assert result["simulated_implications"]["top_one_percent_share_of_total_loss"] > 0.95
    assert interpretation["predictive_validation"] is False
    assert interpretation["calibration_or_representativeness"] is False
    assert interpretation["monte_carlo_variability_is_epistemic_uncertainty"] is False
    assert interpretation["decision_grade"] is False


def test_opt014_coherence_result_retains_gate_and_zero_excluded_activity():
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    accounting = result["accounting"]

    assert result["decision"]["opt_014_status"] == "open-data-gated"
    assert result["decision"]["data_gate_cleared"] is False
    assert accounting["in_memory_prior_predictive_generations"] == 1
    assert accounting["network_reads"] == accounting["network_uploads"] == 0
    assert accounting["provider_calls"] == accounting["provider_reported_tokens"] == 0
    assert accounting["production_store_rows_read"] == 0
    assert accounting["production_store_mutations"] == 0
    assert accounting["persisted_simulation_runs"] == 0
    assert accounting["persisted_risk_scenarios"] == accounting["persisted_prior_sources"] == 0
    assert accounting["assessments_written"] == accounting["labels_written"] == 0
    assert accounting["model_training_runs"] == accounting["rescoring_runs"] == 0

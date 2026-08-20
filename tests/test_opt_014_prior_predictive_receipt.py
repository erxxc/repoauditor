from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / (
    "docs/optimizations/opt-014-prior-predictive-coherence-receipt-2026-08-18.json"
)


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _assert_bound(record: dict) -> None:
    path = (RECEIPT.parent / record["path"]).resolve()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]


def test_opt014_prior_predictive_receipt_binds_protocol_audit_and_store():
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    _assert_bound(payload["protocol"])
    _assert_bound(payload["preconditions"]["eligibility_audit_result"])
    _assert_bound(payload["preconditions"]["production_store"])
    assert payload["preconditions"]["eligibility_audit_result"][
        "observed_outcome_capacity"
    ] == 0


def test_opt014_prior_predictive_receipt_freezes_generation_and_aggregate_result():
    payload = _payload()
    generation = payload["generation_contract"]
    result = payload["result_contract"]

    assert generation["anonymous_organization_years"] == 200000
    assert generation["seed"] == 2014
    assert generation["batch_count"] == 20
    assert generation["trials_per_batch"] == 10000
    assert generation["raw_draws_persisted"] is False
    assert result["aggregate_metrics_only"] is True
    assert result["coherence_checks_required"] == 7
    assert result["fixed_exceedance_points_usd"] == [
        100000, 1000000, 10000000, 50000000, 100000000
    ]


def test_opt014_prior_predictive_receipt_cannot_validate_or_clear_gate():
    result = _payload()["result_contract"]

    assert result["validation_claim_permitted"] is False
    assert result["data_gate_may_be_cleared"] is False
    assert result["prior_or_policy_change_permitted"] is False
    assert "remains open and data-gated" in result["required_disposition"]


def test_opt014_prior_predictive_receipt_has_zero_live_or_persisted_activity():
    payload = _payload()
    ceilings = payload["resource_ceilings"]
    required = payload["authorization"]["required_statement"]

    assert ceilings["network_reads"] == ceilings["network_uploads"] == 0
    assert ceilings["provider_calls"] == ceilings["provider_reported_tokens"] == 0
    assert ceilings["production_store_reads"] == ceilings["production_store_mutations"] == 0
    assert ceilings["persisted_simulation_runs"] == 0
    assert ceilings["persisted_risk_scenarios"] == ceilings["persisted_prior_sources"] == 0
    assert ceilings["assessments_written"] == ceilings["labels_written"] == 0
    assert ceilings["model_training_runs"] == ceilings["rescoring_runs"] == 0
    assert "observed-outcome validation" in required
    assert "OPT-014 promotion or closure" in required

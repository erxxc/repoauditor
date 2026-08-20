from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / (
    "docs/optimizations/opt-014-offline-eligibility-audit-receipt-2026-08-18.json"
)


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _assert_bound(record: dict) -> None:
    path = (RECEIPT.parent / record["path"]).resolve()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]


def test_opt014_eligibility_receipt_binds_protocol_and_store():
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    _assert_bound(payload["protocol"])
    _assert_bound(payload["preconditions"]["production_store"])
    assert payload["preconditions"]["optimization_status"] == {
        "status": "open", "gate": "data", "next_priority": 1
    }


def test_opt014_eligibility_receipt_is_aggregate_and_cannot_clear_gate():
    payload = _payload()
    result = payload["result_contract"]

    assert result["identity_disclosure"] == result["raw_outcome_values"] == 0
    assert result["data_gate_may_be_cleared"] is False
    assert result["adequacy_threshold_may_be_selected"] is False
    assert result["holdout_or_cohort_may_be_selected"] is False
    assert set(result["capacity_states"]) == {
        "structurally-present", "structurally-absent"
    }


def test_opt014_eligibility_receipt_has_zero_live_model_or_store_activity():
    payload = _payload()
    ceilings = payload["resource_ceilings"]
    required = payload["authorization"]["required_statement"]

    assert ceilings["network_reads"] == ceilings["network_uploads"] == 0
    assert ceilings["provider_calls"] == ceilings["provider_reported_tokens"] == 0
    assert ceilings["provider_cost_usd"] == 0.0
    assert ceilings["production_store_mutations"] == ceilings["schema_migrations"] == 0
    assert ceilings["assessments_written"] == ceilings["labels_written"] == 0
    assert ceilings["simulation_runs"] == ceilings["model_training_runs"] == 0
    assert ceilings["rescoring_runs"] == 0
    assert "simulation or prior-predictive generation" in required
    assert "OPT-014 promotion or closure" in required
    assert "portfolio optimization" in required


def test_opt014_eligibility_receipt_stops_before_hybrid_follow_up():
    payload = _payload()

    assert payload["completion_boundary"].endswith(
        "no predictive report, acquisition, fitting, policy, lifecycle, branch, or "
        "deployment action is authorized."
    )
    assert "governed data acquisition" in payload["result_contract"]["next_step"]

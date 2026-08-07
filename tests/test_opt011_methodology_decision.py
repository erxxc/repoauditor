"""OPT-011 freezes an aggregate organization model without changing runtime yet."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DECISION = ROOT / "docs/optimizations/opt-011-methodology-decision-2026-08-07.json"
METHODOLOGY = ROOT / "docs/organization-frequency-methodology.md"


def test_opt011_decision_is_aggregate_nonallocating_and_implementation_gated():
    decision = json.loads(DECISION.read_text(encoding="utf-8"))
    model = decision["decision"]

    assert decision["status"] == "methodology-approved-implementation-pending"
    assert decision["runtime_changed"] is False
    assert model["modeling_unit"] == "organization_all_event"
    assert model["base_probability_at_least_one"] == 0.129
    assert model["base_rate_consumption"] == "exactly once per simulation trial"
    assert model["finding_role"] == "auditable non-allocating evidence membership"
    assert model["scenario_attribution"] == model["remediation_delta"] == "unavailable"
    assert decision["organization_inputs"] == {
        "default_exposure": 1.0,
        "default_control_strength": 0.0,
        "default_loss_scale": 1.0,
        "allowed_override_scope": "engagement-wide * only",
        "scenario_specific_override_behavior": "fail-closed",
    }
    assert "No runtime" in decision["excluded"]


def test_opt011_methodology_preserves_claim_boundary_and_acceptance_contract():
    text = METHODOLOGY.read_text(encoding="utf-8")

    assert "finding count" in text.lower()
    assert "do not multiply" in text
    assert "one full organization rate per finding" in text
    assert "equal allocation across findings" in text
    assert "incremental loss" in text and "remediation" in text
    assert "Historical simulation rows remain immutable" in text
    assert "PR 2 acceptance contract" in text
    assert all(f"{number}." in text for number in range(1, 11))

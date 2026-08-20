from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / (
    "docs/optimizations/opt-014-independent-data-acquisition-design-2026-08-18.json"
)


def _payload() -> dict:
    return json.loads(DESIGN.read_text(encoding="utf-8"))


def _assert_bound(record: dict) -> None:
    path = (DESIGN.parent / record["path"]).resolve()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]


def test_opt014_acquisition_design_binds_negative_gate_and_coherence_evidence():
    payload = _payload()
    evidence = payload["evidence_basis"]

    assert payload["status"] == "design-frozen-source-selection-not-authorized"
    _assert_bound(evidence["offline_eligibility_audit"])
    _assert_bound(evidence["prior_predictive_coherence_report"])
    _assert_bound(evidence["frozen_priors"])
    _assert_bound(evidence["production_store"])
    assert evidence["offline_eligibility_audit"][
        "eligible_observed_organization_period_records"
    ] == 0
    assert evidence["offline_eligibility_audit"]["data_gate_cleared"] is False
    assert evidence["prior_predictive_coherence_report"]["coherence_checks_passed"] == 7
    assert evidence["prior_predictive_coherence_report"]["data_gate_cleared"] is False


def test_opt014_acquisition_design_requires_denominators_zeros_and_independence():
    payload = _payload()
    observation = payload["target_observation_contract"]
    independence = payload["independence_and_leakage_contract"]

    assert observation["primary_unit"] == "organization-period"
    assert "incident_count_including_explicit_zero" in observation["required_fields"]
    assert any("denominator" in item for item in observation["required_frequency_properties"])
    assert any("Zero-incident" in item for item in observation["required_frequency_properties"])
    assert "IRIS 2012-2021 Advisen-based" in independence["prior_source_exclusion"]
    assert any("adequacy criteria" in item for item in independence["required_checks_before_outcome_access"])
    assert any("synthetic" in item for item in independence["ineligible_as_independent_outcomes"])


def test_opt014_acquisition_design_separates_frequency_magnitude_and_context_tiers():
    tiers = {item["tier"]: item for item in _payload()["source_eligibility_tiers"]}

    assert set(tiers) == {
        "full-organization-period-candidate",
        "magnitude-only-candidate",
        "aggregate-context-only",
        "ineligible",
    }
    assert "annual incident frequency validation" in tiers["magnitude-only-candidate"][
        "cannot_support"
    ]
    assert "held-out outcome validation" in tiers["aggregate-context-only"][
        "cannot_support"
    ]
    assert "performance-selected or outcome-peeked source" in tiers["ineligible"][
        "examples"
    ]


def test_opt014_acquisition_design_freezes_outcome_blind_metadata_discovery():
    discovery = _payload()["future_metadata_only_discovery_contract"]

    assert discovery["authorization_required"] is True
    assert discovery["source_identity_disclosure_required_for_review"] is True
    assert discovery["network_hosts"].startswith("not_selected")
    assert discovery["candidate_count_or_adequacy_threshold"] == "not_selected"
    assert any("raw or row-level" in item for item in discovery["forbidden_during_discovery"])
    assert any("summary-distribution" in item for item in discovery["forbidden_during_discovery"])
    assert any("Stop before download" in item for item in discovery["deterministic_funnel"])


def test_opt014_acquisition_design_has_zero_execution_and_cannot_clear_gate():
    payload = _payload()
    accounting = payload["accounting"]

    assert all(value == 0 for value in accounting.values())
    assert payload["claim_boundary"]["a_qualified_source_does_not_clear_the_data_gate"] is True
    assert "does not authorize network access" in payload["completion_boundary"]
    assert "OPT-014 lifecycle changes" in payload["completion_boundary"]

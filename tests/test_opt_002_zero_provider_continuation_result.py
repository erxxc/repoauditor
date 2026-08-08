"""OPT-002 primary continuation result proves identity and zero-provider bounds."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = (
    ROOT
    / "docs/optimizations/opt-002-zero-provider-continuation-result-2026-08-07.json"
)


def _result() -> dict:
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_both_primary_sources_match_the_frozen_scoring_identity():
    payload = _result()

    assert payload["documenso_retriage"]["identity_gate_passed"] is True
    assert payload["lobsters"]["identity_gate_passed"] is True
    identity = payload["scoring_identity"]
    assert identity["model_name"] == "xgboost"
    assert identity["model_version"] == "3.3.0"
    assert identity["feature_schema_version"] == "sha256:89450a98dd4cdc1c"
    assert identity["calibration"] == "isotonic"
    assert identity["semgrep_version"] == "1.170.0"
    assert identity["matched_for_both_sources"] is True


def test_execution_used_no_provider_and_stayed_within_data_ceiling():
    accounting = _result()["authorization_accounting"]

    assert accounting["initial_model_usage_rows"] == 1473
    assert accounting["final_model_usage_rows"] == 1473
    assert accounting["provider_calls"] == 0
    assert accounting["provider_reported_tokens"] == 0
    assert accounting["provider_cost_usd"] == 0
    assert accounting["network_upload_operations"] == 0
    assert accounting["new_data_kib"] < accounting["new_data_ceiling_kib"]
    assert accounting["ceiling_breaches"] == []


def test_reserve_is_not_needed_and_packet_work_remains_gated():
    payload = _result()
    candidates = payload["outcome_blind_candidate_count"]

    assert candidates["eligible_primary_total"] == 218
    assert candidates["eligible_primary_total"] >= candidates["minimum_packet_size"]
    assert candidates["reserve_activation_condition_met"] is False
    assert candidates["packet_selected"] is False
    assert candidates["candidate_identities_exposed"] is False
    assert payload["not_executed"]["human_review"] is True
    assert payload["not_executed"]["automatic_labels"] is True
    assert payload["disposition"]["opt_002_status"] == "open-packet-gated"

"""OPT-002 packet result proves balanced, immutable, non-reviewing selection."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-002-packet-selection-result-2026-08-07.json"


def _result() -> dict:
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_packet_is_unique_balanced_and_bound_to_the_frozen_inventory():
    payload = _result()
    selected = payload["selected_identities"]

    assert payload["selection"]["packet_size"] == 12
    assert payload["selection"]["documenso_count"] == 6
    assert payload["selection"]["lobsters_count"] == 6
    assert len({item["finding_id"] for item in selected}) == 12
    assert len({item["candidate_key"] for item in selected}) == 12
    assert payload["preconditions"]["eligible_inventory_count"] == 218
    assert payload["selection"]["forbidden_fields_present"] == []


def test_selection_was_offline_read_only_and_did_not_review():
    payload = _result()
    accounting = payload["authorization_accounting"]

    assert accounting["store_byte_identical"] is True
    assert accounting["initial_model_usage_rows"] == 1473
    assert accounting["final_model_usage_rows"] == 1473
    assert accounting["final_primary_assessments"] == 0
    assert accounting["final_primary_labels"] == 0
    assert accounting["network_reads"] == 0
    assert accounting["network_uploads"] == 0
    assert accounting["provider_calls"] == 0
    assert accounting["provider_reported_tokens"] == 0
    assert accounting["provider_cost_usd"] == 0
    assert payload["selection"]["source_evidence_rendered"] is False
    assert payload["not_executed"]["human_review"] is True


def test_next_step_remains_separately_review_gated():
    payload = _result()

    assert payload["disposition"]["opt_002_status"] == "open-review-gated"
    assert payload["not_executed"]["labels"] is True
    assert payload["not_executed"]["tuning"] is True
    assert payload["not_executed"]["gate_promotion"] is True

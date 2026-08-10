"""OPT-002 bootstrap activation is family-aware, descriptive, and non-mutating."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-002-bootstrap-implementation-receipt-2026-08-10.json"


def test_receipt_activates_only_after_the_measured_gate():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    evidence = payload["activation_evidence"]
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert evidence["compatible_scored_human_labels"] == 47
    assert evidence["genuine_evaluation_families"] == 9
    assert evidence["data_gate_conditions_met"] is True


def test_receipt_requires_family_block_bootstrap_without_threshold_selection():
    contract = json.loads(RECEIPT.read_text(encoding="utf-8"))["implementation_contract"]
    assert contract["sampling_unit"].startswith("evaluation family")
    assert contract["resamples"] == 2000
    assert contract["confidence_level"] == 0.95
    assert contract["seed"] == 2002
    assert contract["no_optimal_threshold"] is True


def test_receipt_allows_no_external_model_or_store_activity():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    ceilings = payload["resource_ceilings"]
    assert ceilings["network_reads"] == 0
    assert ceilings["provider_calls"] == 0
    assert ceilings["store_mutations"] == 0
    assert ceilings["model_training_runs"] == 0
    assert ceilings["rescored_findings"] == 0
    assert any("automatic threshold selection" in item for item in payload["not_authorized"])

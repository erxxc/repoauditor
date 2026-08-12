"""OPT-003 wave-two import result records the exact one-label shortfall."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-003-wave-2-import-result-2026-08-12.json"


def test_result_binds_receipt_and_exact_atomic_import():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    receipt = ROOT / "docs/optimizations" / payload["execution_receipt"]["path"]
    tx = payload["transaction"]
    assert hashlib.sha256(receipt.read_bytes()).hexdigest() == payload["execution_receipt"]["sha256"]
    assert tx["atomic"] is True
    assert tx["assessment_inserts"] == 18
    assert tx["manual_label_inserts"] == 12
    assert tx["actionable_label_inserts"] == 0
    assert tx["non_actionable_label_inserts"] == 12
    assert tx["other_store_mutations"] == 0
    assert len(tx["assessment_ids"]) == 18
    assert len(tx["label_ids"]) == 12


def test_result_preserves_six_abstentions_and_provider_ledger():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    measured = payload["measured_post_import"]
    accounting = payload["authorization_accounting"]
    assert measured["selected_false_positive"] == 12
    assert measured["selected_uncertain"] == 6
    assert measured["selected_abstention_labels"] == 0
    assert measured["triage_assessments"] == 159
    assert measured["triage_labels"] == 157
    assert measured["triage_model_runs"] == 41
    assert measured["model_usage_rows"] == 1473
    assert accounting["provider_calls"] == 0
    assert accounting["model_training_runs"] == 0
    assert accounting["ceiling_breaches"] == []


def test_result_satisfies_all_but_one_decided_label():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    gate = payload["temporal_gate_report"]
    assert gate["prospective_decided_labels"] == 39
    assert gate["prospective_positive"] == 6
    assert gate["prospective_negative"] == 33
    assert gate["genuine_evaluation_families"] == 8
    assert gate["separately_frozen_prediction_waves"] == 3
    assert gate["label_count_condition_met"] is False
    assert gate["family_condition_met"] is True
    assert gate["both_classes_present"] is True
    assert gate["prediction_wave_condition_met"] is True
    assert gate["activation_conditions_met"] is False
    assert gate["remaining_shortfall"] == {
        "decided_labels": 1,
        "evaluation_families": 0,
        "prediction_waves": 0,
        "both_classes": 0,
    }
    assert all(payload["not_executed"].values())
    assert payload["disposition"]["opt_003_status"] == "open-one-prospective-label-gated"

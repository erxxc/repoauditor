"""OPT-003 import result records exact projections and retains the temporal gate."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-003-wave-1-import-result-2026-08-11.json"


def test_result_records_exact_atomic_import_and_shortfall():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    tx = payload["transaction"]
    measured = payload["measured_post_import"]
    gate = payload["temporal_gate_report"]

    assert tx["atomic"] is True
    assert tx["assessment_inserts"] == 18
    assert tx["manual_label_inserts"] == 16
    assert tx["other_store_mutations"] == 0
    assert measured["selected_true_positive"] == 1
    assert measured["selected_false_positive"] == 15
    assert measured["selected_uncertain"] == 2
    assert measured["selected_abstention_labels"] == 0
    assert gate["prospective_decided_labels"] == 27
    assert gate["genuine_evaluation_families"] == 5
    assert gate["separately_frozen_prediction_waves"] == 2
    assert gate["activation_conditions_met"] is False
    assert gate["remaining_shortfall"] == {
        "decided_labels": 13,
        "evaluation_families": 3,
        "prediction_waves": 0,
        "both_classes": 0,
    }
    assert payload["not_executed"]["opt_003_closure"] is True

"""OPT-002 import result records exact projections and leaves promotion gated."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-002-review-import-result-2026-08-10.json"


def test_result_records_exact_atomic_import_and_gate():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    tx = payload["transaction"]
    measured = payload["measured_post_import"]
    gate = payload["gate_report"]

    assert tx["atomic"] is True
    assert tx["assessment_inserts"] == 12
    assert tx["manual_label_inserts"] == 11
    assert tx["other_store_mutations"] == 0
    assert measured["selected_true_positive"] == 5
    assert measured["selected_false_positive"] == 6
    assert measured["selected_uncertain"] == 1
    assert measured["selected_abstention_labels"] == 0
    assert gate["compatible_scored_human_labels"] == 47
    assert gate["genuine_evaluation_families"] == 9
    assert gate["data_gate_conditions_met"] is True
    assert payload["not_executed"]["opt_002_promotion"] is True

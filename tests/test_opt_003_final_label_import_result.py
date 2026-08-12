"""OPT-003 final-label import result proves the exact atomic gate-closing pair."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-003-final-label-import-result-2026-08-12.json"


def test_final_label_result_binds_inputs_and_exact_transaction():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    for record in (payload["execution_receipt"], payload["followup_result"]):
        path = ROOT / "docs/optimizations" / record["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]
    transaction = payload["transaction"]
    assert transaction["assessment_id"] == 160
    assert transaction["label_id"] == 278
    assert transaction["assessment_inserts"] == 1
    assert transaction["manual_label_inserts"] == 1
    assert transaction["other_store_mutations"] == 0
    assert transaction["prior_abstention_preserved"] is True
    assert transaction["unchanged_table_count"] == 28


def test_final_label_result_measures_passing_gate_without_status_change():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    gate = payload["temporal_gate_report"]
    assert gate["prospective_decided_labels"] == 40
    assert gate["prospective_positive"] == 6
    assert gate["prospective_negative"] == 34
    assert gate["genuine_evaluation_families"] == 8
    assert gate["separately_frozen_prediction_waves"] == 3
    assert gate["activation_conditions_met"] is True
    assert payload["disposition"]["opt_003_status"] == "open-temporal-evaluation-report-gated"
    assert all(payload["not_executed"].values())

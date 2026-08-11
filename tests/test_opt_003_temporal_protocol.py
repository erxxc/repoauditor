"""OPT-003 admits only genuinely prospective, family-aware temporal evidence."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "docs/optimizations/opt-003-temporal-validation-protocol-2026-08-10.json"


def _payload() -> dict:
    return json.loads(PROTOCOL.read_text(encoding="utf-8"))


def test_current_chronology_is_measured_and_remains_data_gated():
    readiness = _payload()["readiness_assessment"]
    assert readiness["compatible_scored_human_labels"] == 47
    assert readiness["prospective_score_before_review_decided_labels"] == 11
    assert readiness["prospective_evaluation_families"] == 2
    assert readiness["prospective_collection_waves"] == 1
    assert readiness["gate_met"] is False
    assert "not train-before/evaluate-after" in readiness["reason"]


def test_activation_requires_depth_families_and_both_classes():
    floor = _payload()["activation_floor"]
    assert floor["minimum_prospective_decided_labels"] == 40
    assert floor["minimum_prospective_evaluation_families"] == 8
    assert floor["minimum_distinct_prediction_waves"] == 2
    assert floor["both_classes_required"] is True
    assert floor["abstentions_preserved"] is True


def test_protocol_prevents_temporal_leakage_and_reclassification():
    payload = _payload()
    rules = " ".join(payload["fail_closed_rules"])
    assert "known before its prediction" in rules
    assert "trained on that finding's label" in rules
    assert "repeated scoring" in rules
    assert "keep OPT-003 data-gated" in rules


def test_protocol_authorizes_no_acquisition_or_execution():
    excluded = _payload()["authorization_boundary"]["not_authorized"]
    assert "repository acquisition" in excluded
    assert "provider or network activity" in excluded
    assert "new model training" in excluded
    assert "store mutation" in excluded
    assert "threshold or policy changes" in excluded

"""OPT-003 wave two fails closed on an unbound Semgrep version check."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ATTEMPT = ROOT / "docs/optimizations/opt-003-wave-2-attempt-2026-08-11.json"


def test_attempt_stops_before_preflight_or_mutation():
    payload = json.loads(ATTEMPT.read_text(encoding="utf-8"))
    accounting = payload["accounting"]

    assert payload["status"] == "stopped-before-preflight"
    assert payload["stop"]["passed"] is False
    assert payload["stop"]["observed_binding"] == "absent"
    assert payload["stop"]["write_succeeded"] is False
    assert payload["verified_before_stop"]["initial_store_sha256"] == accounting["final_store_sha256"]
    assert accounting["store_byte_identical"] is True
    assert accounting["wave_two_artifacts_created"] == 0
    assert accounting["repositories_materialized"] == 0
    assert accounting["scanner_canary_reports"] == 0
    assert accounting["model_training_runs"] == 0
    assert accounting["predictions_persisted"] == 0
    assert all(payload["not_executed"].values())


def test_attempt_preserves_zero_provider_and_outcome_boundary():
    payload = json.loads(ATTEMPT.read_text(encoding="utf-8"))
    accounting = payload["accounting"]
    assert accounting["provider_calls"] == 0
    assert accounting["human_reviews"] == 0
    assert accounting["assessments_written"] == 0
    assert accounting["labels_written"] == 0
    assert payload["verified_before_stop"]["initial_store_sha256"] == accounting["final_store_sha256"]

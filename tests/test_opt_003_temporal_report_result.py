"""OPT-003 temporal report result is aggregate, deterministic, and non-mutating."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-003-temporal-report-result-2026-08-12.json"


def test_temporal_result_binds_receipt_and_aggregate_artifact():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    for record in (payload["execution_receipt"], payload["report_artifact"]):
        path = (RESULT.parent / record["path"]).resolve()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]
    assert payload["report_artifact"]["identity_level_scores_emitted"] is False
    assert payload["chronology_verification"]["identities_checked"] == 40
    assert payload["chronology_verification"]["failures"] == 0


def test_temporal_result_reports_frozen_metrics_without_selection():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    cohort = payload["cohort"]
    assert cohort == {
        "decided_labels": 40,
        "positive": 6,
        "negative": 34,
        "evaluation_families": 8,
        "prediction_waves": 3,
        "activation_conditions_met": True,
    }
    assert len(payload["aggregate_metrics"]["fixed_thresholds"]) == 11
    assert payload["uncertainty_method"]["resamples"] == 2000
    assert payload["uncertainty_method"]["seed"] == 2003
    assert payload["interpretation"]["threshold_selected_or_recommended"] is False


def test_temporal_result_records_zero_mutation_and_keeps_closure_separate():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    accounting = payload["accounting"]
    assert accounting["store_byte_identical"] is True
    assert accounting["store_mutations"] == 0
    assert accounting["network_reads"] == 0
    assert accounting["provider_calls"] == 0
    assert all(payload["not_executed"].values())
    assert payload["disposition"]["bounded_objective_complete"] is True
    assert payload["disposition"]["opt_003_status"] == "open-closure-decision-gated"

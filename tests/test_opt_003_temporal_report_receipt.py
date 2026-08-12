"""OPT-003 temporal report is fixed, aggregate-only, and read-only."""

from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

from repoauditor.eval import temporal_report


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-003-temporal-report-receipt-2026-08-12.json"


def test_temporal_report_receipt_binds_gate_store_and_reporter():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    gate = ROOT / "docs/optimizations" / payload["gate_result"]["path"]
    helper = (RECEIPT.parent / payload["reporter"]["path"]).resolve()
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert hashlib.sha256(gate.read_bytes()).hexdigest() == payload["gate_result"]["sha256"]
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == payload["reporter"]["sha256"]
    assert temporal_report.EXPECTED_STORE_SHA256 == payload["store_precondition"]["sha256"]


def test_temporal_report_method_is_frozen_and_aggregate_only():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    method = payload["fixed_method"]
    assert len(temporal_report.COHORT) == method["cohort_size"] == 40
    assert len({item.family for item in temporal_report.COHORT}) == method["families"] == 8
    assert len({item.wave for item in temporal_report.COHORT}) == method["waves"] == 3
    assert list(temporal_report.THRESHOLDS) == method["thresholds"]
    assert temporal_report.BOOTSTRAP_RESAMPLES == 2000
    assert temporal_report.BOOTSTRAP_SEED == 2003
    assert method["identity_level_scores_in_output"] is False
    assert method["threshold_selected_or_recommended"] is False


def test_temporal_reporter_is_read_only_and_refuses_overwrite():
    source = inspect.getsource(temporal_report.build_report)
    main_source = inspect.getsource(temporal_report.main)
    assert "mode=ro" in source
    assert "scored_at" in source and "first_assessed_at" in source
    assert "INSERT " not in source
    assert "UPDATE " not in source
    assert "DELETE " not in source
    assert "refusing to overwrite" in main_source

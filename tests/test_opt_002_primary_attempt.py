"""The first OPT-002 execution attempt stops on scoring identity drift."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = (
    ROOT
    / "docs/optimizations/opt-002-primary-execution-attempt-2026-08-07.json"
)


def _result() -> dict:
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_attempt_stopped_at_the_frozen_scoring_identity():
    payload = _result()

    assert payload["status"] == "stopped-scoring-identity-drift"
    assert payload["scoring_stop"]["expected"]["model_name"] == "xgboost"
    assert payload["scoring_stop"]["observed"]["model_name"] == "randomforest"
    assert payload["scoring_stop"]["new_derived_label_ids"] == list(
        range(120, 127)
    )
    assert payload["not_executed"]["lobsters_ingest"] is True
    assert payload["disposition"]["opt_002_status"] == "open-data-gated"


def test_attempt_preserved_zero_provider_and_resource_ceilings():
    accounting = _result()["authorization_accounting"]

    assert accounting["provider_calls"] == 0
    assert accounting["provider_reported_tokens"] == 0
    assert accounting["provider_cost_usd"] == 0
    assert accounting["network_uploads"] == 0
    assert accounting["final_model_usage_rows"] == 1473
    assert accounting["new_data_kib"] < accounting["new_data_ceiling_kib"]
    assert accounting["ceiling_breaches"] == []


def test_documenso_scan_was_healthy_but_is_not_review_eligible():
    payload = _result()
    source = payload["completed_source"]

    assert source["full_commit"].startswith(source["stored_commit"])
    assert source["llm_regions"] == 0
    assert source["llm_completed_calls"] == 0
    assert source["triage_feature_count"] == source["triage_score_count"] == 87
    assert all(
        execution["status"] in {"complete", "empty", "not-applicable"}
        for execution in source["scanner_executions"]
    )
    assert payload["disposition"]["documenso_evidence"].startswith("retained")
    assert payload["disposition"]["automatic_labels_added_for_documenso"] == 0

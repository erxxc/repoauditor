"""OPT-003 retry result proves one pre-outcome model and zero outcomes."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-003-wave-1-retry-result-2026-08-11.json"


def _payload() -> dict:
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_result_records_separated_passing_preflights():
    preflight = _payload()["preflight"]
    assert preflight["offline_passed"] is True
    assert preflight["advisory_passed"] is True
    assert preflight["offline_scanners"] == ["semgrep", "semgrep-supplemental", "gitleaks"]
    assert preflight["advisory_scanners"] == ["pip-audit", "osv-scanner"]


def test_result_uses_one_new_model_for_three_exact_sources():
    payload = _payload()
    model = payload["wave_model"]
    repos = payload["repositories"]
    assert model["training_invocations"] == 1
    assert model["trained_before_source_materialization"] is True
    assert model["stopped_model_reused"] is False
    assert model["effective_labels"] == 122
    assert len(repos) == 3
    assert len({row["evaluation_family"] for row in repos}) == 3
    assert all(len(row["commit"]) == 40 for row in repos)
    assert sum(row["persisted_scores"] for row in repos) == 449


def test_result_has_zero_outcomes_providers_and_policy_changes():
    payload = _payload()
    accounting = payload["accounting"]
    assert accounting["triage_assessments_before"] == accounting["triage_assessments_after"]
    assert accounting["triage_labels_before"] == accounting["triage_labels_after"]
    assert accounting["model_usage_rows_before"] == accounting["model_usage_rows_after"]
    assert accounting["provider_calls"] == 0
    assert accounting["ceiling_breaches"] == []
    assert all(payload["not_executed"].values())

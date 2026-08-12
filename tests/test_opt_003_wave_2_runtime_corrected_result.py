"""OPT-003 runtime-corrected result proves predictions and stops before outcomes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-003-wave-2-runtime-corrected-result-2026-08-11.json"


def _payload() -> dict:
    return json.loads(RESULT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_result_binds_receipt_runtime_and_one_model():
    payload = _payload()
    receipt = ROOT / "docs/optimizations" / payload["receipt"]["path"]
    assert payload["status"] == "completed-prospective-prediction-wave"
    assert _sha256(receipt) == payload["receipt"]["sha256"]
    assert payload["runtime_confinement"]["semgrep_version"] == "1.170.0"
    assert payload["runtime_confinement"]["semgrep_dev_contacts"] == 0
    assert payload["preflight"]["offline_passed"] is True
    assert payload["preflight"]["advisory_passed"] is True
    assert payload["preflight"]["completed_before_model_training"] is True
    assert payload["wave_model"]["training_invocations"] == 1
    assert payload["wave_model"]["prior_attempt_model_reused"] is False


def test_result_records_three_exact_compatible_prediction_inventories():
    payload = _payload()
    repositories = payload["repositories"]
    assert len(repositories) == 3
    assert {row["triage_model_run"] for row in repositories} == {39, 40, 41}
    assert len({row["evaluation_family"] for row in repositories}) == 3
    assert all(len(row["commit"]) == 40 for row in repositories)
    assert all(row["scanner_statuses"]["semgrep"] == "complete" for row in repositories)
    assert all(row["persisted_scores"] > 0 for row in repositories)
    assert sum(row["persisted_scores"] for row in repositories) == 368
    assert all(row["eligible_identities"] >= 6 for row in repositories)


def test_result_passes_inventory_capacity_without_selecting_or_disclosing():
    inventory = _payload()["aggregate_inventory"]
    assert inventory["eligible_identities"] == 249
    assert inventory["minimum_total_met"] is True
    assert inventory["all_family_minimums_met"] is True
    assert inventory["candidate_identities_selected"] == 0
    assert inventory["candidate_identities_disclosed"] == 0
    assert inventory["scores_or_ranks_read_by_measurement"] is False


def test_result_preserves_provider_outcome_and_policy_boundaries():
    payload = _payload()
    accounting = payload["accounting"]
    assert accounting["triage_assessments_before"] == accounting["triage_assessments_after"] == 141
    assert accounting["triage_labels_before"] == accounting["triage_labels_after"] == 145
    assert accounting["model_usage_rows_before"] == accounting["model_usage_rows_after"] == 1473
    assert accounting["provider_calls"] == 0
    assert accounting["human_reviews"] == 0
    assert accounting["assessments_written"] == 0
    assert accounting["labels_written"] == 0
    assert accounting["ceiling_breaches"] == []
    assert all(payload["not_executed"].values())
    assert payload["disposition"]["opt_003_status"] == "open-wave-two-packet-gated"

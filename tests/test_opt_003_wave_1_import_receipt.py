"""OPT-003 wave-one import is exact, atomic, abstention-safe, and status-gated."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-003-wave-1-import-receipt-2026-08-11.json"
RESULT = ROOT / "docs/optimizations/opt-003-wave-1-review-result-2026-08-11.json"


def _receipt() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def test_receipt_freezes_exact_review_and_projection():
    payload = _receipt()
    result = json.loads(RESULT.read_text(encoding="utf-8"))

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert payload["review_result"]["sha256"] == hashlib.sha256(
        RESULT.read_bytes()
    ).hexdigest()
    assert payload["review_result"]["responses"] == len(result["responses"]) == 18
    assert payload["review_result"]["decided"] == 16
    assert payload["review_result"]["abstentions"] == 2
    assert payload["import_contract"]["assessment_rows"] == 18
    assert payload["import_contract"]["manual_label_upserts"] == 16


def test_receipt_requires_atomic_non_overwriting_abstention_safe_import():
    contract = _receipt()["import_contract"]

    assert "single SQLite transaction" in contract["transaction"]
    assert "rolls back" in contract["transaction"]
    assert "refuse execution" in contract["idempotence"]
    assert "never overwrite" in contract["idempotence"]
    assert contract["disposition_projection"]["insufficient_evidence"] == (
        "uncertain/no label"
    )


def test_receipt_freezes_expected_temporal_shortfall_without_status_change():
    payload = _receipt()
    expected = payload["expected_post_import"]
    shortfall = payload["gate_assessment"]["expected_shortfall"]
    excluded = payload["result_boundary"]["not_authorized"]

    assert expected["prospective_decided_labels"] == 27
    assert expected["prospective_positive"] == 6
    assert expected["prospective_negative"] == 21
    assert expected["prospective_evaluation_families"] == 5
    assert expected["prospective_prediction_waves"] == 2
    assert shortfall == {
        "decided_labels": 13,
        "evaluation_families": 3,
        "prediction_waves": 0,
        "both_classes": 0,
    }
    assert any("promote/close OPT-003" in item for item in excluded)


def test_receipt_allows_no_external_model_or_second_wave_activity():
    payload = _receipt()
    ceilings = payload["resource_ceilings"]
    excluded = payload["result_boundary"]["not_authorized"]

    assert ceilings["other_store_mutations"] == 0
    assert ceilings["network_reads"] == 0
    assert ceilings["network_uploads"] == 0
    assert ceilings["provider_calls"] == 0
    assert ceilings["provider_reported_tokens"] == 0
    assert ceilings["provider_cost_usd"] == 0
    assert ceilings["model_training_runs"] == 0
    assert ceilings["rescored_findings"] == 0
    assert any("second-wave acquisition" in item for item in excluded)

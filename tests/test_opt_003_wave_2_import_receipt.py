"""OPT-003 wave-two import is exact, atomic, and one-label-short gated."""

from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

from repoauditor.eval import temporal_review_import_two


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-003-wave-2-import-receipt-2026-08-12.json"
RESULT = ROOT / "docs/optimizations/opt-003-wave-2-review-result-2026-08-12.json"


def _receipt() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def test_receipt_freezes_exact_review_and_projection():
    payload = _receipt()
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert payload["review_result"]["sha256"] == hashlib.sha256(RESULT.read_bytes()).hexdigest()
    assert payload["review_result"]["responses"] == len(result["responses"]) == 18
    assert payload["review_result"]["decided"] == 12
    assert payload["review_result"]["abstentions"] == 6
    assert payload["import_contract"]["assessment_rows"] == 18
    assert payload["import_contract"]["manual_label_upserts"] == 12
    assert payload["import_contract"]["actionable_labels"] == 0


def test_importer_binds_result_store_predictions_and_non_actionable_projection():
    source = inspect.getsource(temporal_review_import_two)
    assert temporal_review_import_two.EXPECTED_RESULT_SHA256 == _receipt()["review_result"]["sha256"]
    assert len(temporal_review_import_two.EXPECTED_STORE_SHA256) == 64
    assert "triage_run_id IN (39,40,41)" in source
    assert "len(labels) != 12" in source
    assert "any(label.actionable for label in labels)" in source
    assert "import_triage_review_batch" in source


def test_receipt_freezes_one_label_shortfall_without_status_change():
    payload = _receipt()
    expected = payload["expected_post_import"]
    assert expected["prospective_decided_labels"] == 39
    assert expected["prospective_positive"] == 6
    assert expected["prospective_negative"] == 33
    assert expected["prospective_evaluation_families"] == 8
    assert expected["prospective_prediction_waves"] == 3
    assert payload["gate_assessment"]["expected_shortfall"] == {
        "decided_labels": 1,
        "evaluation_families": 0,
        "prediction_waves": 0,
        "both_classes": 0,
    }
    assert "merge the branch" in payload["result_boundary"]["not_authorized"]


def test_receipt_allows_no_external_model_or_status_activity():
    ceilings = _receipt()["resource_ceilings"]
    assert ceilings["other_store_mutations"] == 0
    assert ceilings["network_reads"] == 0
    assert ceilings["network_uploads"] == 0
    assert ceilings["provider_calls"] == 0
    assert ceilings["model_training_runs"] == 0
    assert ceilings["rescored_findings"] == 0

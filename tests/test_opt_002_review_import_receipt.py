"""OPT-002 review import is exact, atomic, abstention-safe, and promotion-gated."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-002-review-import-receipt-2026-08-10.json"
RESULT = ROOT / "docs/optimizations/opt-002-bounded-review-result-2026-08-10.json"


def _receipt() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def test_receipt_freezes_the_exact_review_result_and_projection():
    payload = _receipt()
    result = json.loads(RESULT.read_text(encoding="utf-8"))

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert payload["review_result"]["sha256"] == hashlib.sha256(
        RESULT.read_bytes()
    ).hexdigest()
    assert payload["review_result"]["responses"] == len(result["responses"]) == 12
    assert payload["review_result"]["decided"] == 11
    assert payload["review_result"]["abstentions"] == 1
    assert payload["import_contract"]["assessment_rows"] == 12
    assert payload["import_contract"]["manual_label_upserts"] == 11


def test_receipt_requires_atomic_non_overwriting_import():
    contract = _receipt()["import_contract"]

    assert "single SQLite transaction" in contract["transaction"]
    assert "rolls back" in contract["transaction"]
    assert "refuse execution" in contract["idempotence"]
    assert "never overwrite" in contract["idempotence"]
    assert contract["disposition_projection"]["insufficient_evidence"] == (
        "uncertain/no label"
    )


def test_receipt_freezes_expected_gate_without_authorizing_promotion():
    payload = _receipt()
    expected = payload["expected_post_import"]
    excluded = payload["result_boundary"]["not_authorized"]

    assert expected["compatible_scored_human_labels"] == 47
    assert expected["compatible_positive"] == 24
    assert expected["compatible_negative"] == 23
    assert expected["compatible_engagements"] == 9
    assert expected["both_classes_present"] is True
    assert any("promote/close OPT-002" in item for item in excluded)
    assert any("production policy" in item for item in excluded)


def test_receipt_allows_no_external_or_model_activity():
    ceilings = _receipt()["resource_ceilings"]

    assert ceilings["other_store_mutations"] == 0
    assert ceilings["network_reads"] == 0
    assert ceilings["network_uploads"] == 0
    assert ceilings["provider_calls"] == 0
    assert ceilings["provider_reported_tokens"] == 0
    assert ceilings["provider_cost_usd"] == 0
    assert ceilings["model_training_runs"] == 0
    assert ceilings["rescored_findings"] == 0

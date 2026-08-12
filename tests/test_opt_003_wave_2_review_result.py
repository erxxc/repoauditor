"""OPT-003 wave-two review preserves explicit outcomes and the final shortfall."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-003-wave-2-review-result-2026-08-12.json"


def test_result_binds_receipt_and_response_evidence():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    base = ROOT / "docs/optimizations"
    response = ROOT / payload["response_evidence"]["path"]
    assert hashlib.sha256((base / payload["receipt"]["path"]).read_bytes()).hexdigest() == payload["receipt"]["sha256"]
    assert hashlib.sha256(response.read_bytes()).hexdigest() == payload["response_evidence"]["sha256"]


def test_result_covers_eighteen_unique_responses_and_projection_counts():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    responses = payload["responses"]
    assert len(responses) == len({row["finding_id"] for row in responses}) == 18
    assert all(row["rationale"].strip() for row in responses)
    assert Counter(row["binary_projection"] for row in responses) == Counter({False: 12, "abstain": 6})
    assert payload["validation"]["decided"] == 12
    assert payload["validation"]["binary_actionable"] == 0
    assert payload["validation"]["binary_non_actionable"] == 12


def test_result_preserves_store_and_retains_one_label_shortfall():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    accounting = payload["accounting"]
    assert accounting["store_byte_identical"] is True
    assert accounting["store_mutations"] == 0
    assert accounting["labels_written"] == 0
    assert all(payload["not_executed"].values())
    projected = payload["disposition"]["prospective_after_import"]
    assert projected["decided_labels"] == 39
    assert projected["evaluation_families"] == 8
    assert projected["prediction_waves"] == 3
    assert projected["both_classes_present"] is True
    shortfall = payload["disposition"]["remaining_activation_shortfall_after_import"]
    assert shortfall == {
        "decided_labels": 1,
        "evaluation_families": 0,
        "prediction_waves": 0,
        "both_classes": 0,
    }

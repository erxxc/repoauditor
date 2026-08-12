"""OPT-003 wave review result preserves explicit outcomes and temporal shortfall."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-003-wave-1-review-result-2026-08-11.json"


def test_result_covers_eighteen_unique_responses_and_counts_projection():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    responses = payload["responses"]
    assert len(responses) == len({row["finding_id"] for row in responses}) == 18
    assert all(row["rationale"].strip() for row in responses)
    assert Counter(row["binary_projection"] for row in responses) == Counter({False: 15, "abstain": 2, True: 1})
    assert payload["validation"]["decided"] == 16
    assert payload["validation"]["both_classes_present"] is True


def test_result_preserves_store_and_keeps_import_and_second_wave_gated():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    accounting = payload["accounting"]
    assert accounting["store_byte_identical"] is True
    assert accounting["store_mutations"] == 0
    assert accounting["labels_written"] == 0
    assert all(payload["not_executed"].values())
    shortfall = payload["disposition"]["remaining_activation_shortfall_after_import"]
    assert shortfall["decided_labels"] == 13
    assert shortfall["evaluation_families"] == 3

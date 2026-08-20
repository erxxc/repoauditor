"""OPT-003 wave one freezes training before outcome-blind acquisition and scoring."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-003-wave-1-prediction-receipt-2026-08-10.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def test_receipt_freezes_three_new_exact_commit_families():
    payload = _payload()
    sources = payload["frozen_sources"]
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert len(sources) == 3
    assert len({item["evaluation_family"] for item in sources}) == 3
    assert all(len(item["commit"]) == 40 for item in sources)
    assert all(item["selection_basis"] for item in sources)


def test_training_is_digest_frozen_before_any_source_or_score():
    payload = _payload()
    cutoff = payload["training_cutoff"]
    sequence = payload["execution_sequence"]
    assert cutoff["effective_family_distinct_labels"] == 122
    assert len(cutoff["effective_label_identity_sha256"]) == 64
    assert "before materializing any source" in sequence[1]
    assert sequence.index(next(x for x in sequence if "Train and persist" in x)) < sequence.index(next(x for x in sequence if "Resolve each remote" in x))


def test_receipt_stops_before_outcomes_and_allows_no_provider():
    payload = _payload()
    ceilings = payload["resource_ceilings"]
    excluded = payload["result_boundary"]["not_authorized"]
    assert ceilings["provider_calls"] == 0
    assert ceilings["human_reviews"] == 0
    assert ceilings["assessments_written"] == 0
    assert ceilings["labels_written"] == 0
    assert "packet selection" in excluded
    assert "human review" in excluded
    assert "assessment or label import" in excluded

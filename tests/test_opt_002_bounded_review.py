"""OPT-002 review rendering is bounded, score-blind, and non-mutating."""

from __future__ import annotations

import json
import inspect
from pathlib import Path

import pytest

from repoauditor.eval.independent_review import (
    ALLOWED_DISPOSITIONS,
    _stored_rows,
    render_review,
)


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-002-bounded-review-receipt-2026-08-08.json"


def _receipt() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def test_receipt_freezes_twelve_entries_and_explicit_abstention():
    payload = _receipt()

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert payload["review_plan"]["entries"] == 12
    assert payload["review_plan"]["documenso"] == 6
    assert payload["review_plan"]["lobsters"] == 6
    assert payload["review_contract"]["abstentions_preserved"] is True
    assert "insufficient_evidence" in ALLOWED_DISPOSITIONS


def test_review_allows_no_provider_store_or_label_activity():
    ceilings = _receipt()["resource_ceilings"]

    assert ceilings["render_runs"] == 1
    assert ceilings["network_reads"] == 0
    assert ceilings["network_uploads"] == 0
    assert ceilings["provider_calls"] == 0
    assert ceilings["provider_reported_tokens"] == 0
    assert ceilings["provider_cost_usd"] == 0
    assert ceilings["store_mutations"] == 0
    assert ceilings["classifier_labels_written"] == 0


def test_renderer_rejects_excess_context_before_reading_plan(tmp_path):
    with pytest.raises(ValueError, match="between 0 and 20"):
        render_review(tmp_path / "missing.json", context_lines=21)


def test_renderer_source_has_no_forbidden_store_columns():
    source = inspect.getsource(_stored_rows)
    query = source.split("rows = conn.execute(", 1)[1].split(").fetchall()", 1)[0]

    for forbidden in (
        "p_actionable", "rank", "suppressed", "severity", "confidence", "prior",
        "outcome",
    ):
        assert forbidden not in query

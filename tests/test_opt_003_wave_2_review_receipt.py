"""OPT-003 wave-two review is bounded, score-blind, and abstention-safe."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from repoauditor.eval.temporal_review_two import _stored_rows, render_review


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-003-wave-2-review-receipt-2026-08-11.json"


def test_receipt_freezes_eighteen_entries_and_abstention():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert payload["review_plan"]["entries"] == 18
    assert payload["review_plan"]["per_family"] == 6
    assert payload["review_contract"]["abstentions_preserved"] is True
    assert "insufficient_evidence" in payload["review_contract"]["allowed_dispositions"]


def test_renderer_rejects_excess_context_before_plan_read(tmp_path):
    with pytest.raises(ValueError, match="between 0 and 20"):
        render_review(tmp_path / "missing.json", context_lines=21)


def test_renderer_store_query_contains_no_forbidden_columns():
    source = inspect.getsource(_stored_rows)
    query = source.split("rows = conn.execute(", 1)[1].split(").fetchall()", 1)[0]
    for forbidden in (
        "p_actionable", "rank", "suppressed", "severity", "confidence", "outcome"
    ):
        assert forbidden not in query


def test_receipt_allows_no_external_or_store_activity():
    ceilings = json.loads(RECEIPT.read_text(encoding="utf-8"))["resource_ceilings"]
    assert ceilings["render_runs"] == 1
    assert ceilings["network_reads"] == 0
    assert ceilings["provider_calls"] == 0
    assert ceilings["store_mutations"] == 0
    assert ceilings["classifier_labels_written"] == 0

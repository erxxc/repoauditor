"""OPT-002 packet selection is outcome-blind and review-gated."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = (
    ROOT / "docs/optimizations/opt-002-packet-selection-receipt-2026-08-07.json"
)


def _receipt() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def test_receipt_freezes_balanced_twelve_entry_packet():
    payload = _receipt()
    contract = payload["selection_contract"]

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert payload["primary_result"]["eligible_primary_count"] == 218
    assert [source["eligible_count"] for source in payload["activated_families"]] == [
        53,
        165,
    ]
    assert contract["packet_size"] == 12
    assert contract["maximum_per_family"] == 6
    assert "p_actionable" in contract["forbidden_read_or_selection_fields"]
    assert "rank" in contract["forbidden_read_or_selection_fields"]


def test_output_excludes_scores_outcomes_and_source_context():
    output = _receipt()["output_contract"]

    assert "p_actionable" in output["forbidden_output_fields"]
    assert "expected_outcome" in output["forbidden_output_fields"]
    assert "source_evidence" in output["forbidden_output_fields"]
    assert output["render_review_packet"] is False
    assert output["render_source_context"] is False
    assert output["overwrite"] is False


def test_selection_allows_no_external_or_mutating_activity():
    payload = _receipt()
    ceilings = payload["resource_ceilings"]

    assert ceilings["selection_runs"] == 1
    assert ceilings["network_reads"] == 0
    assert ceilings["network_uploads"] == 0
    assert ceilings["provider_calls"] == 0
    assert ceilings["provider_reported_tokens"] == 0
    assert ceilings["provider_cost_usd"] == 0
    assert ceilings["store_mutations"] == 0
    assert "human review" in payload["scope"]
    assert "excluded" in payload["scope"]

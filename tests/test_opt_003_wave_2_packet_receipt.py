"""OPT-003 wave-two packet selection is balanced and outcome-blind."""

from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

from repoauditor.eval import temporal_packet_two


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-003-wave-2-packet-receipt-2026-08-11.json"


def test_receipt_binds_prediction_result_and_balanced_inventory():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    result = ROOT / "docs/optimizations" / payload["prediction_result"]["path"]
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert hashlib.sha256(result.read_bytes()).hexdigest() == payload["prediction_result"]["sha256"]
    assert payload["inventory"]["total"] == 249
    assert payload["selection"]["packet_size"] == 18
    assert payload["selection"]["per_family"] == 6
    assert payload["resource_ceilings"]["store_mutations"] == 0
    assert payload["resource_ceilings"]["human_reviews"] == 0


def test_selector_query_never_reads_scores_or_outcomes():
    source = inspect.getsource(temporal_packet_two.build_plan)
    query = source.split("rows = conn.execute(", 1)[1].split(").fetchall()", 1)[0]
    for forbidden in (
        "p_actionable", "rank", "suppressed", "severity", "confidence", "outcome"
    ):
        assert forbidden not in query
    assert "triage_run_id" in query
    assert "NOT EXISTS" in query


def test_selector_freezes_three_six_entry_queues():
    assert len(temporal_packet_two.SOURCES) == 3
    assert {source["eligible"] for source in temporal_packet_two.SOURCES.values()} == {51, 60, 138}
    assert all(source["eligible"] >= 6 for source in temporal_packet_two.SOURCES.values())
    assert len(temporal_packet_two.EXPECTED_INVENTORY_SHA256) == 64

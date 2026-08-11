"""OPT-003 packet result proves balanced selection without outcomes or mutation."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-003-wave-1-packet-result-2026-08-11.json"


def test_result_records_balanced_unique_packet():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    selection = payload["selection"]
    assert payload["status"] == "completed-outcome-blind-packet-selection"
    assert selection["selection_runs"] == 1
    assert selection["packet_size"] == 18
    assert selection["unique_finding_ids"] == 18
    assert selection["unique_selection_keys"] == 18
    assert [selection[name] for name in ("chatwoot", "linkwarden", "paperless_ngx")] == [6, 6, 6]
    assert selection["forbidden_fields_present"] == []


def test_result_is_offline_non_mutating_and_non_reviewing():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    accounting = payload["accounting"]
    assert accounting["store_byte_identical"] is True
    assert accounting["network_reads"] == 0
    assert accounting["provider_calls"] == 0
    assert accounting["store_mutations"] == 0
    assert accounting["human_reviews"] == 0
    assert accounting["labels_written"] == 0
    assert accounting["ceiling_breaches"] == []
    assert all(payload["not_executed"].values())

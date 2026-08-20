"""OPT-003 wave-two packet result proves balanced, outcome-blind selection."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-003-wave-2-packet-result-2026-08-11.json"


def test_result_binds_receipt_and_balanced_unique_selection():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    receipt = ROOT / "docs/optimizations" / payload["receipt"]["path"]
    selection = payload["selection"]
    assert payload["status"] == "completed-outcome-blind-packet-selection"
    assert hashlib.sha256(receipt.read_bytes()).hexdigest() == payload["receipt"]["sha256"]
    assert selection["selection_runs"] == 1
    assert selection["packet_size"] == 18
    assert selection["unique_finding_ids"] == 18
    assert selection["unique_selection_keys"] == 18
    assert selection["actual"] == selection["memos"] == selection["authentik"] == 6
    assert selection["forbidden_fields_present"] == []


def test_result_preserves_store_provider_review_and_status_boundaries():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    accounting = payload["accounting"]
    assert payload["preconditions"]["initial_store_sha256"] == accounting["final_store_sha256"]
    assert accounting["store_byte_identical"] is True
    assert accounting["network_reads"] == 0
    assert accounting["provider_calls"] == 0
    assert accounting["store_mutations"] == 0
    assert accounting["source_lines_rendered"] == 0
    assert accounting["human_reviews"] == 0
    assert accounting["assessments_written"] == 0
    assert accounting["labels_written"] == 0
    assert accounting["ceiling_breaches"] == []
    assert all(payload["not_executed"].values())
    assert payload["disposition"]["opt_003_status"] == "open-wave-two-review-gated"

"""OPT-003 final closure retry adds exactly one assertion correction."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-003-closure-merge-final-retry-receipt-2026-08-12.json"


def test_final_retry_binds_prior_receipt_and_attempt():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    for key in ("prior_corrected_receipt", "second_stopped_attempt"):
        record = payload[key]
        path = ROOT / "docs/optimizations" / record["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]


def test_final_retry_allows_only_one_new_line_and_no_external_action():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    change = payload["only_new_change"]
    assert change["old_assertion"].endswith("is not None")
    assert change["new_assertion"].endswith("is None")
    assert change["historical_evidence_edited"] is False
    assert payload["retained_contract"]["remote_push"] is False
    assert payload["resource_ceilings"]["network_reads"] == 0
    assert payload["resource_ceilings"]["store_mutations"] == 0

"""OPT-003 corrected closure retry permits only three stale-test reconciliations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-003-closure-merge-corrected-receipt-2026-08-12.json"


def test_corrected_closure_receipt_binds_original_and_stopped_attempt():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    for key in ("original_receipt", "stopped_attempt"):
        record = payload[key]
        path = ROOT / "docs/optimizations" / record["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]


def test_corrected_closure_receipt_extends_only_three_tests():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    paths = [item["path"].removeprefix("../../") for item in payload["allowed_test_reconciliations"]]
    assert paths == payload["commit_allowlist_extension"]
    assert paths == [
        "tests/test_documentation_current_state.py",
        "tests/test_opt005_lightweight_completion_receipt.py",
        "tests/test_optimization_status.py",
    ]
    assert payload["retained_closure_contract"]["remote_push"] is False
    assert payload["resource_ceilings"]["network_reads"] == 0
    assert payload["resource_ceilings"]["store_mutations"] == 0

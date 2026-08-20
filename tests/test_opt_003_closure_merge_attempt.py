"""OPT-003 first closure attempt stopped before any commit or merge."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ATTEMPT = ROOT / "docs/optimizations/opt-003-closure-merge-attempt-2026-08-12.json"


def test_closure_attempt_records_exact_validation_stop():
    payload = json.loads(ATTEMPT.read_text(encoding="utf-8"))
    receipt = ROOT / "docs/optimizations" / payload["receipt"]["path"]
    assert payload["status"] == "stopped-before-commit-and-merge"
    assert hashlib.sha256(receipt.read_bytes()).hexdigest() == payload["receipt"]["sha256"]
    assert payload["stop"]["failed_tests"] == 3
    assert payload["stop"]["passed_tests"] == 781
    assert len(payload["stop"]["failures"]) == 3


def test_closure_attempt_preserves_branch_store_and_open_status():
    payload = json.loads(ATTEMPT.read_text(encoding="utf-8"))
    assert payload["accounting"]["branch_commits"] == 0
    assert payload["accounting"]["merge_commits"] == 0
    assert payload["accounting"]["store_byte_identical"] is True
    assert payload["restored_state"]["opt_003_status"] == "open"
    assert payload["restored_state"]["head_unchanged"] is True
    assert payload["restored_state"]["local_main_unchanged"] is True

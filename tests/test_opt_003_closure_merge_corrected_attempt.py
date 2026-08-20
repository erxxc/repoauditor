"""OPT-003 corrected closure attempt stopped on one inverted assertion."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ATTEMPT = ROOT / "docs/optimizations/opt-003-closure-merge-corrected-attempt-2026-08-12.json"


def test_corrected_attempt_binds_receipt_and_exact_residual_failure():
    payload = json.loads(ATTEMPT.read_text(encoding="utf-8"))
    receipt = ROOT / "docs/optimizations" / payload["receipt"]["path"]
    assert hashlib.sha256(receipt.read_bytes()).hexdigest() == payload["receipt"]["sha256"]
    assert payload["status"] == "stopped-before-commit-and-merge"
    assert payload["stop"]["passed_tests"] == 787
    assert payload["stop"]["failed_tests"] == 1
    assert payload["stop"]["failure"]["required_correction"] == (
        "Change only the assertion from is not None to is None; do not edit the historical snapshot."
    )


def test_corrected_attempt_kept_store_branch_and_main_unchanged():
    payload = json.loads(ATTEMPT.read_text(encoding="utf-8"))
    assert payload["accounting"]["store_byte_identical"] is True
    assert payload["accounting"]["branch_commits"] == 0
    assert payload["accounting"]["merge_commits"] == 0
    assert payload["restored_state"]["opt_003_status"] == "open"

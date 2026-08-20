"""OPT-003 first final-label follow-up stopped safely at its frozen ceiling."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ATTEMPT = ROOT / "docs/optimizations/opt-003-final-label-followup-attempt-2026-08-12.json"


def test_attempt_records_fail_closed_without_evidence_or_store_change():
    payload = json.loads(ATTEMPT.read_text(encoding="utf-8"))
    receipt = ROOT / "docs/optimizations" / payload["receipt"]["path"]
    assert payload["status"] == "stopped-before-evidence-output"
    assert hashlib.sha256(receipt.read_bytes()).hexdigest() == payload["receipt"]["sha256"]
    assert payload["stop"]["passed"] is False
    assert payload["accounting"]["evidence_output_created"] is False
    assert payload["accounting"]["store_byte_identical"] is True
    assert payload["accounting"]["store_mutations"] == 0
    assert payload["accounting"]["network_reads"] == 0
    assert payload["accounting"]["provider_calls"] == 0


def test_attempt_preserves_excluded_actions():
    payload = json.loads(ATTEMPT.read_text(encoding="utf-8"))
    assert all(payload["not_executed"].values())
    assert payload["disposition"]["opt_003_status"] == "open-one-prospective-label-gated"

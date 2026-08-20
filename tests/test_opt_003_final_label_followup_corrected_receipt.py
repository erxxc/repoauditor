"""OPT-003 corrected final-label follow-up remains narrowly bounded."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-003-final-label-followup-corrected-receipt-2026-08-12.json"


def test_corrected_receipt_binds_prior_attempt_and_helper():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    prior = ROOT / "docs/optimizations" / payload["prior_attempt"]["path"]
    helper = (RECEIPT.parent / payload["renderer"]["path"]).resolve()
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert hashlib.sha256(prior.read_bytes()).hexdigest() == payload["prior_attempt"]["sha256"]
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == payload["renderer"]["sha256"]


def test_corrected_receipt_freezes_deterministic_truncation_and_limits():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    boundary = payload["evidence_boundary"]
    assert boundary["exact_symbol"] == "requireFileOwner"
    assert boundary["maximum_rendered_matches"] == 4
    assert boundary["maximum_rendered_files"] == 2
    assert boundary["context_lines_before"] == boundary["context_lines_after"] == 20
    ceilings = payload["resource_ceilings"]
    assert ceilings["render_runs"] == 1
    assert ceilings["network_reads"] == 0
    assert ceilings["provider_calls"] == 0
    assert ceilings["store_mutations"] == 0
    assert ceilings["assessments_written"] == ceilings["labels_written"] == 0

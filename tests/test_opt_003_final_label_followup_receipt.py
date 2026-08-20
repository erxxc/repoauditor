"""OPT-003 final-label follow-up is one-abstention, exact-symbol bounded."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-003-final-label-followup-receipt-2026-08-12.json"


def test_receipt_binds_import_result_and_one_abstention():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    result = ROOT / "docs/optimizations" / payload["import_result"]["path"]
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert hashlib.sha256(result.read_bytes()).hexdigest() == payload["import_result"]["sha256"]
    assert payload["import_result"]["prospective_decided_labels"] == 39
    assert payload["import_result"]["remaining_decided_label_shortfall"] == 1
    assert payload["selected_abstention"]["finding_id"] == 2036
    assert payload["selected_abstention"]["assessment_id"] == 159
    assert payload["selected_abstention"]["original_disposition"] == "insufficient_evidence"


def test_receipt_freezes_exact_symbol_and_render_limits():
    boundary = json.loads(RECEIPT.read_text(encoding="utf-8"))["evidence_boundary"]
    assert boundary["exact_symbol"] == "requireFileOwner"
    assert boundary["maximum_matched_files"] == 10
    assert boundary["maximum_rendered_files"] == 2
    assert boundary["maximum_rendered_matches"] == 4
    assert boundary["context_lines_before"] == 20
    assert boundary["context_lines_after"] == 20


def test_receipt_allows_no_external_or_store_activity():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    ceilings = payload["resource_ceilings"]
    assert ceilings["render_runs"] == 1
    assert ceilings["review_entries"] == 1
    assert ceilings["network_reads"] == 0
    assert ceilings["provider_calls"] == 0
    assert ceilings["store_mutations"] == 0
    assert ceilings["assessments_written"] == 0
    assert ceilings["labels_written"] == 0
    assert "branch merge" in payload["authorization"]["required_statement"]

"""OPT-003 closure and local integration remain exact and separately authorized."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-003-closure-merge-receipt-2026-08-12.json"


def test_closure_receipt_binds_completed_temporal_result():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    result = ROOT / "docs/optimizations" / payload["temporal_result"]["path"]
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert hashlib.sha256(result.read_bytes()).hexdigest() == payload["temporal_result"]["sha256"]
    assert payload["temporal_result"]["bounded_objective_complete"] is True
    assert payload["temporal_result"]["decided_labels"] == 40
    assert payload["temporal_result"]["evaluation_families"] == 8
    assert payload["temporal_result"]["prediction_waves"] == 3
    assert payload["temporal_result"]["threshold_selected_or_recommended"] is False


def test_closure_receipt_limits_status_commit_and_merge():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    status = payload["authorized_document_changes"]["optimization_status"]
    assert status["summary"] == {"closed": 32, "open": 3, "total": 35}
    assert status["remaining_priority_order"] == ["OPT-009", "OPT-014", "OPT-010"]
    contract = payload["commit_and_merge_contract"]
    assert contract["branch_commits"] == 1
    assert contract["target_branch"] == "main"
    assert contract["remote_push"] is False
    assert contract["branch_deletion"] is False
    ceilings = payload["resource_ceilings"]
    assert ceilings["network_reads"] == ceilings["remote_pushes"] == 0
    assert ceilings["store_mutations"] == 0

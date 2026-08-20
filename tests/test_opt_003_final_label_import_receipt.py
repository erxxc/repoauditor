"""OPT-003 final-label import is atomic, minimal, and separately gated."""

from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

from repoauditor.eval import temporal_followup_import


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-003-final-label-import-receipt-2026-08-12.json"


def test_import_receipt_binds_result_store_and_helper():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    result = ROOT / "docs/optimizations" / payload["followup_result"]["path"]
    helper = (RECEIPT.parent / payload["importer"]["path"]).resolve()
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert hashlib.sha256(result.read_bytes()).hexdigest() == payload["followup_result"]["sha256"]
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == payload["importer"]["sha256"]
    assert temporal_followup_import.EXPECTED_RESULT_SHA256 == payload["followup_result"]["sha256"]
    assert temporal_followup_import.EXPECTED_STORE_SHA256 == payload["store_precondition"]["sha256"]


def test_import_receipt_allows_exactly_one_append_only_pair():
    payload = json.loads(RECEIPT.read_text(encoding="utf-8"))
    contract = payload["atomic_mutation_contract"]
    assert contract["triage_assessment_inserts"] == 1
    assert contract["triage_label_inserts"] == 1
    assert contract["triage_assessment_updates"] == 0
    assert contract["triage_label_updates"] == 0
    assert contract["other_store_mutations"] == 0
    assert contract["prior_abstention_preserved"] is True
    assert contract["new_label"]["actionable"] is False


def test_import_helper_has_one_transaction_and_no_model_path():
    source = inspect.getsource(temporal_followup_import.import_followup)
    assert "with conn:" in source
    assert source.count("INSERT INTO triage_assessment") == 1
    assert source.count("INSERT INTO triage_label") == 1
    assert "UPDATE " not in source
    assert "DELETE " not in source
    assert "provider" not in source
    assert "train" not in source

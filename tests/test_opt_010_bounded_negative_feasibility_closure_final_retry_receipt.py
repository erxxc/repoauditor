from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-bounded-negative-feasibility-closure-final-retry-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_final_receipt_binds_immutable_prior_receipts_and_retained_twelve():
    payload = _payload()
    for name in ("original_receipt", "corrected_retry_receipt"):
        record = payload["retained_authority"][name]
        assert _sha256(ROOT / record["path"]) == record["sha256"]
    assert len(payload["retained_twelve_reconciliations"]) == 12
    for record in payload["retained_twelve_reconciliations"]:
        assert _sha256(ROOT / record["path"]) == record["sha256"]


def test_mutable_pre_retry_hashes_are_explicit_historical_records():
    authority = _payload()["retained_authority"]
    assert authority["stopped_result"]["sha256"] == "346db5007ef56b0858c37bce99ada1bf0b1709126a173d8d9fc6d1c78552e368"
    assert authority["stopped_closure_test"]["sha256"] == "cd35b3dd960b36833aa82b850bd7fd7314d5381430b93556919730c7de3d324e"
    assert authority["corrected_retry_receipt_test_before_reconciliation"]["sha256"] == "e2cfc242087ae2f9ddd47c466edd53c584e35f1ac5cc48806c5d02119edf81c5"


def test_only_one_additional_test_reconciliation_is_permitted():
    payload = _payload()
    correction = payload["only_additional_reconciliation"]
    assert payload["allowlist_addition"] == [correction["path"]]
    assert correction["receipt_or_evidence_edits"] == 0
    assert correction["implementation_or_helper_edits"] == 0
    assert "immutable historical receipt evidence" in correction["permitted_change"]


def test_final_retry_remains_zero_activity_and_bounded():
    payload = _payload()
    ceilings = payload["cumulative_resource_ceilings"]
    assert payload["execution"]["lifecycle_after"] == {
        "closed": 35, "open": 0, "total": 35, "remaining_priority": []
    }
    assert payload["execution"]["facade_after"] == "qualified-disabled-and-disconnected"
    assert all(
        value == 0 or value == 0.0
        for key, value in ceilings.items()
        if key not in {"maximum_elapsed_minutes", "maximum_new_data_bytes"}
    )


def test_final_receipt_is_pending_and_requires_exact_authorization():
    payload = _payload()
    statement = payload["authorization"]["required_statement"]
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert "only reconciliation of tests/test_opt_010_bounded_negative_feasibility_closure_corrected_retry_receipt.py" in statement
    assert "twelve completed historical-state reconciliations with 66 focused passes" in statement
    assert "35 closed and zero open" in statement

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-bounded-negative-feasibility-closure-corrected-retry-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_corrected_receipt_preserves_original_authority_and_mutable_outputs_as_history():
    payload = _payload()
    authority = payload["original_authority"]
    original = authority["receipt"]
    assert _sha256(ROOT / original["path"]) == original["sha256"]
    assert authority["stopped_result"]["sha256"] == "346db5007ef56b0858c37bce99ada1bf0b1709126a173d8d9fc6d1c78552e368"
    assert authority["focused_closure_test"]["sha256"] == "cd35b3dd960b36833aa82b850bd7fd7314d5381430b93556919730c7de3d324e"
    assert len(_sha256(ROOT / authority["stopped_result"]["path"])) == 64
    assert len(_sha256(ROOT / authority["focused_closure_test"]["path"])) == 64
    assert payload["retained_stopped_attempt"]["full_offline_non_live_suite"] == {
        "passed": 1204,
        "failed": 17,
        "skipped": 2,
        "deselected": 27,
        "command": ".venv/bin/python -m pytest -q -m 'not live'",
    }
    assert payload["retained_stopped_attempt"]["restored_lifecycle"]["summary"] == {
        "closed": 34,
        "open": 1,
        "total": 35,
    }


def test_seven_retained_reconciliations_are_bound_and_twelve_pre_hashes_are_historical():
    payload = _payload()
    assert len(payload["retained_authorized_reconciliations"]) == 7
    assert len(payload["additional_historical_test_reconciliation"]) == 12
    for record in payload["retained_authorized_reconciliations"].values():
        assert _sha256(ROOT / record["path"]) == record["sha256"]
    for record in payload["additional_historical_test_reconciliation"]:
        assert len(record["sha256"]) == 64
        assert len(_sha256(ROOT / record["path"])) == 64
        assert isinstance(record["rule"], str) and len(record["rule"]) > 40


def test_retry_keeps_exact_bounded_closure_and_zero_activity_contract():
    payload = _payload()
    retry = payload["closure_retry"]
    ceilings = payload["cumulative_resource_ceilings"]

    assert retry["lifecycle_after"] == {
        "closed": 35,
        "open": 0,
        "total": 35,
        "remaining_priority": [],
    }
    assert retry["facade_after"] == "qualified-disabled-and-disconnected"
    assert "universal impossibility" in retry["interpretation"]
    assert ceilings["maximum_elapsed_minutes"] == 45
    assert ceilings["maximum_new_data_bytes"] == 2 * 1024**2
    assert all(
        value == 0 or value == 0.0
        for key, value in ceilings.items()
        if key not in {"maximum_elapsed_minutes", "maximum_new_data_bytes"}
    )


def test_allowlist_is_original_scope_plus_exact_twelve_tests():
    payload = _payload()
    allowlist = payload["allowlist"]
    additional = {
        record["path"] for record in payload["additional_historical_test_reconciliation"]
    }

    assert additional <= set(allowlist)
    assert len(additional) == 12
    assert not any(path.endswith((".db", "config.toml", "config.py")) for path in allowlist)
    assert not any("src/repoauditor" in path for path in allowlist)


def test_receipt_is_pending_and_requires_exact_new_authorization():
    payload = _payload()
    statement = payload["authorization"]["required_statement"]

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert "twelve named historical-state test reconciliations" in statement
    assert "1,204 passed, 17 failed" in statement
    assert "35 closed and zero open" in statement
    assert "Any evidence, receipt, artifact, helper" in statement

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-009-closure-result-2026-08-18.json"
LEDGER = ROOT / "docs/optimizations/optimization-status.json"


def _payload() -> dict:
    return json.loads(RESULT.read_text(encoding="utf-8"))


def _assert_bound(record: dict) -> None:
    path = (RESULT.parent / record["path"]).resolve()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]


def test_opt009_closure_result_binds_authorization_attempt_and_terminal_evidence():
    payload = _payload()

    _assert_bound(payload["execution_receipt"])
    _assert_bound(payload["stopped_attempt"])
    for record in payload["terminal_evidence"].values():
        _assert_bound(record)


def test_opt009_closure_result_matches_canonical_lifecycle():
    payload = _payload()
    ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
    open_items = sorted(
        (item for item in ledger["items"] if item["status"] == "open"),
        key=lambda item: item["next_priority"],
    )
    opt009 = next(item for item in ledger["items"] if item["id"] == "OPT-009")

    assert ledger["summary"] == payload["lifecycle"]["summary"]
    assert opt009 == {
        "id": "OPT-009",
        "title": "Novelty prioritization",
        "status": "closed",
        "gate": "none",
        "next_priority": None,
    }
    assert [item["id"] for item in open_items] == ["OPT-014", "OPT-010"]


def test_opt009_closure_result_preserves_checkpoint_and_store():
    payload = _payload()
    checkpoint = payload["historical_checkpoint"]
    store = payload["store"]

    _assert_bound(checkpoint)
    assert checkpoint["byte_identical"] is True
    assert checkpoint["recorded_summary"] == {"closed": 32, "open": 3, "total": 35}
    assert hashlib.sha256((ROOT / "data/repoauditor.db").read_bytes()).hexdigest() == store[
        "final_sha256"
    ]
    assert store["initial_sha256"] == store["final_sha256"]
    assert store["byte_identical"] is True


def test_opt009_closure_result_is_bounded_and_has_zero_live_activity():
    payload = _payload()
    interpretation = payload["terminal_interpretation"]
    accounting = payload["accounting"]

    assert interpretation["universal_impossibility_claim"] is False
    assert "new lifecycle identity" in interpretation["future_work_boundary"]
    assert payload["validation"]["passed"] is True
    assert payload["validation"]["failed_tests"] == 0
    assert accounting["network_reads"] == accounting["network_uploads"] == 0
    assert accounting["provider_calls"] == accounting["provider_reported_tokens"] == 0
    assert accounting["production_store_mutations"] == 0
    assert accounting["assessments_written"] == accounting["labels_written"] == 0
    assert accounting["rescored_findings"] == accounting["model_training_runs"] == 0

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-bounded-negative-feasibility-closure-receipt-2026-08-20.json"
RESULT = ROOT / "docs/optimizations/opt-010-bounded-negative-feasibility-closure-result-2026-08-20.json"
LEDGER = ROOT / "docs/optimizations/optimization-status.json"


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_opt010_remains_closed_while_current_lifecycle_advances_independently():
    ledger = _json(LEDGER)
    opt010 = next(item for item in ledger["items"] if item["id"] == "OPT-010")

    assert ledger["summary"] == {"closed": 38, "open": 0, "total": 38}
    assert [item["id"] for item in ledger["items"] if item["status"] == "open"] == []
    assert opt010 == {
        "id": "OPT-010",
        "title": "Agentic falsification",
        "status": "closed",
        "gate": "none",
        "next_priority": None,
    }


def test_closure_is_bounded_and_does_not_claim_readiness_or_impossibility():
    result = _json(RESULT)
    interpretation = result["interpretation"]

    assert result["status"] == "closed-not-justified-and-not-feasible-at-evaluated-scope"
    assert interpretation["requested_closure_not_finalized"] is False
    assert result["lifecycle"]["restored_after_stop"] is False
    assert len(interpretation["claims_not_made"]) == 4
    assert any("universally impossible" in claim for claim in interpretation["claims_not_made"])
    assert any("production activation" in claim for claim in interpretation["claims_not_made"])
    assert result["preservation"]["read_only_facade"] == "qualified-disabled-and-disconnected"
    assert "new lifecycle identity" in interpretation["future_work_rule"]


def test_named_lifecycle_outputs_are_digest_bound():
    result = _json(RESULT)
    for binding in result["output_bindings"].values():
        assert len(binding["sha256"]) == 64
        assert (ROOT / binding["path"]).is_file()


def test_frozen_evidence_and_historical_checkpoint_remain_immutable():
    receipt = _json(RECEIPT)
    result = _json(RESULT)

    for binding in receipt["frozen_evidence"].values():
        assert _sha256(ROOT / binding["path"]) == binding["sha256"]
    checkpoint = receipt["frozen_current_state"]["historical_checkpoint"]
    assert _sha256(ROOT / checkpoint["path"]) == checkpoint["sha256"]
    assert result["preservation"]["historical_checkpoint_sha256"] == checkpoint["sha256"]
    assert result["preservation"]["production_store_sha256_before"] == result["preservation"]["production_store_sha256_after"]


def test_closure_records_zero_live_mutating_or_integration_activity():
    result = _json(RESULT)
    receipt = _json(RECEIPT)

    expected = {
        key: value
        for key, value in receipt["resource_ceilings"].items()
        if key not in {"maximum_elapsed_minutes", "maximum_new_data_bytes"}
    }
    assert result["activity"] == expected
    assert all(value == 0 or value == 0.0 for value in result["activity"].values())
    assert result["integration"] == "deferred-and-not-authorized"

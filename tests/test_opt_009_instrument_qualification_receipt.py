from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-009-instrument-qualification-receipt-2026-08-13.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assert_bound(record: dict) -> None:
    assert _sha256((RECEIPT.parent / record["path"]).resolve()) == record["sha256"]


def test_instrument_qualification_receipt_binds_retained_and_frozen_inputs():
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    for record in payload["retained_evidence"].values():
        _assert_bound(record)
    for key in ("owasp_prompt", "prompt_security", "ensemble", "planner", "source_bounds"):
        _assert_bound(payload["frozen_instrument"][key])
    benchmark = payload["semantic_canary"]["benchmark"]
    for key in ("ground_truth", "positive", "negative"):
        _assert_bound(benchmark[key])
    _assert_bound(payload["pricing"])


def test_offline_gate_precedes_the_two_case_provider_canary():
    payload = _payload()

    assert payload["offline_audit"]["network_reads"] == 0
    assert payload["offline_audit"]["production_store_mode"] == "read-only"
    assert "Otherwise persist one offline-only stopped result" in payload["offline_audit"]["pass_gate"]
    sequence = payload["semantic_canary"]["sequence"]
    assert "positive case once with no retry" in sequence[0]
    assert "positive attempt has authoritative usage" in sequence[1]
    assert payload["frozen_instrument"]["provider_retries"] == 0


def test_qualification_is_isolated_and_cannot_advance_opt009():
    payload = _payload()
    ceilings = payload["resource_ceilings"]

    assert ceilings["network_hosts"] == ["api.anthropic.com"]
    assert ceilings["provider_attempts"] == 2
    assert ceilings["provider_reported_tokens"] == 30_000
    assert ceilings["known_dated_price_cost_usd"] == 0.5
    assert ceilings["production_store_mutations"] == 0
    assert ceilings["repository_materializations"] == ceilings["scanner_processes"] == 0
    assert ceilings["human_reviews"] == ceilings["assessments"] == ceilings["labels"] == 0
    assert "cannot clear the OPT-009 data gate" in payload["result_boundary"]
    required = payload["authorization"]["required_statement"]
    assert "planner v2 and further sources remain deferred" in required
    assert "Raw model output" in required

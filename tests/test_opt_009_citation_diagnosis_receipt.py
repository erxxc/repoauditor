from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-009-citation-diagnosis-receipt-2026-08-13.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _assert_bound(record: dict) -> None:
    assert _sha256((RECEIPT.parent / record["path"]).resolve()) == record["sha256"]


def test_citation_diagnosis_binds_every_retained_and_frozen_input():
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    for record in payload["retained_evidence"].values():
        _assert_bound(record)
    for key in ("owasp_prompt", "source_rendering", "benchmark_ground_truth", "benchmark_positive", "diagnostic_clarification"):
        _assert_bound(payload["frozen_inputs"][key])
    assert payload["frozen_inputs"]["ensemble"]["sha256"] == (
        "7f0657bb2f9eef23fac79bc393259f5294daf8f4252e046ec4995e184bde31a1"
    )
    _assert_bound(payload["pricing"])


def test_citation_diagnosis_is_offline_gated_and_two_call_bounded():
    payload = _payload()
    ceilings = payload["resource_ceilings"]

    assert payload["offline_diagnosis"]["network_reads"] == 0
    assert payload["offline_diagnosis"]["production_store_mode"] == "read-only"
    assert "Every check must pass before provider use" in payload["offline_diagnosis"]["pass_gate"]
    assert ceilings["network_hosts"] == ["api.anthropic.com"]
    assert ceilings["provider_attempts"] == 2
    assert ceilings["provider_reported_tokens"] == 30_000
    assert ceilings["known_dated_price_cost_usd"] == 0.5
    assert payload["frozen_inputs"]["provider_retries"] == 0


def test_diagnosis_cannot_mutate_instrument_or_close_opt009():
    payload = _payload()
    ceilings = payload["resource_ceilings"]

    assert payload["frozen_inputs"]["diagnostic_clarification"]["production_eligible"] is False
    assert payload["provider_diagnosis"]["ground_truth_transfer"] is False
    assert payload["provider_diagnosis"]["raw_output_persistence"] is False
    assert payload["provider_diagnosis"]["finding_persistence"] is False
    assert ceilings["production_store_mutations"] == 0
    assert ceilings["repository_materializations"] == ceilings["scanner_processes"] == 0
    assert ceilings["human_reviews"] == ceilings["assessments"] == ceilings["labels"] == 0
    assert "close OPT-009" in payload["result_boundary"]
    required = payload["authorization"]["required_statement"]
    assert "OPT-009 status change or closure" in required
    assert "planner v2" in required

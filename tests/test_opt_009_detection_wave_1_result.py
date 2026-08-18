from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = (
    ROOT
    / "docs/optimizations/opt-009-prospective-detection-wave-1-result-2026-08-13.json"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _result() -> dict:
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_wave_one_stops_on_the_unknown_usage_attempt():
    payload = _result()
    accounting = payload["provider_accounting"]

    assert payload["status"] == (
        "stopped-provider-usage-unavailable-after-oversized-prompt"
    )
    assert payload["stop"]["attempt"] == "fourth OWASP region"
    assert accounting["calls_with_authoritative_usage"] == 4
    assert accounting["calls_without_authoritative_usage"] == 1
    assert accounting["complete_cost_status"] == "unavailable"
    assert payload["execution"]["unattempted_source"]["materialized"] is False


def test_wave_one_result_binds_aggregate_evidence_and_preserves_boundaries():
    payload = _result()
    evidence = payload["result_evidence"]
    evidence_path = (RESULT.parent / evidence["path"]).resolve()

    assert _sha256(evidence_path) == evidence["sha256"]
    assert payload["capacity"]["status"] == "not-measured"
    assert payload["store_accounting"]["unexpected_changed_tables"] == []
    assert payload["resource_accounting"]["ceiling_breaches"] == []
    excluded = payload["excluded_actions_accounting"]
    assert excluded["candidate_identities_disclosed"] == 0
    assert excluded["assessments"] == excluded["labels"] == 0
    assert excluded["observational_lens_calls"] == 0
    assert excluded["source_rendered_for_review"] is False


def test_wave_one_requires_a_new_corrected_receipt_before_retry():
    payload = _result()

    assert payload["disposition"]["opt_009_status"] == "open-data-gated"
    assert payload["disposition"]["wave_one_completed"] is False
    assert "new corrected receipt" in payload[
        "required_correction_before_retry"
    ]["authorization"]

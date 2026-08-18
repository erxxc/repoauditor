from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = (
    ROOT
    / "docs/optimizations/opt-009-prospective-detection-wave-1-corrected-retry-receipt-2026-08-13.json"
)


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_corrected_retry_binds_prior_failure_and_implementation():
    payload = _payload()
    stopped = json.loads(
        (ROOT / "data/artifacts/opt009-wave-1-corrected-retry/stopped-attempt.json")
        .read_text(encoding="utf-8")
    )
    assert payload["status"] == "authorization-pending"
    for key in ("prior_receipt", "stopped_result", "stopped_execution_evidence"):
        record = payload[key]
        assert _sha256((RECEIPT.parent / record["path"]).resolve()) == record["sha256"]
    for key, record in payload["implementation_identity"].items():
        if key == "retry_runner":
            assert record["sha256"] == stopped["runner_sha256"]
            continue
        assert _sha256((RECEIPT.parent / record["path"]).resolve()) == record["sha256"]


def test_corrected_retry_preserves_unknown_historical_usage_without_zeroing_it():
    provider = _payload()["stopped_state"]["provider"]
    assert provider["attempts"] == 5
    assert provider["calls_without_authoritative_usage"] == 1
    assert provider["complete_historical_cost_status"] == "unavailable"
    assert "not assigned zero tokens or zero cost" in provider["unknown_attempt_treatment"]


def test_corrected_retry_bounds_every_new_provider_content_path():
    instrument = _payload()["corrected_detection_instrument"]
    assert instrument["active_lenses"] == ["owasp"]
    assert instrument["complete_region_maximum_utf8_bytes"] == 240_000
    assert instrument["complete_structured_request_content_maximum_utf8_bytes"] == 320_000
    assert instrument["rescore_evidence_maximum_utf8_bytes"] == 240_000
    assert instrument["offline_failed_region_validation"]["within_all_corrected_bounds"]
    assert instrument["offline_failed_region_validation"]["source_path_or_content_emitted"] is False


def test_corrected_retry_retains_cumulative_resource_ceilings():
    ceilings = _payload()["resource_ceilings"]
    assert ceilings["vikunja_remaining_provider_attempts"] + 5 == 75
    assert ceilings["vikunja_remaining_provider_reported_tokens"] + 99_846 == 250_000
    assert ceilings["maximum_new_provider_attempts"] + 5 == 150
    assert ceilings["maximum_new_provider_reported_tokens"] + 99_846 == 500_000
    assert round(ceilings["maximum_new_known_dated_price_cost_usd"] + 0.546170, 6) == 12.5
    assert ceilings["complete_historical_cost_claim"].startswith("unavailable")


def test_corrected_retry_stops_before_any_outcome_or_later_stage():
    payload = _payload()
    statement = payload["authorization"]["required_statement"]
    assert payload["authorization"]["granted"] is False
    assert "fresh scanner health persisted before provider use" in statement
    assert "accepting the retained oversized-prompt rejection" in statement
    assert "Candidate identity disclosure" in statement
    assert "OPT-009 promotion or closure" in statement
    assert "branch integration" in statement

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-009-prospective-detection-wave-1-serialization-retry-receipt-2026-08-13.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_serialization_retry_binds_both_stopped_attempts_and_corrected_code():
    payload = _payload()
    assert payload["status"] == "authorization-pending"
    for key in ("prior_corrected_receipt", "stopped_attempt_result", "stopped_attempt_evidence"):
        record = payload[key]
        assert _sha256((RECEIPT.parent / record["path"]).resolve()) == record["sha256"]
    assert _sha256((RECEIPT.parent / payload["serialization_correction"]["runner"]["path"]).resolve()) == payload["serialization_correction"]["runner"]["sha256"]
    for name, record in payload["retained_corrected_instrument"].items():
        if isinstance(record, dict) and "path" in record:
            if name == "config":
                assert record["sha256"] == "30d8837bdb63b56a50aefb0cd9bc18a0a7173ac86cd8581d4af6f2b2b21f3d09"
                assert len(_sha256((RECEIPT.parent / record["path"]).resolve())) == 64
                continue
            if name == "ensemble":
                assert record["sha256"] == (
                    "7f0657bb2f9eef23fac79bc393259f5294daf8f4252e046ec4995e184bde31a1"
                )
                continue
            assert _sha256((RECEIPT.parent / record["path"]).resolve()) == record["sha256"]


def test_serialization_retry_is_narrow_and_resumes_pipeline_in_place():
    payload = _payload()
    correction = payload["serialization_correction"]
    assert correction["policy"] == "opt009-stage-summary-json-v1"
    assert "datetime values through ISO-8601" in correction["allowed_change"]
    assert "No scanner execution" in correction["forbidden_changes"]
    assert payload["stopped_state"]["pipeline_115"]["resume_in_place"] is True
    assert payload["resource_ceilings"]["resumed_vikunja_pipelines"] == 1
    assert payload["resource_ceilings"]["new_miniflux_pipelines"] == 1


def test_serialization_retry_preserves_provider_and_outcome_boundaries():
    payload = _payload()
    ceilings = payload["resource_ceilings"]
    assert ceilings["maximum_new_provider_attempts"] + 5 == 150
    assert ceilings["maximum_new_provider_reported_tokens"] + 99_846 == 500_000
    assert round(ceilings["maximum_new_known_dated_price_cost_usd"] + 0.546170, 6) == 12.5
    assert ceilings["complete_historical_cost_claim"] == "unavailable"
    assert ceilings["human_reviews"] == ceilings["assessments_written"] == 0
    assert ceilings["labels_written"] == ceilings["models_trained"] == 0
    required = payload["authorization"]["required_statement"]
    assert "recursive JSON-safe conversion" in required
    assert "Candidate identity disclosure" in required
    assert "OPT-009 promotion or closure" in required

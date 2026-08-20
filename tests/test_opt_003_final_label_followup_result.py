"""OPT-003 corrected final-label follow-up result is response-bound and non-mutating."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-003-final-label-followup-result-2026-08-12.json"


def test_followup_result_binds_receipt_evidence_and_response():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    for record in (payload["execution_receipt"], payload["evidence"], payload["response_artifact"]):
        path = (RESULT.parent / record["path"]).resolve()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]
    response = payload["response"]
    assert response["finding_id"] == 2036
    assert response["prior_assessment_id"] == 159
    assert response["disposition"] == "not_attacker_controlled"
    assert response["binary_projection"] == "non_actionable"
    assert response["abstained"] is False


def test_followup_result_records_zero_store_or_external_activity():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    accounting = payload["accounting"]
    assert accounting["store_byte_identical"] is True
    assert accounting["store_mutations"] == 0
    assert accounting["assessments_written"] == 0
    assert accounting["labels_written"] == 0
    assert accounting["network_reads"] == 0
    assert accounting["provider_calls"] == 0
    assert all(payload["not_executed"].values())

"""Corrected OPT-003 wave-two retry binds every Semgrep process."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-003-wave-2-corrected-receipt-2026-08-11.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_retry_binds_original_receipt_and_stopped_attempt():
    payload = _payload()
    base = ROOT / "docs/optimizations"
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert _sha256(base / payload["original_receipt"]["path"]) == payload["original_receipt"]["sha256"]
    assert _sha256(base / payload["stopped_attempt"]["path"]) == payload["stopped_attempt"]["sha256"]
    assert payload["unchanged_scope"]["model_trained_in_stopped_attempt"] is False
    assert payload["unchanged_scope"]["new_training_run_required"] is True


def test_retry_binds_version_check_and_all_semgrep_processes():
    payload = _payload()
    binding = payload["corrected_semgrep_binding"]
    sequence = " ".join(payload["retry_sequence"])

    assert binding["artifact_directory"] == "data/artifacts/opt003-wave-2"
    assert binding["SEMGREP_LOG_FILE"] == "data/artifacts/opt003-wave-2/semgrep.log"
    assert binding["version_command"].startswith("SEMGREP_LOG_FILE=data/artifacts/opt003-wave-2/semgrep.log")
    assert binding["expected_version"] == "1.170.0"
    assert "any Semgrep process" in binding["requirement"]
    assert "version check and both reports pass" in sequence


def test_retry_preserves_hosts_capacity_and_zero_outcomes():
    payload = _payload()
    ceilings = payload["resource_ceilings"]
    assert set(ceilings["allowed_network_hosts"]) == {
        "github.com", "pypi.org", "api.osv.dev", "osv.dev",
    }
    assert ceilings["repositories"] == 3
    assert ceilings["new_model_training_runs"] == 1
    assert ceilings["provider_calls"] == 0
    assert ceilings["human_reviews"] == 0
    assert ceilings["assessments_written"] == 0
    assert ceilings["labels_written"] == 0
    assert "six-eligible-identities-per-family" in payload["authorization"]["required_statement"]

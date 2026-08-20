"""Corrected OPT-003 retry binds Semgrep writes and separates networked canaries."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-003-wave-1-corrected-receipt-2026-08-11.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def test_retry_binds_semgrep_log_inside_wave_artifacts():
    payload = _payload()
    binding = payload["corrected_binding"]
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert binding["SEMGREP_LOG_FILE"] == "data/artifacts/opt003-wave-1-retry/semgrep.log"
    assert binding["semgrep_version"] == "1.170.0"
    assert binding["rule_or_configuration_changes"] is False


def test_retry_separates_offline_and_advisory_canaries():
    preflight = _payload()["separated_preflight"]
    assert "--scanner semgrep" in preflight["offline_command"]
    assert "--scanner semgrep-supplemental" in preflight["offline_command"]
    assert "--scanner gitleaks" in preflight["offline_command"]
    assert "pip-audit" not in preflight["offline_command"]
    assert "osv-scanner" not in preflight["offline_command"]
    assert "--scanner pip-audit" in preflight["advisory_command"]
    assert "--scanner osv-scanner" in preflight["advisory_command"]
    assert set(preflight["advisory_network_hosts"]) == {"pypi.org", "api.osv.dev", "osv.dev"}


def test_retry_forbids_stopped_model_reuse_and_outcomes():
    payload = _payload()
    assert payload["unchanged_scope"]["stopped_model_reuse"] is False
    assert payload["unchanged_scope"]["new_training_run_required"] is True
    ceilings = payload["resource_ceilings"]
    assert ceilings["provider_calls"] == 0
    assert ceilings["human_reviews"] == 0
    assert ceilings["assessments_written"] == 0
    assert ceilings["labels_written"] == 0

"""Runtime-corrected OPT-003 retry confines Semgrep logs and version cache."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-003-wave-2-runtime-corrected-receipt-2026-08-11.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_receipt_binds_stopped_retry_helper_and_retained_log():
    payload = _payload()
    base = ROOT / "docs/optimizations"
    helper = (base / payload["runtime_helper"]["path"]).resolve()

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert _sha256(base / payload["prior_corrected_receipt"]["path"]) == payload["prior_corrected_receipt"]["sha256"]
    assert _sha256(base / payload["stopped_retry"]["path"]) == payload["stopped_retry"]["sha256"]
    assert _sha256(helper) == payload["runtime_helper"]["sha256"]
    assert len(payload["retained_failed_artifact"]["sha256"]) == 64
    assert payload["unchanged_scope"]["model_trained_in_prior_attempts"] is False


def test_receipt_confines_both_semgrep_paths_and_avoids_cli_version_check():
    payload = _payload()
    runtime = payload["corrected_runtime"]
    preflight = payload["separated_preflight"]

    assert runtime["artifact_directory"] == "data/artifacts/opt003-wave-2-runtime-retry"
    assert runtime["SEMGREP_LOG_FILE"].startswith(runtime["artifact_directory"])
    assert runtime["SEMGREP_VERSION_CACHE_PATH"].startswith(runtime["artifact_directory"])
    assert "from semgrep import __VERSION__" in runtime["version_import_command"]
    assert "semgrep --version" not in runtime["version_import_command"]
    assert "SEMGREP_LOG_FILE=" in preflight["offline_command"]
    assert "SEMGREP_VERSION_CACHE_PATH=" in preflight["offline_command"]
    assert preflight["offline_network_reads"] == 0
    assert runtime["forbidden_version_host"] == "semgrep.dev"


def test_receipt_preserves_exact_hosts_capacity_and_zero_outcomes():
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
    statement = payload["authorization"]["required_statement"]
    assert "no semgrep.dev contact" in statement
    assert "six-eligible-identities-per-family" in statement

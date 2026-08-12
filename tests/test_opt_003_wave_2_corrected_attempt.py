"""The corrected OPT-003 retry stops on Semgrep's separate default cache."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ATTEMPT = ROOT / "docs/optimizations/opt-003-wave-2-corrected-attempt-2026-08-11.json"


def test_corrected_attempt_stops_before_canaries_or_store_mutation():
    payload = json.loads(ATTEMPT.read_text(encoding="utf-8"))
    accounting = payload["accounting"]

    assert payload["status"] == "stopped-before-offline-preflight"
    assert payload["stop"]["passed"] is False
    assert payload["stop"]["observed_version"] == "1.170.0"
    assert payload["stop"]["write_succeeded"] is False
    assert payload["retained_artifacts"]["offline_canary_report_created"] is False
    assert payload["retained_artifacts"]["advisory_canary_report_created"] is False
    assert payload["verified_before_stop"]["initial_store_sha256"] == accounting["final_store_sha256"]
    assert accounting["store_byte_identical"] is True
    assert accounting["model_training_runs"] == 0
    assert accounting["repositories_materialized"] == 0
    assert accounting["predictions_persisted"] == 0
    assert all(payload["not_executed"].values())


def test_corrected_attempt_accounts_for_cache_and_zero_outcomes():
    payload = json.loads(ATTEMPT.read_text(encoding="utf-8"))
    assert payload["stop"]["external_cache_read"]["network_version_fetch_required"] is False
    assert payload["accounting"]["network_reads"] == 0
    assert payload["accounting"]["provider_calls"] == 0
    assert payload["accounting"]["human_reviews"] == 0
    assert payload["accounting"]["assessments_written"] == 0
    assert payload["accounting"]["labels_written"] == 0

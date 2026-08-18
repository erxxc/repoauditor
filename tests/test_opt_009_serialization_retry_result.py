from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = (
    ROOT
    / "docs/optimizations/opt-009-prospective-detection-wave-1-serialization-retry-result-2026-08-13.json"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _result() -> dict:
    return json.loads(RESULT.read_text(encoding="utf-8"))


def _assert_bound(record: dict) -> None:
    path = (RESULT.parent / record["path"]).resolve()
    assert _sha256(path) == record["sha256"]


def test_serialization_retry_result_binds_receipt_execution_and_preflights():
    payload = _result()

    assert payload["status"] == "complete-capacity-shortfall"
    _assert_bound(payload["receipt"])
    _assert_bound(payload["execution_evidence"])
    _assert_bound(payload["preflight_evidence"]["offline"])
    _assert_bound(payload["preflight_evidence"]["advisory"])
    _assert_bound(payload["preflight_evidence"]["stopped_state_backup"])
    semgrep = payload["preflight_evidence"]["semgrep"]
    assert _sha256((RESULT.parent / semgrep["log_path"]).resolve()) == semgrep[
        "log_sha256"
    ]
    assert semgrep == {
        "version": "1.170.0",
        "log_path": semgrep["log_path"],
        "log_sha256": hashlib.sha256(b"").hexdigest(),
        "log_bytes": 0,
    }


def test_serialization_retry_completed_exact_resume_with_healthy_scanners():
    payload = _result()
    execution = payload["execution"]

    assert execution["repositories_processed"] == 2
    vikunja, miniflux = execution["pipelines"]
    assert vikunja["pipeline_run_id"] == 115
    assert vikunja["resumed_in_place"] is True
    assert vikunja["reused_completed_regions"] == 3
    assert vikunja["new_completed_regions"] == 3
    assert vikunja["resume_plan_verified"] is True
    assert miniflux["pipeline_run_id"] == 116
    assert miniflux["new_pipeline"] is True
    assert miniflux["new_completed_regions"] == 6
    assert all(run["status"] == "completed" for run in execution["pipelines"])
    assert payload["scanner_health"]["persisted_before_provider_use"] is True
    assert payload["scanner_health"]["unhealthy_or_incomplete_scanners"] == 0


def test_serialization_retry_accounting_stays_within_authorized_ceilings():
    payload = _result()
    provider = payload["provider_accounting"]

    assert provider["new_calls"] == 10
    assert provider["new_calls_without_authoritative_usage"] == 0
    assert provider["new_provider_reported_tokens"] == 310_314
    assert provider["new_known_dated_price_cost_usd"] == 1.598170
    assert provider["historical_unknown_usage_attempts"] == 1
    assert provider["complete_historical_cost_status"] == "unavailable"
    assert provider["ceiling_breaches"] == []
    assert payload["resource_accounting"]["ceiling_breaches"] == []
    assert payload["store_accounting"]["unexpected_changed_tables"] == []
    assert payload["store_accounting"]["assessment_delta"] == 0
    assert payload["store_accounting"]["label_delta"] == 0


def test_serialization_retry_stops_without_disclosure_on_capacity_shortfall():
    payload = _result()
    capacity = payload["capacity"]

    assert capacity["minimum_eligible_groups_per_family"] == 8
    assert capacity["families_meeting_capacity"] == 0
    assert [family["eligible_deduplicated_issue_groups"] for family in capacity["families"]] == [0, 0]
    assert capacity["candidate_identities_disclosed"] == 0
    assert all(value in (0, False) for value in payload["outcome_and_exclusion_accounting"].values())
    assert payload["disposition"]["opt_009_status"] == "open-data-gated"
    assert payload["disposition"]["data_gate_cleared"] is False
    assert payload["disposition"]["wave_one_runtime_completed"] is True
    assert payload["disposition"]["capacity_contract_satisfied"] is False
    assert payload["disposition"]["reserve_activation"] == "not authorized"
    assert payload["disposition"]["branch_merge"] == "deferred"

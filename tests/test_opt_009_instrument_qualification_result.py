from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-009-instrument-qualification-result-2026-08-13.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _payload() -> dict:
    return json.loads(RESULT.read_text(encoding="utf-8"))


def _assert_bound(record: dict) -> None:
    assert _sha256((RESULT.parent / record["path"]).resolve()) == record["sha256"]


def test_qualification_result_binds_receipt_and_all_execution_evidence():
    payload = _payload()

    _assert_bound(payload["receipt"])
    for name, record in payload["execution_evidence"].items():
        if name == "offline_audit":
            assert record["sha256"] == (
                "02c3e48941da46b450caabbccbf0a16712f6cb60e1d45c74987a506762c78e41"
            )
            continue
        _assert_bound(record)


def test_offline_gate_passed_but_semantic_positive_failed_citation_gate():
    payload = _payload()

    assert payload["status"] == "qualification-failed"
    assert payload["offline_audit"]["status"] == "passed"
    assert payload["offline_audit"]["completed_owasp_regions"] == 12
    assert payload["offline_audit"]["persisted_llm_origin_findings"] == 0
    semantic = payload["semantic_canary"]
    assert semantic["attempts"] == semantic["attempts_with_authoritative_usage"] == 2
    assert semantic["unknown_usage_attempts"] == 0
    assert semantic["positive"]["schema_valid_findings"] == 1
    assert semantic["positive"]["citation_valid_findings"] == 0
    assert semantic["positive"]["expected_anchor_matches"] == 0
    assert semantic["negative"]["citation_valid_findings"] == 0


def test_qualification_stays_isolated_within_every_ceiling():
    payload = _payload()
    isolation = payload["isolation_and_resources"]

    assert isolation["production_store_unchanged"] is True
    assert isolation["scratch_model_usage_rows"] == 2
    assert isolation["raw_provider_outputs_persisted"] == 0
    assert isolation["new_data_bytes"] < 10_485_760
    assert isolation["elapsed_seconds"] < 1800
    assert isolation["ceiling_breaches"] == []
    assert all(value == 0 for value in payload["excluded_actions_accounting"].values())


def test_failed_qualification_defers_planner_and_sources():
    disposition = _payload()["disposition"]

    assert disposition["opt_009_status"] == "open-data-gated"
    assert disposition["instrument_qualified"] is False
    assert disposition["data_gate_cleared"] is False
    assert disposition["planner_v2"] == "deferred"
    assert disposition["further_sources"] == "deferred"
    assert disposition["required_stop"] is True
    assert disposition["branch_merge"] == "deferred"

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-009-citation-diagnosis-result-2026-08-13.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _payload() -> dict:
    return json.loads(RESULT.read_text(encoding="utf-8"))


def _assert_bound(record: dict) -> None:
    assert _sha256((RESULT.parent / record["path"]).resolve()) == record["sha256"]


def test_diagnosis_result_binds_receipt_and_execution_evidence():
    payload = _payload()

    _assert_bound(payload["receipt"])
    for record in payload["execution_evidence"].values():
        _assert_bound(record)


def test_provider_comparison_does_not_support_the_prefix_correction():
    payload = _payload()
    diagnosis = payload["provider_diagnosis"]

    assert payload["status"] == "citation-diagnosis-inconclusive"
    assert payload["offline_diagnosis"]["status"] == "passed"
    assert diagnosis["attempts"] == diagnosis["attempts_with_authoritative_usage"] == 2
    assert diagnosis["unknown_usage_attempts"] == 0
    assert diagnosis["exact_frozen_repeat"]["exact_anchor_matches"] == 1
    assert diagnosis["exact_frozen_repeat"]["display_prefix_recoverable_citations"] == 0
    assert diagnosis["diagnostic_clarification"]["exact_citations"] == 0
    assert diagnosis["diagnostic_clarification"]["other_nonverbatim_citations"] == 1
    assert diagnosis["diagnosis_success_gate"] is False


def test_diagnosis_is_isolated_and_within_every_ceiling():
    payload = _payload()
    isolation = payload["isolation_and_resources"]

    assert isolation["production_store_unchanged"] is True
    assert isolation["scratch_model_usage_rows"] == 2
    assert isolation["scratch_findings"] == isolation["scratch_assessments"] == 0
    assert isolation["scratch_labels"] == isolation["scratch_model_runs"] == 0
    assert isolation["raw_provider_output_bytes_persisted"] == 0
    assert isolation["new_data_bytes"] < 10_485_760
    assert isolation["elapsed_seconds"] < 1200
    assert isolation["ceiling_breaches"] == []
    assert all(value == 0 for value in payload["excluded_actions_accounting"].values())


def test_inconclusive_diagnosis_recommends_but_does_not_perform_closure():
    disposition = _payload()["disposition"]

    assert disposition["opt_009_status"] == "open-data-gated"
    assert disposition["bounded_correction_supported"] is False
    assert disposition["recommendation"] == "close-opt009-at-current-scope"
    assert disposition["required_stop"] is True
    assert disposition["closure"] == "not authorized by this receipt"
    assert disposition["branch_merge"] == "deferred"

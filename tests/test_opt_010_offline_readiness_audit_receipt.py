from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / (
    "docs/optimizations/opt-010-offline-readiness-audit-receipt-2026-08-18.json"
)


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _assert_bound(record: dict) -> None:
    path = (RECEIPT.parent / record["path"]).resolve()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]


def test_receipt_binds_gate_status_handoff_reserve_store_and_implementation() -> None:
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    # These are immutable receipt-time bindings to files that were explicitly
    # authorized to evolve after the 2026-08-18 audit.
    assert len(payload["activation_gate"]["sha256"]) == 64
    assert len(payload["optimization_status"]["sha256"]) == 64
    _assert_bound(payload["opt_014_handoff"])
    _assert_bound(payload["sec_edgar_reserve"])
    _assert_bound(payload["production_store"])
    for name, record in payload["frozen_implementation"].items():
        if name == "config":
            assert len(record["sha256"]) == 64
        else:
            _assert_bound(record)
    assert payload["opt_014_handoff"]["next_work_item"] == "OPT-010"
    assert payload["sec_edgar_reserve"]["selected_or_acquired"] is False


def test_receipt_freezes_all_seven_activation_gates() -> None:
    contract = _payload()["readiness_contract"]

    assert contract["gate_states"] == [
        "documented-pass",
        "partial",
        "documented-fail",
        "unresolved",
    ]
    assert [gate["gate_id"] for gate in contract["gates"]] == [
        "G01",
        "G02",
        "G03",
        "G04",
        "G05",
        "G06",
        "G07",
    ]
    assert "no favorable inference" in contract["pass_rule"]
    assert "all seven gates" in contract["activation_rule"]


def test_receipt_is_aggregate_only_and_identity_safe() -> None:
    store = _payload()["aggregate_store_contract"]
    statement = _payload()["authorization"]["required_statement"]

    assert len(store["allowed_measurements"]) == 5
    assert len(store["forbidden_measurements"]) == 3
    assert "aggregate in memory" in store["store_rule"]
    assert "Finding, repository, organization" in statement
    assert "individual usage rows" in statement


def test_receipt_allows_only_small_offline_audit_outputs() -> None:
    payload = _payload()
    ceilings = payload["resource_ceilings"]

    assert ceilings["maximum_elapsed_minutes"] == 10
    assert ceilings["maximum_new_data_bytes"] == 1024 * 1024
    assert ceilings["maximum_new_helpers"] == 1
    assert ceilings["maximum_new_test_files"] == 1
    assert ceilings["maximum_aggregate_artifacts"] == 1
    assert ceilings["maximum_result_documents"] == 1
    assert payload["allowed_file_changes"] == [
        "src/repoauditor/eval/opt010_readiness.py",
        "tests/test_opt_010_readiness_audit.py",
        "docs/optimizations/opt-010-offline-readiness-audit-artifact-2026-08-18.json",
        "docs/optimizations/opt-010-offline-readiness-audit-result-2026-08-18.json",
    ]


def test_receipt_prohibits_agent_provider_store_and_lifecycle_activity() -> None:
    payload = _payload()
    ceilings = payload["resource_ceilings"]
    boundary = payload["result_boundary"]

    assert ceilings["network_reads"] == ceilings["network_uploads"] == 0
    assert ceilings["provider_calls"] == ceilings["agentic_falsification_runs"] == 0
    assert ceilings["repository_materializations"] == 0
    assert ceilings["repository_code_executions"] == 0
    assert ceilings["scanner_processes"] == 0
    assert ceilings["production_store_mutations"] == ceilings["schema_migrations"] == 0
    assert ceilings["assessments_written"] == ceilings["labels_written"] == 0
    assert ceilings["model_training_runs"] == ceilings["rescoring_runs"] == 0
    assert "may not render source" in boundary
    assert "activate or close OPT-010" in boundary
    assert "reopen OPT-014 acquisition" in boundary

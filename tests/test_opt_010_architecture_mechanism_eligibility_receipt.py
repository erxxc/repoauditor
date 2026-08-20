from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-architecture-mechanism-eligibility-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text())


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_receipt_binds_completed_six_subject_wave_and_frozen_instruments():
    payload = _payload()
    wave = payload["frozen_wave"]["qualification_result"]
    assert _sha256(ROOT / wave["path"]) == wave["sha256"]

    for binding in payload["frozen_architecture_instrument"]["implementation_bindings"].values():
        assert _sha256(ROOT / binding["path"]) == binding["sha256"]
    for binding in payload["concrete_mechanism_matrix"]["implementation_bindings"].values():
        assert _sha256(ROOT / binding["path"]) == binding["sha256"]


def test_mechanism_matrix_is_exhaustive_fixed_and_preserves_unsupported_languages():
    matrix = _payload()["concrete_mechanism_matrix"]

    assert matrix["freeze_before_provider_use"] is True
    assert matrix["matrix"] == {
        "Python": ["sql_injection", "command_injection", "ssrf"],
        "TypeScript": ["command_injection", "ssrf"],
        "Java": ["ssrf"],
        "Ruby": ["unsafe_deserialization"],
        "Go": [],
        "Rust": [],
    }
    assert "stay in every denominator" in matrix["unsupported_rule"]
    assert "No per-subject mechanism is selected" in matrix["assignment_rule"]


def test_architecture_calls_are_bounded_and_have_no_general_retry():
    instrument = _payload()["frozen_architecture_instrument"]

    assert instrument["provider"] == "anthropic"
    assert instrument["model"] == "claude-opus-4-8"
    assert instrument["prompt_version"] == "architecture_recovery_v2"
    assert instrument["complete_request_maximum_utf8_bytes"] == 320000
    assert "one broader-context repass" in instrument["call_policy"]
    assert "No transport, status, schema, parse, refusal, missing-usage, or other retry" in instrument["call_policy"]


def test_provider_resources_and_all_other_live_activity_are_explicit():
    ceilings = _payload()["resource_ceilings"]

    assert ceilings["subjects"] == 6
    assert ceilings["provider_attempts"] == 12
    assert ceilings["provider_reported_tokens"] == 500000
    assert ceilings["maximum_known_dated_price_cost_usd"] == 7.5
    assert ceilings["allowed_network_hosts"] == ["api.anthropic.com"]
    zero_fields = (
        "other_network_reads_or_uploads", "repository_materializations",
        "repository_code_executions", "scanner_processes", "production_store_reads",
        "production_store_mutations", "schema_migrations", "findings_or_candidates_created",
        "assessments", "labels", "model_training_runs", "rescoring_runs", "human_reviews",
        "agentic_runs", "workspace_branch_or_index_operations", "commits", "merges", "pushes",
        "lifecycle_changes",
    )
    assert all(ceilings[field] == 0 for field in zero_fields)


def test_receipt_does_not_claim_this_closes_opt010():
    payload = _payload()
    statement = payload["authorization"]["required_statement"]

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert "12 provider attempts" in statement
    assert "explicit unsupported Go and Rust states" in statement
    assert "paired G03b comparison" in statement
    assert "OPT-010 promotion or closure" in statement
    assert "It cannot claim empirical safety" in payload["result_boundary"]

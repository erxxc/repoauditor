from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-prospective-source-selection-receipt-2026-08-18.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_workspace_preflight_preserves_main_wip_and_opt_036_isolation():
    preflight = _payload()["workspace_preflight"]

    assert preflight["branch"] == "main"
    assert preflight["staged_paths"] == 0
    assert preflight["OPT_036_changed_paths"] == 10
    assert preflight["OPT_036_overlap_with_current_OPT_010_or_closure_WIP"] == 0
    assert preflight["branch_or_index_change_authorized"] is False


def test_frozen_inputs_and_unopened_store_are_digest_bound():
    mutable_documents = {"agentic_gate", "optimization_status"}
    for name, binding in _payload()["frozen_inputs"].items():
        if name in mutable_documents:
            assert len(binding["sha256"]) == 64
        else:
            assert _sha256(ROOT / binding["path"]) == binding["sha256"]

    assert _payload()["frozen_inputs"]["production_store"]["access"] == "before-and-after-hash-only"


def test_selection_has_exact_buffer_and_language_family_boundaries():
    payload = _payload()
    roles = payload["metadata_discovery"]["selected_roles"]
    floors = payload["eligibility_contract"]["fixed_metadata_floors"]

    assert roles == {"primary": 12, "reserve": 4}
    assert payload["metadata_discovery"]["maximum_selected_identities_disclosed"] == 16
    assert floors["minimum_distinct_primary_languages_across_selected_identities"] == 4
    assert floors["maximum_selected_repositories_per_owner"] == 1
    assert "no more than four" in payload["coverage_and_selection"]["ordering"]


def test_shortfall_discloses_no_partial_list_and_never_relaxes_contract():
    rule = _payload()["coverage_and_selection"]["shortfall_rule"]

    assert "aggregate shortfall counts" in rule
    assert "do not relax" in rule
    assert "disclose a partial selected list" in rule


def test_forbidden_inputs_exclude_security_outcomes_code_and_opt_036():
    forbidden = " ".join(_payload()["forbidden_inputs"])

    assert "security advisories" in forbidden
    assert "repository code search" in forbidden
    assert "scores" in forbidden and "expected outcomes" in forbidden
    assert "OPT-036" in forbidden


def test_receipt_has_zero_live_mutating_agentic_and_branch_activity():
    ceilings = _payload()["resource_ceilings"]
    zero_fields = (
        "network_uploads", "provider_calls", "provider_reported_tokens",
        "provider_cost_usd", "repository_materializations", "repository_code_executions",
        "scanner_processes", "agentic_falsification_runs", "production_store_reads",
        "production_store_mutations", "schema_migrations", "assessments_written",
        "labels_written", "model_training_runs", "rescoring_runs", "branch_operations",
        "source_commits", "merge_commits", "remote_pushes",
    )

    assert all(ceilings[field] == 0 for field in zero_fields)
    assert ceilings["network_reads"] == ceilings["maximum_metadata_documents"] == 64


def test_receipt_requires_exact_separate_authorization():
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "exactly twelve primary and four reserve" in statement
    assert "preservation of the current main WIP" in statement
    assert "if exactly sixteen identities do not qualify" in statement
    assert "remain excluded" in statement

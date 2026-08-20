from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-protected-cohort-design-receipt-2026-08-18.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_frozen_document_inputs_and_unopened_store_are_digest_bound():
    mutable_documents = {"triage_accuracy_roadmap", "agentic_gate"}
    for name, binding in _payload()["frozen_inputs"].items():
        if name in mutable_documents:
            assert len(binding["sha256"]) == 64
            assert len(_sha256(ROOT / binding["path"])) == 64
        else:
            assert _sha256(ROOT / binding["path"]) == binding["sha256"]

    store = _payload()["frozen_inputs"]["production_store"]
    assert store["access"] == "before-and-after-hash-only"


def test_contract_freezes_independence_identity_dimensions_and_terminal_states():
    contract = _payload()["design_contract"]

    assert contract["source_independence"]
    assert contract["subject_identity"]
    assert contract["subgroup_metadata"]["dimensions"] == [
        "source_family",
        "mechanism",
        "language",
        "detector_provenance",
    ]
    assert contract["terminal_observation_completeness"]
    assert "insufficient-metadata" in contract["aggregate_inventory_classes"]


def test_sufficiency_is_calculation_only_and_never_selection():
    sufficiency = _payload()["design_contract"]["prospective_sufficiency_calculations"]

    assert any("40-decided-identity" in item for item in sufficiency["permitted"])
    assert "selecting or recommending an adequacy threshold" in sufficiency["not_permitted"]
    assert any("choosing a cohort" in item for item in sufficiency["not_permitted"])


def test_opt_036_is_not_admitted_as_dependency_evidence():
    treatment = _payload()["execution"]["opt_036_treatment"]

    assert treatment.startswith("OPT-036 is excluded")
    assert "corroboration input" in treatment


def test_receipt_has_zero_live_mutating_and_agentic_activity():
    ceilings = _payload()["resource_ceilings"]
    zero_fields = (
        "network_reads",
        "network_uploads",
        "provider_calls",
        "provider_reported_tokens",
        "provider_cost_usd",
        "production_store_reads",
        "production_store_mutations",
        "schema_migrations",
        "repository_materializations",
        "repository_code_executions",
        "scanner_processes",
        "agentic_falsification_runs",
        "assessments_written",
        "labels_written",
        "model_training_runs",
        "rescoring_runs",
        "source_commits",
        "merge_commits",
    )

    assert all(ceilings[field] == 0 for field in zero_fields)


def test_receipt_requires_exact_separate_authorization():
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "outcome-blind offline protected-cohort" in statement
    assert "without selecting or recommending an adequacy threshold" in statement
    assert "OPT-036" in statement
    assert "remain excluded" in statement

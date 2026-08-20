from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / (
    "docs/optimizations/opt-010-offline-containment-foundation-receipt-2026-08-18.json"
)
ARTIFACT = ROOT / (
    "docs/optimizations/opt-010-offline-containment-foundation-artifact-2026-08-18.json"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def test_all_frozen_inputs_match_and_store_is_hash_only():
    payload = _payload()
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    authorized_outputs = artifact["authorized_output_bindings"]
    mutable_output_bindings = {
        "agentic_gate": "agentic_gate_sha256",
        "configuration": "configuration_sha256",
        "config_schema": "configuration_schema_sha256",
    }
    historical_current_files = {*mutable_output_bindings, "optimization_status"}
    for name, item in payload["frozen_inputs"].items():
        path = (RECEIPT.parent / item["path"]).resolve()
        if name in historical_current_files:
            assert len(item["sha256"]) == 64
            if name in mutable_output_bindings:
                assert len(authorized_outputs[mutable_output_bindings[name]]) == 64
            assert len(_sha256(path)) == 64
        else:
            assert _sha256(path) == item["sha256"]
    assert payload["frozen_inputs"]["production_store"]["access"] == (
        "before-and-after-hash-only"
    )


def test_g03_split_removes_cycle_without_authorizing_qualification():
    split = _payload()["g03_decomposition_contract"]

    assert split["G03a"]["name"] == "baseline-comparison-protocol-readiness"
    assert split["G03b"]["state_after_this_work"] == "pending-separate-authorization"
    assert "grants no provider" in split["policy_boundary"]


def test_g06_surface_is_disabled_typed_bounded_and_not_integrated():
    contract = _payload()["g06_implementation_contract"]

    assert contract["default_state"] == "disabled"
    assert contract["typed_allowlist"] == [
        "indexed_source_excerpt",
        "structural_slice",
        "callers",
        "references",
        "architecture_evidence",
    ]
    assert "challenger.py" in contract["integration_boundary"]
    assert any("subprocess" in item for item in contract["required_enforcement"])
    assert any("symlink escape" in item for item in contract["qualification"])


def test_file_allowlist_is_exact_and_preserves_existing_security_implementations():
    allowed = set(_payload()["allowed_file_changes"])

    assert allowed == {
        "docs/agentic-escalation-gate.md",
        "config.toml",
        "src/repoauditor/config.py",
        "src/repoauditor/falsify/read_only_tools.py",
        "tests/test_read_only_agent_tools.py",
        "tests/test_opt_010_gate_decomposition.py",
        "docs/optimizations/opt-010-baseline-comparison-protocol-2026-08-18.json",
        "docs/optimizations/opt-010-offline-containment-foundation-artifact-2026-08-18.json",
        "docs/optimizations/opt-010-offline-containment-foundation-result-2026-08-18.json",
    }
    assert not any(
        path.endswith(("challenger.py", "claims.py", "slicing.py", "index.py"))
        for path in allowed
    )


def test_all_live_mutating_and_evaluation_activity_is_zero():
    ceilings = _payload()["resource_ceilings"]
    zero_fields = (
        "network_reads", "network_uploads", "provider_calls",
        "provider_reported_tokens", "provider_cost_usd", "production_store_reads",
        "production_store_mutations", "schema_migrations",
        "repository_materializations", "repository_code_executions",
        "scanner_processes", "agentic_falsification_runs", "assessments_written",
        "labels_written", "model_training_runs", "rescoring_runs",
    )

    assert all(ceilings[field] == 0 for field in zero_fields)
    assert ceilings["maximum_new_implementation_files"] == 1
    assert ceilings["maximum_new_test_files"] == 2


def test_receipt_requires_fresh_exact_authorization_and_preserves_lifecycle():
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "G03b later separately authorized" in statement
    assert "disabled-by-default" in statement
    assert "OPT-010 activation, promotion, or closure" in statement
    assert "SEC/EDGAR activation" in statement

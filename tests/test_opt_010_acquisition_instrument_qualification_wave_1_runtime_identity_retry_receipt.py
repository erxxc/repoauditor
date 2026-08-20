from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / (
    "docs/optimizations/"
    "opt-010-prospective-acquisition-instrument-qualification-wave-1-"
    "runtime-identity-retry-receipt-2026-08-19.json"
)


def _payload() -> dict:
    return json.loads(RECEIPT.read_text())


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_receipt_binds_both_stopped_attempts_and_unchanged_helper():
    payload = _payload()
    for key in ("first_stopped_result", "corrected_stopped_result", "corrected_receipt"):
        binding = payload["retained_attempts"][key]
        assert _sha256(ROOT / binding["path"]) == binding["sha256"]
    helper = payload["unchanged_instrument"]["helper"]
    assert _sha256(ROOT / helper["path"]) == helper["sha256"]
    assert helper["mutable"] is False


def test_only_change_accepts_exact_canary_qualified_osv_binary():
    correction = _payload()["only_runtime_identity_correction"]

    assert correction["prior_expected_version"] == "2.3.8"
    assert correction["corrected_exact_version"] == "2.4.0"
    assert correction["binary_sha256"] == "77e5286bd4f45bfe904389043f87958f30a0d1da62017a3323aadd064549fce1"
    assert correction["observed_functional_evidence"]["canary_passed"] is True
    assert correction["installation_or_downgrade"] is False
    assert correction["adapter_or_invocation_change"] is False


def test_same_six_sources_and_fresh_five_canaries_remain_required():
    payload = _payload()

    assert len(payload["unchanged_sources"]["subjects"]) == 6
    assert payload["unchanged_sources"]["architecture_map_slot"].startswith("pending")
    requirements = " ".join(payload["runtime"]["requirements"])
    assert payload["runtime"]["must_be_absent_before_authorization"] is True
    assert "Rerun separated Semgrep" in requirements
    assert "exact OSV Scanner 2.4.0 canaries" in requirements


def test_cumulative_resources_and_zero_activity_are_explicit():
    ceilings = _payload()["resource_ceilings"]

    assert ceilings["retained_logical_scanner_canaries"] == 9
    assert ceilings["new_logical_scanner_processes_maximum"] == 35
    assert ceilings["cumulative_logical_scanner_processes_maximum"] == 44
    assert ceilings["maximum_cumulative_data_bytes"] == 20 * 1024**3
    zero_fields = (
        "network_uploads", "provider_calls", "provider_reported_tokens",
        "provider_cost_usd", "repository_code_executions", "dependency_resolutions",
        "dependency_installations", "agentic_runs", "production_store_reads",
        "production_store_mutations", "schema_migrations", "assessments", "labels",
        "model_training_runs", "rescoring_runs", "human_finding_reviews",
        "workspace_branch_or_index_operations", "commits", "merges", "pushes",
        "lifecycle_changes",
    )
    assert all(ceilings[field] == 0 for field in zero_fields)


def test_receipt_requires_exact_fresh_authorization():
    payload = _payload()
    statement = payload["authorization"]["required_statement"]

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert "accepting only the installed OSV Scanner 2.4.0 binary" in statement
    assert "35 new and 44 cumulative logical scanner processes" in statement
    assert "no tool installation or downgrade" in statement
    assert "The remaining six primaries and all reserves" in statement

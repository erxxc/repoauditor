from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / (
    "docs/optimizations/"
    "opt-010-prospective-acquisition-instrument-qualification-wave-1-"
    "receipt-2026-08-19.json"
)


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_receipt_binds_frozen_selection_design_and_protocol():
    inputs = _payload()["frozen_inputs"]

    for key in (
        "source_selection_result",
        "protected_cohort_design",
        "baseline_comparison_protocol",
    ):
        binding = inputs[key]
        assert _sha256(ROOT / binding["path"]) == binding["sha256"]

    assert inputs["production_store"]["access"] == "before-and-after-hash-only"


def test_wave_is_exactly_first_primary_per_six_frozen_languages():
    wave = _payload()["protected_wave"]
    subjects = wave["subjects"]

    assert [item["order"] for item in subjects] == [1, 2, 3, 4, 5, 6]
    assert [item["language"] for item in subjects] == [
        "Python",
        "TypeScript",
        "Go",
        "Java",
        "Ruby",
        "Rust",
    ]
    assert len({item["repository"].split("/", 1)[0].casefold() for item in subjects}) == 6
    assert all(len(item["exact_commit"]) == 40 for item in subjects)
    assert wave["architecture_map_slot_rule"].startswith(
        "Record architecture_map_sha256 as pending-separate-provider-authorization"
    )


def test_receipt_binds_scanners_retrieval_and_structural_instruments():
    implementation = _payload()["frozen_implementation"]
    historically_frozen_but_later_extended = {
        "scanner_canaries",
        "scanner_execution_inventory",
    }

    for key, binding in implementation.items():
        expected = binding.get("sha256", binding.get("file_sha256"))
        assert expected is not None, key
        if key not in historically_frozen_but_later_extended:
            assert _sha256(ROOT / binding["path"]) == expected

    # These values remain immutable receipt-time evidence. The current production files
    # are independently exercised by scanner capability and canary tests after the
    # separately authorized weak-RNG extension.
    assert implementation["scanner_canaries"]["sha256"] == (
        "8e93fcb7c568cc32f7d0c00062d24b01e98279d8370e49f933459f262012d497"
    )
    assert implementation["scanner_execution_inventory"]["sha256"] == (
        "582ee2c12f75d340bf1fdc50b4d1d9fa684b95c8742570ad9fe583739c6b7d77"
    )

    runtime = _payload()["runtime_and_preflight_contract"]
    assert runtime["semgrep_version"] == "1.170.0"
    assert runtime["pip_audit_version"] == "2.10.1"
    assert runtime["osv_scanner_version"] == "2.3.8"
    assert runtime["gitleaks_version"] == "8.30.1"
    assert "SEMGREP_LOG_FILE" in " ".join(runtime["requirements"])
    assert "SEMGREP_VERSION_CACHE_PATH" in " ".join(runtime["requirements"])


def test_qualification_is_aggregate_only_and_retains_terminal_failures():
    contract = _payload()["acquisition_and_qualification_contract"]

    assert contract["scanners"] == [
        "semgrep",
        "semgrep-supplemental",
        "gitleaks",
        "pip-audit",
        "osv-scanner",
    ]
    assert "failed" in contract["terminal_states"]
    assert "timed_out" in contract["terminal_states"]
    assert "budget_exhausted" in contract["terminal_states"]
    assert "no finding identity" in contract["artifact_rule"]
    assert "do not infer a mechanism from scanner output" in contract["verifier_eligibility"]


def test_resource_boundary_has_zero_live_store_review_and_git_activity():
    ceilings = _payload()["resource_ceilings"]

    assert ceilings["repositories_materialized"] == 6
    assert ceilings["scanner_processes_maximum"] == 35
    assert ceilings["maximum_new_data_bytes"] == 20 * 1024**3
    assert ceilings["allowed_network_hosts"] == [
        "github.com",
        "pypi.org",
        "api.osv.dev",
        "osv.dev",
    ]
    zero_fields = (
        "network_uploads",
        "provider_calls",
        "provider_reported_tokens",
        "provider_cost_usd",
        "repository_code_executions",
        "dependency_installations",
        "agentic_falsification_runs",
        "production_store_reads",
        "production_store_mutations",
        "schema_migrations",
        "assessments_written",
        "labels_written",
        "model_training_runs",
        "rescoring_runs",
        "human_finding_reviews",
        "source_commits",
        "merge_commits",
        "remote_pushes",
        "branch_or_index_operations",
        "lifecycle_changes",
    )
    assert all(ceilings[field] == 0 for field in zero_fields)


def test_receipt_requires_exact_fresh_authorization():
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "only unslothai/unsloth" in statement
    assert "35 scanner processes" in statement
    assert "20 GiB new data" in statement
    assert "architecture recovery" in statement
    assert "OPT-036 use or change" in statement

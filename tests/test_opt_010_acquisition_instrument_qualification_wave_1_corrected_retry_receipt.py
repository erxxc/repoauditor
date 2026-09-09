from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / (
    "docs/optimizations/"
    "opt-010-prospective-acquisition-instrument-qualification-wave-1-"
    "corrected-retry-receipt-2026-08-19.json"
)


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_retry_binds_and_preserves_the_stopped_attempt():
    retained = _payload()["retained_stopped_attempt"]

    for key in ("original_receipt", "stopped_result"):
        binding = retained[key]
        assert _sha256(ROOT / binding["path"]) == binding["sha256"]
    assert retained["stopped_result_test"]["sha256"] == (
        "9d0ec3e206a6a9fc953be99417ee2d80dfdf5973309dcd9c945fe4889c725290"
    )
    assert retained["accepted_state"]["offline_canaries_passed"] == 3
    assert retained["accepted_state"]["pip_audit_canary_failed"] == 1
    assert retained["accepted_state"]["repositories_materialized"] == 0


def test_only_correction_is_no_resolution_pip_audit():
    correction = _payload()["only_instrument_correction"]

    assert correction["pip_audit_version"] == "2.10.1"
    assert correction["exact_invocation"] == [
        "pip-audit",
        "--disable-pip",
        "--no-deps",
        "-r",
        "$MANIFEST",
        "-f",
        "json",
        "--progress-spinner",
        "off",
    ]
    assert correction["dependency_resolution"] is False
    assert correction["dependency_installation"] is False
    assert correction["fallback"] is False
    assert correction["retry_inside_attempt"] is False


def test_retry_retains_exact_six_sources_and_pending_architecture_slot():
    scope = _payload()["retained_frozen_scope"]

    assert len(scope["subjects"]) == 6
    assert len({repository.split("/", 1)[0].casefold() for repository, _ in scope["subjects"]}) == 6
    assert all(len(commit) == 40 for _, commit in scope["subjects"])
    assert scope["languages"] == [
        "Python",
        "TypeScript",
        "Go",
        "Java",
        "Ruby",
        "Rust",
    ]
    assert scope["architecture_map_slot"] == "pending-separate-provider-authorization"


def test_retry_requires_fresh_runtime_and_all_separated_canaries():
    runtime = _payload()["corrected_runtime"]
    joined = " ".join(runtime["requirements"])

    assert runtime["must_be_absent_before_authorization"] is True
    assert runtime["semgrep_version"] == "1.170.0"
    assert "Rerun separated offline Semgrep" in joined
    assert "corrected no-resolution pip-audit canary" in joined
    assert "unchanged OSV canary" in joined


def test_retry_counts_resources_cumulatively_and_keeps_prohibited_activity_zero():
    ceilings = _payload()["resource_ceilings"]

    assert ceilings["retained_logical_scanner_canaries"] == 4
    assert ceilings["new_logical_scanner_processes_maximum"] == 35
    assert ceilings["cumulative_logical_scanner_processes_maximum"] == 39
    assert ceilings["maximum_cumulative_data_bytes"] == 20 * 1024**3
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
        "dependency_resolutions",
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
        "branch_or_index_operations",
        "source_commits",
        "merge_commits",
        "remote_pushes",
        "lifecycle_changes",
    )
    assert all(ceilings[field] == 0 for field in zero_fields)


def test_retry_requires_exact_fresh_authorization():
    payload = _payload()
    statement = payload["authorization"]["required_statement"]

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert "three passed offline canaries, one failed pip-audit canary" in statement
    assert "--disable-pip and --no-deps" in statement
    assert "35 new and 39 cumulative logical scanner processes" in statement
    assert "The remaining six primaries and all reserves" in statement

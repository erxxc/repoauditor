from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / (
    "docs/optimizations/opt-010-prospective-source-selection-corrected-retry-receipt-2026-08-19.json"
)


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_retry_binds_retained_shortfall_without_selection_or_disclosure():
    retained = _payload()["retained_attempt"]

    for key in ("receipt", "result", "focused_test"):
        binding = retained[key]
        assert _sha256(ROOT / binding["path"]) == binding["sha256"]
    assert retained["candidate_metadata_identities_inspected"] == 40
    assert retained["structurally_eligible_identities"] == 8
    assert retained["selected_or_disclosed_identities"] == 0
    assert retained["exact_commit_resolutions"] == 0


def test_corrected_queries_apply_age_and_maintenance_before_truncation():
    correction = _payload()["only_query_correction"]
    queries = correction["queries"]

    assert len(queries) == 6
    assert sum(item["per_page"] for item in queries) == 40
    assert {item["language"] for item in queries} == {
        "Python", "TypeScript", "Go", "Java", "Ruby", "Rust"
    }
    assert all("created:<=2024-08-18" in item["q"] for item in queries)
    assert all("pushed:>=2025-08-19" in item["q"] for item in queries)
    assert correction["sort"] == "updated"
    assert correction["order"] == "desc"
    assert correction["no_relaxation"] is True


def test_retry_preserves_exact_selection_and_no_partial_shortfall_contract():
    resolution = _payload()["selected_metadata_resolution"]

    assert resolution["selected_identities_required"] == 16
    assert resolution["primary"] == 12
    assert resolution["reserve"] == 4
    assert "disclose no partial identity" in resolution["shortfall_rule"]


def test_retry_counts_retained_and_corrected_resources_cumulatively():
    ceilings = _payload()["resource_ceilings"]

    assert ceilings["candidate_metadata_identities_inspected_retained"] == 40
    assert ceilings["candidate_metadata_identities_inspected_corrected"] == 40
    assert ceilings["candidate_metadata_identities_inspected_cumulative"] == 80
    assert ceilings["network_reads_retained"] == 4
    assert ceilings["network_reads_corrected_maximum"] == 60
    assert ceilings["network_reads_cumulative_maximum"] == 64


def test_retry_has_zero_upload_provider_store_agentic_and_branch_activity():
    ceilings = _payload()["resource_ceilings"]
    zero_fields = (
        "network_uploads", "provider_calls", "provider_reported_tokens",
        "provider_cost_usd", "repository_materializations", "repository_code_executions",
        "scanner_processes", "agentic_falsification_runs", "production_store_reads",
        "production_store_mutations", "schema_migrations", "assessments_written",
        "labels_written", "model_training_runs", "rescoring_runs", "branch_operations",
        "source_commits", "merge_commits", "remote_pushes", "lifecycle_changes",
    )

    assert all(ceilings[field] == 0 for field in zero_fields)


def test_retry_requires_exact_fresh_authorization():
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "six frozen Python, TypeScript, Go, Java, Ruby, and Rust queries" in statement
    assert "created:<=2024-08-18" in statement
    assert "accepting the retained four-read" in statement
    assert "disclose no partial list" in statement

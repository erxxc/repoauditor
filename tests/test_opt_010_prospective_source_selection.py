from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-010-prospective-source-selection-result-2026-08-18.json"
STORE = ROOT / "data/repoauditor.db"


def _payload() -> dict:
    return json.loads(RESULT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_aggregate_filter_counts_close_without_identity_disclosure():
    payload = _payload()
    counts = payload["aggregate_filter_closure"]

    assert counts["inspected"] == 40
    assert counts["rejected_created_after_2024_08_18"] + counts[
        "rejected_missing_or_ambiguous_license_after_age_floor"
    ] + counts["passed_license_product_structure_and_prior_exposure_filters"] == 40
    assert counts["counts_close"] is True
    assert counts["shortfall"] == 8


def test_language_capacity_is_aggregate_and_totals_eight():
    languages = _payload()["aggregate_language_capacity_after_all_filters"]

    assert languages == {"Python": 2, "TypeScript": 2, "Go": 3, "Rust": 1, "total": 8}
    assert sum(value for key, value in languages.items() if key != "total") == languages["total"]


def test_shortfall_persists_no_partial_selection_or_exact_commits():
    selection = _payload()["selection"]

    assert selection["primary_identities_selected"] == 0
    assert selection["reserve_identities_selected"] == 0
    assert selection["selected_identities_disclosed"] == 0
    assert selection["partial_list_persisted"] is False
    assert selection["stable_identity_hashes_persisted"] == 0
    assert selection["exact_commits_persisted"] == 0


def test_result_recommends_query_correction_not_eligibility_relaxation():
    interpretation = _payload()["interpretation"]

    assert interpretation["data_absence_claim"] is False
    assert "not evidence" in interpretation["bounded_claim"]
    assert "creation-date ceiling directly" in interpretation["smallest_next_prerequisite"]
    assert interpretation["eligibility_floor_relaxation_recommended"] is False
    assert interpretation["source_ceiling_or_adequacy_threshold_selected"] is False


def test_network_and_store_remain_within_metadata_only_boundary():
    payload = _payload()
    discovery = payload["discovery"]

    assert discovery["network_reads"] == discovery["metadata_documents"] == 4
    assert discovery["candidate_metadata_identities_inspected"] == 40
    assert discovery["hosts_used"] == ["api.github.com"]
    assert discovery["other_hosts_used"] == 0
    assert discovery["README_documents_opened"] == 0
    assert discovery["exact_commit_resolutions"] == 0
    assert _sha256(STORE) == payload["store"]["before_sha256"]
    assert payload["store"]["byte_identical"] is True


def test_workspace_and_all_live_mutating_activity_are_unchanged():
    payload = _payload()

    assert payload["workspace"]["index_or_branch_changed"] is False
    assert payload["workspace"]["branch_before"] == payload["workspace"]["branch_after"] == "main"
    zero_fields = (
        "network_uploads", "provider_calls", "provider_reported_tokens",
        "provider_cost_usd", "repository_materializations", "repository_code_executions",
        "scanner_processes", "agentic_falsification_runs", "production_store_reads",
        "production_store_mutations", "schema_migrations", "assessments_written",
        "labels_written", "model_training_runs", "rescoring_runs", "branch_operations",
        "source_commits", "merge_commits", "remote_pushes", "lifecycle_changes",
    )
    assert all(payload["accounting"][field] == 0 for field in zero_fields)

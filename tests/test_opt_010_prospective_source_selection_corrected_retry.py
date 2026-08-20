from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / (
    "docs/optimizations/opt-010-prospective-source-selection-corrected-retry-result-2026-08-19.json"
)
STORE = ROOT / "data/repoauditor.db"


def _payload() -> dict:
    return json.loads(RESULT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_corrected_pool_filter_counts_close_and_supplies_sixteen():
    counts = _payload()["aggregate_filter_closure"]

    assert counts["inspected"] == 40
    assert counts["rejected_missing_or_ambiguous_license"] + counts[
        "rejected_non_product_or_template"
    ] + counts["rejected_prior_exposure"] + counts["eligible"] == 40
    assert counts["counts_close"] is True
    assert counts["eligible"] == counts["selected"] + counts["unselected_eligible"]
    assert counts["selected"] == 16


def test_selected_roles_languages_owners_and_identifiers_are_exact():
    selected = _payload()["selected_identities"]
    languages = Counter(item["primary_language"] for item in selected)
    owners = [item["repository"].split("/", 1)[0].lower() for item in selected]

    assert len(selected) == 16
    assert [item["order"] for item in selected] == list(range(1, 17))
    assert Counter(item["role"] for item in selected) == {"primary": 12, "reserve": 4}
    assert len(languages) == 6
    assert max(languages.values()) == 3
    assert len(owners) == len(set(owners))
    assert len({item["repository"].lower() for item in selected}) == 16
    assert len({item["exact_commit"] for item in selected}) == 16
    assert len({item["stable_identity_sha256"] for item in selected}) == 16


def test_stable_hashes_recompute_from_repository_and_exact_commit():
    for item in _payload()["selected_identities"]:
        material = (
            "opt-010-prospective-source-v1"
            + item["repository"].lower()
            + item["exact_commit"]
        ).encode()
        assert hashlib.sha256(material).hexdigest() == item["stable_identity_sha256"]


def test_selected_metadata_is_complete_and_prior_sources_are_absent():
    selected = _payload()["selected_identities"]
    repositories = {item["repository"].lower() for item in selected}

    assert "documenso/documenso" not in repositories
    assert "go-vikunja/vikunja" not in repositories
    for item in selected:
        assert len(item["exact_commit"]) == 40
        assert item["license"]
        assert item["README_path"].lower().endswith("readme.md")
        assert len(item["README_sha"]) == 40
        assert item["selection_basis"]
        assert item["pre_outcome_mechanism_hypotheses"]


def test_corrected_and_cumulative_network_accounting_stays_bounded():
    payload = _payload()
    corrected = payload["corrected_discovery"]
    cumulative = payload["cumulative_accounting"]

    assert corrected["repository_search_reads"] == 6
    assert corrected["eligible_exact_commit_reads"] == 28
    assert corrected["selected_README_metadata_reads"] == 16
    assert corrected["network_reads"] == 50
    assert cumulative["network_reads"] == cumulative["metadata_documents"] == 54
    assert cumulative["network_reads"] <= 64
    assert corrected["hosts_used"] == ["api.github.com"]
    assert corrected["other_hosts_used"] == 0


def test_store_workspace_and_all_live_activity_remain_unchanged():
    payload = _payload()

    assert _sha256(STORE) == payload["store"]["before_sha256"]
    assert payload["store"]["byte_identical"] is True
    assert payload["workspace"]["branch_before"] == payload["workspace"]["branch_after"] == "main"
    assert payload["workspace"]["index_or_branch_changed"] is False
    assert payload["workspace"]["OPT_036_used_or_changed"] is False
    zero_fields = (
        "network_uploads", "provider_calls", "provider_reported_tokens",
        "provider_cost_usd", "repository_materializations", "repository_code_executions",
        "scanner_processes", "agentic_falsification_runs", "production_store_reads",
        "production_store_mutations", "schema_migrations", "assessments_written",
        "labels_written", "model_training_runs", "rescoring_runs", "branch_operations",
        "source_commits", "merge_commits", "remote_pushes", "lifecycle_changes",
    )
    assert all(payload["cumulative_accounting"][field] == 0 for field in zero_fields)


def test_result_waits_for_owner_review_and_authorizes_no_acquisition():
    decision = _payload()["decision"]

    assert decision["result_state"] == "complete-awaiting-project-owner-source-review"
    assert decision["source_selection_complete"] is True
    assert decision["source_acquisition_authorized"] is False
    assert decision["reserve_activation_authorized"] is False
    assert decision["adequacy_threshold_selected"] is False
    assert decision["agentic_experiment_permitted"] is False

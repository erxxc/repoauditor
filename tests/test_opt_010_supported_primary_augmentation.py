from __future__ import annotations

import json
from pathlib import Path

import pytest

from repoauditor.eval.opt010_supported_primary_augmentation import (
    SUBJECTS,
    provisional_feasibility,
)


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-010-supported-primary-augmentation-result-2026-08-20.json"


def test_frozen_subjects_are_exactly_the_second_supported_primaries():
    assert [(item.order, item.language) for item in SUBJECTS] == [
        (7, "Python"),
        (8, "TypeScript"),
        (10, "Java"),
        (11, "Ruby"),
    ]
    assert len({item.repository.split("/", 1)[0].lower() for item in SUBJECTS}) == 4


def test_provisional_capacity_requires_all_families_and_capped_total():
    assert provisional_feasibility({"Python": 20, "TypeScript": 10, "Java": 5, "Ruby": 5})
    assert not provisional_feasibility({"Python": 40, "TypeScript": 1, "Java": 1, "Ruby": 1})
    assert not provisional_feasibility({"Python": 20, "TypeScript": 20, "Java": 1, "Ruby": 0})
    assert not provisional_feasibility({"Python": 20, "TypeScript": 20, "Java": 1})


def test_result_is_aggregate_outcome_blind_and_within_boundaries():
    if not RESULT.exists():
        pytest.skip("authorized result not yet written")
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    assert payload["status"] in {
        "completed-evidence-nonqualifying-preflight-deviation",
        "stopped-before-aggregate-screen",
    }
    assert payload["augmentation"]["go_rust_or_reserve_sources_activated"] == 0
    assert payload["decision"]["packet_frozen"] is False
    assert payload["decision"]["paired_execution_started"] is False
    assert payload["decision"]["g03b_decided"] is False
    assert payload["decision"]["g04_decided"] is False
    assert payload["decision"]["opt010_status_changed"] is False
    assert payload["decision"]["receipt_qualified"] is False
    assert payload["preflight_chronology"]["receipt_stop_condition_triggered"] is True
    accounting = payload["resource_accounting"]
    assert accounting["logical_scanner_processes"] <= 12
    assert accounting["new_data_bytes"] <= 15 * 1024**3
    for field in (
        "network_uploads",
        "provider_calls",
        "provider_reported_tokens",
        "keychain_or_credential_reads",
        "repository_code_executions",
        "dependency_resolutions_or_installations",
        "other_scanner_processes",
        "production_store_reads",
        "production_store_mutations",
        "human_reviews",
        "outcomes_read",
        "assessments",
        "labels",
        "model_training_runs",
        "rescoring_runs",
        "agentic_or_baseline_runs",
        "workspace_branch_or_index_mutations",
        "commits",
        "merges",
        "pushes",
        "lifecycle_changes",
    ):
        assert accounting[field] == 0
    assert payload["production_store"]["byte_identical"] is True

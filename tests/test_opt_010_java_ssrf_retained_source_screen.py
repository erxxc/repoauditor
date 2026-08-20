from __future__ import annotations

import json
from pathlib import Path

import pytest

from repoauditor.eval.opt010_java_ssrf_retained_source_screen import combined_capacity


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "data/artifacts/opt010-java-ssrf-retained-source-screen/screen-artifact.json"
RESULT = ROOT / "docs/optimizations/opt-010-java-ssrf-retained-source-screen-result-2026-08-20.json"


def test_combined_capacity_preserves_ruby_zero_and_never_constructs_packet():
    zero = combined_capacity(0, 0)
    assert zero["capped_packet_capacity"] == 39
    assert zero["supported_families_contributing"] == 2
    assert zero["provisionally_feasible"] is False
    recovered = combined_capacity(25, 25)
    assert recovered["by_supported_family"] == {
        "Java": 25,
        "Python": 29,
        "Ruby": 0,
        "TypeScript": 19,
    }
    assert recovered["capped_packet_capacity"] == 59
    assert recovered["supported_families_contributing"] == 3
    assert recovered["provisionally_feasible"] is False


def test_combined_capacity_adds_only_java_counts_to_frozen_base():
    aggregate = combined_capacity(7, 5)
    assert aggregate["metadata_compatible_results"] == 64
    assert aggregate["metadata_deduplicated_issue_groups"] == 53
    assert aggregate["by_mechanism"] == {
        "command_injection": 30,
        "sql_injection": 18,
        "ssrf": 5,
        "unsafe_deserialization": 0,
    }


def test_screen_result_is_aggregate_only_and_packet_free():
    if not RESULT.exists():
        pytest.skip("authorized retained Java source-screen result not yet written")
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert result["status"] in {
        "completed-outcome-blind-java-cell-recovered",
        "completed-negative-java-and-ruby-source-scarcity",
    }
    assert result["combined_capacity"]["provisionally_feasible"] is False
    assert result["combined_capacity"]["by_supported_family"]["Ruby"] == 0
    assert artifact["frozen_subjects_verified"] == 2
    assert artifact["scanner_executions_valid"] == 2
    assert artifact["normalized_candidate_or_issue_group_identities_persisted_or_disclosed"] == 0
    assert artifact["subject_level_counts_persisted_or_disclosed"] == 0
    assert artifact["packet_constructed"] is False
    assert result["boundaries"]["packet_constructed"] is False


def test_screen_has_exact_process_counts_zero_external_activity_and_unchanged_state():
    if not RESULT.exists():
        pytest.skip("authorized retained Java source-screen result not yet written")
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    accounting = result["resource_accounting"]
    assert accounting["frozen_snapshot_subjects"] == 2
    assert accounting["runtime_import_checks"] == 1
    assert accounting["logical_scanner_processes"] == 2
    assert accounting["new_data_bytes"] <= 10 * 1024**2
    assert accounting["elapsed_seconds"] <= 30 * 60
    for field, value in accounting.items():
        if field not in {
            "frozen_snapshot_subjects",
            "runtime_import_checks",
            "logical_scanner_processes",
            "new_data_bytes",
            "elapsed_seconds",
        }:
            assert value in {0, 0.0}
    assert result["production_supplemental_ruleset"]["byte_identical"] is True
    assert result["production_store"]["byte_identical"] is True

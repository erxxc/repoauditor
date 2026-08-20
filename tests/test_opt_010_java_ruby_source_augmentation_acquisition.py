from __future__ import annotations

import json
from pathlib import Path

import pytest

from repoauditor.eval.opt010_java_ruby_source_augmentation_acquisition import (
    SUBJECTS,
    combined_capacity,
    validate_java_sarif,
    validate_java_scratch_configuration,
)


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-010-java-ruby-source-augmentation-acquisition-screen-final-retry-result-2026-08-20.json"
ARTIFACT = ROOT / "data/artifacts/opt010-java-ruby-source-augmentation-acquisition-screen-final-retry/aggregate-artifact.json"


def test_frozen_subjects_are_exactly_two_java_and_two_ruby():
    assert [(item.order, item.language) for item in SUBJECTS] == [
        (1, "Java"), (2, "Java"), (3, "Ruby"), (4, "Ruby")
    ]
    assert len({item.repository.split("/", 1)[0].lower() for item in SUBJECTS}) == 4


def test_capacity_requires_both_new_families_and_fixed_floor():
    assert combined_capacity(1, 1, 1, 1)["provisionally_feasible"] is True
    assert combined_capacity(20, 20, 0, 0)["provisionally_feasible"] is False
    assert combined_capacity(0, 0, 20, 20)["provisionally_feasible"] is False
    assert combined_capacity(1, 1, 1, 1)["capped_packet_capacity"] == 41


def test_java_json_rule_and_retained_sarif_validate_without_yaml_text_count():
    rule = json.loads(
        (ROOT / "data/artifacts/opt010-java-ssrf-supplemental-qualification/candidate-rule.json").read_text()
    )
    sarif = json.loads(
        (ROOT / "data/artifacts/opt010-java-ruby-source-augmentation-acquisition-screen-corrected-retry/canary-scans/01/semgrep.sarif").read_text()
    )
    assert validate_java_scratch_configuration(rule) is True
    assert validate_java_sarif(sarif) is True
    rule["rules"][0]["id"] = "different-rule"
    assert validate_java_scratch_configuration(rule) is False
    sarif["runs"][0]["results"][0]["ruleId"] = "different-rule"
    assert validate_java_sarif(sarif) is False


def test_completed_result_is_aggregate_only_and_bounded():
    if not RESULT.exists():
        pytest.skip("corrected retry result not yet written")
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    accounting = payload["resource_accounting"]
    assert accounting["runtime_import_checks"] <= 2
    assert accounting["logical_scanner_processes"] <= 9
    assert accounting["repositories_materialized"] <= 4
    assert accounting["retrieval_index_builds"] <= 4
    assert accounting["new_data_bytes"] <= 15 * 1024**3
    assert accounting["network_hosts_used"] in ([], ["github.com"])
    for field, value in accounting.items():
        if field not in {
            "elapsed_seconds", "new_data_bytes", "runtime_import_checks",
            "logical_scanner_processes", "repositories_materialized",
            "retrieval_index_builds", "network_hosts_used",
        }:
            assert value in {0, 0.0}
    assert payload["decision"]["candidate_or_issue_group_identities_persisted_or_disclosed"] == 0
    assert payload["decision"]["subject_level_finding_counts_persisted_or_disclosed"] == 0
    assert payload["decision"]["packet_constructed"] is False
    assert payload["decision"]["g03b_decided"] is False
    assert payload["decision"]["g04_decided"] is False
    assert payload["production_store"]["byte_identical"] is True
    assert payload["production_supplemental_ruleset"]["byte_identical"] is True


def test_completed_artifact_contains_no_identity_list_or_packet():
    if not ARTIFACT.exists():
        pytest.skip("aggregate artifact not written on stopped retry")
    payload = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert payload["candidate_or_issue_group_identities_persisted_or_disclosed"] == 0
    assert payload["subject_level_finding_counts_persisted_or_disclosed"] == 0
    assert payload["packet_constructed"] is False
    assert "identities" not in payload
    assert "packet" not in payload

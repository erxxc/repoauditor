from __future__ import annotations

import json
from pathlib import Path

from repoauditor.eval.opt010_paired_wave import (
    Candidate,
    CWE_MAPPING,
    deduplicate,
    mechanism_from_rule_properties,
    select_packet,
)


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-010-outcome-blind-packet-paired-run-result-2026-08-20.json"
SHORTFALL = ROOT / "data/artifacts/opt010-outcome-blind-packet-paired-run/packet-shortfall.json"
PACKET = ROOT / "data/artifacts/opt010-outcome-blind-packet-paired-run/packet.json"


def _candidate(identity: str, start: int, end: int) -> Candidate:
    return Candidate(
        identity=identity,
        subject="a" * 64,
        language="Python",
        scanner="semgrep",
        rule="frozen-rule",
        path="app.py",
        line_start=start,
        line_end=end,
        mechanism="sql_injection",
    )


def test_rule_metadata_is_the_only_mechanism_source():
    assert mechanism_from_rule_properties({"tags": ["CWE-89: SQL Injection"]}) == "sql_injection"
    assert mechanism_from_rule_properties({"tags": ["CWE-77", "CWE-78"]}) == "command_injection"
    assert mechanism_from_rule_properties({"tags": ["CWE-89", "CWE-918"]}) is None
    assert mechanism_from_rule_properties({"message": "CWE-89"}) == "sql_injection"
    assert mechanism_from_rule_properties({}) is None
    assert set(CWE_MAPPING) == {"CWE-77", "CWE-78", "CWE-89", "CWE-502", "CWE-918"}


def test_issue_group_deduplication_is_transitive_and_stable():
    groups = deduplicate([
        _candidate("c", 8, 10),
        _candidate("a", 1, 5),
        _candidate("b", 5, 8),
        _candidate("d", 20, 21),
    ])
    assert [(item.line_start, item.line_end, item.member_count) for item in groups] == [
        (20, 21, 1),
        (1, 10, 3),
    ] or [(item.line_start, item.line_end, item.member_count) for item in groups] == [
        (1, 10, 3),
        (20, 21, 1),
    ]
    assert len({item.identity for item in groups}) == 2


def test_selection_fails_closed_on_shortfall():
    assert select_packet(deduplicate([_candidate("a", 1, 1)])) is None


def test_result_records_only_aggregate_shortfall_and_zero_live_activity():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    shortfall = json.loads(SHORTFALL.read_text(encoding="utf-8"))
    assert payload["status"] == "stopped-aggregate-packet-shortfall"
    assert payload["packet"]["complete"] is False
    assert payload["packet"]["metadata_compatible_results"] == 36
    assert payload["packet"]["metadata_deduplicated_issue_groups"] == 30
    assert payload["packet"]["verifier_constructible_results"] == 25
    assert payload["packet"]["eligible_issue_groups"] == 19
    assert payload["packet"]["supported_families_with_eligible_groups"] == 1
    assert payload["packet"]["partial_packet_persisted_or_disclosed"] is False
    assert shortfall["complete_packet_frozen"] is False
    assert not PACKET.exists()
    accounting = payload["resource_accounting"]
    for field in (
        "provider_attempts",
        "public_source_transmissions",
        "provider_reported_tokens",
        "network_reads_or_uploads",
        "keychain_or_credential_reads",
        "production_store_reads",
        "production_store_mutations",
        "scanner_processes",
        "human_reviews",
        "outcomes_read",
        "assessments",
        "labels",
        "model_training_runs",
        "rescoring_runs",
        "workspace_branch_or_index_mutations",
        "lifecycle_changes",
    ):
        assert accounting[field] == 0
    assert payload["production_store"]["byte_identical"] is True
    assert payload["gates"] == {
        "g03b_decided": False,
        "g04_empirical_decided": False,
        "opt010_status_changed": False,
    }

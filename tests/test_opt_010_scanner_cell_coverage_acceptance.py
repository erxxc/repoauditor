from __future__ import annotations

import json
from pathlib import Path

import pytest

from repoauditor.eval.opt010_scanner_cell_coverage_acceptance import (
    classify_cell,
    supported_cells_match,
)


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "data/artifacts/opt010-java-ruby-scanner-cell-coverage/acceptance-artifact.json"
RESULT = ROOT / "docs/optimizations/opt-010-java-ruby-scanner-cell-coverage-corrected-acceptance-result-2026-08-20.json"


def test_corrected_acceptance_classification_is_fail_closed():
    assert classify_cell(positive_valid=True, clean_valid=True, positive_mapped=1, clean_mapped=0) == "qualified-detectable"
    assert classify_cell(positive_valid=True, clean_valid=True, positive_mapped=0, clean_mapped=0) == "coverage-gap"
    assert classify_cell(positive_valid=True, clean_valid=True, positive_mapped=1, clean_mapped=1) == "clean-control-failure"
    assert classify_cell(positive_valid=False, clean_valid=True, positive_mapped=0, clean_mapped=0) == "scanner-or-provenance-failure"


def test_supported_cell_comparison_preserves_membership_but_ignores_list_order():
    frozen = {
        "Java": ["ssrf"],
        "Python": ["command_injection", "sql_injection", "ssrf"],
        "Ruby": ["unsafe_deserialization"],
        "TypeScript": ["command_injection", "ssrf"],
    }
    reordered = {
        "Python": ["command_injection", "ssrf", "sql_injection"],
        "TypeScript": ["ssrf", "command_injection"],
        "Java": ["ssrf"],
        "Ruby": ["unsafe_deserialization"],
    }
    assert supported_cells_match(frozen, reordered) is True
    assert supported_cells_match(frozen, {**reordered, "Go": []}) is False
    assert supported_cells_match(frozen, {**reordered, "Java": ["ssrf", "sql_injection"]}) is False


def test_corrected_acceptance_result_is_exact_bounded_and_negative():
    if not RESULT.exists():
        pytest.skip("authorized corrected acceptance result not yet written")
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert result["status"] == "completed-negative-corrected-offline-acceptance"
    assert result["acceptance"] == {
        "retained_bindings_verified": True,
        "exact_classification_reproduction": True,
        "completed_negative": True,
        "next_prerequisite": "supplemental-rule-qualification-prerequisite",
    }
    assert artifact["exact_reproduction"] is True
    assert artifact["reproduced"]["cells"] == artifact["expected"]["cells"]
    assert artifact["reproduced"]["supplemental_applicability"] == artifact["expected"]["supplemental_applicability"]
    assert artifact["reproduced"]["routing"] == artifact["expected"]["routing"]
    assert artifact["original_result_edited_or_requalified"] is False
    assert result["original_evidence"]["original_result_remains_nonqualifying"] is True
    assert result["routing"] == "supplemental-rule-qualification-prerequisite"


def test_corrected_acceptance_has_zero_live_activity_and_unchanged_store():
    if not RESULT.exists():
        pytest.skip("authorized corrected acceptance result not yet written")
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    accounting = result["resource_accounting"]
    assert accounting["retained_evidence_bytes"] == 7_841_236
    assert accounting["retained_evidence_bytes"] <= 8 * 1024**2
    assert accounting["new_data_bytes"] <= 1 * 1024**2
    assert accounting["elapsed_seconds"] <= 10 * 60
    for field, value in accounting.items():
        if field not in {"retained_evidence_bytes", "new_data_bytes", "elapsed_seconds"}:
            assert value in {0, 0.0}
    assert artifact["runtime_import_checks"] == 0
    assert artifact["scanner_or_canary_processes"] == 0
    assert artifact["repository_or_source_reads"] == 0
    assert artifact["finding_identities_persisted_or_disclosed"] == 0
    assert result["production_store"]["byte_identical"] is True
    assert result["gates"] == {
        "packet_frozen": False,
        "paired_execution_started": False,
        "g03b_decided": False,
        "g04_decided": False,
        "opt010_status_changed": False,
    }

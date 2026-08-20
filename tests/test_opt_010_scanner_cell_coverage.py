from __future__ import annotations

import json
from pathlib import Path

import pytest

from repoauditor.eval.opt010_scanner_cell_coverage import (
    FIXTURE_SET_SHA256,
    classify_cell,
    fixture_set_digest,
    route,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "data/artifacts/opt010-java-ruby-scanner-cell-coverage/fixture-manifest.json"
ARTIFACT = ROOT / "data/artifacts/opt010-java-ruby-scanner-cell-coverage/coverage-artifact.json"
RESULT = ROOT / "docs/optimizations/opt-010-java-ruby-scanner-cell-coverage-result-2026-08-20.json"


def test_fixture_manifest_is_frozen_before_scanning():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["frozen_before_runtime_import_or_scanner_activity"] is True
    assert manifest["fixture_set_sha256"] == FIXTURE_SET_SHA256
    assert fixture_set_digest(manifest["fixtures"]) == FIXTURE_SET_SHA256
    assert len(manifest["fixtures"]) == 4


def test_cell_classification_is_fail_closed():
    assert classify_cell(positive_valid=True, clean_valid=True, positive_mapped=1, clean_mapped=0) == "qualified-detectable"
    assert classify_cell(positive_valid=True, clean_valid=True, positive_mapped=0, clean_mapped=0) == "coverage-gap"
    assert classify_cell(positive_valid=True, clean_valid=True, positive_mapped=1, clean_mapped=1) == "clean-control-failure"
    assert classify_cell(positive_valid=False, clean_valid=True, positive_mapped=0, clean_mapped=0) == "scanner-or-provenance-failure"


def test_routing_prefers_failure_then_gap_then_source_scarcity():
    assert route(["qualified-detectable", "qualified-detectable"]) == "source-scarcity-diagnosis"
    assert route(["qualified-detectable", "coverage-gap"]) == "supplemental-rule-qualification-prerequisite"
    assert route(["coverage-gap", "clean-control-failure"]) == "stop-instrument-audit-failure"


def test_result_is_synthetic_aggregate_and_zero_live_external_activity():
    if not RESULT.exists():
        pytest.skip("authorized coverage result not yet written")
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert result["status"] == "stopped-nonqualifying-new-data-ceiling-exceeded"
    assert result["boundary"] == {
        "ceiling_bytes": 2 * 1024**2,
        "observed_bytes": 7841236,
        "receipt_qualified": False,
        "retained_evidence_use": "descriptive-non-qualifying-only",
        "stop_reason": "new-data-ceiling-exceeded",
    }
    assert {item["cell"] for item in result["cells"]} == {
        "Java:ssrf",
        "Ruby:unsafe_deserialization",
    }
    assert result["supplemental_semgrep"] == {
        "java": "not-applicable",
        "ruby": "not-applicable",
        "processes": 0,
    }
    assert artifact["retained_canaries_verified_without_rerun"] is True
    assert artifact["production_or_repository_source_access"] == 0
    assert result["gates"] == {
        "packet_frozen": False,
        "architecture_recovery_started": False,
        "g03b_decided": False,
        "g04_decided": False,
        "opt010_status_changed": False,
    }
    accounting = result["resource_accounting"]
    assert accounting["logical_scanner_processes"] == 4
    assert accounting["new_data_bytes"] > 2 * 1024**2
    assert accounting["elapsed_seconds"] <= 10 * 60
    for field, value in accounting.items():
        if field not in {"logical_scanner_processes", "new_data_bytes", "elapsed_seconds"}:
            assert value in {0, 0.0}
    assert result["production_store"]["byte_identical"] is True

from __future__ import annotations

import json
from pathlib import Path

import pytest

from repoauditor.eval.opt010_supported_primary_augmentation_acceptance import reproduce


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "data/artifacts/opt010-supported-primary-augmentation/acceptance-artifact.json"
RESULT = ROOT / "docs/optimizations/opt-010-supported-primary-augmentation-corrected-acceptance-result-2026-08-20.json"


def test_empty_retained_subject_set_reproduces_a_negative_zero_aggregate():
    aggregate = reproduce([])
    assert aggregate["metadata_compatible_results"] == 0
    assert aggregate["metadata_deduplicated_issue_groups"] == 0
    assert aggregate["supported_families_contributing"] == 0
    assert aggregate["capped_packet_capacity"] == 0
    assert aggregate["provisionally_feasible"] is False


def test_corrected_acceptance_result_is_exact_bounded_and_negative():
    if not RESULT.exists():
        pytest.skip("authorized corrected acceptance result not yet written")
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert result["status"] == "completed-negative-corrected-offline-acceptance"
    assert result["acceptance"] == {
        "retained_bindings_verified": True,
        "exact_aggregate_reproduction": True,
        "completed_negative": True,
        "architecture_and_verifier_gate_justified": False,
    }
    assert artifact["exact_reproduction"] is True
    assert artifact["aggregate"] == artifact["expected"]
    assert artifact["original_result_edited_or_requalified"] is False
    assert artifact["snapshot_source_files_opened"] == 0
    assert artifact["candidate_identities_persisted_or_disclosed"] == 0
    assert result["original_evidence"]["original_result_remains_nonqualifying"] is True
    assert result["gates"] == {
        "packet_frozen": False,
        "paired_execution_started": False,
        "g03b_decided": False,
        "g04_decided": False,
        "opt010_status_changed": False,
    }


def test_corrected_acceptance_has_zero_live_activity_and_unchanged_store():
    if not RESULT.exists():
        pytest.skip("authorized corrected acceptance result not yet written")
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    accounting = result["resource_accounting"]
    assert accounting["new_data_bytes"] <= 2 * 1024**2
    assert accounting["elapsed_seconds"] <= 10 * 60
    for field, value in accounting.items():
        if field not in {"new_data_bytes", "elapsed_seconds"}:
            assert value in {0, 0.0}
    assert result["production_store"]["byte_identical"] is True

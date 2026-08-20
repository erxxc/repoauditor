"""Frozen offline eligibility audit for the existing OPT-009 Lens cohort."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path

from repoauditor.eval.novelty_eligibility import build_audit


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "docs/optimizations/opt-009-eligibility-protocol-2026-08-12.json"
ARTIFACT = ROOT / "data/artifacts/opt009-eligibility-audit.json"
RESULT = ROOT / "docs/optimizations/opt-009-eligibility-audit-result-2026-08-12.json"
PRE_WAVE_STORE = ROOT / "data/backups/repoauditor-opt009-wave1.sqlite"


def test_protocol_preserves_outcome_blind_non_mutating_boundary():
    payload = json.loads(PROTOCOL.read_text(encoding="utf-8"))
    boundary = payload["outcome_blindness"]
    assert boundary == {
        "assessment_existence_may_be_read": True,
        "assessment_outcomes_may_be_read": False,
        "scores_ranks_severity_confidence_priors_may_be_read": False,
        "source_content_may_be_rendered": False,
        "selection_or_review_authorized": False,
    }
    assert "OPT-009 promotion or closure" in payload["excluded"]


def test_audit_is_reproducible_and_finds_no_eligible_existing_evidence():
    persisted = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    measured = build_audit(PRE_WAVE_STORE)
    # The artifact names the live path as it existed at capture time; the frozen
    # byte-identical backup is the reproducibility input after prospective mutation.
    measured["store"]["path"] = persisted["store"]["path"]
    assert measured == persisted
    assert persisted["inventory"]["source_lens_finding_records"] == 63
    assert persisted["inventory"]["previously_assessed_records"] == 2
    assert persisted["inventory"]["evidence_eligible_records"] == 0
    assert persisted["inventory"]["candidate_identities_emitted"] == 0
    assert persisted["gate"]["existing_cohort_can_supply_retrospective_pilot"] is False


def test_all_existing_lens_findings_are_protocol_development_only():
    payload = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert payload["inventory"]["category_counts"] == {
        "calibration_fixture": 60,
        "known_answer_pre_fix_fixture": 2,
        "protected_post_fix_holdout": 1,
    }
    assert sum(row["evidence_eligible_records"] for row in payload["cohorts"]) == 0
    assert all(
        row["protocol_development_only_records"] == row["finding_records"]
        for row in payload["cohorts"]
    )
    assert payload["accounting"] == {
        "network_reads": 0,
        "provider_calls": 0,
        "tokens": 0,
        "store_mutations": 0,
        "assessments_added": 0,
        "labels_added": 0,
        "models_trained": 0,
        "scores_read_or_written": 0,
    }


def test_result_binds_protocol_artifact_helper_and_unchanged_store():
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    for key in ("protocol", "audit_artifact", "helper"):
        record = payload[key]
        path = (RESULT.parent / record["path"]).resolve()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]
    store = payload["store"]
    assert store["byte_identical"] is True
    assert store["sha256_before"] == store["sha256_after"]
    assert payload["decision"]["opt_009_data_gate_cleared"] is False
    assert payload["decision"]["opt_009_status"] == "open-data-gated"
    assert all(payload["not_executed"].values())

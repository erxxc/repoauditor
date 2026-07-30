"""Frozen OPT-029 review-acquisition funnel contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from repoauditor.triage.acquisition_funnel import (
    AcquisitionFunnelCounts,
    AcquisitionIdentityInput,
    ReviewPathClass,
    ReviewPathTier,
    classify_review_path,
    exact_location_identity,
    pre_post_identity,
    repeated_family_identity,
    review_path_tier,
)

PROTOCOL = (
    Path(__file__).parents[1]
    / "docs"
    / "optimizations"
    / "opt-029-acquisition-funnel-protocol-2026-07-29.json"
)


def _candidate(**changes) -> AcquisitionIdentityInput:
    values = {
        "engagement": "repo-pre",
        "producer": "Semgrep Supplemental",
        "rule_id": "repoauditor.javascript.dynamic-shell",
        "file": "./src\\runner.ts",
        "line_start": 10,
        "line_end": 12,
        "sink": " execSync( command ) ",
    }
    values.update(changes)
    return AcquisitionIdentityInput(**values)


@pytest.mark.parametrize(
    ("path", "expected_class", "expected_tier"),
    [
        ("src/auth/login.py", ReviewPathClass.PRODUCTION, ReviewPathTier.PRIMARY),
        ("deploy/compose.yml", ReviewPathClass.DEPLOYMENT, ReviewPathTier.PRIMARY),
        (".github/workflows/scan.yml", ReviewPathClass.CI, ReviewPathTier.SUPPORTING),
        ("tests/security/test_auth.py", ReviewPathClass.TEST, ReviewPathTier.SUPPORTING),
        ("examples/session/app.js", ReviewPathClass.DOCS_EXAMPLES, ReviewPathTier.SUPPORTING),
        ("vendor/jquery/dist.js", ReviewPathClass.VENDOR_GENERATED, ReviewPathTier.DEFERRED),
        ("frontend/dist/app.js", ReviewPathClass.VENDOR_GENERATED, ReviewPathTier.DEFERRED),
    ],
)
def test_path_taxonomy_is_explicit(path, expected_class, expected_tier):
    path_class = classify_review_path(path)

    assert path_class is expected_class
    assert review_path_tier(path_class) is expected_tier


def test_identities_normalize_format_without_cross_location_semantic_collapse():
    original = _candidate()
    same_evidence_post = _candidate(
        engagement="repo-post",
        producer=" Semgrep Supplemental ",
        file="src/runner.ts",
        sink="execSync( command )",
    )
    another_location = _candidate(file="src/other.ts")
    case_distinct_path = _candidate(file="src/Runner.ts")

    assert pre_post_identity(original) == pre_post_identity(same_evidence_post)
    assert exact_location_identity(original) != exact_location_identity(
        same_evidence_post
    )
    assert exact_location_identity(original) != exact_location_identity(
        another_location
    )
    assert pre_post_identity(original) != pre_post_identity(case_distinct_path)
    assert repeated_family_identity(original) == repeated_family_identity(
        another_location
    )


def test_family_identity_does_not_use_outcome_severity_or_score():
    assert set(AcquisitionIdentityInput.__dataclass_fields__) == {
        "engagement",
        "producer",
        "rule_id",
        "file",
        "line_start",
        "line_end",
        "sink",
    }


def test_funnel_discloses_every_stage_delta():
    counts = AcquisitionFunnelCounts(
        raw=1941,
        after_pre_post_collapse=1100,
        after_exact_duplicate_collapse=1000,
        after_path_policy=800,
        after_family_cap=200,
        after_engagement_balance=100,
        selected=32,
    )

    assert counts.deferred_by_stage() == {
        "pre_post_collapse": 841,
        "exact_duplicate_collapse": 100,
        "path_policy": 200,
        "family_cap": 600,
        "engagement_balance": 100,
        "packet_limit": 68,
    }


def test_funnel_rejects_negative_or_non_monotonic_counts():
    with pytest.raises(ValueError, match="negative"):
        AcquisitionFunnelCounts(-1, 0, 0, 0, 0, 0, 0)
    with pytest.raises(ValueError, match="monotonic"):
        AcquisitionFunnelCounts(10, 11, 9, 8, 7, 6, 5)


def test_protocol_freezes_approved_scope_and_provenance_gap():
    protocol = json.loads(PROTOCOL.read_text(encoding="utf-8"))

    assert protocol["approval"]["selected_options"] == [
        "1A",
        "2A",
        "3A",
        "4A",
        "5A",
        "6A",
    ]
    assert protocol["scope_boundary"]["production_selection_changed_in_this_pr"] is False
    assert protocol["identity_contract"]["family_cap_per_engagement"] == 2
    assert protocol["representative_measurement"]["raw_candidate_count"] == 1331
    assert protocol["provenance_gap"]["final_audit_raw_candidate_count"] == 1941
    assert (
        "predicted outcome"
        in protocol["identity_contract"]["forbidden_identity_inputs"]
    )

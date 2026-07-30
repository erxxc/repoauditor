"""Stable, ground-truth-blind human-review acquisition planning."""

from __future__ import annotations

import json

import pytest

from repoauditor.store.models import (
    Finding,
    IngestedRepo,
    TriageAssessment,
    TriageAssessmentOutcome,
    TriageFeatureRecord,
    TriageLabel,
)
from repoauditor.triage.acquisition import (
    ReviewAcquisitionCandidate,
    ReviewAcquisitionPlan,
    build_review_acquisition_plan,
    load_review_acquisition_plan,
    render_review_acquisition_plan,
    render_review_packet,
)


def _finding(finding_id: int, repo_id: str) -> Finding:
    return Finding(
        id=finding_id,
        repo_id=repo_id,
        title=f"candidate {finding_id}",
        file=f"module_{finding_id}.py",
        line_start=finding_id,
        line_end=finding_id,
        citation_snippet=f"value_{finding_id}",
        source_tool="semgrep",
        confidence=0.5,
        severity="medium",
    )


def _finding_at(finding_id: int, repo_id: str, file: str) -> Finding:
    return _finding(finding_id, repo_id).model_copy(update={"file": file})


def _feature(
    finding_id: int,
    engagement: str,
    rule_id: str,
) -> TriageFeatureRecord:
    return TriageFeatureRecord(
        finding_id=finding_id,
        engagement=engagement,
        rule_id=rule_id,
        fingerprint=f"fingerprint-{finding_id}",
        features=[0.0],
        feature_names=["example"],
    )


def test_acquisition_prefers_least_reviewed_rules_and_round_robins_engagements(
    tmp_config, monkeypatch,
):
    features = [
        _feature(1, "repo-a", "reviewed-rule"),
        _feature(2, "repo-a", "new-rule-a"),
        _feature(3, "repo-a", "new-rule-b"),
        _feature(4, "repo-b", "new-rule-c"),
        _feature(5, "repo-b", "new-rule-c"),
        _feature(6, "repo-b", "assessed-rule"),
    ]
    labels = [
        TriageLabel(
            engagement="prior",
            rule_id="reviewed-rule",
            finding_fingerprint="prior-fingerprint",
            actionable=True,
        )
    ]
    assessments = [
        TriageAssessment(
            finding_id=6,
            engagement="repo-b",
            outcome=TriageAssessmentOutcome.UNCERTAIN,
            rationale="needs runtime evidence",
            analyst="analyst",
        )
    ]
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_features",
        lambda config=None: features,
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_labels",
        lambda config=None: labels,
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_assessments",
        lambda repo_id=None, config=None: assessments,
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_findings",
        lambda repo_id=None, config=None: [
            _finding(index, "repo-a" if index <= 3 else "repo-b")
            for index in range(1, 7)
        ],
    )

    first = build_review_acquisition_plan(
        tmp_config, limit=4, max_per_engagement=2
    )
    second = build_review_acquisition_plan(
        tmp_config, limit=4, max_per_engagement=2
    )

    assert first == second
    assert len(first.entries) == 4
    assert {item.engagement for item in first.entries} == {"repo-a", "repo-b"}
    assert all(item.finding_id != 6 for item in first.entries)
    repo_a = [item for item in first.entries if item.engagement == "repo-a"]
    assert {item.rule_id for item in repo_a} == {"new-rule-a", "new-rule-b"}
    assert all(item.prior_human_labels_for_rule == 0 for item in repo_a)
    assert first.evaluation_eligible is False
    assert "predicted classes" in first.selection_policy
    assert first.eligible_after_rule_cap == 5


def test_acquisition_json_exposes_policy_and_not_candidate_scores(
    tmp_config, monkeypatch,
):
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_features",
        lambda config=None: [_feature(1, "repo", "rule")],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_labels",
        lambda config=None: [],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_assessments",
        lambda repo_id=None, config=None: [],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_findings",
        lambda repo_id=None, config=None: [_finding(1, "repo")],
    )

    payload = json.loads(render_review_acquisition_plan(
        build_review_acquisition_plan(tmp_config, limit=1)
    ))

    assert payload["entries"][0]["finding_id"] == 1
    assert payload["entries"][0]["selection_hash"]
    assert payload["entries"][0]["surface"] == "production"
    assert "score" not in payload["entries"][0]
    assert payload["evaluation_eligible"] is False
    assert payload["schema_version"] == "triage-review-acquisition-v3"
    assert payload["funnel"] == {
        "after_engagement_balance": 1,
        "after_exact_duplicate_collapse": 1,
        "after_family_cap": 1,
        "after_path_policy": 1,
        "after_pre_post_collapse": 1,
        "raw": 1,
        "selected": 1,
    }
    assert payload["deferred_by_stage"] == {
        "engagement_balance": 0,
        "exact_duplicate_collapse": 0,
        "family_cap": 0,
        "packet_limit": 0,
        "path_policy": 0,
        "pre_post_collapse": 0,
    }
    assert payload["input_digest"]


def test_acquisition_accounts_for_declared_pairs_duplicates_paths_and_family_cap(
    tmp_config, monkeypatch,
):
    findings = [
        _finding(1, "repo-pre").model_copy(update={
            "file": "src/shared.py", "line_start": 10, "line_end": 10,
            "citation_snippet": "dangerous(value)",
        }),
        _finding(2, "repo-post").model_copy(update={
            "file": "src/shared.py", "line_start": 10, "line_end": 10,
            "citation_snippet": "dangerous(value)",
        }),
        _finding(3, "repo-pre").model_copy(update={
            "file": "src/shared.py", "line_start": 10, "line_end": 10,
            "citation_snippet": "dangerous(value)",
        }),
        _finding_at(4, "repo-pre", "vendor/library.js"),
        _finding(5, "repo-pre").model_copy(update={
            "file": "src/a.py", "citation_snippet": "repeat(value)",
        }),
        _finding(6, "repo-pre").model_copy(update={
            "file": "src/b.py", "citation_snippet": "repeat(value)",
        }),
        _finding(7, "repo-pre").model_copy(update={
            "file": "src/c.py", "citation_snippet": "repeat(value)",
        }),
    ]
    features = [
        _feature(1, "repo-pre", "stable-rule"),
        _feature(2, "repo-post", "stable-rule"),
        _feature(3, "repo-pre", "stable-rule"),
        _feature(4, "repo-pre", "vendor-rule"),
        _feature(5, "repo-pre", "family-rule"),
        _feature(6, "repo-pre", "family-rule"),
        _feature(7, "repo-pre", "family-rule"),
    ]
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_features",
        lambda config=None: features,
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_labels",
        lambda config=None: [],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_assessments",
        lambda repo_id=None, config=None: [],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_findings",
        lambda repo_id=None, config=None: findings,
    )

    plan = build_review_acquisition_plan(
        tmp_config,
        limit=10,
        max_per_engagement=10,
        pre_post_pairs=(("repo-pre", "repo-post"),),
    )

    assert plan.funnel is not None
    assert plan.funnel.raw == 7
    assert plan.funnel.after_pre_post_collapse == 6
    assert plan.funnel.after_exact_duplicate_collapse == 5
    assert plan.funnel.after_path_policy == 4
    assert plan.funnel.after_family_cap == 3
    assert plan.funnel.after_engagement_balance == 3
    assert plan.funnel.selected == 3
    assert plan.deferred_by_stage == {
        "pre_post_collapse": 1,
        "exact_duplicate_collapse": 1,
        "path_policy": 1,
        "family_cap": 1,
        "engagement_balance": 0,
        "packet_limit": 0,
    }
    assert plan.path_class_counts == {"production": 4, "vendor_generated": 1}
    assert len(plan.family_counts_before_cap or {}) == 2
    assert all(item.finding_id not in {2, 3, 4} for item in plan.entries)
    assert len({item.family_hash for item in plan.entries[:2]}) == 2


def test_acquisition_is_stable_under_input_reordering(tmp_config, monkeypatch):
    findings = [_finding(index, "repo") for index in range(1, 5)]
    features = [_feature(index, "repo", f"rule-{index}") for index in range(1, 5)]
    state = {"reversed": False}
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_features",
        lambda config=None: list(reversed(features)) if state["reversed"] else features,
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_labels",
        lambda config=None: [],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_assessments",
        lambda repo_id=None, config=None: [],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_findings",
        lambda repo_id=None, config=None: (
            list(reversed(findings)) if state["reversed"] else findings
        ),
    )

    first = build_review_acquisition_plan(tmp_config, limit=3)
    state["reversed"] = True
    second = build_review_acquisition_plan(tmp_config, limit=3)

    assert first == second


def test_acquisition_vendor_generated_paths_are_explicitly_requestable(
    tmp_config, monkeypatch,
):
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_features",
        lambda config=None: [_feature(1, "repo", "vendor-rule")],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_labels",
        lambda config=None: [],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_assessments",
        lambda repo_id=None, config=None: [],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_findings",
        lambda repo_id=None, config=None: [
            _finding_at(1, "repo", "vendor/library.js")
        ],
    )

    default = build_review_acquisition_plan(tmp_config, limit=1)
    included = build_review_acquisition_plan(
        tmp_config, limit=1, include_vendor_generated=True
    )

    assert default.entries == ()
    assert default.deferred_by_stage["path_policy"] == 1
    assert [item.finding_id for item in included.entries] == [1]
    assert "tier_3_vendor_generated" in included.included_path_tiers


def test_acquisition_excludes_saturated_rule_families(tmp_config, monkeypatch):
    labels = [
        TriageLabel(
            engagement=f"prior-{index}",
            rule_id="saturated",
            finding_fingerprint=f"prior-{index}",
            actionable=True,
        )
        for index in range(3)
    ]
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_features",
        lambda config=None: [
            _feature(1, "repo", "saturated"),
            _feature(2, "repo", "new-rule"),
        ],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_labels",
        lambda config=None: labels,
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_assessments",
        lambda repo_id=None, config=None: [],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_findings",
        lambda repo_id=None, config=None: [
            _finding(1, "repo"),
            _finding(2, "repo"),
        ],
    )

    plan = build_review_acquisition_plan(
        tmp_config,
        limit=2,
        max_prior_human_labels_per_rule=2,
    )

    assert [item.rule_id for item in plan.entries] == ["new-rule"]
    assert plan.available_unassessed == 2
    assert plan.eligible_after_rule_cap == 1


def test_acquisition_prioritizes_production_without_using_outcomes(
    tmp_config, monkeypatch
):
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_features",
        lambda config=None: [
            _feature(1, "repo-a", "ci-rule"),
            _feature(2, "repo-b", "production-rule"),
            _feature(3, "repo-b", "deployment-rule"),
        ],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_labels",
        lambda config=None: [],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_assessments",
        lambda repo_id=None, config=None: [],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_findings",
        lambda repo_id=None, config=None: [
            _finding_at(1, "repo-a", ".github/workflows/test.yml"),
            _finding_at(2, "repo-b", "src/service.py"),
            _finding_at(3, "repo-b", "Dockerfile"),
        ],
    )

    plan = build_review_acquisition_plan(
        tmp_config, limit=3, max_per_engagement=3
    )

    assert [item.surface for item in plan.entries] == [
        "production", "deployment", "supporting",
    ]
    assert [item.finding_id for item in plan.entries] == [2, 3, 1]


def test_review_packet_anchors_frozen_candidate_to_exact_snapshot(
    tmp_config, monkeypatch, tmp_path,
):
    feature = _feature(1, "repo", "rule")
    finding = _finding(1, "repo")
    commit = "abc123"
    source = tmp_config.paths.data_dir / "raw" / "repo" / commit / finding.file
    source.parent.mkdir(parents=True)
    source.write_text("\n".join(f"line {index}" for index in range(1, 12)) + "\n")
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_features",
        lambda config=None: [feature],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_labels",
        lambda config=None: [],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_assessments",
        lambda repo_id=None, config=None: [],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_findings",
        lambda repo_id=None, config=None: [finding],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_ingested_repos",
        lambda config=None, all_snapshots=False: [
            IngestedRepo(repo_id="repo", source="fixture", commit_hash=commit)
        ],
    )
    plan = build_review_acquisition_plan(tmp_config, limit=1)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(render_review_acquisition_plan(plan))

    loaded = load_review_acquisition_plan(plan_path)
    rendered = render_review_packet(loaded, tmp_config, context_lines=1)

    assert loaded == plan
    assert "## 1. Finding #1" in rendered
    assert f"- Snapshot: `{commit}`" in rendered
    assert f"- Source: `{finding.file}:1`" in rendered
    assert "1  line 1\n2  line 2" in rendered
    assert "--disposition <detailed-disposition>" in rendered
    assert "does not recommend a" in rendered


def test_review_packet_rejects_changed_frozen_evidence(tmp_config, monkeypatch):
    feature = _feature(1, "repo", "rule")
    finding = _finding(1, "repo")
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_triage_features",
        lambda config=None: [feature],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_findings",
        lambda repo_id=None, config=None: [finding.model_copy(update={"file": "changed.py"})],
    )
    monkeypatch.setattr(
        "repoauditor.triage.acquisition.db.list_ingested_repos",
        lambda config=None, all_snapshots=False: [],
    )
    packet_plan = ReviewAcquisitionPlan(
        schema_version="triage-review-acquisition-v1",
        selection_policy="test",
        evaluation_eligible=False,
        requested_limit=1,
        max_per_engagement=1,
        max_prior_human_labels_per_rule=5,
        existing_human_labels=0,
        available_unassessed=1,
        eligible_after_rule_cap=1,
        entries=(ReviewAcquisitionCandidate(
            finding_id=1,
            engagement="repo",
            rule_id="rule",
            fingerprint="fingerprint-1",
            title="candidate 1",
            file="module_1.py",
            line=1,
            prior_human_labels_for_rule=0,
            selection_hash="hash",
        ),),
        limitations=(),
    )

    with pytest.raises(ValueError, match="differs from stored evidence"):
        render_review_packet(packet_plan, tmp_config)

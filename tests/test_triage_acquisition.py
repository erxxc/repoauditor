"""Stable, ground-truth-blind human-review acquisition planning."""

from __future__ import annotations

import json

from repoauditor.store.models import (
    Finding,
    TriageAssessment,
    TriageAssessmentOutcome,
    TriageFeatureRecord,
    TriageLabel,
)
from repoauditor.triage.acquisition import (
    build_review_acquisition_plan,
    render_review_acquisition_plan,
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
    assert "score" not in payload["entries"][0]
    assert payload["evaluation_eligible"] is False


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

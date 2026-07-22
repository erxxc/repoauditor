"""Controlled collection gates count human evidence and preserve abstentions."""

from types import SimpleNamespace

from repoauditor.store.models import (
    TriageAssessment,
    TriageAssessmentOutcome,
    TriageLabel,
    TriageLabelSource,
)
from repoauditor.triage.collection import collection_status, render_collection_status


def _label(engagement, fingerprint, actionable, source):
    return TriageLabel(
        engagement=engagement, rule_id="rule", finding_fingerprint=fingerprint,
        actionable=actionable, source=source,
    )


def test_collection_gate_excludes_automation_derived_labels(tmp_config, monkeypatch):
    labels = [
        _label("human-repo", "a", True, TriageLabelSource.MANUAL),
        _label("auto-repo", "b", False, TriageLabelSource.DERIVED_FALSIFY),
        _label("review-repo", "c", False, TriageLabelSource.DERIVED_REVIEW),
    ]
    features = [
        SimpleNamespace(engagement="human-repo", fingerprint="a"),
        SimpleNamespace(engagement="auto-repo", fingerprint="b"),
        SimpleNamespace(engagement="review-repo", fingerprint="c"),
    ]
    assessment = TriageAssessment(
        finding_id=4, engagement="human-repo",
        outcome=TriageAssessmentOutcome.UNCERTAIN,
        rationale="runtime evidence absent", analyst="alice",
        dimensions=["authorization"],
    )
    monkeypatch.setattr(
        "repoauditor.triage.collection.db.list_triage_labels", lambda config=None: labels
    )
    monkeypatch.setattr(
        "repoauditor.triage.collection.db.list_triage_features", lambda config=None: features
    )
    monkeypatch.setattr(
        "repoauditor.triage.collection.db.list_triage_assessments",
        lambda repo_id=None, config=None: [assessment],
    )

    status = collection_status(config=tmp_config)
    rendered = render_collection_status(status)

    assert status.labels == 2
    assert status.engagements == 2
    assert status.unlabeled_triaged == 1  # automation-only evidence still needs human review
    assert status.uncertain == 1
    assert status.source_counts == {
        "derived_falsify": 1, "derived_review": 1, "manual": 1,
    }
    assert "usable human labels=2/40" in rendered

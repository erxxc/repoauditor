"""Controlled collection gates count human evidence and preserve abstentions."""

from types import SimpleNamespace

from repoauditor.store.models import (
    TriageAssessment,
    TriageAssessmentOutcome,
    TriageDisposition,
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
    assert "authorization" not in status.missing_dimensions
    assert "tenant-isolation" in status.missing_dimensions
    assert "usable human labels=2/40" in rendered
    assert "unrepresented target dimensions:" in rendered


def test_collection_reports_actionability_and_technical_validity_separately(
    tmp_config, monkeypatch
):
    assessments = [
        TriageAssessment(
            finding_id=1, engagement="repo",
            outcome=TriageAssessmentOutcome.TRUE_POSITIVE,
            disposition=TriageDisposition.CONFIRMED_ACTIONABLE,
            rationale="reachable attacker-controlled sink", analyst="alice",
            dimensions=["authorization"],
        ),
        TriageAssessment(
            finding_id=2, engagement="repo",
            outcome=TriageAssessmentOutcome.FALSE_POSITIVE,
            disposition=TriageDisposition.VALID_NOT_ACTIONABLE,
            rationale="valid but accepted low-impact behavior", analyst="alice",
            dimensions=["authorization"],
        ),
        TriageAssessment(
            finding_id=3, engagement="repo",
            outcome=TriageAssessmentOutcome.FALSE_POSITIVE,
            disposition=TriageDisposition.MITIGATED,
            rationale="effective authorization guard", analyst="alice",
            dimensions=["authorization"],
        ),
        TriageAssessment(
            finding_id=4, engagement="repo",
            outcome=TriageAssessmentOutcome.FALSE_POSITIVE,
            disposition=TriageDisposition.DUPLICATE,
            rationale="same root cause as finding 1", analyst="alice",
        ),
        TriageAssessment(
            finding_id=5, engagement="repo",
            outcome=TriageAssessmentOutcome.UNCERTAIN,
            disposition=TriageDisposition.INSUFFICIENT_EVIDENCE,
            rationale="runtime evidence unavailable", analyst="alice",
        ),
    ]
    monkeypatch.setattr(
        "repoauditor.triage.collection.db.list_triage_labels",
        lambda config=None: [],
    )
    monkeypatch.setattr(
        "repoauditor.triage.collection.db.list_triage_features",
        lambda config=None: [],
    )
    monkeypatch.setattr(
        "repoauditor.triage.collection.db.list_triage_assessments",
        lambda repo_id=None, config=None: assessments,
    )

    status = collection_status(config=tmp_config)
    rendered = render_collection_status(status)

    assert (status.operational_positive, status.operational_negative) == (1, 2)
    assert (status.technical_positive, status.technical_negative) == (2, 1)
    assert status.duplicate_assessments == 1
    assert status.uncertain == 1
    assert "operational actionability (decided, unique): positive=1, negative=2" in rendered
    assert "technical validity (decided, unique): positive=2, negative=1" in rendered
    assert "duplicates excluded=1" in rendered
    assert status.dimension_cohorts == {
        "authorization": {
            "decided": 3, "positive": 1, "negative": 2, "sufficient": False,
        }
    }
    assert "authorization=insufficient(decided=3, positive=1, negative=2)" in rendered
    assert "language/detector cohort metrics unavailable" in rendered


def test_collection_audits_independent_review_and_disagreement(
    tmp_config, monkeypatch
):
    assessments = [
        TriageAssessment(
            finding_id=1, engagement="repo",
            outcome=TriageAssessmentOutcome.TRUE_POSITIVE,
            disposition=TriageDisposition.CONFIRMED_ACTIONABLE,
            rationale="reachable sink", analyst="alice",
        ),
        TriageAssessment(
            finding_id=1, engagement="repo",
            outcome=TriageAssessmentOutcome.FALSE_POSITIVE,
            disposition=TriageDisposition.MITIGATED,
            rationale="runtime policy blocks the path", analyst="bob",
        ),
        TriageAssessment(
            finding_id=2, engagement="repo",
            outcome=TriageAssessmentOutcome.FALSE_POSITIVE,
            disposition=TriageDisposition.TOOL_INCORRECT,
            rationale="cited API is not a sink", analyst="alice",
        ),
        TriageAssessment(
            finding_id=2, engagement="repo",
            outcome=TriageAssessmentOutcome.FALSE_POSITIVE,
            disposition=TriageDisposition.TOOL_INCORRECT,
            rationale="confirmed against framework docs", analyst="bob",
        ),
        TriageAssessment(
            finding_id=3, engagement="repo",
            outcome=TriageAssessmentOutcome.UNCERTAIN,
            disposition=TriageDisposition.INSUFFICIENT_EVIDENCE,
            rationale="initial evidence incomplete", analyst="alice",
        ),
        TriageAssessment(
            finding_id=3, engagement="repo",
            outcome=TriageAssessmentOutcome.TRUE_POSITIVE,
            disposition=TriageDisposition.CONFIRMED_ACTIONABLE,
            rationale="later runtime trace establishes reachability", analyst="alice",
        ),
    ]
    monkeypatch.setattr(
        "repoauditor.triage.collection.db.list_triage_labels",
        lambda config=None: [],
    )
    monkeypatch.setattr(
        "repoauditor.triage.collection.db.list_triage_features",
        lambda config=None: [],
    )
    monkeypatch.setattr(
        "repoauditor.triage.collection.db.list_triage_assessments",
        lambda repo_id=None, config=None: assessments,
    )

    status = collection_status(config=tmp_config)

    assert status.reassessed_findings == 3
    assert status.independently_reviewed_findings == 2
    assert status.cross_analyst_disagreements == 1
    assert (
        "adjudication QA: reassessed=3, independently reviewed=2, "
        "cross-analyst disagreements=1"
        in render_collection_status(status)
    )

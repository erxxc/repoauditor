"""Controlled real-label collection status for triage model maturation.

The activation floor is deliberately two-dimensional: at least 40 effective binary labels
and at least eight genuinely distinct engagement identities. An explicit analyst abstention
is retained as an assessment but excluded from both counts. Coverage dimensions are analyst-
declared rather than inferred from rule names, so this view never fabricates taxonomy.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ..config import Config, get_config
from ..store import db
from ..store.models import (
    TriageAssessment,
    TriageAssessmentOutcome,
    TriageDisposition,
    TriageLabelSource,
)


MIN_LABELS = 40
MIN_ENGAGEMENTS = 8
# Descriptive coverage targets from the durable Phase-3 roadmap. They do not advance the
# numeric activation gate merely by being named; each remains analyst-declared evidence.
TARGET_DIMENSIONS = frozenset({
    "authorization",
    "business-logic",
    "tenant-isolation",
    "cross-service",
    "ci-iac",
    "agent-tool-boundary",
    "dependencies",
    "secrets",
    "dead-code",
    "mitigating-control",
    "near-miss-negative",
})


@dataclass(frozen=True)
class CollectionStatus:
    labels: int
    true_positive: int
    false_positive: int
    engagements: int
    uncertain: int
    unlabeled_triaged: int
    operational_positive: int = 0
    operational_negative: int = 0
    technical_positive: int = 0
    technical_negative: int = 0
    duplicate_assessments: int = 0
    reassessed_findings: int = 0
    independently_reviewed_findings: int = 0
    cross_analyst_disagreements: int = 0
    dimension_cohorts: dict[str, dict[str, int | bool]] = field(default_factory=dict)
    language_cohorts: dict[str, dict[str, int | bool]] = field(default_factory=dict)
    detector_cohorts: dict[str, dict[str, int | bool]] = field(default_factory=dict)
    labels_without_language: int = 0
    labels_without_detector: int = 0
    disposition_counts: dict[str, int] = field(default_factory=dict)
    source_counts: dict[str, int] = field(default_factory=dict)
    dimension_counts: dict[str, int] = field(default_factory=dict)
    missing_dimensions: tuple[str, ...] = ()

    @property
    def activation_ready(self) -> bool:
        return self.labels >= MIN_LABELS and self.engagements >= MIN_ENGAGEMENTS


def _adjudication_views(
    assessments: list[TriageAssessment],
) -> tuple[int, int, int, int, int]:
    """Project detailed dispositions into the two documented reporting views.

    Duplicates and abstentions are excluded from both decided denominators. Legacy
    assessments without a detailed disposition retain their documented CLI mapping:
    true-positive means confirmed-actionable, false-positive means tool-incorrect, and
    uncertain remains an abstention.
    """
    operational_positive = operational_negative = 0
    technical_positive = technical_negative = duplicates = 0
    for assessment in assessments:
        disposition = assessment.disposition
        if disposition is TriageDisposition.DUPLICATE:
            duplicates += 1
            continue
        if (
            disposition is TriageDisposition.INSUFFICIENT_EVIDENCE
            or assessment.outcome is TriageAssessmentOutcome.UNCERTAIN
        ):
            continue
        actionable = (
            disposition is TriageDisposition.CONFIRMED_ACTIONABLE
            or (
                disposition is None
                and assessment.outcome is TriageAssessmentOutcome.TRUE_POSITIVE
            )
        )
        technically_valid = (
            actionable or disposition is TriageDisposition.VALID_NOT_ACTIONABLE
        )
        operational_positive += int(actionable)
        operational_negative += int(not actionable)
        technical_positive += int(technically_valid)
        technical_negative += int(not technically_valid)
    return (
        operational_positive,
        operational_negative,
        technical_positive,
        technical_negative,
        duplicates,
    )


def _review_audit(assessments: list[TriageAssessment]) -> tuple[int, int, int]:
    """Count observable review history without inferring materiality or rationale quality."""
    by_finding: dict[int, list[TriageAssessment]] = {}
    for assessment in assessments:
        by_finding.setdefault(assessment.finding_id, []).append(assessment)
    reassessed = sum(len(history) > 1 for history in by_finding.values())
    independently_reviewed = 0
    disagreements = 0
    for history in by_finding.values():
        latest_by_analyst = {
            assessment.analyst: assessment for assessment in history
        }
        if len(latest_by_analyst) < 2:
            continue
        independently_reviewed += 1
        positions = {
            (
                assessment.disposition.value
                if assessment.disposition is not None
                else assessment.outcome.value
            )
            for assessment in latest_by_analyst.values()
        }
        disagreements += len(positions) > 1
    return reassessed, independently_reviewed, disagreements


def _cohort_sufficiency(
    assessments: list[TriageAssessment],
) -> tuple[dict[str, dict[str, int | bool]], dict[str, int]]:
    """Describe persisted cohorts; do not infer missing language or detector metadata."""
    cohorts: dict[str, list[TriageAssessment]] = {}
    dispositions: Counter[str] = Counter()
    for assessment in assessments:
        disposition = (
            assessment.disposition.value
            if assessment.disposition is not None
            else assessment.outcome.value
        )
        dispositions[disposition] += 1
        for dimension in assessment.dimensions:
            cohorts.setdefault(dimension, []).append(assessment)
    result: dict[str, dict[str, int | bool]] = {}
    for dimension, members in sorted(cohorts.items()):
        positive, negative, _tp, _tn, _duplicates = _adjudication_views(members)
        decided = positive + negative
        result[dimension] = {
            "decided": decided,
            "positive": positive,
            "negative": negative,
            "sufficient": (
                decided >= MIN_LABELS and positive > 0 and negative > 0
            ),
        }
    return result, dict(sorted(dispositions.items()))


def _metadata_cohort_sufficiency(
    labels: list,
    features: list,
    attribute: str,
) -> tuple[dict[str, dict[str, int | bool]], int]:
    """Count human-label cohorts only where explicitly persisted metadata is available."""
    feature_by_key = {
        (feature.engagement, feature.fingerprint): feature for feature in features
    }
    counts: dict[str, Counter[str]] = {}
    unavailable = 0
    for label in labels:
        feature = feature_by_key.get((label.engagement, label.finding_fingerprint))
        value = getattr(feature, attribute, "unknown") if feature is not None else "unknown"
        if not value or value == "unknown":
            unavailable += 1
            continue
        cohort = counts.setdefault(value, Counter())
        cohort["positive" if label.actionable else "negative"] += 1
    result: dict[str, dict[str, int | bool]] = {}
    for name, cohort in sorted(counts.items()):
        positive = cohort["positive"]
        negative = cohort["negative"]
        decided = positive + negative
        result[name] = {
            "decided": decided,
            "positive": positive,
            "negative": negative,
            "sufficient": decided >= MIN_LABELS and positive > 0 and negative > 0,
        }
    return result, unavailable


def collection_status(
    repo_id: str | None = None, config: Config | None = None
) -> CollectionStatus:
    """Summarize effective labels and latest analyst assessments without scoring them."""
    config = config or get_config()
    all_labels = db.list_triage_labels(config=config)
    if repo_id is not None:
        all_labels = [label for label in all_labels if label.engagement == repo_id]
    labels = [label for label in all_labels if label.source in {
        TriageLabelSource.MANUAL, TriageLabelSource.DERIVED_REVIEW,
    }]
    features = db.list_triage_features(config)
    if repo_id is not None:
        features = [feature for feature in features if feature.engagement == repo_id]
    labelled_keys = {(label.engagement, label.finding_fingerprint) for label in labels}

    assessments = db.list_triage_assessments(repo_id, config)
    latest_by_finding = {assessment.finding_id: assessment for assessment in assessments}
    (
        operational_positive,
        operational_negative,
        technical_positive,
        technical_negative,
        duplicates,
    ) = _adjudication_views(list(latest_by_finding.values()))
    reassessed, independently_reviewed, disagreements = _review_audit(assessments)
    dimension_cohorts, disposition_counts = _cohort_sufficiency(
        list(latest_by_finding.values())
    )
    language_cohorts, labels_without_language = _metadata_cohort_sufficiency(
        labels, features, "language"
    )
    detector_cohorts, labels_without_detector = _metadata_cohort_sufficiency(
        labels, features, "detector"
    )
    uncertain = sum(
        assessment.outcome is TriageAssessmentOutcome.UNCERTAIN
        for assessment in latest_by_finding.values()
    )
    dimensions = Counter(
        dimension
        for assessment in latest_by_finding.values()
        for dimension in assessment.dimensions
    )
    sources = Counter(str(label.source) for label in all_labels)
    return CollectionStatus(
        labels=len(labels),
        true_positive=sum(label.actionable for label in labels),
        false_positive=sum(not label.actionable for label in labels),
        engagements=len({label.engagement for label in labels}),
        uncertain=uncertain,
        unlabeled_triaged=sum(
            (feature.engagement, feature.fingerprint) not in labelled_keys
            for feature in features
        ),
        operational_positive=operational_positive,
        operational_negative=operational_negative,
        technical_positive=technical_positive,
        technical_negative=technical_negative,
        duplicate_assessments=duplicates,
        reassessed_findings=reassessed,
        independently_reviewed_findings=independently_reviewed,
        cross_analyst_disagreements=disagreements,
        dimension_cohorts=dimension_cohorts,
        language_cohorts=language_cohorts,
        detector_cohorts=detector_cohorts,
        labels_without_language=labels_without_language,
        labels_without_detector=labels_without_detector,
        disposition_counts=disposition_counts,
        source_counts=dict(sorted(sources.items())),
        dimension_counts=dict(sorted(dimensions.items())),
        missing_dimensions=tuple(sorted(TARGET_DIMENSIONS - dimensions.keys())),
    )


def render_collection_status(status: CollectionStatus) -> str:
    readiness = "ready" if status.activation_ready else "not ready"
    lines = [
        f"Controlled triage collection — {readiness}",
        f"usable human labels={status.labels}/{MIN_LABELS} "
        f"(true_positive={status.true_positive}, false_positive={status.false_positive}); "
        f"engagements={status.engagements}/{MIN_ENGAGEMENTS}",
        f"explicit abstentions={status.uncertain}; unlabeled triaged findings="
        f"{status.unlabeled_triaged}",
        "operational actionability (decided, unique): "
        f"positive={status.operational_positive}, negative={status.operational_negative}",
        "technical validity (decided, unique): "
        f"positive={status.technical_positive}, negative={status.technical_negative}; "
        f"duplicates excluded={status.duplicate_assessments}",
        "adjudication QA: "
        f"reassessed={status.reassessed_findings}, independently reviewed="
        f"{status.independently_reviewed_findings}, cross-analyst disagreements="
        f"{status.cross_analyst_disagreements}",
        "label sources: " + (
            ", ".join(f"{key}={value}" for key, value in status.source_counts.items())
            or "none"
        ),
        "declared dimensions: " + (
            ", ".join(f"{key}={value}" for key, value in status.dimension_counts.items())
            or "none"
        ),
        "unrepresented target dimensions: " + (
            ", ".join(status.missing_dimensions) or "none"
        ),
        "dimension cohort sufficiency: " + (
            ", ".join(
                f"{name}={'sufficient' if values['sufficient'] else 'insufficient'}"
                f"(decided={values['decided']}, positive={values['positive']}, "
                f"negative={values['negative']})"
                for name, values in status.dimension_cohorts.items()
            )
            or "none"
        ),
        "language cohort sufficiency: " + (
            ", ".join(
                f"{name}={'sufficient' if values['sufficient'] else 'insufficient'}"
                f"(decided={values['decided']}, positive={values['positive']}, "
                f"negative={values['negative']})"
                for name, values in status.language_cohorts.items()
            )
            or "none"
        ) + f"; unavailable labels={status.labels_without_language}",
        "detector cohort sufficiency: " + (
            ", ".join(
                f"{name}={'sufficient' if values['sufficient'] else 'insufficient'}"
                f"(decided={values['decided']}, positive={values['positive']}, "
                f"negative={values['negative']})"
                for name, values in status.detector_cohorts.items()
            )
            or "none"
        ) + f"; unavailable labels={status.labels_without_detector}",
        "detailed dispositions: " + (
            ", ".join(
                f"{name}={count}" for name, count in status.disposition_counts.items()
            )
            or "none"
        ),
    ]
    if not status.activation_ready:
        lines.append(
            "Continue representative UAT collection; do not interpret grouped validation "
            "as mature until both gates are met."
        )
    return "\n".join(lines)

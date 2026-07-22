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
from ..store.models import TriageAssessmentOutcome, TriageLabelSource


MIN_LABELS = 40
MIN_ENGAGEMENTS = 8


@dataclass(frozen=True)
class CollectionStatus:
    labels: int
    true_positive: int
    false_positive: int
    engagements: int
    uncertain: int
    unlabeled_triaged: int
    source_counts: dict[str, int] = field(default_factory=dict)
    dimension_counts: dict[str, int] = field(default_factory=dict)

    @property
    def activation_ready(self) -> bool:
        return self.labels >= MIN_LABELS and self.engagements >= MIN_ENGAGEMENTS


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
        source_counts=dict(sorted(sources.items())),
        dimension_counts=dict(sorted(dimensions.items())),
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
        "label sources: " + (
            ", ".join(f"{key}={value}" for key, value in status.source_counts.items())
            or "none"
        ),
        "declared dimensions: " + (
            ", ".join(f"{key}={value}" for key, value in status.dimension_counts.items())
            or "none"
        ),
    ]
    if not status.activation_ready:
        lines.append(
            "Continue representative UAT collection; do not interpret grouped validation "
            "as mature until both gates are met."
        )
    return "\n".join(lines)

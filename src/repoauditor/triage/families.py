"""Evaluation-family identity and exact cross-alias label reconciliation."""

from __future__ import annotations

from collections.abc import Iterable

from ..config import Config
from ..store.models import TriageLabel, TriageLabelSource


_SOURCE_PRIORITY = {
    TriageLabelSource.MANUAL: 0,
    TriageLabelSource.DERIVED_REVIEW: 1,
    TriageLabelSource.DERIVED_FALSIFY: 2,
}


def evaluation_family(engagement: str, config: Config) -> str:
    """Return the evaluation-only family id for one persisted engagement."""
    return config.triage.evaluation_family_overrides.get(engagement, engagement)


def family_distinct_labels(
    labels: Iterable[TriageLabel], config: Config
) -> list[TriageLabel]:
    """Collapse the same labelled finding repeated under related repo identities.

    The immutable label rows remain untouched. Exact family/rule/fingerprint copies carry
    one unit of training/prior evidence, preferring human review over derived falsification.
    A contradictory outcome for the same identity fails closed instead of choosing a side.
    """
    grouped: dict[tuple[str, str, str], list[TriageLabel]] = {}
    for label in labels:
        key = (
            evaluation_family(label.engagement, config),
            label.rule_id,
            label.finding_fingerprint,
        )
        grouped.setdefault(key, []).append(label)

    selected: list[TriageLabel] = []
    for key in sorted(grouped):
        candidates = grouped[key]
        outcomes = {label.actionable for label in candidates}
        if len(outcomes) != 1:
            raise ValueError(
                "contradictory labels share evaluation family/rule/fingerprint "
                f"identity {key!r}"
            )
        selected.append(min(
            candidates,
            key=lambda label: (
                _SOURCE_PRIORITY[label.source],
                label.id if label.id is not None else 2**63,
                label.engagement,
            ),
        ))
    return selected

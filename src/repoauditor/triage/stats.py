"""Observed threshold tradeoffs from real triage outcomes.

This is descriptive, not prescriptive: it reports precision/recall at fixed candidate
P(actionable) thresholds and never selects or recommends one. The table is withheld until
the existing 40-real-label evaluation gate is met. Scores are the probabilities persisted
when findings were triaged, joined to later authoritative labels; they are operational
retrospective evidence, not a substitute for the classifier's held-out validation.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import Config, get_config
from ..store import db
from ..store.models import ScoredTriageLabel, TriageLabelSource


@dataclass(frozen=True)
class ThresholdRow:
    threshold: float
    selected: int
    precision: float | None
    recall: float


@dataclass(frozen=True)
class ThresholdStats:
    repo_id: str | None
    n_labels: int
    n_positive: int
    n_negative: int
    n_engagements: int
    minimum_labels: int
    rows: list[ThresholdRow]
    label_cohort: str = "human"
    triage_run_id: int | None = None

    @property
    def available(self) -> bool:
        return self.n_labels >= self.minimum_labels and self.n_positive > 0


def threshold_stats(
    repo_id: str | None = None,
    config: Config | None = None,
    *,
    label_cohort: str = "human",
    triage_run_id: int | None = None,
) -> ThresholdStats:
    """Compute an observed precision/recall table without choosing an optimal threshold."""
    config = config or get_config()
    if label_cohort not in {"human", "derived", "all"}:
        raise ValueError("label cohort must be human, derived, or all")
    observations: list[ScoredTriageLabel] = db.list_scored_triage_labels(
        config, repo_id=repo_id
    )
    if label_cohort == "human":
        observations = [item for item in observations if item.label_source in {
            TriageLabelSource.MANUAL, TriageLabelSource.DERIVED_REVIEW,
        }]
    elif label_cohort == "derived":
        observations = [
            item for item in observations
            if item.label_source is TriageLabelSource.DERIVED_FALSIFY
        ]
    if triage_run_id is not None:
        observations = [item for item in observations if item.triage_run_id == triage_run_id]
    else:
        # Compare like with like. Default to the newest scored cohort and include prior
        # runs only when model package, feature schema, and calibration are identical.
        versioned = [item for item in observations if item.triage_run_id is not None]
        if versioned and all(item.model_name and item.model_version
                             and item.feature_schema_version and item.calibration
                             for item in versioned):
            newest = max(versioned, key=lambda item: item.triage_run_id or 0)
            compatible = (
                newest.model_name, newest.model_version,
                newest.feature_schema_version, newest.calibration,
            )
            observations = [item for item in versioned if (
                item.model_name, item.model_version,
                item.feature_schema_version, item.calibration,
            ) == compatible]
    positives = sum(item.actionable for item in observations)
    minimum = config.triage.min_real_labels_for_holdout_eval
    rows: list[ThresholdRow] = []
    if len(observations) >= minimum and positives:
        for step in range(11):
            threshold = step / 10
            selected = [item for item in observations if item.p_actionable >= threshold]
            true_positive = sum(item.actionable for item in selected)
            precision = true_positive / len(selected) if selected else None
            recall = true_positive / positives
            rows.append(ThresholdRow(threshold, len(selected), precision, recall))
    return ThresholdStats(
        repo_id=repo_id,
        n_labels=len(observations),
        n_positive=positives,
        n_negative=len(observations) - positives,
        n_engagements=len({item.engagement for item in observations}),
        minimum_labels=minimum,
        rows=rows,
        label_cohort=label_cohort,
        triage_run_id=triage_run_id,
    )


def render_threshold_stats(stats: ThresholdStats) -> str:
    scope = stats.repo_id or "all engagements"
    lines = [
        f"Triage threshold tradeoffs — {scope}",
        f"label cohort={stats.label_cohort}; triage run="
        f"{stats.triage_run_id if stats.triage_run_id is not None else 'all compatible runs'}",
        f"real scored labels={stats.n_labels} (true_positive={stats.n_positive}, "
        f"false_positive={stats.n_negative}); engagements={stats.n_engagements}",
    ]
    if not stats.available:
        lines.append(
            "Curve unavailable: real scored labels have not met the existing "
            f">={stats.minimum_labels} label gate (or contain no true positives). "
            "Synthetic-heavy data is not substituted."
        )
        return "\n".join(lines)
    lines += [
        "Observed retrospective tradeoff; no threshold is recommended.",
        "threshold  selected  precision  recall",
    ]
    for row in stats.rows:
        precision = "n/a" if row.precision is None else f"{row.precision:.3f}"
        lines.append(f"{row.threshold:>9.1f}  {row.selected:>8}  {precision:>9}  {row.recall:>6.3f}")
    return "\n".join(lines)

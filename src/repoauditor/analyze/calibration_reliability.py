"""Pure descriptive reliability calculations for OPT-037 Tier 1."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
import math

from .calibration import wilson_interval
from .calibration_readiness import (
    AUTHORITATIVE_SOURCES,
    ReliabilityEligibilityRow,
    ReadinessSummary,
    assess_reliability_readiness,
)


EXPECTED_IDENTITIES = 104
EXPECTED_FAMILIES = 15
EXPECTED_COMPATIBILITY_DIGEST = (
    "310fa764b46b714535c982d3cf1383435cade02e0d005b9f29c484ad3d0cf070"
)
BIN_EDGES = tuple(step / 10 for step in range(11))


class ReliabilityValidationError(ValueError):
    """The outcome rows do not reproduce the frozen readiness cohort."""


@dataclass(frozen=True)
class ReliabilityOutcomeRow:
    identity: str
    evaluation_family: str
    actionable: bool
    p_actionable: float
    label_source: str
    triage_run_id: int | None
    scored_at: str | None
    first_assessed_at: str | None
    model_name: str | None
    model_version: str | None
    feature_schema_version: str | None
    calibration: str | None

    def eligibility(self) -> ReliabilityEligibilityRow:
        return ReliabilityEligibilityRow(
            identity=self.identity,
            evaluation_family=self.evaluation_family,
            actionable=self.actionable,
            label_source=self.label_source,
            triage_run_id=self.triage_run_id,
            scored_at=self.scored_at,
            first_assessed_at=self.first_assessed_at,
            model_name=self.model_name,
            model_version=self.model_version,
            feature_schema_version=self.feature_schema_version,
            calibration=self.calibration,
        )


def _time(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _compatibility(row: ReliabilityOutcomeRow) -> tuple[str, str, str, str] | None:
    values = (
        row.model_name,
        row.model_version,
        row.feature_schema_version,
        row.calibration,
    )
    if not all(isinstance(value, str) and value.strip() for value in values):
        return None
    return tuple(values)  # type: ignore[return-value]


def _validate_probability(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0.0 <= value <= 1.0
    ):
        raise ReliabilityValidationError("probabilities must be finite and within [0, 1]")
    return float(value)


def select_qualified_outcomes(
    rows: Iterable[ReliabilityOutcomeRow],
    *,
    expected_compatibility_digest: str = EXPECTED_COMPATIBILITY_DIGEST,
) -> tuple[tuple[ReliabilityOutcomeRow, ...], ReadinessSummary]:
    """Reproduce and return only the frozen ready cohort, without persistence."""
    materialized = list(rows)
    for row in materialized:
        _validate_probability(row.p_actionable)
    readiness = assess_reliability_readiness(row.eligibility() for row in materialized)
    if not readiness.ready:
        raise ReliabilityValidationError("readiness gates no longer pass")
    if (
        readiness.eligible_identities != EXPECTED_IDENTITIES
        or readiness.evaluation_families != EXPECTED_FAMILIES
        or readiness.compatibility_digest != expected_compatibility_digest
    ):
        raise ReliabilityValidationError("frozen readiness identity changed")

    eligible: list[tuple[ReliabilityOutcomeRow, datetime, tuple[str, str, str, str]]] = []
    for row in materialized:
        scored = _time(row.scored_at)
        assessed = _time(row.first_assessed_at)
        compatibility = _compatibility(row)
        if (
            row.label_source not in AUTHORITATIVE_SOURCES
            or scored is None
            or assessed is None
            or scored >= assessed
            or compatibility is None
            or row.triage_run_id is None
            or row.triage_run_id < 0
            or not row.identity
            or not row.evaluation_family
        ):
            continue
        eligible.append((row, scored, compatibility))
    newest = max(eligible, key=lambda item: (item[0].triage_run_id or -1, item[1]))
    compatible = [item for item in eligible if item[2] == newest[2]]
    selected: dict[str, tuple[ReliabilityOutcomeRow, datetime]] = {}
    for row, scored, _ in compatible:
        prior = selected.get(row.identity)
        if prior and prior[0].actionable != row.actionable:
            raise ReliabilityValidationError("conflicting outcomes for one identity")
        if prior is None or scored > prior[1]:
            selected[row.identity] = (row, scored)
    outcomes = tuple(selected[key][0] for key in sorted(selected))
    if len(outcomes) != readiness.eligible_identities:
        raise ReliabilityValidationError("selection disagrees with readiness summary")
    return outcomes, readiness


def descriptive_reliability(
    rows: Iterable[ReliabilityOutcomeRow],
    *,
    expected_compatibility_digest: str = EXPECTED_COMPATIBILITY_DIGEST,
) -> dict[str, object]:
    """Calculate the frozen aggregate table, Brier score, and fixed-bin ECE."""
    outcomes, readiness = select_qualified_outcomes(
        rows, expected_compatibility_digest=expected_compatibility_digest
    )
    bins: list[dict[str, object]] = []
    weighted_error = 0.0
    for index, (low, high) in enumerate(zip(BIN_EDGES, BIN_EDGES[1:])):
        members = [
            row for row in outcomes
            if low <= row.p_actionable < high
            or (index == 9 and row.p_actionable == 1.0)
        ]
        if members:
            count = len(members)
            successes = sum(row.actionable for row in members)
            mean_predicted = sum(row.p_actionable for row in members) / count
            observed = successes / count
            lower, upper = wilson_interval(successes, count)
            weighted_error += count * abs(mean_predicted - observed)
        else:
            count = successes = 0
            mean_predicted = observed = lower = upper = None
        bins.append({
            "bin_low": low,
            "bin_high": high,
            "count": count,
            "mean_predicted_probability": mean_predicted,
            "observed_actionable_fraction": observed,
            "observed_actionable_wilson_95": [lower, upper] if count else None,
        })
    brier = sum(
        (row.p_actionable - int(row.actionable)) ** 2 for row in outcomes
    ) / len(outcomes)
    return {
        "eligible_identities": len(outcomes),
        "positive_identities": sum(row.actionable for row in outcomes),
        "negative_identities": sum(not row.actionable for row in outcomes),
        "evaluation_families": len({row.evaluation_family for row in outcomes}),
        "compatibility_digest": readiness.compatibility_digest,
        "bins": bins,
        "brier_score": brier,
        "expected_calibration_error": weighted_error / len(outcomes),
    }

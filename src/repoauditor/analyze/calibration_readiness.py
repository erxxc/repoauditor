"""Pure aggregate readiness audit for OPT-037 Tier 1."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json


AUTHORITATIVE_SOURCES = frozenset({"manual", "derived_review"})
MIN_IDENTITIES = 40
MIN_FAMILIES = 8


@dataclass(frozen=True)
class ReliabilityEligibilityRow:
    identity: str
    evaluation_family: str
    actionable: bool
    label_source: str
    triage_run_id: int | None
    scored_at: str | None
    first_assessed_at: str | None
    model_name: str | None
    model_version: str | None
    feature_schema_version: str | None
    calibration: str | None


@dataclass(frozen=True)
class ReadinessSummary:
    joined_rows: int
    authoritative_rows: int
    excluded_non_authoritative_rows: int
    missing_assessment_rows: int
    chronology_failure_rows: int
    missing_compatibility_rows: int
    compatible_rows: int
    duplicate_rows_removed: int
    eligible_identities: int
    positive_identities: int
    negative_identities: int
    evaluation_families: int
    compatibility_digest: str | None
    chronology_pass: bool
    provenance_pass: bool
    compatibility_pass: bool
    identity_deduplication_pass: bool
    both_classes_pass: bool
    identity_floor_pass: bool
    family_floor_pass: bool

    @property
    def ready(self) -> bool:
        return all((
            self.chronology_pass,
            self.provenance_pass,
            self.compatibility_pass,
            self.identity_deduplication_pass,
            self.both_classes_pass,
            self.identity_floor_pass,
            self.family_floor_pass,
        ))

    def aggregate_record(self) -> dict[str, int | str | bool | None]:
        return {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
        } | {"ready": self.ready}


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


def _compatibility(row: ReliabilityEligibilityRow) -> tuple[str, str, str, str] | None:
    values = (
        row.model_name,
        row.model_version,
        row.feature_schema_version,
        row.calibration,
    )
    if not all(isinstance(value, str) and value.strip() for value in values):
        return None
    return tuple(values)  # type: ignore[return-value]


def _compatibility_digest(identity: tuple[str, str, str, str]) -> str:
    encoded = json.dumps(identity, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def assess_reliability_readiness(
    rows: Iterable[ReliabilityEligibilityRow],
    *,
    minimum_identities: int = MIN_IDENTITIES,
    minimum_families: int = MIN_FAMILIES,
) -> ReadinessSummary:
    """Apply the frozen gates and return aggregate counts only."""
    if minimum_identities <= 0 or minimum_families <= 0:
        raise ValueError("readiness floors must be positive")
    materialized = list(rows)
    authoritative = [row for row in materialized if row.label_source in AUTHORITATIVE_SOURCES]
    missing_assessment = 0
    chronology_failures = 0
    missing_compatibility = 0
    eligible: list[tuple[ReliabilityEligibilityRow, datetime, tuple[str, str, str, str]]] = []
    for row in authoritative:
        scored = _time(row.scored_at)
        assessed = _time(row.first_assessed_at)
        if assessed is None:
            missing_assessment += 1
            continue
        if scored is None or scored >= assessed:
            chronology_failures += 1
            continue
        compatibility = _compatibility(row)
        if compatibility is None or row.triage_run_id is None or row.triage_run_id < 0:
            missing_compatibility += 1
            continue
        if not row.identity or not row.evaluation_family:
            missing_compatibility += 1
            continue
        eligible.append((row, scored, compatibility))

    selected_compatibility: tuple[str, str, str, str] | None = None
    if eligible:
        newest = max(eligible, key=lambda item: (item[0].triage_run_id or -1, item[1]))
        selected_compatibility = newest[2]
    compatible = [item for item in eligible if item[2] == selected_compatibility]

    deduplicated: dict[str, tuple[ReliabilityEligibilityRow, datetime]] = {}
    consistent = True
    for row, scored, _ in compatible:
        prior = deduplicated.get(row.identity)
        if prior and prior[0].actionable != row.actionable:
            consistent = False
        if prior is None or scored > prior[1]:
            deduplicated[row.identity] = (row, scored)
    selected = [item[0] for item in deduplicated.values()]
    positives = sum(row.actionable for row in selected)
    negatives = len(selected) - positives
    families = len({row.evaluation_family for row in selected})
    compatibility_digest = (
        _compatibility_digest(selected_compatibility) if selected_compatibility else None
    )
    return ReadinessSummary(
        joined_rows=len(materialized),
        authoritative_rows=len(authoritative),
        excluded_non_authoritative_rows=len(materialized) - len(authoritative),
        missing_assessment_rows=missing_assessment,
        chronology_failure_rows=chronology_failures,
        missing_compatibility_rows=missing_compatibility,
        compatible_rows=len(compatible),
        duplicate_rows_removed=len(compatible) - len(selected),
        eligible_identities=len(selected),
        positive_identities=positives,
        negative_identities=negatives,
        evaluation_families=families,
        compatibility_digest=compatibility_digest,
        chronology_pass=bool(selected) and all(
            _time(row.scored_at) < _time(row.first_assessed_at)  # type: ignore[operator]
            for row in selected
        ),
        provenance_pass=bool(selected) and all(
            row.label_source in AUTHORITATIVE_SOURCES for row in selected
        ),
        compatibility_pass=selected_compatibility is not None and bool(compatible),
        identity_deduplication_pass=consistent,
        both_classes_pass=positives > 0 and negatives > 0,
        identity_floor_pass=len(selected) >= minimum_identities,
        family_floor_pass=families >= minimum_families,
    )

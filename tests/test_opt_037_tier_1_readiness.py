from __future__ import annotations

from dataclasses import replace

import pytest

from repoauditor.analyze.calibration_readiness import (
    ReliabilityEligibilityRow,
    assess_reliability_readiness,
)


def _row(index: int, **changes) -> ReliabilityEligibilityRow:
    row = ReliabilityEligibilityRow(
        identity=f"finding-{index}",
        evaluation_family=f"family-{index % 8}",
        actionable=index % 2 == 0,
        label_source="manual",
        triage_run_id=7,
        scored_at="2026-01-01T00:00:00Z",
        first_assessed_at="2026-01-02T00:00:00Z",
        model_name="model",
        model_version="1",
        feature_schema_version="2",
        calibration="sigmoid",
    )
    return replace(row, **changes)


def test_ready_cohort_meets_every_gate_without_disclosing_rows():
    summary = assess_reliability_readiness([_row(index) for index in range(40)])
    assert summary.ready
    assert summary.eligible_identities == 40
    assert summary.positive_identities == summary.negative_identities == 20
    assert summary.evaluation_families == 8
    assert len(summary.compatibility_digest or "") == 64
    assert set(summary.aggregate_record()) == set(summary.__dataclass_fields__) | {"ready"}


def test_latest_preassessment_score_is_selected_once_per_identity():
    rows = [_row(index) for index in range(40)]
    rows += [replace(rows[0], scored_at="2026-01-01T12:00:00Z")]
    summary = assess_reliability_readiness(rows)
    assert summary.ready
    assert summary.compatible_rows == 41
    assert summary.duplicate_rows_removed == 1
    assert summary.eligible_identities == 40


def test_newest_compatible_model_cohort_is_used_without_pooling():
    old = [_row(index, triage_run_id=1, model_version="old") for index in range(40)]
    current = [_row(index + 40, triage_run_id=2, model_version="new") for index in range(8)]
    summary = assess_reliability_readiness(old + current)
    assert summary.eligible_identities == 8
    assert not summary.identity_floor_pass
    assert not summary.ready


@pytest.mark.parametrize(
    ("change", "counter"),
    [
        ({"label_source": "derived_falsify"}, "excluded_non_authoritative_rows"),
        ({"first_assessed_at": None}, "missing_assessment_rows"),
        ({"scored_at": "2026-01-02T00:00:00Z"}, "chronology_failure_rows"),
        ({"scored_at": "2026-01-03T00:00:00Z"}, "chronology_failure_rows"),
        ({"model_version": None}, "missing_compatibility_rows"),
        ({"evaluation_family": ""}, "missing_compatibility_rows"),
    ],
)
def test_invalid_rows_are_excluded_and_cannot_inflate_the_floor(change, counter):
    rows = [_row(index) for index in range(40)]
    rows[0] = replace(rows[0], **change)
    summary = assess_reliability_readiness(rows)
    assert getattr(summary, counter) == 1
    assert summary.eligible_identities == 39
    assert not summary.ready


def test_one_class_or_too_few_families_is_not_ready():
    rows = [_row(index, actionable=True, evaluation_family="one") for index in range(40)]
    summary = assess_reliability_readiness(rows)
    assert not summary.both_classes_pass
    assert not summary.family_floor_pass
    assert not summary.ready


def test_conflicting_duplicate_outcomes_fail_identity_gate():
    rows = [_row(index) for index in range(40)]
    rows.append(replace(rows[0], actionable=not rows[0].actionable))
    summary = assess_reliability_readiness(rows)
    assert not summary.identity_deduplication_pass
    assert not summary.ready


def test_invalid_floor_is_rejected():
    with pytest.raises(ValueError):
        assess_reliability_readiness([], minimum_identities=0)

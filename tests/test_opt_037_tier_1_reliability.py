from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import math

import pytest

from repoauditor.analyze.calibration_reliability import (
    ReliabilityOutcomeRow,
    ReliabilityValidationError,
    descriptive_reliability,
    select_qualified_outcomes,
)


def _row(index: int, **changes) -> ReliabilityOutcomeRow:
    row = ReliabilityOutcomeRow(
        identity=f"finding-{index}",
        evaluation_family=f"family-{index % 15}",
        actionable=index < 24,
        p_actionable=(index + 0.5) / 104,
        label_source="manual",
        triage_run_id=7,
        scored_at="2026-01-01T00:00:00Z",
        first_assessed_at="2026-01-02T00:00:00Z",
        model_name="xgboost",
        model_version="1",
        feature_schema_version="2",
        calibration="sigmoid",
    )
    return replace(row, **changes)


def _cohort() -> list[ReliabilityOutcomeRow]:
    return [_row(index) for index in range(104)]


SYNTHETIC_COMPATIBILITY_DIGEST = hashlib.sha256(
    json.dumps(
        ("xgboost", "1", "2", "sigmoid"), separators=(",", ":"), ensure_ascii=True
    ).encode()
).hexdigest()


def _report(rows: list[ReliabilityOutcomeRow]) -> dict[str, object]:
    return descriptive_reliability(
        rows, expected_compatibility_digest=SYNTHETIC_COMPATIBILITY_DIGEST
    )


def test_fixed_ten_bin_table_conserves_the_qualified_cohort() -> None:
    report = _report(_cohort())
    assert len(report["bins"]) == 10
    assert sum(row["count"] for row in report["bins"]) == 104
    assert report["positive_identities"] == 24
    assert report["negative_identities"] == 80
    assert report["evaluation_families"] == 15
    assert 0 <= report["brier_score"] <= 1
    assert 0 <= report["expected_calibration_error"] <= 1
    assert all(
        row["observed_actionable_wilson_95"] is not None
        for row in report["bins"] if row["count"]
    )


def test_latest_score_is_selected_without_duplicate_weight() -> None:
    rows = _cohort()
    rows.append(replace(rows[0], p_actionable=0.75, scored_at="2026-01-01T12:00:00Z"))
    selected, readiness = select_qualified_outcomes(
        rows, expected_compatibility_digest=SYNTHETIC_COMPATIBILITY_DIGEST
    )
    assert readiness.duplicate_rows_removed == 1
    assert len(selected) == 104
    assert next(row for row in selected if row.identity == "finding-0").p_actionable == 0.75


@pytest.mark.parametrize("probability", [-0.01, 1.01, math.nan, math.inf, True])
def test_malformed_probability_fails_closed(probability: object) -> None:
    rows = _cohort()
    rows[0] = replace(rows[0], p_actionable=probability)  # type: ignore[arg-type]
    with pytest.raises(ReliabilityValidationError, match="probabilities"):
        _report(rows)


def test_readiness_or_frozen_compatibility_drift_fails_closed() -> None:
    rows = _cohort()
    rows[0] = replace(rows[0], first_assessed_at=None)
    with pytest.raises(ReliabilityValidationError):
        _report(rows)

    with pytest.raises(ReliabilityValidationError, match="frozen readiness identity"):
        descriptive_reliability(_cohort())

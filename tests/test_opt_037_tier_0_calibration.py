from __future__ import annotations

from copy import deepcopy
import json
import math
from pathlib import Path

import pytest

from repoauditor.analyze.calibration import (
    FixtureValidationError,
    coverage_rows,
    coverage_summary,
    ideal_hash_probability,
    recoverability_regime,
    reliability_table,
    validate_fixture,
    wilson_interval,
)


ROOT = Path(__file__).parents[1]
FIXTURE_PATH = ROOT / "tests/fixtures/opt037-tier0-oracle-aggregate.json"


def _fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_exact_oracle_boundary_and_wilson_interval():
    assert recoverability_regime(47.49) == "underdetermined"
    assert recoverability_regime(47.5) == "edge"
    assert recoverability_regime(48.49) == "edge"
    assert recoverability_regime(48.5) == "overdetermined"
    assert ideal_hash_probability(47.49) == 0.0
    assert ideal_hash_probability(48.0) == pytest.approx(math.exp(-1.0))
    assert ideal_hash_probability(60.0) > 0.999
    lower, upper = wilson_interval(0, 200)
    assert lower == 0.0 and 0.0 < upper < 0.02
    lower, upper = wilson_interval(200, 200)
    assert 0.98 < lower < 1.0 and upper == 1.0


def test_frozen_fixture_reproduces_expected_model_and_regime_coverage():
    fixture = _fixture()
    assert len(validate_fixture(fixture)) == 91
    summary = coverage_summary(fixture)
    assert summary["nextint_odd"]["covered"] == 48
    assert summary["nextint_odd"]["eligible"] == 49
    assert summary["bit_length"]["covered"] == 31
    assert summary["bit_length"]["eligible"] == 31
    assert sum(row.model == "nextint_odd" and not row.covered for row in coverage_rows(fixture)) == 1
    assert summary["nextint_odd"]["by_regime"]["edge"] == {"covered": 3, "eligible": 4}


def test_reliability_table_is_fixed_bin_aggregate_only():
    table = reliability_table(_fixture())
    assert table
    assert sum(row["cells"] for row in table) == 80
    assert all(row["trials"] > 0 for row in table)
    assert all(0.0 <= row["mean_predicted"] <= 1.0 for row in table)
    assert all(0.0 <= row["mean_observed"] <= 1.0 for row in table)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda data: data.update(schema_version=2), "schema"),
        (lambda data: data["provenance"].update(seed=1), "provenance"),
        (lambda data: data["aggregate_verification"].update(raw_trial_records_exported=1), "raw trial"),
        (lambda data: data["cells"].append(deepcopy(data["cells"][0])), "91 aggregate"),
        (lambda data: data["cells"][0].update(model="other"), "unknown model"),
        (lambda data: data["cells"][0].update(requested_trials=199), "requested trials"),
        (lambda data: data["cells"][0].update(unique_count=1), "scored counts"),
        (lambda data: data["cells"][0].update(realized_leaked_bits_mean=float("nan")), "leaked-bit"),
        (lambda data: data.update(raw_states=[]), "forbidden raw"),
        (lambda data: data.update(unexpected_aggregate=True), "fixture fields differ"),
    ],
)
def test_malformed_fixture_fails_closed(mutation, message):
    fixture = _fixture()
    mutation(fixture)
    with pytest.raises(FixtureValidationError, match=message):
        validate_fixture(fixture)


@pytest.mark.parametrize(
    "call",
    [
        lambda: wilson_interval(-1, 2),
        lambda: wilson_interval(3, 2),
        lambda: wilson_interval(0, 0),
        lambda: ideal_hash_probability(float("inf")),
        lambda: reliability_table(_fixture(), bins=(0.0, 0.5, 0.5, 1.0)),
    ],
)
def test_public_functions_reject_invalid_inputs(call):
    with pytest.raises(ValueError):
        call()

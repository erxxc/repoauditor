"""Pure exact-oracle calibration utilities for OPT-037 Tier 0.

This module validates and summarizes the frozen aggregate lattice-lab fixture. It is not
connected to production analysis, triage, reporting, configuration, or persistence.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import math
from typing import Any


SECRET_BITS = 48.0
EDGE_HALF_WIDTH = 0.5
Z95 = 1.959963984540054
RELIABILITY_BINS = (0.0, 0.2, 0.4, 0.6, 0.8, 1.0001)

_MODELS = {
    "nextint_odd": {
        "bits": (2, 4, 8, 12, 16, 20, 24),
        "observations": (2, 3, 4, 6, 8, 12, 16),
    },
    "bit_length": {
        "bits": (2, 4, 8, 12, 16, 20, 24),
        "observations": (8, 16, 24, 32, 48, 64),
    },
}
_CLASSIFICATIONS = {"recovered", "ambiguous", "underdetermined", "infeasible"}
_COUNT_KEYS = (
    "requested_trials",
    "scored_trials",
    "unique_count",
    "ambiguous_count",
    "unrecovered_count",
    "underdetermined_count",
    "infeasible_count",
    "rejected_window_count",
)
_FORBIDDEN_KEYS = {
    "raw_state", "raw_states", "token", "tokens", "predictions", "source_excerpt",
    "source_excerpts", "trial_identity", "trial_identities", "demonstration_artifact",
    "demonstration_artifacts", "jvm_output",
}
_FIXTURE_KEYS = {"schema_version", "fixture_kind", "generated_at", "provenance", "aggregate_verification", "cells"}
_PROVENANCE_KEYS = {
    "lab_commit", "lab_tree", "lab_version", "sweep_grid_sha256",
    "calibration_reference_sha256", "temporary_database_sha256", "runtime", "seed",
    "trials_per_cell",
}
_CELL_KEYS = {
    "model", "bits_per_call", "num_observations", "bound", *_COUNT_KEYS,
    "realized_leaked_bits_mean", "mean_consistent_states", "classification",
}


class FixtureValidationError(ValueError):
    """The aggregate fixture violates its frozen contract."""


@dataclass(frozen=True)
class CoverageRow:
    model: str
    bits_per_call: int
    num_observations: int
    regime: str
    trials: int
    successes: int
    observed: float
    predicted: float
    lower: float
    upper: float
    covered: bool


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _finite_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _walk_keys(value: object) -> None:
    if isinstance(value, Mapping):
        forbidden = _FORBIDDEN_KEYS.intersection(value)
        if forbidden:
            raise FixtureValidationError(f"forbidden raw field(s): {sorted(forbidden)}")
        for child in value.values():
            _walk_keys(child)


def _require_keys(value: Mapping[str, Any], expected: set[str], location: str) -> None:
    actual = set(value)
    if actual != expected:
        raise FixtureValidationError(
            f"{location} fields differ: missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )
    elif isinstance(value, list):
        for child in value:
            _walk_keys(child)


def validate_fixture(fixture: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    """Validate the exact aggregate fixture and return its cells without mutation."""
    if not isinstance(fixture, Mapping):
        raise FixtureValidationError("fixture must be an object")
    _walk_keys(fixture)
    _require_keys(fixture, _FIXTURE_KEYS, "fixture")
    if fixture.get("schema_version") != 1:
        raise FixtureValidationError("unsupported fixture schema")
    if fixture.get("fixture_kind") != "opt037_tier0_outcome_free_exact_oracle_aggregate":
        raise FixtureValidationError("unexpected fixture kind")

    provenance = fixture.get("provenance")
    expected_provenance = {
        "lab_commit": "c248eea5c2bd25b7dfcf077049a060ac6aa435d2",
        "lab_tree": "9c956842beb0366a404a8dad084661d961ef8c00",
        "lab_version": "0.2.0",
        "sweep_grid_sha256": "d059fb0d0594422d96e429bf04d5b143b054091420eb5c82d0f762ac672eb32e",
        "calibration_reference_sha256": "6b10b940d46f6a94c842cebdcf1d8c63920867ed19bb3cbb54f30d8c72a91465",
        "seed": 0,
        "trials_per_cell": 200,
    }
    if not isinstance(provenance, Mapping):
        raise FixtureValidationError("missing provenance")
    _require_keys(provenance, _PROVENANCE_KEYS, "provenance")
    runtime = provenance.get("runtime")
    if not isinstance(runtime, Mapping):
        raise FixtureValidationError("missing runtime provenance")
    _require_keys(runtime, {"python", "numpy", "fpylll"}, "runtime provenance")
    for key, expected in expected_provenance.items():
        if provenance.get(key) != expected:
            raise FixtureValidationError(f"provenance mismatch: {key}")

    verification = fixture.get("aggregate_verification")
    if not isinstance(verification, Mapping) or verification.get("raw_trial_records_exported") != 0:
        raise FixtureValidationError("raw trial export boundary violated")
    _require_keys(
        verification,
        {"nextint_odd", "bit_length", "oracle", "raw_trial_records_exported"},
        "aggregate verification",
    )
    if not isinstance(verification["nextint_odd"], Mapping):
        raise FixtureValidationError("invalid nextint_odd verification")
    if not isinstance(verification["bit_length"], Mapping):
        raise FixtureValidationError("invalid bit_length verification")
    _require_keys(verification["nextint_odd"], {"grid_cells", "eligible_cells", "covered_cells"}, "nextint_odd verification")
    _require_keys(verification["bit_length"], {"grid_cells", "eligible_scored_cells", "covered_cells"}, "bit_length verification")
    cells = fixture.get("cells")
    if not isinstance(cells, list) or len(cells) != 91:
        raise FixtureValidationError("fixture must contain exactly 91 aggregate cells")

    seen: set[tuple[str, int, int]] = set()
    for index, cell in enumerate(cells):
        if not isinstance(cell, Mapping):
            raise FixtureValidationError(f"cell {index} must be an object")
        _require_keys(cell, _CELL_KEYS, f"cell {index}")
        model = cell.get("model")
        if model not in _MODELS:
            raise FixtureValidationError(f"cell {index} has unknown model")
        bits = cell.get("bits_per_call")
        observations = cell.get("num_observations")
        if not _is_int(bits) or bits not in _MODELS[model]["bits"]:
            raise FixtureValidationError(f"cell {index} has invalid bits")
        if not _is_int(observations) or observations not in _MODELS[model]["observations"]:
            raise FixtureValidationError(f"cell {index} has invalid observations")
        identity = (model, bits, observations)
        if identity in seen:
            raise FixtureValidationError(f"duplicate cell: {identity}")
        seen.add(identity)
        expected_bound = (1 << bits) - 1 if model == "nextint_odd" else 1 << bits
        if cell.get("bound") != expected_bound:
            raise FixtureValidationError(f"cell {index} has invalid bound")

        for key in _COUNT_KEYS:
            value = cell.get(key)
            if not _is_int(value) or value < 0:
                raise FixtureValidationError(f"cell {index} has invalid {key}")
        if cell["requested_trials"] != 200:
            raise FixtureValidationError(f"cell {index} changed requested trials")
        if cell["unique_count"] + cell["ambiguous_count"] + cell["unrecovered_count"] != cell["scored_trials"]:
            raise FixtureValidationError(f"cell {index} scored counts do not conserve")
        if cell["scored_trials"] + cell["underdetermined_count"] + cell["infeasible_count"] + cell["rejected_window_count"] != cell["requested_trials"]:
            raise FixtureValidationError(f"cell {index} requested counts do not conserve")

        classification = cell.get("classification")
        if classification not in _CLASSIFICATIONS:
            raise FixtureValidationError(f"cell {index} has invalid classification")
        if classification == "underdetermined" and cell["underdetermined_count"] == 0:
            raise FixtureValidationError(f"cell {index} classification/count mismatch")
        if classification == "infeasible" and cell["infeasible_count"] == 0:
            raise FixtureValidationError(f"cell {index} classification/count mismatch")
        if classification in {"recovered", "ambiguous"} and cell["scored_trials"] == 0:
            raise FixtureValidationError(f"cell {index} classification/count mismatch")

        leaked = cell.get("realized_leaked_bits_mean")
        candidates = cell.get("mean_consistent_states")
        if not _finite_number(leaked) or leaked < 0:
            raise FixtureValidationError(f"cell {index} has invalid leaked-bit mean")
        if candidates is not None and (not _finite_number(candidates) or candidates < 0):
            raise FixtureValidationError(f"cell {index} has invalid candidate mean")

    expected = {
        (model, bits, observations)
        for model, axes in _MODELS.items()
        for bits in axes["bits"]
        for observations in axes["observations"]
    }
    if seen != expected:
        raise FixtureValidationError("fixture grid is incomplete or expanded")
    return tuple(cells)


def recoverability_regime(leaked_bits: float) -> str:
    if not _finite_number(leaked_bits) or leaked_bits < 0:
        raise ValueError("leaked_bits must be a finite non-negative number")
    if leaked_bits < SECRET_BITS - EDGE_HALF_WIDTH:
        return "underdetermined"
    if leaked_bits < SECRET_BITS + EDGE_HALF_WIDTH:
        return "edge"
    return "overdetermined"


def ideal_hash_probability(leaked_bits: float) -> float:
    """Probability of a unique 48-bit state under the frozen ideal-hash oracle."""
    regime = recoverability_regime(leaked_bits)
    if regime == "underdetermined":
        return 0.0
    return math.exp(-(2.0 ** (SECRET_BITS - leaked_bits)))


def wilson_interval(successes: int, trials: int, z: float = Z95) -> tuple[float, float]:
    if not _is_int(successes) or not _is_int(trials) or successes < 0 or trials <= 0 or successes > trials:
        raise ValueError("require integer counts with 0 <= successes <= trials and trials > 0")
    if not _finite_number(z) or z <= 0:
        raise ValueError("z must be finite and positive")
    proportion = successes / trials
    z2 = z * z
    denominator = 1.0 + z2 / trials
    center = (proportion + z2 / (2.0 * trials)) / denominator
    half = (z / denominator) * math.sqrt(
        proportion * (1.0 - proportion) / trials + z2 / (4.0 * trials * trials)
    )
    return max(0.0, center - half), min(1.0, center + half)


def coverage_rows(fixture: Mapping[str, Any]) -> tuple[CoverageRow, ...]:
    rows: list[CoverageRow] = []
    for cell in validate_fixture(fixture):
        model = str(cell["model"])
        scored = int(cell["scored_trials"])
        if model == "bit_length" and scored == 0:
            continue
        trials = scored or int(cell["requested_trials"])
        successes = int(cell["unique_count"])
        leaked = float(cell["realized_leaked_bits_mean"])
        lower, upper = wilson_interval(successes, trials)
        predicted = ideal_hash_probability(leaked)
        rows.append(CoverageRow(
            model=model,
            bits_per_call=int(cell["bits_per_call"]),
            num_observations=int(cell["num_observations"]),
            regime=recoverability_regime(leaked),
            trials=trials,
            successes=successes,
            observed=successes / trials,
            predicted=predicted,
            lower=lower,
            upper=upper,
            covered=lower - 1e-12 <= predicted <= upper + 1e-12,
        ))
    return tuple(rows)


def coverage_summary(fixture: Mapping[str, Any]) -> dict[str, Any]:
    rows = coverage_rows(fixture)
    summary: dict[str, Any] = {}
    for model in _MODELS:
        members = [row for row in rows if row.model == model]
        regimes: dict[str, dict[str, int]] = {}
        for regime in ("underdetermined", "edge", "overdetermined"):
            selected = [row for row in members if row.regime == regime]
            if selected:
                regimes[regime] = {
                    "covered": sum(row.covered for row in selected),
                    "eligible": len(selected),
                }
        summary[model] = {
            "covered": sum(row.covered for row in members),
            "eligible": len(members),
            "by_regime": regimes,
        }
    return summary


def reliability_table(
    fixture: Mapping[str, Any], bins: Sequence[float] = RELIABILITY_BINS,
) -> tuple[dict[str, float | int], ...]:
    if len(bins) < 2 or any(not _finite_number(value) for value in bins):
        raise ValueError("bins must contain at least two finite boundaries")
    if any(left >= right for left, right in zip(bins, bins[1:])):
        raise ValueError("bins must be strictly increasing")
    rows = coverage_rows(fixture)
    output: list[dict[str, float | int]] = []
    for lower, upper in zip(bins, bins[1:]):
        members = [row for row in rows if lower <= row.predicted < upper]
        if members:
            output.append({
                "bin_low": float(lower),
                "bin_high": min(float(upper), 1.0),
                "cells": len(members),
                "trials": sum(row.trials for row in members),
                "mean_predicted": sum(row.predicted for row in members) / len(members),
                "mean_observed": sum(row.observed for row in members) / len(members),
            })
    return tuple(output)

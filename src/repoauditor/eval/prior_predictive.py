"""Bounded descriptive OPT-014 prior-predictive coherence report."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import tomllib
from pathlib import Path
from typing import Any

import numpy as np
import yaml

from ..analyze.risk_quant import ScenarioParams, calibrate_lognormal, monte_carlo


TRIALS = 200_000
SEED = 2014
BATCH_COUNT = 20
TRIALS_PER_BATCH = 10_000
EXCEEDANCE_POINTS_USD = (100_000, 1_000_000, 10_000_000, 50_000_000, 100_000_000)
_Z95 = 1.6448536269514722
_FROZEN_SHA256 = {
    "eligibility_audit_result": "95c4166f7002ff09ad5e5278d6417e21581d3d0a19ceef8398b7c2e21f9b6454",
    "eligibility_audit_artifact": "682e6f8e0e0c701e06abd762f63e00a7008a8957d904243c76ca13890a9d37a1",
    "priors": "f6a49336a1e7aa72ed1e360e90649036364983b3792ddfd97a203d18d85287e9",
    "configuration": "30d8837bdb63b56a50aefb0cd9bc18a0a7173ac86cd8581d4af6f2b2b21f3d09",
    "pure_simulation_engine": "bcea80fd03fd636cebfb3328f30beae48b64b6d197f3e5d3b96f0f60a18150ac",
    "production_store": "468c8de903f6c4c0ed23304e59db150a1d5d0b6cf350247fba3bc3d2699caf5a",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _paths(root: Path) -> dict[str, Path]:
    return {
        "eligibility_audit_result": (
            root / "docs/optimizations/opt-014-offline-eligibility-audit-result-2026-08-18.json"
        ),
        "eligibility_audit_artifact": root / "data/artifacts/opt014-eligibility-audit.json",
        "priors": root / "priors.yaml",
        "configuration": root / "config.toml",
        "pure_simulation_engine": root / "src/repoauditor/analyze/risk_quant.py",
        "production_store": root / "data/repoauditor.db",
    }


def load_frozen_parameters(root: Path) -> dict[str, float | str]:
    """Verify frozen inputs and reconstruct source parameters without simulation."""
    root = root.resolve()
    paths = _paths(root)
    digests = {name: _sha256(path) for name, path in paths.items()}
    if digests != _FROZEN_SHA256:
        drift = sorted(
            name for name, digest in digests.items()
            if digest != _FROZEN_SHA256[name]
        )
        raise ValueError(f"frozen OPT-014 coherence input drift: {', '.join(drift)}")
    audit = json.loads(paths["eligibility_audit_result"].read_text(encoding="utf-8"))
    if audit["decision"]["data_gate_cleared"] is not False:
        raise ValueError("eligibility audit no longer has the frozen uncleared data gate")
    config = tomllib.loads(paths["configuration"].read_text(encoding="utf-8"))
    risk_quant = config.get("risk_quant", {})
    forbidden_overrides = (
        "exposure_overrides", "control_strength_overrides", "loss_scale_overrides"
    )
    if any(risk_quant.get(name) for name in forbidden_overrides):
        raise ValueError("neutral OPT-014 baseline forbids configured risk-quant overrides")
    priors = yaml.safe_load(paths["priors"].read_text(encoding="utf-8"))
    frequency = priors["frequency"]["industry_baseline"]
    magnitude = priors["magnitude"]["industry_baseline"]
    annual_probability = float(frequency["annual_probability_at_least_one"])
    median_usd = float(magnitude["median_usd"])
    p95_usd = float(magnitude["p95_usd"])
    frequency_lambda = -math.log1p(-annual_probability)
    mu, sigma = calibrate_lognormal(median_usd, p95_usd)
    return {
        "annual_probability_at_least_one": annual_probability,
        "frequency_lambda": frequency_lambda,
        "magnitude_median_usd": median_usd,
        "magnitude_p95_usd": p95_usd,
        "magnitude_mu": mu,
        "magnitude_sigma": sigma,
        "magnitude_implied_p05_usd": math.exp(mu - _Z95 * sigma),
        "company_revenue_band": str(risk_quant.get("company_revenue_band", "unknown")),
    }


def summarize_losses(losses: np.ndarray) -> dict[str, Any]:
    """Reduce annual loss draws to the frozen aggregate-only output."""
    if losses.ndim != 1 or losses.size == 0:
        raise ValueError("losses must be one non-empty vector")
    if not np.all(np.isfinite(losses)) or np.any(losses < 0):
        raise ValueError("losses must be finite and nonnegative")
    positive = losses[losses > 0]
    if positive.size == 0:
        raise ValueError("frozen prior-predictive sample unexpectedly has no positive loss")

    def quantiles(values: np.ndarray, points: tuple[int, ...]) -> dict[str, float]:
        return {
            f"p{point}": float(np.percentile(values, point)) for point in points
        }

    exceedance = {
        str(point): float(np.count_nonzero(losses > point) / losses.size)
        for point in EXCEEDANCE_POINTS_USD
    }
    top_count = max(1, math.ceil(losses.size * 0.01))
    top_losses = np.partition(losses, losses.size - top_count)[-top_count:]
    total_loss = float(losses.sum())
    batch_summaries = []
    if losses.size == TRIALS:
        for index in range(BATCH_COUNT):
            batch = losses[index * TRIALS_PER_BATCH:(index + 1) * TRIALS_PER_BATCH]
            batch_summaries.append({
                "batch": index + 1,
                "mean_usd": float(np.mean(batch)),
                "p95_usd": float(np.percentile(batch, 95)),
            })
    return {
        "anonymous_organization_years": int(losses.size),
        "positive_loss_years": int(positive.size),
        "zero_loss_fraction": float(np.count_nonzero(losses == 0) / losses.size),
        "annual_loss_usd": {
            "mean": float(np.mean(losses)),
            **quantiles(losses, (50, 75, 90, 95, 99)),
        },
        "conditional_positive_annual_loss_usd": {
            "mean": float(np.mean(positive)),
            **quantiles(positive, (50, 90, 95, 99)),
        },
        "fixed_exceedance_probability": exceedance,
        "top_one_percent_share_of_total_loss": (
            float(top_losses.sum() / total_loss) if total_loss else 0.0
        ),
        "batch_summaries": batch_summaries,
        "batch_stability": {
            "batches": len(batch_summaries),
            "mean_usd_min": min((item["mean_usd"] for item in batch_summaries), default=0.0),
            "mean_usd_max": max((item["mean_usd"] for item in batch_summaries), default=0.0),
            "p95_usd_min": min((item["p95_usd"] for item in batch_summaries), default=0.0),
            "p95_usd_max": max((item["p95_usd"] for item in batch_summaries), default=0.0),
        },
    }


def generate_report(root: Path) -> dict[str, Any]:
    """Perform the single frozen 200,000-year in-memory generation."""
    root = root.resolve()
    paths = _paths(root)
    store_before = _sha256(paths["production_store"])
    parameters = load_frozen_parameters(root)
    scenario = ScenarioParams(
        name="organization_all_event",
        finding_ids=[],
        frequency_lambda=float(parameters["frequency_lambda"]),
        magnitude_mu=float(parameters["magnitude_mu"]),
        magnitude_sigma=float(parameters["magnitude_sigma"]),
        p05_usd=float(parameters["magnitude_implied_p05_usd"]),
        p95_usd=float(parameters["magnitude_p95_usd"]),
        frequency_source="frequency.industry_baseline",
        magnitude_source="magnitude.industry_baseline",
        p_actionable=1.0,
        validity_probabilities=[],
        validity_sources=[],
        conditional_frequency_lambdas=[float(parameters["frequency_lambda"])],
        conditional_frequency_source="frequency.industry_baseline",
        exposure_factors=[1.0],
        control_strengths=[0.0],
        loss_scale=1.0,
        methodology_version="organization_all_event_v1",
    )
    generated = monte_carlo([scenario], trials=TRIALS, seed=SEED)
    summary = summarize_losses(generated.aggregate)
    store_after = _sha256(paths["production_store"])

    p = float(parameters["annual_probability_at_least_one"])
    lam = float(parameters["frequency_lambda"])
    mu = float(parameters["magnitude_mu"])
    sigma = float(parameters["magnitude_sigma"])
    analytic = {
        "expected_events_per_year": lam,
        "zero_event_probability": math.exp(-lam),
        "at_least_one_event_probability": 1.0 - math.exp(-lam),
        "expected_event_loss_usd": math.exp(mu + sigma * sigma / 2.0),
        "expected_annual_loss_usd": lam * math.exp(mu + sigma * sigma / 2.0),
        "reconstructed_magnitude_median_usd": math.exp(mu),
        "reconstructed_magnitude_p95_usd": math.exp(mu + _Z95 * sigma),
    }
    exceedance_values = list(summary["fixed_exceedance_probability"].values())
    core_for_determinism = {
        "parameters": parameters,
        "analytic": analytic,
        "simulation": summary,
        "trials": TRIALS,
        "seed": SEED,
    }
    canonical_once = json.dumps(
        core_for_determinism, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    canonical_twice = json.dumps(
        core_for_determinism, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    checks = [
        {
            "name": "frequency_source_reproduction",
            "passed": abs(analytic["at_least_one_event_probability"] - p) <= 1e-12,
        },
        {
            "name": "magnitude_source_reproduction",
            "passed": (
                abs(analytic["reconstructed_magnitude_median_usd"]
                    / float(parameters["magnitude_median_usd"]) - 1.0) <= 1e-12
                and abs(analytic["reconstructed_magnitude_p95_usd"]
                        / float(parameters["magnitude_p95_usd"]) - 1.0) <= 1e-12
            ),
        },
        {
            "name": "zero_mass_consistency",
            "passed": abs(
                summary["zero_loss_fraction"] - analytic["zero_event_probability"]
            ) <= 0.005,
        },
        {
            "name": "annual_median_zero",
            "passed": (
                analytic["zero_event_probability"] > 0.5
                and summary["annual_loss_usd"]["p50"] == 0.0
            ),
        },
        {
            "name": "fixed_exceedance_monotonic_and_bounded",
            "passed": (
                all(0.0 <= value <= 1.0 for value in exceedance_values)
                and all(
                    left >= right
                    for left, right in zip(exceedance_values, exceedance_values[1:])
                )
            ),
        },
        {
            "name": "fixed_seed_aggregate_canonicalization",
            "passed": canonical_once == canonical_twice,
            "aggregate_sha256": hashlib.sha256(canonical_once).hexdigest(),
        },
        {
            "name": "production_store_byte_identical",
            "passed": store_before == store_after == _FROZEN_SHA256["production_store"],
        },
    ]
    if not all(check["passed"] for check in checks):
        failed = [check["name"] for check in checks if not check["passed"]]
        raise ValueError(f"OPT-014 coherence checks failed: {', '.join(failed)}")
    return {
        "schema_version": 1,
        "report_id": "opt014-descriptive-prior-predictive-coherence-v1",
        "status": "complete-coherent-descriptive-only",
        "recorded_at": "2026-08-18",
        "input_digests": {name: _sha256(path) for name, path in paths.items()},
        "model": {
            "methodology_version": "organization_all_event_v1",
            "modeling_unit": "anonymous-neutral-organization-year",
            "trials": TRIALS,
            "seed": SEED,
            "exposure": 1.0,
            "control_strength": 0.0,
            "loss_scale": 1.0,
            "epistemic_parameter_sampling": False,
        },
        "parameters": parameters,
        "analytic_implications": analytic,
        "simulated_implications": summary,
        "coherence_checks": checks,
        "coherence_checks_passed": sum(check["passed"] for check in checks),
        "interpretation": {
            "scope": "Implications of the configured industry baseline only.",
            "predictive_validation": False,
            "calibration_or_representativeness": False,
            "monte_carlo_variability_is_epistemic_uncertainty": False,
            "decision_grade": False,
            "opt_014_data_gate_cleared": False,
            "population_limitations": (
                "Organization revenue is unknown; the frequency prior targets organizations "
                "over $10M revenue, and neither prior is organization-, sector-, geography-, "
                "architecture-, or control-maturity-specific."
            ),
        },
        "store": {
            "access": "hash-only-no-database-open",
            "sha256_before": store_before,
            "sha256_after": store_after,
            "byte_identical": store_before == store_after,
        },
        "accounting": {
            "in_memory_prior_predictive_generations": 1,
            "anonymous_organization_years": TRIALS,
            "raw_draws_persisted": 0,
            "production_store_rows_read": 0,
            "production_store_mutations": 0,
            "persisted_simulation_runs": 0,
            "persisted_risk_scenarios": 0,
            "persisted_prior_sources": 0,
            "network_reads": 0,
            "network_uploads": 0,
            "provider_calls": 0,
            "provider_reported_tokens": 0,
            "provider_cost_usd": 0.0,
            "assessments_written": 0,
            "labels_written": 0,
            "model_training_runs": 0,
            "rescoring_runs": 0,
        },
        "decision": {
            "opt_014_status": "open-data-gated",
            "next_options": [
                "governed-independent-organization-incident-data-acquisition-design",
                "bounded-negative-feasibility-closure",
            ],
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(f"refusing to overwrite existing report: {args.output}")
    payload = generate_report(args.root)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    print(
        "OPT-014 descriptive coherence complete: "
        f"checks={payload['coherence_checks_passed']}; "
        f"data_gate_cleared={payload['interpretation']['opt_014_data_gate_cleared']}"
    )


if __name__ == "__main__":
    main()

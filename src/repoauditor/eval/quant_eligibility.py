"""Aggregate-only, read-only OPT-014 data-eligibility audit."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import tomllib
from pathlib import Path
from typing import Any

import yaml


_FROZEN_SHA256 = {
    "production_store": "468c8de903f6c4c0ed23304e59db150a1d5d0b6cf350247fba3bc3d2699caf5a",
    "configuration": "30d8837bdb63b56a50aefb0cd9bc18a0a7173ac86cd8581d4af6f2b2b21f3d09",
    "priors": "f6a49336a1e7aa72ed1e360e90649036364983b3792ddfd97a203d18d85287e9",
    "prior_scope_roadmap": "2c869ffafc40e2bd8d871c3ccbbe89e54b1a1fdb1164d74acdf57eeac7843b44",
    "organization_frequency_methodology": "645aa1c29d58ca299cfa27c3c1d15c315366cad1d80b8b051744d6c6b6c01ef5",
    "optimization_status": "a8d33e0d3f27e686b120213689223fb29b83834245ffc2f0b147f33f7842c6fa",
}

_AGGREGATE_COUNT_TABLES = {
    "ingested_repositories": "ingested_repo",
    "findings": "finding",
    "assessments": "triage_assessment",
    "labels": "triage_label",
    "risk_scenarios": "risk_scenario",
    "simulation_runs": "simulation_run",
    "scenario_inputs": "scenario_input",
    "persisted_prior_sources": "prior_source",
}

_OBSERVED_TABLE_CONCEPTS = {
    "organization_period_outcomes": (
        "organization_period_outcome", "organization_year_outcome"
    ),
    "incident_observations": ("incident_observation", "incident_outcome"),
    "realized_losses": ("realized_loss", "loss_observation"),
    "interventions": ("intervention", "remediation_intervention"),
    "portfolio_units": ("portfolio_unit", "portfolio_member"),
    "portfolio_dependencies": ("portfolio_dependency",),
    "portfolio_objectives": ("portfolio_objective",),
    "portfolio_constraints": ("portfolio_constraint",),
}

_PRIOR_METADATA_FIELDS = (
    "target_population",
    "effective_date",
    "data_vintage",
    "aleatory_representation",
    "epistemic_status",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_only_connection(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)


def _table_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall()
    return {str(row[0]) for row in rows}


def _count(conn: sqlite3.Connection, table: str, tables: set[str]) -> int:
    if table not in tables:
        return 0
    # Every table name is selected from a module-owned constant, never store content.
    return int(conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])


def _methodology_counts(
    conn: sqlite3.Connection, tables: set[str]
) -> dict[str, int]:
    if "risk_scenario" not in tables:
        return {}
    rows = conn.execute(
        "SELECT methodology_version, COUNT(*) FROM risk_scenario "
        "GROUP BY methodology_version ORDER BY methodology_version"
    ).fetchall()
    return {str(method): int(count) for method, count in rows}


def _persisted_prior_metadata(
    conn: sqlite3.Connection, tables: set[str]
) -> dict[str, int]:
    if "prior_source" not in tables:
        return {"verified_rows": 0, "verified_rows_with_complete_scope_metadata": 0}
    verified = int(conn.execute(
        "SELECT COUNT(*) FROM prior_source WHERE provenance_status = 'verified'"
    ).fetchone()[0])
    complete = int(conn.execute(
        "SELECT COUNT(*) FROM prior_source WHERE provenance_status = 'verified' "
        "AND COALESCE(target_population, '') <> '' "
        "AND COALESCE(effective_date, '') <> '' "
        "AND COALESCE(data_vintage, '') <> '' "
        "AND COALESCE(aleatory_representation, '') <> '' "
        "AND COALESCE(epistemic_status, '') <> ''"
    ).fetchone()[0])
    return {
        "verified_rows": verified,
        "verified_rows_with_complete_scope_metadata": complete,
    }


def _configured_prior_metadata(priors: dict[str, Any]) -> dict[str, Any]:
    selected = {
        "magnitude.industry_baseline": priors.get("magnitude", {}).get(
            "industry_baseline", {}
        ),
        "frequency.industry_baseline": priors.get("frequency", {}).get(
            "industry_baseline", {}
        ),
    }
    completeness = {
        name: {
            field: bool(record.get(field)) for field in _PRIOR_METADATA_FIELDS
        }
        for name, record in selected.items()
    }
    return {
        "configured_priors_checked": len(selected),
        "configured_priors_complete": sum(
            all(fields.values()) for fields in completeness.values()
        ),
        "field_completeness": completeness,
    }


def build_audit(root: Path) -> dict[str, Any]:
    """Build one deterministic aggregate audit without writing or simulating."""
    root = root.resolve()
    paths = {
        "production_store": root / "data/repoauditor.db",
        "configuration": root / "config.toml",
        "priors": root / "priors.yaml",
        "prior_scope_roadmap": root / "docs/prior-scope-roadmap.md",
        "organization_frequency_methodology": (
            root / "docs/organization-frequency-methodology.md"
        ),
        "optimization_status": root / "docs/optimizations/optimization-status.json",
    }
    observed_digests = {name: _sha256(path) for name, path in paths.items()}
    if observed_digests != _FROZEN_SHA256:
        drift = sorted(
            name for name, digest in observed_digests.items()
            if digest != _FROZEN_SHA256[name]
        )
        raise ValueError(f"frozen OPT-014 input digest drift: {', '.join(drift)}")

    lifecycle = json.loads(paths["optimization_status"].read_text(encoding="utf-8"))
    opt014 = next(item for item in lifecycle["items"] if item["id"] == "OPT-014")
    expected_lifecycle = {
        "id": "OPT-014",
        "title": "Predictive checks and portfolio modeling",
        "status": "open",
        "gate": "data",
        "next_priority": 1,
    }
    if opt014 != expected_lifecycle:
        raise ValueError("OPT-014 is not at the frozen open/data-gated lifecycle state")

    config = tomllib.loads(paths["configuration"].read_text(encoding="utf-8"))
    priors = yaml.safe_load(paths["priors"].read_text(encoding="utf-8"))
    before_store_sha256 = observed_digests["production_store"]
    with _read_only_connection(paths["production_store"]) as conn:
        conn.execute("PRAGMA query_only = ON")
        tables = _table_names(conn)
        aggregate_counts = {
            name: _count(conn, table, tables)
            for name, table in _AGGREGATE_COUNT_TABLES.items()
        }
        methodology_counts = _methodology_counts(conn, tables)
        persisted_prior_metadata = _persisted_prior_metadata(conn, tables)
        observed_schema = {
            concept: {
                "table_present": any(table in tables for table in candidates),
                "aggregate_rows": sum(_count(conn, table, tables) for table in candidates),
            }
            for concept, candidates in _OBSERVED_TABLE_CONCEPTS.items()
        }
    after_store_sha256 = _sha256(paths["production_store"])
    if after_store_sha256 != before_store_sha256:
        raise ValueError("production store changed during read-only OPT-014 audit")

    configured_prior_metadata = _configured_prior_metadata(priors)
    observed_capacity = any(
        item["aggregate_rows"] > 0 for item in observed_schema.values()
    )
    prior_plumbing = (
        configured_prior_metadata["configured_priors_checked"]
        == configured_prior_metadata["configured_priors_complete"]
    )
    absent_reason = (
        "No eligible observed organization-period outcome schema or rows exist in the "
        "digest-frozen store."
    )
    capacity = {
        "descriptive_prior_predictive_plumbing": {
            "state": "structurally-present" if prior_plumbing else "structurally-absent",
            "reason": (
                "The two configured industry priors contain complete population, temporal, "
                "aleatory, and epistemic metadata. This supports only a later descriptive "
                "coherence report, not predictive validation."
                if prior_plumbing else
                "Configured industry prior scope metadata is incomplete."
            ),
        },
        "independent_held_out_validation_and_backtesting": {
            "state": "structurally-present" if observed_capacity else "structurally-absent",
            "reason": (
                "Observed outcome schema exists; adequacy and split selection remain unfrozen."
                if observed_capacity else absent_reason
            ),
        },
        "hierarchical_cohorts": {
            "state": "structurally-absent",
            "reason": (
                "No observed organization-period outcomes with predefined cohort dimensions "
                "exist; repository or finding groupings are ineligible substitutes."
            ),
        },
        "remediation_effect_analysis": {
            "state": "structurally-absent",
            "reason": (
                "No time-stamped intervention records with comparable outcome windows exist; "
                "finding closure is not a realized incident/loss outcome."
            ),
        },
        "portfolio_modeling": {
            "state": "structurally-absent",
            "reason": (
                "No portfolio-unit, dependency, objective, or constraint records exist; "
                "summing repository or scenario simulations is ineligible."
            ),
        },
    }
    return {
        "schema_version": 1,
        "audit_id": "opt014-offline-data-eligibility-v1",
        "status": "complete-observed-outcome-capacity-absent",
        "recorded_at": "2026-08-18",
        "input_digests": observed_digests,
        "store": {
            "open_mode": "sqlite-uri-mode-ro-plus-query-only",
            "sha256_before": before_store_sha256,
            "sha256_after": after_store_sha256,
            "byte_identical": True,
        },
        "lifecycle_observed": opt014,
        "aggregate_inventory": aggregate_counts,
        "model_output_inventory": {
            "methodology_counts": methodology_counts,
            "all_risk_scenarios_are_model_generated": True,
            "all_simulation_runs_are_model_generated": True,
            "model_outputs_eligible_as_validation_outcomes": False,
        },
        "observed_outcome_schema": observed_schema,
        "prior_metadata": {
            "configured": configured_prior_metadata,
            "persisted_historical_rows": persisted_prior_metadata,
            "company_revenue_band": config.get("risk_quant", {}).get(
                "company_revenue_band", "unknown"
            ),
            "frequency_population_applicability_verified": False,
        },
        "evidence_classification": {
            "eligible_observed_outcome_records": 0,
            "finding_rows_are_outcomes": False,
            "assessment_or_label_rows_are_outcomes": False,
            "simulation_or_scenario_rows_are_outcomes": False,
            "configured_or_persisted_priors_are_independent_outcomes": False,
        },
        "capacity": capacity,
        "decision": {
            "opt_014_data_gate_cleared": False,
            "adequacy_threshold_selected": False,
            "holdout_or_cohort_selected": False,
            "model_or_prior_compared": False,
            "next_step_options": [
                "descriptive-prior-predictive-coherence-report",
                "governed-independent-data-acquisition",
                "bounded-negative-feasibility-closure",
            ],
        },
        "accounting": {
            "row_identities_emitted": 0,
            "raw_outcome_values_emitted": 0,
            "network_reads": 0,
            "network_uploads": 0,
            "provider_calls": 0,
            "provider_reported_tokens": 0,
            "provider_cost_usd": 0.0,
            "production_store_mutations": 0,
            "schema_migrations": 0,
            "assessments_written": 0,
            "labels_written": 0,
            "simulation_runs": 0,
            "model_training_runs": 0,
            "rescoring_runs": 0,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(f"refusing to overwrite existing audit: {args.output}")
    payload = build_audit(args.root)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        "OPT-014 eligibility audit complete: "
        f"observed_outcomes={payload['evidence_classification']['eligible_observed_outcome_records']}; "
        f"data_gate_cleared={payload['decision']['opt_014_data_gate_cleared']}"
    )


if __name__ == "__main__":
    main()

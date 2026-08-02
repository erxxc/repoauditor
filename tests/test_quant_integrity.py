"""Offline quantitative-input integrity checks never alter simulation behavior."""

from __future__ import annotations

import math

from typer.testing import CliRunner

from repoauditor import cli
from repoauditor.analyze.integrity import (
    AuditLevel,
    audit_resolved_inputs,
    quantitative_disclosure,
    render_quant_audit,
)
from repoauditor.analyze.risk_quant import ScenarioParams
from repoauditor.config import load_priors


def _scenario(*, members: int) -> ScenarioParams:
    lam = -math.log1p(-0.129)
    return ScenarioParams(
        name="data_breach",
        finding_ids=list(range(1, members + 1)),
        frequency_lambda=lam * members,
        magnitude_mu=1.0,
        magnitude_sigma=0.5,
        p05_usd=1.0,
        p95_usd=10.0,
        frequency_source="frequency.industry_baseline",
        magnitude_source="magnitude.industry_baseline",
        p_actionable=1.0,
        validity_probabilities=[1.0] * members,
        validity_sources=["falsify:confirmed"] * members,
        conditional_frequency_lambdas=[lam] * members,
        conditional_frequency_source="frequency.industry_baseline",
        exposure_factors=[1.0] * members,
        control_strengths=[0.0] * members,
    )


def _config(tmp_config, revenue_band: str = "unknown", **updates):
    risk_quant = tmp_config.risk_quant.model_copy(update={
        "company_revenue_band": revenue_band,
        **updates,
    })
    return tmp_config.model_copy(update={
        "priors": load_priors(),
        "risk_quant": risk_quant,
    })


def test_audit_blocks_repeated_organization_frequency_per_finding(tmp_config):
    result = audit_resolved_inputs(
        [_scenario(members=2)], _config(tmp_config), repo_id="repo"
    )
    by_code = {issue.code: issue for issue in result.issues}

    assert result.blocking == 1
    assert (
        by_code["organization_frequency_repeated_per_finding"].level
        is AuditLevel.BLOCKING
    )
    assert "findings=2" in by_code[
        "organization_frequency_repeated_per_finding"
    ].evidence
    assert (
        by_code["frequency_population_unverified"].level is AuditLevel.WARNING
    )
    assert not any(
        issue.code == "prior_temporal_scope_unverified" for issue in result.issues
    )
    assert sum(
        issue.code == "prior_uncertainty_scope" for issue in result.issues
    ) == 2
    assert "decision-grade" in render_quant_audit(result)
    disclosure = quantitative_disclosure(result)
    assert disclosure is not None
    assert "EXPERIMENTAL QUANTITATIVE OUTPUT" in disclosure
    assert "NOT DECISION-GRADE" in disclosure


def test_audit_does_not_flag_frequency_repetition_for_one_finding(tmp_config):
    result = audit_resolved_inputs(
        [_scenario(members=1)], _config(tmp_config, "10m_to_100m")
    )
    codes = {issue.code for issue in result.issues}

    assert result.blocking == 0
    assert "organization_frequency_repeated_per_finding" not in codes
    assert "frequency_population_unverified" not in codes
    assert "frequency_population_mismatch" not in codes
    assert quantitative_disclosure(result) is None


def test_audit_discloses_out_of_population_band_and_analyst_overrides(tmp_config):
    result = audit_resolved_inputs(
        [_scenario(members=1)],
        _config(
            tmp_config,
            "1m_to_10m",
            exposure_overrides={"data_breach": 0.5},
        ),
    )
    codes = {issue.code for issue in result.issues}

    assert "frequency_population_mismatch" in codes
    assert "analyst_overrides_present" in codes


def test_quant_audit_cli_is_a_thin_read_only_projection(tmp_config, monkeypatch):
    result = audit_resolved_inputs(
        [_scenario(members=1)], _config(tmp_config, "10m_to_100m"), repo_id="repo"
    )
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    monkeypatch.setattr(
        cli, "audit_quantitative_inputs", lambda repo_id, config: result
    )

    response = CliRunner().invoke(cli.app, ["quant-audit", "repo"])

    assert response.exit_code == 0, response.output
    assert "Quantitative input integrity — repo" in response.stdout
    assert "fair_factor_separation" in response.stdout


def test_quantify_cli_surfaces_blocking_disclosure(tmp_config, monkeypatch, tmp_path):
    result = audit_resolved_inputs(
        [_scenario(members=2)], _config(tmp_config), repo_id="repo"
    )
    appendix = tmp_path / "risk_appendix.md"
    appendix.write_text("# fixture\n")
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    monkeypatch.setattr(
        cli, "quantify_appendix", lambda *args, **kwargs: (appendix, 1)
    )
    monkeypatch.setattr(
        cli, "audit_quantitative_inputs", lambda repo_id, config: result
    )

    response = CliRunner().invoke(cli.app, ["quantify", "repo", "--trials", "10"])

    assert response.exit_code == 0, response.output
    assert "EXPERIMENTAL QUANTITATIVE OUTPUT" in response.output
    assert "NOT DECISION-GRADE" in response.output

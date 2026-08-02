"""Tests for analyze/risk_quant.py — calibration, the Monte Carlo engine (property
tests: moment convergence + uncertainty behaviour), tornado, and appendix export."""

from __future__ import annotations

import math

import numpy as np
import pytest

from repoauditor.analyze import risk_quant
from repoauditor.analyze.risk_quant import ScenarioParams
from repoauditor.config import RiskQuantConfig, load_deal_risk, load_priors
from repoauditor.review import correct_decision, raise_review_requests, record_decision
from repoauditor.store import db
from repoauditor.store.models import (
    Entity, EntityKind, FalsificationStatus, Finding, TrustBoundary,
)


@pytest.fixture
def cfg(tmp_config):
    return tmp_config.model_copy(update={
        "priors": load_priors(), "deal_risk": load_deal_risk(),
    })


def _scenario(name="s", lam=1.0, median=1_000.0, p95=1_000_000.0, p_act=1.0):
    mu, sigma = risk_quant.calibrate_lognormal(median, p95)
    return ScenarioParams(
        name=name, finding_ids=[1], frequency_lambda=lam, magnitude_mu=mu,
        magnitude_sigma=sigma, p05_usd=median, p95_usd=p95,
        frequency_source="frequency.industry_baseline",
        magnitude_source="magnitude.industry_baseline", p_actionable=p_act,
        validity_probabilities=[p_act], validity_sources=["triage:p_actionable"],
        conditional_frequency_lambdas=[lam],
        conditional_frequency_source="frequency.industry_baseline",
        threat_signal_labels=["industry-baseline:no-CVE-signal"],
        exposure_factors=[1.0], control_strengths=[0.0], loss_scale=1.0,
    )


def _analytic_mean(scenarios) -> float:
    """FAIR expectation: sum lambda * E[lognormal]."""
    return sum(s.frequency_lambda * math.exp(s.magnitude_mu + s.magnitude_sigma ** 2 / 2)
               for s in scenarios)


# --------------------------------------------------------------------------- #
# Calibration (published median + p95 -> lognormal)
# --------------------------------------------------------------------------- #
def test_calibrate_lognormal_recovers_the_ci():
    median, p95 = 100.0, 10_000.0
    mu, sigma = risk_quant.calibrate_lognormal(median, p95)
    z = 1.6448536269514722
    assert math.exp(mu) == pytest.approx(median, rel=1e-9)
    assert math.exp(mu + z * sigma) == pytest.approx(p95, rel=1e-9)


# --------------------------------------------------------------------------- #
# Monte Carlo property tests
# --------------------------------------------------------------------------- #
def test_mc_mean_converges_to_analytic_expectation_as_trials_grow():
    # Moderately skewed fixtures isolate engine convergence; the published IRIS baseline
    # is much heavier-tailed and therefore intentionally not used as a convergence toy.
    scenarios = [_scenario(lam=1.5, p95=10_000),
                 _scenario(name="s2", lam=0.4, median=5_000, p95=25_000)]
    analytic = _analytic_mean(scenarios)

    def rel_err(trials):
        # Average a few seeds to reduce seed-specific noise at each trial count.
        errs = []
        for seed in range(5):
            res = risk_quant.monte_carlo(scenarios, trials=trials, seed=seed)
            errs.append(abs(np.mean(res.aggregate) - analytic) / analytic)
        return float(np.mean(errs))

    coarse, fine = rel_err(2_000), rel_err(100_000)
    assert fine < coarse                 # more trials -> tighter estimate
    assert fine < 0.05                   # and close in absolute terms


def test_mc_output_is_right_skewed_range_not_point_estimate():
    res = risk_quant.monte_carlo([_scenario(lam=2.0)], trials=80_000, seed=1)
    s = res.summary()
    # Lognormal severity -> heavy right tail: mean > median, p95 > median.
    assert s["mean"] > s["median"]
    assert s["p95"] > s["median"]
    assert s["p99"] >= s["p95"]


def test_uncertainty_widens_with_wider_magnitude_ci():
    narrow = [_scenario(name="n", lam=1.0, median=90_000, p95=110_000)]
    wide = [_scenario(name="w", lam=1.0, median=1_000, p95=10_000_000)]
    rn = risk_quant.monte_carlo(narrow, trials=60_000, seed=2).summary()
    rw = risk_quant.monte_carlo(wide, trials=60_000, seed=2).summary()
    spread_n = rn["p95"] - rn["p05"]
    spread_w = rw["p95"] - rw["p05"]
    assert spread_w > spread_n            # wider input uncertainty -> wider output range


def test_higher_frequency_raises_expected_loss():
    lo = risk_quant.monte_carlo([_scenario(lam=0.2)], trials=60_000, seed=4).summary()
    hi = risk_quant.monte_carlo([_scenario(lam=3.0)], trials=60_000, seed=4).summary()
    assert hi["mean"] > lo["mean"]


def test_lower_exposure_reduces_loss_event_frequency():
    full = _scenario(p95=10_000)
    limited = _scenario(name="limited", p95=10_000)
    limited.exposure_factors = [0.2]
    full_result = risk_quant.monte_carlo([full], trials=100_000, seed=23).summary()
    limited_result = risk_quant.monte_carlo([limited], trials=100_000, seed=23).summary()
    assert limited_result["mean"] < full_result["mean"] * 0.25


def test_stronger_controls_reduce_successful_loss_events():
    weak = _scenario(p95=10_000)
    strong = _scenario(name="strong", p95=10_000)
    strong.control_strengths = [0.8]
    weak_result = risk_quant.monte_carlo([weak], trials=100_000, seed=29).summary()
    strong_result = risk_quant.monte_carlo([strong], trials=100_000, seed=29).summary()
    assert strong_result["mean"] < weak_result["mean"] * 0.25


def test_loss_scale_changes_magnitude_not_event_generation():
    baseline = _scenario(p95=10_000)
    scaled = _scenario(name="scaled", p95=10_000)
    scaled.loss_scale = 2.5
    base_losses = risk_quant.monte_carlo([baseline], trials=50_000, seed=31).aggregate
    scaled_losses = risk_quant.monte_carlo([scaled], trials=50_000, seed=31).aggregate
    # Same seed preserves validity, event counts, and unscaled draws: only dollars move.
    assert scaled_losses == pytest.approx(base_losses * 2.5)


@pytest.mark.parametrize("field", [
    "control_strength_overrides", "exposure_overrides", "loss_scale_overrides",
])
def test_override_typo_fails_with_recognized_scenario_names(field):
    with pytest.raises(ValueError, match="unknown risk scenario.*data_breach"):
        RiskQuantConfig(**{field: {"data-breach": 0.5}})


def test_engagement_wide_override_key_is_accepted():
    config = RiskQuantConfig(exposure_overrides={"*": 0.5})
    assert config.exposure_overrides == {"*": 0.5}


def test_bernoulli_validity_is_distributionally_distinct_from_scaled_frequency():
    """Both formulations have equal means, but only the new one models issue existence."""
    p, conditional_lam = 0.2, 2.0
    separated = risk_quant.monte_carlo(
        [_scenario(lam=conditional_lam, p_act=p, p95=10_000)], trials=200_000, seed=11
    ).aggregate
    conflated = risk_quant.monte_carlo(
        [_scenario(name="old", lam=p * conditional_lam, p_act=1.0, p95=10_000)],
        trials=200_000, seed=11,
    ).aggregate
    # Expected loss is approximately conserved, but the Bernoulli mixture has much more
    # zero mass and a materially heavier conditional tail than a thinned Poisson process.
    assert np.mean(separated) == pytest.approx(np.mean(conflated), rel=0.08)
    assert np.mean(separated == 0) > np.mean(conflated == 0) + 0.1
    assert np.percentile(separated, 99) > np.percentile(conflated, 99)


# --------------------------------------------------------------------------- #
# Tornado sensitivity
# --------------------------------------------------------------------------- #
def test_tornado_ranks_by_swing_and_carries_sources():
    scenarios = [_scenario(name="big", lam=2.0, median=10_000, p95=5_000_000),
                 _scenario(name="small", lam=0.1, median=1_000, p95=50_000)]
    bars = risk_quant.tornado_sensitivity(scenarios)
    swings = [b["swing"] for b in bars]
    assert swings == sorted(swings, reverse=True)     # ranked, largest first
    assert all(b["source"] for b in bars)             # each bar cites a prior source
    # The high-frequency / high-magnitude scenario dominates the ranking.
    assert bars[0]["scenario"] == "big"


# --------------------------------------------------------------------------- #
# Scenario building + appendix export (end-to-end, sourced priors)
# --------------------------------------------------------------------------- #
def _persist_finding(
    cfg, title, sev, desc, status=FalsificationStatus.CONFIRMED, *,
    file="a.py", line=1,
):
    return db.insert_finding(Finding(
        repo_id="r", title=title, file=file, line_start=line, line_end=line,
        citation_snippet="code", source_tool="semgrep", confidence=0.6,
        severity=sev, falsification_status=status, description=desc,
    ), cfg)


def test_build_scenarios_excludes_killed_and_writes_prior_sources(cfg):
    db.init_db(cfg)
    _persist_finding(cfg, "SQL Injection", "critical", "sqli [CWE-89]")
    _persist_finding(cfg, "Command Injection", "critical", "os command [CWE-78]")
    _persist_finding(cfg, "Dead", "high", "killed one",
                     status=FalsificationStatus.KILLED)

    scenarios = risk_quant.build_scenarios("r", cfg, persist=True)
    names = {s.name for s in scenarios}
    assert "data_breach" in names and "rce_full_compromise" in names
    # Killed finding did not create a scenario / inflate frequency.
    all_ids = [fid for s in scenarios for fid in s.finding_ids]
    assert len(all_ids) == 2

    # Every parameter used wrote a sourced prior_source row (no magic numbers).
    sources = db.list_prior_sources(cfg)
    assert sources
    assert all(ps.source for ps in sources)
    assert all(
        ps.provenance_status == "verified" and ps.publication and ps.edition
        and ps.locator and ps.url and ps.transformation
        for ps in sources
    )
    assert all(ps.target_population for ps in sources)
    assert all(ps.aleatory_representation for ps in sources)
    assert all(ps.epistemic_status for ps in sources)
    assert all(ps.effective_date == "2022-07" for ps in sources)
    assert all(ps.data_vintage == "2012-01-01/2021-12-31" for ps in sources)
    paths = {ps.param_path for ps in sources}
    assert any(p.startswith("magnitude.") for p in paths)
    assert any(p.startswith("frequency.") for p in paths)


def test_scenario_inputs_persist_origin_and_allow_analyst_overrides(cfg):
    db.init_db(cfg)
    _persist_finding(cfg, "SQL Injection", "critical", "sqli [CWE-89]")
    rq = cfg.risk_quant.model_copy(update={
        "company_revenue_band": "10m_to_100m",
        "exposure_overrides": {"data_breach": 0.25},
        "control_strength_overrides": {"data_breach": 0.75},
        "loss_scale_overrides": {"data_breach": 1.4},
    })
    overridden = cfg.model_copy(update={"risk_quant": rq})

    scenario = risk_quant.build_scenarios("r", overridden, persist=True)[0]
    assert scenario.exposure_factors == [0.25]
    assert scenario.control_strengths == [0.75]
    assert scenario.loss_scale == 1.4
    inputs = {value.input_name: value for value in db.list_scenario_inputs("r", overridden)}
    assert set(inputs) == {"exposure", "control_strength", "loss_scale"}
    assert all(value.origin == "analyst_override" for value in inputs.values())
    assert "company_revenue_band=10m_to_100m" in inputs["loss_scale"].detail


def test_default_inputs_are_transparently_derived_or_conservative(cfg):
    db.init_db(cfg)
    _persist_finding(cfg, "SQL Injection", "critical", "sqli [CWE-89]")

    scenario = risk_quant.build_scenarios("r", cfg, persist=True)[0]
    inputs = {value.input_name: value for value in db.list_scenario_inputs("r", cfg)}
    assert scenario.exposure_factors == [cfg.deal_risk.exposure.default_score]
    assert scenario.control_strengths == [0.0]
    assert scenario.loss_scale == 1.0
    assert inputs["exposure"].origin == "derived"
    assert inputs["control_strength"].origin == "derived"
    assert inputs["loss_scale"].origin == "conservative_default"
    assert "withheld" in inputs["loss_scale"].detail


def test_risk_scenario_reuses_map_backed_deal_risk_exposure(cfg):
    """Regression: risk quant consumes deal_risk's map signal, not a second heuristic."""
    db.init_db(cfg)
    boundary_id = db.insert_trust_boundary(
        TrustBoundary(repo_id="r", name="public API", description="customer traffic"), cfg
    )
    entity_id = db.insert_entity(
        Entity(repo_id="r", kind=EntityKind.ENTRY_POINT, name="POST /orders",
               trust_boundary_id=boundary_id), cfg
    )
    db.insert_finding(Finding(
        repo_id="r", title="SQL Injection", file="api.py", line_start=10, line_end=10,
        citation_snippet="query + user_input", source_tool="semgrep", confidence=0.9,
        severity="critical", description="sqli [CWE-89]",
        falsification_status=FalsificationStatus.CONFIRMED,
        trust_boundary_id=boundary_id, entity_id=entity_id,
    ), cfg)

    scenario = risk_quant.build_scenarios("r", cfg, persist=False)[0]
    assert scenario.exposure_factors == [cfg.deal_risk.exposure.matched_score]
    assert scenario.input_provenance[0].source == (
        "analyze.deal_risk production-exposure component"
    )


def test_cve_without_real_enrichment_uses_explicit_industry_baseline(cfg):
    db.init_db(cfg)
    finding_id = _persist_finding(
        cfg, "Vulnerable dependency demo (CVE-2024-12345)", "medium",
        "Published package advisory CVE-2024-12345",
        status=FalsificationStatus.CONFIRMED,
    )

    scenario = risk_quant.build_scenarios("r", cfg, persist=True)[0]

    assert scenario.finding_ids == [finding_id]
    assert scenario.validity_probabilities == [1.0]
    assert scenario.validity_sources == ["falsify:confirmed"]
    assert scenario.conditional_frequency_source == "frequency.industry_baseline"
    assert scenario.threat_signal_labels == [
        "industry-baseline:no-cached-EPSS-or-KEV (CVE-2024-12345)"
    ]
    persisted = db.list_risk_scenarios("r", cfg)[0]
    assert persisted.validity_probabilities == [1.0]
    assert persisted.conditional_frequency_lambdas == scenario.conditional_frequency_lambdas


def test_build_scenarios_counts_a_merged_group_once(cfg):
    """Regression: two sources flagging the SAME issue (a MatchGroup with 2 members) must
    contribute exactly one countable finding to build_scenarios — not be double-counted as
    two. Guards the fix for apply_adjudication leaving non-representative rows in the store."""
    db.init_db(cfg)
    rep = db.insert_finding(Finding(
        repo_id="r", title="SQL injection", file="app.py", line_start=24, line_end=24,
        citation_snippet="code", source_lens="owasp", confidence=0.9,
        severity="critical", falsification_status=FalsificationStatus.CONFIRMED,
        description="sqli [CWE-89]"), cfg)
    db.insert_finding(Finding(  # independent source, same file+line, same CWE -> merged
        repo_id="r", title="SQL injection", file="app.py", line_start=24, line_end=24,
        citation_snippet="code", source_tool="sast", confidence=0.6,
        severity="high", falsification_status=FalsificationStatus.CONFIRMED,
        description="sqli [CWE-89]"), cfg)

    scenarios = risk_quant.build_scenarios("r", cfg, persist=False)
    all_ids = [fid for s in scenarios for fid in s.finding_ids]
    assert all_ids == [rep]   # counted once, as the max-confidence representative


def test_build_scenarios_enforces_the_review_gate(cfg):
    """A finding held at the human-review checkpoint is unreachable by the MC scenario
    builder until a reviewer confirms it — the gate is enforced *from within* analyze,
    not just available as a separate query."""
    db.init_db(cfg)
    held = _persist_finding(cfg, "SQL Injection", "critical", "sqli [CWE-89]",
                            status=FalsificationStatus.UNRESOLVED)
    released = _persist_finding(cfg, "Command Injection", "critical", "os command [CWE-78]",
                                status=FalsificationStatus.UNRESOLVED)

    # Both unresolved findings are routed to review; each gets an open ReviewRequest.
    raise_review_requests("r", cfg)

    # A reviewer confirms only the second one; the first stays open (no decision).
    request = db.get_review_request(released, cfg)
    record_decision(request.id, reviewer="alice", disposition="confirm",
                    rationale="Traced the sink; it is reachable.", config=cfg)

    scenarios = risk_quant.build_scenarios("r", cfg, persist=True)
    scenario_ids = {fid for s in scenarios for fid in s.finding_ids}

    # The still-open finding is excluded; only the confirmed one drives loss.
    assert held not in scenario_ids
    assert released in scenario_ids
    assert scenario_ids == {released}

    # A dismissal of the open one keeps it out (a decision that isn't `confirm` does not
    # release the finding); an append-only correction to `confirm` then lets it through.
    held_request = db.get_review_request(held, cfg)
    dismissed = record_decision(held_request.id, reviewer="bob", disposition="dismiss",
                                rationale="Constant input; not exploitable.", config=cfg)
    after_dismiss = {fid for s in risk_quant.build_scenarios("r", cfg, persist=False)
                     for fid in s.finding_ids}
    assert held not in after_dismiss

    correct_decision(dismissed.id, reviewer="carol", disposition="confirm",
                     rationale="On review the input is attacker-controlled.", config=cfg)
    after_confirm = {fid for s in risk_quant.build_scenarios("r", cfg, persist=False)
                     for fid in s.finding_ids}
    assert held in after_confirm and released in after_confirm


def test_build_scenarios_refuses_unsourced_validity_probability(cfg):
    db.init_db(cfg)
    _persist_finding(
        cfg, "Untriaged candidate", "medium", "no verdict",
        status=FalsificationStatus.UNRESOLVED,
    )

    with pytest.raises(ValueError, match="refusing to invent a validity probability"):
        risk_quant.build_scenarios("r", cfg, persist=False)


@pytest.mark.integration
def test_generate_appendix_writes_artifact_and_simulation_run(cfg, tmp_path):
    db.init_db(cfg)
    _persist_finding(cfg, "SQL Injection", "critical", "sqli [CWE-89]")
    _persist_finding(cfg, "Hardcoded credential", "high", "secret [CWE-798]")

    out_dir = tmp_path / "appendix"
    path = risk_quant.generate_appendix("r", cfg, trials=5_000, seed=0, out_dir=out_dir)

    assert path.exists() and path.name == "risk_appendix.md"
    text = path.read_text()
    assert "FAIR" in text and "IRIS 2022" in text
    assert "90% interval" in text                        # range, not a single number
    assert "Engagement inputs" in text and "conservative no-scaling default" in text
    assert (out_dir / "loss_exceedance.png").exists()
    assert (out_dir / "tornado.png").exists()

    runs = db.list_simulation_runs("r", cfg)
    assert len(runs) == 1
    run = runs[0]
    assert run.trials == 5_000
    assert run.p95_loss >= run.median_loss               # uncertainty preserved
    assert run.tornado                                   # sensitivity persisted


def test_generate_appendix_handles_no_findings(cfg, tmp_path):
    db.init_db(cfg)
    path = risk_quant.generate_appendix("empty", cfg, out_dir=tmp_path / "a")
    assert path.exists()
    assert "No surviving" in path.read_text()


def test_appendix_gates_repeated_organization_frequency(cfg, tmp_path, monkeypatch):
    db.init_db(cfg)
    _persist_finding(
        cfg, "SQL Injection A", "critical", "sqli [CWE-89]", file="a.py", line=1
    )
    _persist_finding(
        cfg, "SQL Injection B", "critical", "sqli [CWE-89]", file="b.py", line=2
    )

    def fake_charts(_result, _tornado, out_dir):
        for name in ("loss_exceedance.png", "tornado.png"):
            (out_dir / name).write_bytes(b"chart")
        return {"exceedance": "loss_exceedance.png", "tornado": "tornado.png"}

    monkeypatch.setattr(risk_quant, "_render_charts", fake_charts)
    path = risk_quant.generate_appendix(
        "r", cfg, trials=100, seed=0, out_dir=tmp_path / "gated", persist=False
    )

    text = path.read_text()
    assert "EXPERIMENTAL QUANTITATIVE OUTPUT" in text
    assert "NOT DECISION-GRADE" in text
    assert text.index("NOT DECISION-GRADE") < text.index("## Headline")


def test_quantify_appendix_returns_reusable_artifact_metadata(cfg):
    db.init_db(cfg)
    _persist_finding(cfg, "SQL Injection", "critical", "sqli [CWE-89]")

    artifacts = risk_quant.quantify_appendix(
        "r", cfg, trials=1_234, seed=17, persist=False
    )

    # Historical callers can still unpack the result while new report callers receive
    # the complete, reproducible artifact description.
    path, count = artifacts
    assert path == artifacts.appendix_path
    assert count == artifacts.scenario_count == 1
    assert artifacts.trials == 1_234 and artifacts.seed == 17
    assert artifacts.audit_recorded is False
    assert {p.name for p in artifacts.artifact_paths} == {
        "risk_appendix.md", "loss_exceedance.png", "tornado.png"
    }

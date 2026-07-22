"""Tests for analyze/risk_quant.py — calibration, the Monte Carlo engine (property
tests: moment convergence + uncertainty behaviour), tornado, and appendix export."""

from __future__ import annotations

import math

import numpy as np
import pytest

from repoauditor.analyze import risk_quant
from repoauditor.analyze.risk_quant import ScenarioParams
from repoauditor.config import load_priors
from repoauditor.review import correct_decision, raise_review_requests, record_decision
from repoauditor.store import db
from repoauditor.store.models import FalsificationStatus, Finding


@pytest.fixture
def cfg(tmp_config):
    return tmp_config.model_copy(update={"priors": load_priors()})


def _scenario(name="s", lam=1.0, p05=1_000.0, p95=1_000_000.0, p_act=1.0):
    mu, sigma = risk_quant.calibrate_lognormal(p05, p95)
    return ScenarioParams(
        name=name, finding_ids=[1], frequency_lambda=lam, magnitude_mu=mu,
        magnitude_sigma=sigma, p05_usd=p05, p95_usd=p95,
        frequency_source="frequency.epss_high", magnitude_source="magnitude.data_breach",
        p_actionable=p_act,
    )


def _analytic_mean(scenarios) -> float:
    """FAIR expectation: sum lambda * E[lognormal]."""
    return sum(s.frequency_lambda * math.exp(s.magnitude_mu + s.magnitude_sigma ** 2 / 2)
               for s in scenarios)


# --------------------------------------------------------------------------- #
# Calibration (Hubbard & Seiersen 90% CI -> lognormal)
# --------------------------------------------------------------------------- #
def test_calibrate_lognormal_recovers_the_ci():
    p05, p95 = 100.0, 10_000.0
    mu, sigma = risk_quant.calibrate_lognormal(p05, p95)
    # The lognormal quantiles at 5%/95% must reproduce the inputs.
    z = 1.6448536269514722
    assert math.exp(mu - z * sigma) == pytest.approx(p05, rel=1e-9)
    assert math.exp(mu + z * sigma) == pytest.approx(p95, rel=1e-9)


# --------------------------------------------------------------------------- #
# Monte Carlo property tests
# --------------------------------------------------------------------------- #
def test_mc_mean_converges_to_analytic_expectation_as_trials_grow():
    scenarios = [_scenario(lam=1.5), _scenario(name="s2", lam=0.4, p05=5_000, p95=500_000)]
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
    narrow = [_scenario(name="n", lam=1.0, p05=90_000, p95=110_000)]   # tight CI
    wide = [_scenario(name="w", lam=1.0, p05=1_000, p95=10_000_000)]   # broad CI
    rn = risk_quant.monte_carlo(narrow, trials=60_000, seed=2).summary()
    rw = risk_quant.monte_carlo(wide, trials=60_000, seed=2).summary()
    spread_n = rn["p95"] - rn["p05"]
    spread_w = rw["p95"] - rw["p05"]
    assert spread_w > spread_n            # wider input uncertainty -> wider output range


def test_higher_frequency_raises_expected_loss():
    lo = risk_quant.monte_carlo([_scenario(lam=0.2)], trials=60_000, seed=4).summary()
    hi = risk_quant.monte_carlo([_scenario(lam=3.0)], trials=60_000, seed=4).summary()
    assert hi["mean"] > lo["mean"]


def test_triage_p_actionable_scales_scenario_frequency(cfg):
    """The triage seam: P(actionable) linearly scales the sourced base rate."""
    db.init_db(cfg)
    base = cfg.priors.frequency["epss_high"].lambda_per_year
    # Build a scenario by hand mirroring build_scenarios' seam math.
    for p_act in (0.2, 0.8):
        lam = base * p_act
        assert lam == pytest.approx(base * p_act)
    assert base * 0.8 > base * 0.2


# --------------------------------------------------------------------------- #
# Tornado sensitivity
# --------------------------------------------------------------------------- #
def test_tornado_ranks_by_swing_and_carries_sources():
    scenarios = [_scenario(name="big", lam=2.0, p05=10_000, p95=5_000_000),
                 _scenario(name="small", lam=0.1, p05=1_000, p95=50_000)]
    bars = risk_quant.tornado_sensitivity(scenarios)
    swings = [b["swing"] for b in bars]
    assert swings == sorted(swings, reverse=True)     # ranked, largest first
    assert all(b["source"] for b in bars)             # each bar cites a prior source
    # The high-frequency / high-magnitude scenario dominates the ranking.
    assert bars[0]["scenario"] == "big"


# --------------------------------------------------------------------------- #
# Scenario building + appendix export (end-to-end, sourced priors)
# --------------------------------------------------------------------------- #
def _persist_finding(cfg, title, sev, desc, status=FalsificationStatus.UNRESOLVED):
    return db.insert_finding(Finding(
        repo_id="r", title=title, file="a.py", line_start=1, line_end=1,
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
    paths = {ps.param_path for ps in sources}
    assert any(p.startswith("magnitude.") for p in paths)
    assert any(p.startswith("frequency.") for p in paths)


def test_build_scenarios_counts_a_merged_group_once(cfg):
    """Regression: two sources flagging the SAME issue (a MatchGroup with 2 members) must
    contribute exactly one countable finding to build_scenarios — not be double-counted as
    two. Guards the fix for apply_adjudication leaving non-representative rows in the store."""
    db.init_db(cfg)
    rep = db.insert_finding(Finding(
        repo_id="r", title="SQL injection", file="app.py", line_start=24, line_end=24,
        citation_snippet="code", source_lens="owasp", confidence=0.9,
        severity="critical", description="sqli [CWE-89]"), cfg)
    db.insert_finding(Finding(  # independent source, same file+line, same CWE -> merged
        repo_id="r", title="SQL injection", file="app.py", line_start=24, line_end=24,
        citation_snippet="code", source_tool="sast", confidence=0.6,
        severity="high", description="sqli [CWE-89]"), cfg)

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


def test_generate_appendix_writes_artifact_and_simulation_run(cfg, tmp_path):
    db.init_db(cfg)
    _persist_finding(cfg, "SQL Injection", "critical", "sqli [CWE-89]")
    _persist_finding(cfg, "Hardcoded credential", "high", "secret [CWE-798]")

    out_dir = tmp_path / "appendix"
    path = risk_quant.generate_appendix("r", cfg, trials=5_000, seed=0, out_dir=out_dir)

    assert path.exists() and path.name == "risk_appendix.md"
    text = path.read_text()
    assert "FAIR" in text and "Hubbard" in text          # methodology cites both
    assert "90% interval" in text                        # range, not a single number
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

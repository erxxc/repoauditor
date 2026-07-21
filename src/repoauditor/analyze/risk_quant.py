"""FAIR-style Monte Carlo risk quantification.

Implements Factor Analysis of Information Risk (FAIR): annualized loss = Loss Event
Frequency x Loss Magnitude, estimated by Monte Carlo. Loss Event Frequency is modelled
Poisson; Loss Magnitude lognormal. Distribution inputs come *only* from `priors.yaml`,
and every parameter consumed writes a `PriorSource` row — there are no magic numbers in
this module (a CLAUDE.md rule).

Two published methods are combined:
  * FAIR (Freund & Jones) for the frequency x magnitude decomposition and the loss
    exceedance curve as the primary output.
  * Hubbard & Seiersen calibrated estimation for turning a sourced 90% confidence
    interval (p05, p95) on single-loss cost into lognormal (mu, sigma):
        mu    = (ln p05 + ln p95) / 2
        sigma = (ln p95 - ln p05) / (2 * z),   z = 1.6448536  (the 0.95 normal quantile)

The seam with `triage/`: a scenario's Poisson rate is the exploitation-frequency base
rate (selected from `priors.yaml` by the finding's signal band) *scaled by the triage
P(actionable)* of its member findings — a finding the triage classifier thinks is
probably a false positive contributes proportionally less expected frequency. That
scaling is applied explicitly in `build_scenarios` and commented at the call site.

Uncertainty survives to the output: results are always reported as a range (p5 / median
/ mean / p95 and a full loss exceedance curve), never a single expected-loss number, and
a tornado sensitivity analysis shows which priors dominate.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from ..config import Config, MagnitudePrior, get_config
from ..store import db
from ..store.models import (
    FalsificationStatus,
    Finding,
    PriorSource,
    RiskScenario,
    SimulationRun,
)

_Z95 = 1.6448536269514722  # standard-normal 0.95 quantile (Hubbard 90% CI half-width)


# --------------------------------------------------------------------------- #
# Calibration: sourced 90% CI -> lognormal (mu, sigma)
# --------------------------------------------------------------------------- #
def calibrate_lognormal(p05_usd: float, p95_usd: float) -> tuple[float, float]:
    """Hubbard & Seiersen: a 90% CI (p05, p95) on cost -> lognormal (mu, sigma)."""
    ln05, ln95 = math.log(p05_usd), math.log(p95_usd)
    mu = (ln05 + ln95) / 2.0
    sigma = (ln95 - ln05) / (2.0 * _Z95)
    return mu, sigma


# --------------------------------------------------------------------------- #
# Finding -> scenario category / exploitation band mapping
# --------------------------------------------------------------------------- #
# Magnitude categories key into priors.yaml `magnitude`. Chosen by keyword/CWE so a
# finding's impact class picks its loss distribution. Falls back to the sourced SME
# default so no scenario ever runs on an unsourced number.
_MAGNITUDE_KEYWORDS = {
    "rce_full_compromise": ("command injection", "rce", "code execution", "os command",
                            "deserial", "cwe-78", "cwe-94", "cwe-502"),
    "data_breach": ("sql injection", "sqli", "data exposure", "path traversal",
                    "cwe-89", "cwe-22", "cwe-200"),
    "credential_compromise": ("hardcoded", "credential", "secret", "password", "token",
                              "auth", "cwe-798", "cwe-287", "cwe-862"),
    "service_disruption": ("ssrf", "denial of service", "dos", "open redirect",
                           "cwe-918", "cwe-400", "cwe-601"),
}


def _magnitude_category(finding: Finding) -> str:
    text = f"{finding.title} {finding.description or ''}".lower()
    for category, needles in _MAGNITUDE_KEYWORDS.items():
        if any(n in text for n in needles):
            return category
    return "default_magnitude"  # -> priors.sme_estimates


def _magnitude_prior(category: str, config: Config) -> tuple[MagnitudePrior, str, str]:
    """Return (prior, kind, param_path) for a category, using the SME default fallback."""
    if category in config.priors.magnitude:
        return config.priors.magnitude[category], "magnitude", f"magnitude.{category}"
    prior = config.priors.sme_estimates["default_magnitude"]
    return prior, "sme_estimate", "sme_estimates.default_magnitude"


def _frequency_band(finding: Finding, config: Config) -> str:
    """Select an exploitation-frequency band from priors.yaml for a finding.

    Ideally driven by per-CVE KEV/EPSS enrichment. SAST findings rarely carry a CVE, so
    absent that signal we proxy the exploitation band by adjudicated severity — and
    record which band (and thus which sourced base rate) was used on the scenario. When
    KEV/EPSS enrichment is present on the finding it should override this proxy.
    """
    bands = config.priors.frequency
    # (Enrichment hook: if finding metadata carried kev=True -> "kev_listed";
    #  epss>=threshold -> "epss_high"/"epss_moderate". Not present on SAST findings here.)
    sev = finding.severity
    if sev in ("critical", "high") and "epss_high" in bands:
        return "epss_high"
    if sev == "medium" and "epss_moderate" in bands:
        return "epss_moderate"
    return "baseline_no_signal"


# --------------------------------------------------------------------------- #
# Scenario construction (the triage -> frequency seam lives here)
# --------------------------------------------------------------------------- #
@dataclass
class ScenarioParams:
    """Resolved simulation inputs for one scenario (pure numbers + provenance)."""

    name: str
    finding_ids: list[int]
    frequency_lambda: float
    magnitude_mu: float
    magnitude_sigma: float
    p05_usd: float
    p95_usd: float
    frequency_source: str  # param_path(s) into priors.yaml
    magnitude_source: str
    p_actionable: float    # mean triage P(actionable) across members (record/seam)


def build_scenarios(
    repo_id: str, config: Config | None = None, *, persist: bool = True
) -> list[ScenarioParams]:
    """Group a repo's triaged/falsified findings into FAIR scenarios with sourced priors.

    Excludes killed findings. Each surviving finding contributes to its magnitude
    category's scenario an expected frequency of `base_rate(band) * P(actionable)` — the
    explicit triage seam. Every distinct magnitude/frequency parameter used writes one
    `PriorSource` row (no unsourced numbers).
    """
    config = config or get_config()
    findings = db.list_findings(repo_id, config)
    triage = {tr.finding_id: tr for tr in db.list_triage_results(repo_id, config)}

    # Default P(actionable) when a finding was never triaged: the sourced global prior
    # mean, so we never invent a number.
    bp = config.priors.triage.global_actionable_prior
    default_p = bp.alpha / (bp.alpha + bp.beta)

    groups: dict[str, list[tuple[Finding, float, str]]] = defaultdict(list)
    for f in findings:
        if f.falsification_status == FalsificationStatus.KILLED:
            continue  # killed candidates don't drive loss
        p_act = triage[f.id].p_actionable if f.id in triage else default_p
        category = _magnitude_category(f)
        band = _frequency_band(f, config)
        groups[category].append((f, p_act, band))

    used_sources: dict[str, PriorSource] = {}  # param_path -> row (dedup within a run)
    scenarios: list[ScenarioParams] = []
    for category, members in groups.items():
        mag_prior, mag_kind, mag_path = _magnitude_prior(category, config)
        mu, sigma = calibrate_lognormal(mag_prior.p05_usd, mag_prior.p95_usd)
        used_sources[mag_path] = PriorSource(
            kind=mag_kind, param_path=mag_path, source=mag_prior.source,
            detail=mag_prior.detail,
        )

        lam = 0.0
        bands_used: set[str] = set()
        for _finding, p_act, band in members:
            freq_prior = config.priors.frequency[band]
            # --- triage seam: scale the sourced base rate by P(actionable) --------- #
            lam += freq_prior.lambda_per_year * p_act
            bands_used.add(band)
            fpath = f"frequency.{band}"
            used_sources[fpath] = PriorSource(
                kind="frequency", param_path=fpath, source=freq_prior.source,
                detail=freq_prior.detail,
            )

        freq_source = ", ".join(sorted(f"frequency.{b}" for b in bands_used))
        mean_p = float(np.mean([p for _, p, _ in members]))
        scenarios.append(
            ScenarioParams(
                name=category,
                finding_ids=[f.id for f, _, _ in members if f.id is not None],
                frequency_lambda=lam,
                magnitude_mu=mu,
                magnitude_sigma=sigma,
                p05_usd=mag_prior.p05_usd,
                p95_usd=mag_prior.p95_usd,
                frequency_source=freq_source,
                magnitude_source=mag_path,
                p_actionable=mean_p,
            )
        )

    if persist:
        for ps in used_sources.values():
            db.insert_prior_source(ps, config)
        for s in scenarios:
            db.insert_risk_scenario(
                RiskScenario(
                    repo_id=repo_id, name=s.name, finding_ids=s.finding_ids,
                    frequency_lambda=s.frequency_lambda, magnitude_mu=s.magnitude_mu,
                    magnitude_sigma=s.magnitude_sigma, frequency_source=s.frequency_source,
                    magnitude_source=s.magnitude_source, p_actionable=s.p_actionable,
                ),
                config,
            )
    return scenarios


# --------------------------------------------------------------------------- #
# Monte Carlo engine (vectorized compound Poisson-lognormal)
# --------------------------------------------------------------------------- #
@dataclass
class SimulationResult:
    """Simulated annualized-loss distribution — a range, never a point estimate."""

    trials: int
    seed: int
    aggregate: np.ndarray                  # per-trial total annual loss
    per_scenario: dict[str, np.ndarray]    # scenario name -> per-trial loss
    scenario_params: list[ScenarioParams] = field(default_factory=list)

    def summary(self, losses: np.ndarray | None = None) -> dict:
        x = self.aggregate if losses is None else losses
        return {
            "mean": float(np.mean(x)),
            "median": float(np.median(x)),
            "p05": float(np.percentile(x, 5)),
            "p95": float(np.percentile(x, 95)),
            "p99": float(np.percentile(x, 99)),
        }


def _compound_poisson_lognormal(
    lam: float, mu: float, sigma: float, trials: int, rng: np.random.Generator
) -> np.ndarray:
    """Per-trial loss = sum of Poisson(lam) lognormal(mu,sigma) event losses. Vectorized."""
    counts = rng.poisson(lam, trials)
    total_events = int(counts.sum())
    out = np.zeros(trials)
    if total_events == 0:
        return out
    draws = rng.lognormal(mu, sigma, total_events)
    # Map each event draw to its trial via run-length expansion, then segment-sum.
    trial_index = np.repeat(np.arange(trials), counts)
    np.add.at(out, trial_index, draws)
    return out


def monte_carlo(
    scenarios: list[ScenarioParams], trials: int = 50_000, seed: int = 0
) -> SimulationResult:
    """Run the FAIR Monte Carlo over all scenarios. Pure (no persistence)."""
    rng = np.random.default_rng(seed)
    per_scenario: dict[str, np.ndarray] = {}
    aggregate = np.zeros(trials)
    for s in scenarios:
        losses = _compound_poisson_lognormal(
            s.frequency_lambda, s.magnitude_mu, s.magnitude_sigma, trials, rng
        )
        per_scenario[s.name] = losses
        aggregate += losses
    return SimulationResult(
        trials=trials, seed=seed, aggregate=aggregate,
        per_scenario=per_scenario, scenario_params=list(scenarios),
    )


def loss_exceedance_curve(losses: np.ndarray, points: int = 200) -> list[tuple[float, float]]:
    """Loss exceedance curve: [(loss_threshold, P(annual loss > threshold))].

    The primary FAIR output: for each loss level, the probability annual loss exceeds it.
    Sampled at `points` quantiles so it persists compactly.
    """
    if losses.size == 0:
        return []
    qs = np.linspace(0, 100, points)
    thresholds = np.percentile(losses, qs)
    n = losses.size
    curve = []
    for t in np.unique(thresholds):
        prob = float(np.count_nonzero(losses > t) / n)
        curve.append((float(t), prob))
    return curve


# --------------------------------------------------------------------------- #
# Tornado sensitivity (analytic expected-loss swings — shows dominant priors)
# --------------------------------------------------------------------------- #
def tornado_sensitivity(scenarios: list[ScenarioParams]) -> list[dict]:
    """Rank parameters by their swing in expected aggregate loss (largest first).

    Uses the analytic expectation E[loss] = lambda * E[magnitude] so the sweep is exact
    and fast. Each scenario contributes two bars:
      * frequency: lambda swept +/-50% (frequency uncertainty band).
      * magnitude: single-loss cost swept across its sourced 90% CI (p05..p95),
        i.e. lambda * p05 vs lambda * p95.
    The swing (|high - low| of aggregate expected loss with only that parameter moved)
    ranks which prior the headline number is most sensitive to.
    """
    # Baseline expected loss per scenario: lambda * lognormal mean.
    def mag_mean(s: ScenarioParams) -> float:
        return math.exp(s.magnitude_mu + s.magnitude_sigma ** 2 / 2.0)

    baseline = {s.name: s.frequency_lambda * mag_mean(s) for s in scenarios}
    base_total = sum(baseline.values())

    bars: list[dict] = []
    for s in scenarios:
        others = base_total - baseline[s.name]
        # Frequency sweep +/-50%.
        f_low = others + (s.frequency_lambda * 0.5) * mag_mean(s)
        f_high = others + (s.frequency_lambda * 1.5) * mag_mean(s)
        bars.append({
            "parameter": f"{s.name}: frequency (lambda)",
            "scenario": s.name, "source": s.frequency_source,
            "low": f_low, "high": f_high, "swing": abs(f_high - f_low),
            "baseline": base_total,
        })
        # Magnitude sweep across the sourced 90% CI.
        m_low = others + s.frequency_lambda * s.p05_usd
        m_high = others + s.frequency_lambda * s.p95_usd
        bars.append({
            "parameter": f"{s.name}: magnitude (90% CI)",
            "scenario": s.name, "source": s.magnitude_source,
            "low": m_low, "high": m_high, "swing": abs(m_high - m_low),
            "baseline": base_total,
        })
    bars.sort(key=lambda b: b["swing"], reverse=True)
    return bars


# --------------------------------------------------------------------------- #
# Charts + appendix artifact
# --------------------------------------------------------------------------- #
def _fmt_usd(x: float) -> str:
    if x >= 1e6:
        return f"${x/1e6:.2f}M"
    if x >= 1e3:
        return f"${x/1e3:.1f}k"
    return f"${x:.0f}"


def _render_charts(result: SimulationResult, tornado: list[dict], out_dir: Path) -> dict:
    """Write the exceedance-curve and tornado PNGs; return their relative filenames."""
    import matplotlib

    matplotlib.use("Agg")  # headless
    import matplotlib.pyplot as plt

    # Loss exceedance curve.
    curve = loss_exceedance_curve(result.aggregate)
    fig, ax = plt.subplots(figsize=(7, 4.2))
    if curve:
        xs, ys = zip(*curve)
        ax.plot(xs, ys, color="#b3261e", lw=2)
        ax.fill_between(xs, ys, color="#b3261e", alpha=0.12)
    ax.set_xlabel("Annualized loss (USD)")
    ax.set_ylabel("P(annual loss > x)")
    ax.set_title("Loss Exceedance Curve (FAIR / Monte Carlo)")
    ax.grid(True, alpha=0.3)
    ax.set_ylim(0, 1)
    fig.tight_layout()
    fig.savefig(out_dir / "loss_exceedance.png", dpi=120)
    plt.close(fig)

    # Tornado (top 10 parameters).
    top = tornado[:10][::-1]
    fig, ax = plt.subplots(figsize=(7, 0.5 * len(top) + 1.5))
    labels = [b["parameter"] for b in top]
    lows = [b["low"] for b in top]
    highs = [b["high"] for b in top]
    base = top[0]["baseline"] if top else 0.0
    y = np.arange(len(top))
    ax.barh(y, [h - l for l, h in zip(lows, highs)], left=lows,
            color="#2e6ff2", alpha=0.75)
    ax.axvline(base, color="#333", ls="--", lw=1, label="baseline expected loss")
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel("Aggregate expected annual loss (USD)")
    ax.set_title("Tornado — parameter sensitivity")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(out_dir / "tornado.png", dpi=120)
    plt.close(fig)

    return {"exceedance": "loss_exceedance.png", "tornado": "tornado.png"}


_METHODOLOGY = (
    "This appendix quantifies risk with a FAIR-style (Factor Analysis of Information "
    "Risk) Monte Carlo model: for each scenario, the number of loss events per year is "
    "drawn from a Poisson distribution and each event's cost from a lognormal "
    "distribution, then summed over {trials:,} simulated years. Loss-magnitude ranges "
    "come from published industry loss data (Verizon DBIR, Cyentia IRIS); a sourced 90% "
    "confidence interval on single-event cost is converted to lognormal parameters using "
    "Hubbard & Seiersen calibrated estimation. Event frequency uses exploitation base "
    "rates (EPSS/KEV-style bands) scaled by the triage classifier's calibrated "
    "P(actionable) for each finding. Every distribution parameter traces to `priors.yaml` "
    "and is recorded as a prior-source row; results are reported as a range (with a loss "
    "exceedance curve), never a single expected-loss figure, and the tornado chart shows "
    "which priors the headline numbers are most sensitive to."
)


def generate_appendix(
    repo_id: str,
    config: Config | None = None,
    *,
    trials: int = 50_000,
    seed: int = 0,
    out_dir: Path | None = None,
    persist: bool = True,
) -> Path:
    """Run the simulation and write the standalone findings-appendix artifact.

    Produces `<out_dir>/risk_appendix.md` plus the two chart PNGs, and (when `persist`)
    a `SimulationRun` row. This is the export stub wired into `report --mode=memo`
    later; here it is generatable on its own. Returns the appendix markdown path.
    """
    config = config or get_config()
    scenarios = build_scenarios(repo_id, config, persist=persist)
    out_dir = out_dir or (config.resolve(config.paths.data_dir)
                          / "reports" / f"{repo_id}_risk_appendix")
    out_dir.mkdir(parents=True, exist_ok=True)

    if not scenarios:
        text = (f"# Risk Quantification Appendix — {repo_id}\n\n"
                "_No surviving (non-killed) findings to quantify._\n")
        path = out_dir / "risk_appendix.md"
        path.write_text(text)
        return path

    result = monte_carlo(scenarios, trials=trials, seed=seed)
    tornado = tornado_sensitivity(scenarios)
    charts = _render_charts(result, tornado, out_dir)
    agg = result.summary()

    if persist:
        db.insert_simulation_run(
            SimulationRun(
                repo_id=repo_id, trials=trials,
                mean_loss=agg["mean"], median_loss=agg["median"], p95_loss=agg["p95"],
                scenario_summary={
                    s.name: result.summary(result.per_scenario[s.name])
                    for s in scenarios
                },
                tornado=tornado, seed=seed,
            ),
            config,
        )

    path = out_dir / "risk_appendix.md"
    path.write_text(_appendix_markdown(repo_id, scenarios, result, tornado, agg, charts, trials))
    return path


def _appendix_markdown(repo_id, scenarios, result, tornado, agg, charts, trials) -> str:
    lines = [
        f"# Risk Quantification Appendix — {repo_id}",
        "",
        "## Methodology",
        "",
        _METHODOLOGY.format(trials=trials),
        "",
        "## Headline (annualized loss — a range, not a point estimate)",
        "",
        f"- **90% interval:** {_fmt_usd(agg['p05'])} – {_fmt_usd(agg['p95'])}",
        f"- **Median:** {_fmt_usd(agg['median'])}  |  **Mean:** {_fmt_usd(agg['mean'])}"
        f"  |  **p99:** {_fmt_usd(agg['p99'])}",
        f"- Simulated over **{trials:,}** trial-years across {len(scenarios)} scenario(s).",
        "",
        "![Loss exceedance curve](" + charts["exceedance"] + ")",
        "",
        "## Scenarios",
        "",
        "| Scenario | Findings | λ (events/yr) | Magnitude 90% CI | mean P(actionable) | Sources |",
        "|---|---|---|---|---|---|",
    ]
    for s in scenarios:
        lines.append(
            f"| {s.name} | {len(s.finding_ids)} | {s.frequency_lambda:.3f} | "
            f"{_fmt_usd(s.p05_usd)}–{_fmt_usd(s.p95_usd)} | {s.p_actionable:.2f} | "
            f"{s.magnitude_source}; {s.frequency_source} |"
        )
    lines += [
        "",
        "## Sensitivity (tornado)",
        "",
        "Parameters ranked by their swing in expected aggregate annual loss:",
        "",
        "![Tornado sensitivity](" + charts["tornado"] + ")",
        "",
        "| Parameter | Low | High | Swing | Source |",
        "|---|---|---|---|---|",
    ]
    for b in tornado[:10]:
        lines.append(
            f"| {b['parameter']} | {_fmt_usd(b['low'])} | {_fmt_usd(b['high'])} | "
            f"{_fmt_usd(b['swing'])} | {b['source']} |"
        )
    lines += [
        "",
        "## Prior sources",
        "",
        "Every distribution parameter above traces to `priors.yaml`; provenance is "
        "persisted as `prior_source` rows in the store. Loss magnitudes derive from "
        "DBIR/IRIS industry data; frequencies from EPSS/KEV-style exploitation bands; "
        "SME-calibrated 90% intervals are used only where dataset backing is absent.",
        "",
        "> Generated by `analyze/risk_quant.py` (FAIR + Hubbard/Seiersen calibrated "
        "estimation). Uncertainty is intrinsic — treat the range, not any single figure, "
        "as the result.",
        "",
    ]
    return "\n".join(lines)

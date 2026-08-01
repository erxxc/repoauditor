"""FAIR-style Monte Carlo risk quantification.

Implements a FAIR-style decomposition with an explicit epistemic finding-validity gate,
conditional Poisson Loss Event Frequency, and lognormal Loss Magnitude. Distribution inputs
come *only* from `priors.yaml`,
and every parameter consumed writes a `PriorSource` row — there are no magic numbers in
this module (a CLAUDE.md rule).

FAIR supplies the frequency/magnitude decomposition and loss exceedance output. The
lognormal is fitted directly to IRIS 2022's published event-loss median and p95; the
lower percentile is explicitly model-implied rather than attributed to the publication.

The seam with `triage/` is Bernoulli validity, never Poisson-rate scaling. Confirmed
findings have validity 1; otherwise P(actionable) gates whether the issue exists in each
trial. Conditional frequency uses the exactly cited industry baseline. EPSS and KEV are
not inferred from severity. Explicitly refreshed cached enrichment is retained as an
informational threat-signal label and does not change quantitative inputs.

Organization context follows the Open FAIR factor mapping rather than being blended into
one opaque multiplier: map/deal-risk production exposure scales Threat Event Frequency
(contact rate); falsification evidence informs control strength, which reduces
Vulnerability (the probability that a threat event becomes a loss event); and engagement
loss scale multiplies Loss Magnitude. The simulation therefore draws finding validity,
then threat events, then control-conditioned successful events, then loss magnitude. A
revenue band is recorded but does not change magnitude until a band curve can be tied to
an exact published source; the conservative default multiplier is 1.0.

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
from .deal_risk import weigh_deal_risk
from ..store import db
from ..store.models import (
    FalsificationStatus,
    Finding,
    PriorSource,
    RiskScenario,
    ScenarioInput,
    SimulationRun,
)
from .threat_intel import load_threat_intel, threat_signal_label

_Z95 = 1.6448536269514722  # standard-normal 0.95 quantile


# --------------------------------------------------------------------------- #
# Calibration: published median + p95 -> lognormal (mu, sigma)
# --------------------------------------------------------------------------- #
def calibrate_lognormal(median_usd: float, p95_usd: float) -> tuple[float, float]:
    """Fit a lognormal to a published median and 95th percentile."""
    mu = math.log(median_usd)
    sigma = (math.log(p95_usd) - mu) / _Z95
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
    return "uncategorized"


def _magnitude_prior(config: Config) -> tuple[MagnitudePrior, str, str]:
    """Return the exact all-event baseline; category differentiation is not sourced yet."""
    prior = config.priors.magnitude["industry_baseline"]
    return prior, "magnitude", "magnitude.industry_baseline"


def _frequency_prior(config: Config) -> tuple[float, str]:
    """Return the conditional industry rate; no EPSS/KEV proxying is permitted."""
    prior = config.priors.frequency["industry_baseline"]
    return -math.log1p(-prior.annual_probability_at_least_one), "frequency.industry_baseline"


def _prior_source(kind: str, path: str, prior) -> PriorSource:
    return PriorSource(
        kind=kind, param_path=path, source=prior.source, detail=prior.detail,
        publication=prior.publication, edition=prior.edition, locator=prior.locator,
        url=prior.url, transformation=prior.transformation, provenance_status="verified",
        target_population=prior.target_population, effective_date=prior.effective_date,
        data_vintage=prior.data_vintage,
        aleatory_representation=prior.aleatory_representation,
        epistemic_status=prior.epistemic_status,
    )


def _validity(finding: Finding, triage_result, config: Config) -> tuple[float, str]:
    """Resolve epistemic finding validity without modifying event frequency."""
    if finding.falsification_status is FalsificationStatus.CONFIRMED:
        return 1.0, "falsify:confirmed"
    if finding.id is not None:
        request = db.get_review_request(finding.id, config)
        if request is not None:
            decision = db.latest_review_decision(request.id, config)
            if decision is not None and str(decision.disposition) == "confirm":
                return 1.0, "review:human-confirmed"
    if triage_result is not None:
        return triage_result.p_actionable, "triage:p_actionable"
    raise ValueError(
        f"finding #{finding.id} has neither confirmation nor a triage P(actionable); "
        "refusing to invent a validity probability"
    )


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
    validity_probabilities: list[float] = field(default_factory=list)
    validity_sources: list[str] = field(default_factory=list)
    conditional_frequency_lambdas: list[float] = field(default_factory=list)
    conditional_frequency_source: str = ""
    threat_signal_labels: list[str] = field(default_factory=list)
    exposure_factors: list[float] = field(default_factory=list)
    control_strengths: list[float] = field(default_factory=list)
    loss_scale: float = 1.0
    input_provenance: list[ScenarioInput] = field(default_factory=list)
    persisted_id: int | None = None


def _override(values: dict[str, float], scenario_name: str) -> float | None:
    """Resolve a scenario override before the engagement-wide ``*`` fallback."""
    return values.get(scenario_name, values.get("*"))


def build_scenarios(
    repo_id: str, config: Config | None = None, *, persist: bool = True
) -> list[ScenarioParams]:
    """Group a repo's triaged/falsified findings into FAIR scenarios with sourced priors.

    Excludes killed findings. Each surviving finding contributes a Bernoulli validity
    probability and a separate conditional industry-baseline event rate. Every magnitude
    and frequency parameter used writes one exact-provenance `PriorSource` row.
    """
    config = config or get_config()
    # Review gate + de-duplication: the analyze stage consumes only findings that cleared the
    # human-review checkpoint, and it must count each *issue* once. `list_countable_findings`
    # composes both: it applies the review gate (dropping KILLED/deferred and anything held at
    # review, so an `unresolved` finding cannot reach the Monte Carlo builder until confirmed)
    # AND collapses a merged MatchGroup to its single representative, so a finding corroborated
    # by N sources is one scenario contribution, not N. See db.list_countable_findings for why
    # this is a read-side view (Option B) rather than a persisted supersede flag.
    findings = db.list_countable_findings(repo_id, config)
    triage = {tr.finding_id: tr for tr in db.list_triage_results(repo_id, config)}
    # Reuse the existing map-backed production-exposure computation verbatim. This call is
    # read-only (`persist=False`) and avoids a second, subtly divergent exposure heuristic.
    exposure_by_finding = {
        result.finding_id: result.deal_risk
        for result in weigh_deal_risk(repo_id, config, persist=False)
    }
    threat_intel = load_threat_intel(repo_id, config)

    groups: dict[str, list[tuple[Finding, float, str, str]]] = defaultdict(list)
    for f in findings:
        if f.falsification_status == FalsificationStatus.KILLED:
            continue  # killed candidates don't drive loss
        p_act, validity_source = _validity(f, triage.get(f.id), config)
        category = _magnitude_category(f)
        signal = threat_signal_label(f, threat_intel)
        groups[category].append((f, p_act, validity_source, signal))

    used_sources: dict[str, PriorSource] = {}  # param_path -> row (dedup within a run)
    scenarios: list[ScenarioParams] = []
    for category, members in groups.items():
        mag_prior, mag_kind, mag_path = _magnitude_prior(config)
        mu, sigma = calibrate_lognormal(mag_prior.median_usd, mag_prior.p95_usd)
        implied_p05 = math.exp(mu - _Z95 * sigma)
        used_sources[mag_path] = _prior_source(mag_kind, mag_path, mag_prior)

        conditional_lambda, freq_source = _frequency_prior(config)
        freq_prior = config.priors.frequency["industry_baseline"]
        used_sources[freq_source] = _prior_source("frequency", freq_source, freq_prior)
        validities = [p for _, p, _, _ in members]
        validity_sources = [source for _, _, source, _ in members]
        conditional_lambdas = [conditional_lambda] * len(members)
        signals = [signal for _, _, _, signal in members]
        derived_exposures = [
            exposure_by_finding[f.id].exposure_component
            if f.id in exposure_by_finding else config.deal_risk.exposure.default_score
            for f, _, _, _ in members
        ]
        exposure_override = _override(config.risk_quant.exposure_overrides, category)
        exposures = (
            [exposure_override] * len(members)
            if exposure_override is not None else derived_exposures
        )

        # A confirmed falsification verdict means the challenger found the path reachable
        # and unmitigated. Its persisted result carries no structured positive-control
        # field, so survivors receive no invented control credit. Human-confirmed findings
        # use the same numeric conservative default but are labelled unavailable rather
        # than presented as scanner-derived evidence.
        derived_controls = [0.0] * len(members)
        control_override = _override(config.risk_quant.control_strength_overrides, category)
        controls = (
            [control_override] * len(members)
            if control_override is not None else derived_controls
        )
        loss_override = _override(config.risk_quant.loss_scale_overrides, category)
        loss_scale = loss_override if loss_override is not None else 1.0

        exposure_origin = "analyst_override" if exposure_override is not None else "derived"
        control_origin = (
            "analyst_override" if control_override is not None
            else "derived" if all(source == "falsify:confirmed" for source in validity_sources)
            else "conservative_default"
        )
        loss_origin = "analyst_override" if loss_override is not None else "conservative_default"
        provenance = [
            ScenarioInput(
                repo_id=repo_id, scenario_name=category, input_name="exposure",
                value=float(np.mean(exposures)), origin=exposure_origin,
                source=("analyst override [risk_quant.exposure_overrides]"
                        if exposure_override is not None
                        else "analyze.deal_risk production-exposure component"),
                detail=f"per-finding values={exposures}",
            ),
            ScenarioInput(
                repo_id=repo_id, scenario_name=category, input_name="control_strength",
                value=float(np.mean(controls)), origin=control_origin,
                source=("analyst override [risk_quant.control_strength_overrides]"
                        if control_override is not None
                        else ("falsify: confirmed reachable and unmitigated"
                              if control_origin == "derived"
                              else "derived-unavailable:no-structured-control-evidence")),
                detail=f"per-finding values={controls}; validity sources={validity_sources}",
            ),
            ScenarioInput(
                repo_id=repo_id, scenario_name=category, input_name="loss_scale",
                value=loss_scale, origin=loss_origin,
                source=("analyst override [risk_quant.loss_scale_overrides]"
                        if loss_override is not None
                        else "conservative no-scaling default"),
                detail=(f"company_revenue_band={config.risk_quant.company_revenue_band}; "
                        "automatic revenue-band curve withheld pending exact source mapping"),
            ),
        ]
        mean_p = float(np.mean(validities))
        scenarios.append(
            ScenarioParams(
                name=category,
                finding_ids=[f.id for f, _, _, _ in members if f.id is not None],
                frequency_lambda=sum(conditional_lambdas),
                magnitude_mu=mu,
                magnitude_sigma=sigma,
                p05_usd=implied_p05,
                p95_usd=mag_prior.p95_usd,
                frequency_source=freq_source,
                magnitude_source=mag_path,
                p_actionable=mean_p,
                validity_probabilities=validities, validity_sources=validity_sources,
                conditional_frequency_lambdas=conditional_lambdas,
                conditional_frequency_source=freq_source, threat_signal_labels=signals,
                exposure_factors=exposures, control_strengths=controls,
                loss_scale=loss_scale, input_provenance=provenance,
            )
        )

    if persist:
        for ps in used_sources.values():
            db.insert_prior_source(ps, config)
        for s in scenarios:
            scenario_id = db.insert_risk_scenario(
                RiskScenario(
                    repo_id=repo_id, name=s.name, finding_ids=s.finding_ids,
                    frequency_lambda=s.frequency_lambda, magnitude_mu=s.magnitude_mu,
                    magnitude_sigma=s.magnitude_sigma, frequency_source=s.frequency_source,
                    magnitude_source=s.magnitude_source, p_actionable=s.p_actionable,
                    validity_probabilities=s.validity_probabilities,
                    validity_sources=s.validity_sources,
                    conditional_frequency_lambdas=s.conditional_frequency_lambdas,
                    conditional_frequency_source=s.conditional_frequency_source,
                    threat_signal_labels=s.threat_signal_labels,
                    exposure_factors=s.exposure_factors,
                    control_strengths=s.control_strengths,
                    loss_scale=s.loss_scale,
                ),
                config,
            )
            s.persisted_id = scenario_id
            for value in s.input_provenance:
                db.insert_scenario_input(
                    value.model_copy(update={"risk_scenario_id": scenario_id}), config
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


@dataclass(frozen=True)
class QuantificationArtifacts:
    """Files and metadata produced by one quantitative analysis pass.

    Iteration intentionally preserves the historical ``(path, scenario_count)``
    unpacking contract while giving report builders access to all generated files.
    """

    appendix_path: Path
    scenario_count: int
    artifact_paths: tuple[Path, ...]
    trials: int
    seed: int
    audit_recorded: bool

    def __iter__(self):
        yield self.appendix_path
        yield self.scenario_count


def _compound_poisson_lognormal(
    lam: float, mu: float, sigma: float, trials: int, rng: np.random.Generator,
    validity_probability: float = 1.0, exposure: float = 1.0,
    control_strength: float = 0.0, loss_scale: float = 1.0,
) -> np.ndarray:
    """Validity -> exposed threat events -> control-conditioned losses -> magnitude."""
    valid = rng.binomial(1, validity_probability, trials)
    threat_events = rng.poisson(lam * exposure, trials) * valid
    counts = rng.binomial(threat_events, 1.0 - control_strength)
    total_events = int(counts.sum())
    out = np.zeros(trials)
    if total_events == 0:
        return out
    draws = rng.lognormal(mu, sigma, total_events) * loss_scale
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
        losses = np.zeros(trials)
        validities = s.validity_probabilities or [s.p_actionable]
        conditional_lambdas = s.conditional_frequency_lambdas or [s.frequency_lambda]
        exposures = s.exposure_factors or [1.0] * len(validities)
        controls = s.control_strengths or [0.0] * len(validities)
        for validity, conditional_lambda, exposure, control in zip(
            validities, conditional_lambdas, exposures, controls, strict=True
        ):
            losses += _compound_poisson_lognormal(
                conditional_lambda, s.magnitude_mu, s.magnitude_sigma, trials, rng,
                validity_probability=validity, exposure=exposure,
                control_strength=control, loss_scale=s.loss_scale,
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

    Uses the analytic expectation E[loss] = validity * exposure * lambda *
    (1-control strength) * loss scale * E[magnitude], so the sweep is exact
    and fast. Each scenario contributes a magnitude bar using the model-implied p05 and
    published p95. The old arbitrary +/-50% frequency shock was removed because it had
    no source and therefore violated the prior-governance rule.
    The swing (|high - low| of aggregate expected loss with only that parameter moved)
    ranks which prior the headline number is most sensitive to.
    """
    # Baseline expected loss per scenario: lambda * lognormal mean.
    def mag_mean(s: ScenarioParams) -> float:
        return math.exp(s.magnitude_mu + s.magnitude_sigma ** 2 / 2.0) * s.loss_scale

    def expected_events(s: ScenarioParams) -> float:
        validities = s.validity_probabilities or [s.p_actionable]
        lambdas = s.conditional_frequency_lambdas or [s.frequency_lambda]
        exposures = s.exposure_factors or [1.0] * len(validities)
        controls = s.control_strengths or [0.0] * len(validities)
        return sum(
            p * lam * exposure * (1.0 - control)
            for p, lam, exposure, control in zip(
                validities, lambdas, exposures, controls, strict=True
            )
        )

    baseline = {s.name: expected_events(s) * mag_mean(s) for s in scenarios}
    base_total = sum(baseline.values())

    bars: list[dict] = []
    for s in scenarios:
        others = base_total - baseline[s.name]
        # Magnitude sweep across the fitted distribution's implied p05 and published p95.
        events = expected_events(s)
        m_low = others + events * s.p05_usd * s.loss_scale
        m_high = others + events * s.p95_usd * s.loss_scale
        bars.append({
            "parameter": f"{s.name}: magnitude (model p05 / published p95)",
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
    "first gated by an explicit Bernoulli finding-validity draw. For valid findings, "
    "map-derived production exposure scales the Poisson threat-event/contact rate; "
    "control strength then reduces the probability that a threat event becomes a loss "
    "event. Each resulting event's "
    "cost from a lognormal "
    "distribution, then summed over {trials:,} simulated years. Loss-magnitude ranges "
    "come from published industry loss data (Verizon DBIR, Cyentia IRIS); a sourced 90% "
    "published median and p95 are converted to lognormal parameters. Conditional event "
    "frequency uses the IRIS 2022 industry baseline; triage P(actionable) affects only "
    "the Bernoulli validity gate. Organization loss scale multiplies magnitude; revenue "
    "bands currently retain a conservative 1.0 scale because no exact sourced band curve "
    "has been accepted. EPSS/KEV are never inferred from severity. Explicitly refreshed, "
    "dated cache values are retained as informational finding-level threat evidence but "
    "do not change validity, frequency, or magnitude. Every distribution parameter traces to `priors.yaml` "
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

    # Local import avoids a module-load cycle: integrity resolves ScenarioParams from this
    # module, while this presentation-only gate reuses the already-built scenarios.
    from .integrity import audit_resolved_inputs, quantitative_disclosure

    disclosure = quantitative_disclosure(
        audit_resolved_inputs(scenarios, config, repo_id=repo_id)
    )
    result = monte_carlo(scenarios, trials=trials, seed=seed)
    tornado = tornado_sensitivity(scenarios)
    charts = _render_charts(result, tornado, out_dir)
    agg = result.summary()

    if persist:
        simulation_run_id = db.insert_simulation_run(
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
        db.link_risk_scenarios_to_simulation(
            [s.persisted_id for s in scenarios if s.persisted_id is not None],
            simulation_run_id,
            config,
        )

    path = out_dir / "risk_appendix.md"
    path.write_text(_appendix_markdown(
        repo_id, scenarios, result, tornado, agg, charts, trials,
        disclosure=disclosure,
    ))
    return path


def quantify_appendix(
    repo_id: str,
    config: Config | None = None,
    *,
    trials: int = 50_000,
    seed: int = 0,
    persist: bool = True,
) -> QuantificationArtifacts:
    """Generate one reusable quantitative result for reports and CLI summaries."""
    config = config or get_config()
    before = len(db.list_risk_scenarios(repo_id, config)) if persist else 0
    projected_count = None if persist else len(build_scenarios(repo_id, config, persist=False))
    path = generate_appendix(repo_id, config, trials=trials, seed=seed, persist=persist)
    count = len(db.list_risk_scenarios(repo_id, config)) - before if persist else projected_count
    artifacts = tuple(sorted(candidate for candidate in path.parent.iterdir() if candidate.is_file()))
    return QuantificationArtifacts(
        appendix_path=path,
        scenario_count=count,
        artifact_paths=artifacts,
        trials=trials,
        seed=seed,
        audit_recorded=persist,
    )


def _appendix_markdown(
    repo_id, scenarios, result, tornado, agg, charts, trials, *, disclosure=None
) -> str:
    lines = [
        f"# Risk Quantification Appendix — {repo_id}",
        "",
    ]
    if disclosure:
        lines += [f"> **{disclosure}**", ""]
    lines += [
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
        "| Scenario | Findings | Conditional λ/finding | Validity | Exposure | Control strength | Loss scale | Magnitude p05*–p95 | Sources |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for s in scenarios:
        lines.append(
            f"| {s.name} | {len(s.finding_ids)} | "
            f"{','.join(f'{value:.3f}' for value in s.conditional_frequency_lambdas)} | "
            f"{','.join(f'{value:.2f}' for value in s.validity_probabilities)} | "
            f"{','.join(f'{value:.2f}' for value in s.exposure_factors)} | "
            f"{','.join(f'{value:.2f}' for value in s.control_strengths)} | "
            f"{s.loss_scale:.2f}× | "
            f"{_fmt_usd(s.p05_usd * s.loss_scale)}*–{_fmt_usd(s.p95_usd * s.loss_scale)} | "
            f"{s.magnitude_source}; {s.frequency_source} |"
        )
    lines += [
        "",
        "## Engagement inputs",
        "",
        "`origin` distinguishes map/falsify-derived evidence, an analyst override, and a "
        "conservative default used where the stored evidence cannot support an estimate.",
        "",
        "| Scenario | Input | Value | Origin | Source | Detail |",
        "|---|---|---:|---|---|---|",
    ]
    for s in scenarios:
        for value in s.input_provenance:
            lines.append(
                f"| {s.name} | {value.input_name} | {value.value:.3f} | "
                f"{value.origin} | {value.source} | {value.detail or ''} |"
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
        "Cyentia IRIS 2022 Table 3 (magnitude) and Figure 4 (frequency). The p05 marked "
        "with an asterisk is implied by the fitted lognormal; it is not a published statistic. "
        "Dated cached EPSS/KEV values, when present, are informational labels only and do "
        "not modify a distribution input.",
        "",
        "> Generated by `analyze/risk_quant.py` (FAIR-style Bernoulli validity + "
        "conditional compound Poisson-lognormal). Uncertainty is intrinsic — treat the range, not any single figure, "
        "as the result.",
        "",
    ]
    return "\n".join(lines)

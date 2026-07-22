"""Single configuration loader.

`config.toml` at the repo root is read *only* here. Every other module receives a
`Config` object (or pulls the cached default via `get_config()`); nothing else parses
the TOML or hardcodes paths. Relative paths in `[paths]` are resolved against the repo
root through `Config.resolve()`.
"""

from __future__ import annotations

import tomllib
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

# src/repoauditor/config.py -> parents[2] == repo root.
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = REPO_ROOT / "config.toml"
DEFAULT_PRIORS_PATH = REPO_ROOT / "priors.yaml"
DEFAULT_DEAL_RISK_PATH = REPO_ROOT / "deal_risk.yaml"


class ScanConfig(BaseModel):
    targets: list[str] = Field(default_factory=list)
    watchlist: list[str] = Field(default_factory=list)


class ModelConfig(BaseModel):
    name: str = "claude-opus-4-8"
    temperature: float = 0.0
    max_tokens: int = 4096


class LLMConfig(BaseModel):
    """Reliability knobs for the shared `llm/client.py`."""

    # Below this, a stage's reported confidence is treated as "not confident" and
    # routed to a broader-context re-score or to `unresolved` — never rounded up.
    confidence_threshold: float = 0.5
    # Bounded retries on parse/validation failure before a ValidationFailure is logged.
    max_retries: int = 2


class FalsifyConfig(BaseModel):
    """Iteration budget for the falsification challenger's observe-think-act-reflect loop.

    The challenger is a *bounded* loop (challenger.py): each candidate gets at most
    `max_iterations` rounds of evidence-gathering + verdict + self-critique. If the loop
    hits the limit without a confident, self-critique-upheld confirm/kill it degrades
    gracefully to `unresolved` — it never forces a verdict past the limit, never loops
    unbounded. Small by design.
    """

    max_iterations: int = 3
    # LLM budget for a single falsify run: the maximum number of candidate findings put
    # through the (expensive) observe-think-act-reflect loop this run. Candidates are
    # taken in triage-priority order (highest P(actionable) first); any beyond the budget
    # are persisted `deferred` — not dropped — and resumed by a later run. `0` means
    # unlimited (challenge every unresolved candidate, the pre-budget behavior).
    max_findings_per_run: int = 0


class DetectConfig(BaseModel):
    """Knobs for the detect stage's deterministic tool adapters (detect/deterministic).

    Operational, not risk priors. The adapters shell out to external scanners (Semgrep,
    pip-audit, OSV-Scanner, gitleaks); each degrades to no findings when its binary is
    absent, so a partial toolchain never breaks a run.
    """

    # Run the deterministic tool adapters alongside the LLM lenses. Off = LLM-only detect.
    run_deterministic_tools: bool = True
    # Per-tool subprocess timeout (seconds). A tool exceeding it contributes no findings.
    tool_timeout_seconds: int = 180


class ReviewConfig(BaseModel):
    """Thresholds for the human-review checkpoint (review/checkpoint.py).

    These are *operational* gating knobs (like `llm.confidence_threshold`), not risk
    priors — they decide when the pipeline hands a finding to a human, and so live in
    `config.toml`, not `priors.yaml`.
    """

    # A triage result whose winning-class probability (max(p, 1-p)) is below this is
    # too uncertain to auto-act on and is routed to human review rather than silently
    # suppressed or promoted.
    triage_confidence_threshold: float = 0.65


class TriageConfig(BaseModel):
    """How the triage classifier blends the synthetic teacher with real accumulated labels.

    These are *operational* training-procedure knobs (like `llm.max_retries` or the review
    thresholds), not risk distribution priors — but the synthetic-vs-real weighting still
    carries a documented `basis` so it is principled, not a magic number.

    Weighting scheme (documented rationale, mirrors the Beta-Binomial shrinkage in
    triage/priors.py, lifted from the per-rule rate to the whole training corpus):

      * The synthetic corpus is treated as a fixed pool of *pseudo-observations* of total
        weight `synthetic_pseudocount`. Each real label carries weight 1.0. So synthetic's
        share of the effective training mass is
              synthetic_pseudocount / (synthetic_pseudocount + n_real)
        which starts at 1.0 when there are no real labels and shrinks monotonically toward
        0 as real labels accumulate — exactly the shrinkage a Beta(α₀+a, β₀+b) posterior
        applies as observations arrive. Real data is never merely co-equal; it dominates
        once `n_real` exceeds `synthetic_pseudocount`.
      * `synthetic_cutoff_labels` is a hard stop: at/above this many real labels the
        synthetic pool is dropped entirely (weight 0). Beyond a corpus this size the
        synthetic teacher can only inject its own generative bias, so it is retired.
      * Held-out precision-recall + Brier are computed on a *real* label split once at least
        `min_real_labels_for_holdout_eval` real labels exist; below that the eval runs on a
        synthetic split and is flagged `eval_on='synthetic'` — a statement about the
        generator, never presented as a real-performance number.
    """

    # Size of the synthetic teacher corpus generated per training run.
    synthetic_corpus_size: int = 2000
    # Total effective weight (pseudo-observations) assigned to the whole synthetic pool.
    # ~200: enough to define the decision surface at cold start, matched then overtaken by
    # a few hundred real labels — the same "weak prior, ~N real obs dominate" calibration
    # as priors.yaml's Beta(3,7) (10 pseudo-obs per rule), scaled up for a 21-feature space.
    synthetic_pseudocount: float = 200.0
    # At/above this many real labels, stop using synthetic data at all (comparable to the
    # synthetic corpus size — real data then fully specifies the problem).
    synthetic_cutoff_labels: int = 2000
    # Minimum real labels before held-out PR/Brier is computed on a real split. 40 gives a
    # stratified 25% test set of ~10 rows with ~3 positives at the ~0.30 base rate — the
    # floor for a non-degenerate estimate; below it the eval is synthetic (and flagged).
    min_real_labels_for_holdout_eval: int = 40
    basis: str = (
        "Synthetic-vs-real weighting = Beta-Binomial shrinkage (triage/priors.py) applied "
        "to the training corpus: synthetic is a fixed pseudo-observation pool whose share "
        "decays as 1/(1+n_real/pseudocount), retired entirely past a real-corpus-sized "
        "cutoff. SME-calibrated, editable in config.toml [triage]; not a magic number."
    )


class RateLimitConfig(BaseModel):
    requests_per_minute: int = 30
    max_concurrency: int = 4


class PathsConfig(BaseModel):
    data_dir: Path = Path("data")
    raw_dir: Path = Path("data/raw")
    db_path: Path = Path("data/repoauditor.db")


class MagnitudePrior(BaseModel):
    """A calibrated loss-magnitude prior: a 90% CI on single-event cost (USD).

    Stored as (p05, p95) rather than lognormal mu/sigma directly — `analyze/risk_quant`
    converts to log space via Hubbard & Seiersen calibration. `source` is mandatory:
    this is the object that makes "no unsourced priors" enforceable.
    """

    p05_usd: float = Field(gt=0.0)
    p95_usd: float = Field(gt=0.0)
    source: str
    detail: str | None = None


class FrequencyPrior(BaseModel):
    """A Loss Event Frequency base rate (Poisson lambda, events/year) for a signal band.

    Selected by the strongest exploitation signal on a finding (KEV / EPSS band /
    none) and then scaled by triage P(actionable) in `analyze/risk_quant`.
    """

    lambda_per_year: float = Field(ge=0.0)
    source: str
    epss_threshold: float | None = None
    detail: str | None = None


class BetaPrior(BaseModel):
    """A sourced Beta(alpha, beta) prior — the triage cold-start actionable-rate prior."""

    alpha: float = Field(gt=0.0)
    beta: float = Field(gt=0.0)
    source: str
    detail: str | None = None


class TriagePriorsConfig(BaseModel):
    """Triage-stage priors block of `priors.yaml`."""

    global_actionable_prior: BetaPrior = Field(
        # Fallback matches the documented priors.yaml value so triage still has a
        # sourced cold-start prior even if the file is absent (tests, fresh checkout).
        default_factory=lambda: BetaPrior(
            alpha=3.0,
            beta=7.0,
            source="SME-calibrated cold-start default (see priors.yaml triage block)",
        )
    )


class PriorsConfig(BaseModel):
    """Parsed `priors.yaml`: every magnitude/frequency/triage parameter with provenance.

    Loaded alongside `config.toml`. `analyze/risk_quant` and `triage/priors` read only
    from here for their distribution inputs and write a `PriorSource`/`RulePrior` row
    naming the backing source for each parameter consumed.
    """

    triage: TriagePriorsConfig = Field(default_factory=TriagePriorsConfig)
    magnitude: dict[str, MagnitudePrior] = Field(default_factory=dict)
    frequency: dict[str, FrequencyPrior] = Field(default_factory=dict)
    sme_estimates: dict[str, MagnitudePrior] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Deal-risk weighting config (analyze/deal_risk.py) — sourced, editable mapping.
# --------------------------------------------------------------------------- #
# This is the config-driven layer behind `analyze/deal_risk.py`: it turns a finding's
# type + trust-boundary context into a deal-relevant weight distinct from technical
# severity. Like `priors.yaml`, the risk-bearing parameters carry a documented basis so
# nothing is a silently-invented magic number (CLAUDE.md "no unsourced priors"). The
# scalar priors (blend weights, ordinal scores, band cutoffs) default here in code — a
# documented fallback so the module works even if `deal_risk.yaml` is absent — while the
# richer, per-engagement-editable taxonomy (categories + rep-&-warranty mapping) lives in
# `deal_risk.yaml` and overrides these defaults.
class DealWeightBlend(BaseModel):
    """The four weights blending a finding into its deal-risk score. Must sum to ~1.0."""

    severity: float = Field(ge=0.0, le=1.0, default=0.30)
    production_exposure: float = Field(ge=0.0, le=1.0, default=0.30)
    remediation: float = Field(ge=0.0, le=1.0, default=0.20)
    rep_warranty: float = Field(ge=0.0, le=1.0, default=0.20)
    basis: str = (
        "Analyst-calibrated diligence blend (stated assumption, not empirical): a deal "
        "reviewer weights 'is it on a production/customer-data path' and 'how impactful' "
        "roughly equally, with remediation burden and rep-&-warranty exposure as secondary "
        "modifiers. Editable per engagement in deal_risk.yaml."
    )

    @model_validator(mode="after")
    def _weights_sum_to_one(self) -> "DealWeightBlend":
        total = self.severity + self.production_exposure + self.remediation + self.rep_warranty
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"deal-risk blend weights must sum to 1.0 (got {total})")
        return self


class ExposureConfig(BaseModel):
    """How a finding's map linkage becomes a production/customer-data exposure score."""

    # Score by the kind of entity the finding is anchored to (data at rest / edge / etc.).
    entity_kind_scores: dict[str, float] = Field(
        default_factory=lambda: {
            "data_store": 1.0, "entry_point": 0.9, "integration": 0.5, "component": 0.2,
        }
    )
    # Keywords in a trust-boundary/entity name or description that signal a production or
    # customer-data path directly.
    production_indicators: list[str] = Field(
        default_factory=lambda: [
            "production", "prod", "customer", "pii", "personal data", "public", "internet",
            "external", "payment", "card", "phi", "user data", "sensitive",
        ]
    )
    matched_score: float = 1.0  # exposure when a production indicator matches
    default_score: float = 0.5  # no map linkage / no signal — conservative moderate
    basis: str = (
        "Data-at-rest and internet-facing edges are the diligence-relevant production/"
        "customer-data surfaces; internal components score low. 'Unknown' is treated as "
        "moderate (0.5), not zero — deal risk should not under-report on missing context."
    )


class RepWarrantyEntry(BaseModel):
    """Whether a finding category falls under a standard acquisition security rep."""

    relevant: bool = False
    weight: float = Field(ge=0.0, le=1.0, default=0.0)
    rep_clause: str = ""  # which standard rep it maps to
    source: str = ""  # documented basis for the mapping


class DealCategory(BaseModel):
    """One finding category: how to recognise it + its remediation/rep-&-warranty profile."""

    cwes: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    source_tools: list[str] = Field(default_factory=list)
    remediation: str = "moderate"  # fast | moderate | major | redesign
    rep_warranty: RepWarrantyEntry = Field(default_factory=RepWarrantyEntry)

    @field_validator("cwes", mode="before")
    @classmethod
    def _cwes_to_str(cls, v: object) -> object:
        # Allow bare integers in YAML (cwes: [798, 89]) — normalise to "798"/"89".
        if isinstance(v, list):
            return [str(item).removeprefix("CWE-").removeprefix("cwe-") for item in v]
        return v


class DealRiskConfig(BaseModel):
    """Parsed `deal_risk.yaml` — the config-driven mapping behind analyze/deal_risk.py.

    `categories` is the editable taxonomy (recognition rules + remediation cost class +
    rep-&-warranty relevance, each with a documented `source`); it defaults to a single
    `other` bucket in code so a bare Config still runs, and is populated from
    `deal_risk.yaml` for a real audit. `remediation_scores` maps each remediation class to
    an ordinal burden in [0,1] (harder/longer to fix == higher deal risk); `bands` bucket
    the final weight for reporting.
    """

    blend: DealWeightBlend = Field(default_factory=DealWeightBlend)
    exposure: ExposureConfig = Field(default_factory=ExposureConfig)
    remediation_scores: dict[str, float] = Field(
        default_factory=lambda: {
            "fast": 0.25, "moderate": 0.5, "major": 0.75, "redesign": 1.0,
        }
    )
    bands: dict[str, float] = Field(
        default_factory=lambda: {"elevated": 0.4, "high": 0.6, "critical": 0.8}
    )
    default_category: str = "other"
    categories: dict[str, DealCategory] = Field(
        default_factory=lambda: {
            "other": DealCategory(
                remediation="moderate",
                rep_warranty=RepWarrantyEntry(
                    relevant=False, weight=0.3,
                    rep_clause="not squarely under a standard security rep",
                    source="Default fallback (see deal_risk.yaml).",
                ),
            )
        }
    )


class Config(BaseModel):
    scan: ScanConfig = Field(default_factory=ScanConfig)
    model: ModelConfig = Field(default_factory=ModelConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    detect: DetectConfig = Field(default_factory=DetectConfig)
    falsify: FalsifyConfig = Field(default_factory=FalsifyConfig)
    triage: TriageConfig = Field(default_factory=TriageConfig)
    review: ReviewConfig = Field(default_factory=ReviewConfig)
    rate_limits: RateLimitConfig = Field(default_factory=RateLimitConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)
    priors: PriorsConfig = Field(default_factory=PriorsConfig)
    deal_risk: DealRiskConfig = Field(default_factory=DealRiskConfig)

    # Root against which relative `paths` are resolved. Not read from TOML.
    root: Path = REPO_ROOT

    def resolve(self, path: Path | str) -> Path:
        """Resolve a possibly-relative path against the repo root."""
        p = Path(path)
        return p if p.is_absolute() else (self.root / p)

    @property
    def db_path(self) -> Path:
        return self.resolve(self.paths.db_path)

    @property
    def raw_dir(self) -> Path:
        return self.resolve(self.paths.raw_dir)


def load_priors(path: Path | str | None = None) -> PriorsConfig:
    """Load and validate `priors.yaml`. Missing file -> empty (validated) priors.

    Kept separate from TOML loading so tests can point at a fixture priors file, but
    called by `load_config` so a `Config` always carries its priors.
    """
    priors_path = Path(path) if path is not None else DEFAULT_PRIORS_PATH
    if not priors_path.is_file():
        return PriorsConfig()
    with priors_path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return PriorsConfig(**raw)


def load_deal_risk(path: Path | str | None = None) -> DealRiskConfig:
    """Load and validate `deal_risk.yaml`. Missing file -> code defaults (documented).

    Same pattern as `load_priors`: the file is the editable source of truth for the
    deal-risk taxonomy, but its absence falls back to the model defaults so the tool still
    runs (degraded to the coarse `other` category) without a code change.
    """
    deal_risk_path = Path(path) if path is not None else DEFAULT_DEAL_RISK_PATH
    if not deal_risk_path.is_file():
        return DealRiskConfig()
    with deal_risk_path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    # Allow either a top-level `deal_risk:` block or the bare mapping.
    return DealRiskConfig(**raw.get("deal_risk", raw))


def load_config(path: Path | str | None = None) -> Config:
    """Load and validate configuration from a TOML file.

    Missing file falls back to model defaults, so the tool works before a
    `config.toml` exists. Pass an explicit `path` (e.g. in tests) to override.
    `priors.yaml` and `deal_risk.yaml` are loaded from the same root alongside the TOML.
    """
    config_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    if config_path.is_file():
        with config_path.open("rb") as fh:
            raw = tomllib.load(fh)
    else:
        raw = {}

    root = config_path.resolve().parent if config_path.is_file() else REPO_ROOT
    priors = load_priors(root / "priors.yaml")
    deal_risk = load_deal_risk(root / "deal_risk.yaml")
    return Config(**raw, root=root, priors=priors, deal_risk=deal_risk)


@lru_cache(maxsize=1)
def get_config() -> Config:
    """Cached default configuration loaded from the repo-root `config.toml`."""
    return load_config()

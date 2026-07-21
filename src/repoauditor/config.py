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
from pydantic import BaseModel, Field

# src/repoauditor/config.py -> parents[2] == repo root.
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = REPO_ROOT / "config.toml"
DEFAULT_PRIORS_PATH = REPO_ROOT / "priors.yaml"


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


class Config(BaseModel):
    scan: ScanConfig = Field(default_factory=ScanConfig)
    model: ModelConfig = Field(default_factory=ModelConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    falsify: FalsifyConfig = Field(default_factory=FalsifyConfig)
    review: ReviewConfig = Field(default_factory=ReviewConfig)
    rate_limits: RateLimitConfig = Field(default_factory=RateLimitConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)
    priors: PriorsConfig = Field(default_factory=PriorsConfig)

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


def load_config(path: Path | str | None = None) -> Config:
    """Load and validate configuration from a TOML file.

    Missing file falls back to model defaults, so the tool works before a
    `config.toml` exists. Pass an explicit `path` (e.g. in tests) to override.
    `priors.yaml` is loaded from the same root alongside the TOML.
    """
    config_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    if config_path.is_file():
        with config_path.open("rb") as fh:
            raw = tomllib.load(fh)
    else:
        raw = {}

    root = config_path.resolve().parent if config_path.is_file() else REPO_ROOT
    priors = load_priors(root / "priors.yaml")
    return Config(**raw, root=root, priors=priors)


@lru_cache(maxsize=1)
def get_config() -> Config:
    """Cached default configuration loaded from the repo-root `config.toml`."""
    return load_config()

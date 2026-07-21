"""Canonical pydantic models for the findings store.

These mirror the SQLite DDL in `ddl/` one-to-one and are the in-memory contract
every other stage speaks. Persistence lives in `db.py`; these are pure data shapes.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, model_validator


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Total order over severities, low → high. Used to enforce the core rule that a
# resolved severity is never higher than the evidence supports.
_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(severity: Severity) -> int:
    """Ordinal rank of a severity (info=0 … critical=4)."""
    return _SEVERITY_RANK[Severity(severity)]


def cap_severity(proposed: Severity, ceiling: Severity) -> Severity:
    """Return `proposed` unless it exceeds `ceiling`, in which case return `ceiling`.

    Encodes "severity is never upgraded beyond what the evidence supports": the
    ceiling is the strongest severity any single source actually asserted.
    """
    return proposed if severity_rank(proposed) <= severity_rank(ceiling) else ceiling


class FalsificationStatus(StrEnum):
    CONFIRMED = "confirmed"
    KILLED = "killed"
    UNRESOLVED = "unresolved"


class SourceType(StrEnum):
    LENS = "lens"
    TOOL = "tool"


class EntityKind(StrEnum):
    ENTRY_POINT = "entry_point"
    DATA_STORE = "data_store"
    INTEGRATION = "integration"
    COMPONENT = "component"


class TrustBoundary(BaseModel):
    """A boundary across which trust changes — the anchor findings trace back to."""

    id: int | None = None
    repo_id: str
    name: str
    description: str | None = None


class Entity(BaseModel):
    """Architectural entity from the map stage (entry point / data store / etc.)."""

    id: int | None = None
    repo_id: str
    kind: EntityKind
    name: str
    location: str | None = None
    trust_boundary_id: int | None = None
    metadata: dict | None = None


class Corroboration(BaseModel):
    """An independent lens/tool that also flagged a given finding."""

    id: int | None = None
    finding_id: int | None = None
    source_type: SourceType
    source_name: str
    note: str | None = None


class Finding(BaseModel):
    """Atomic unit of the pipeline. Always carries its citation and its origin.

    Invariant: at least one of `source_lens` / `source_tool` is set. Severity is
    only ever raised given corroboration or a confirming falsification pass — that
    rule is enforced in the analyze/normalize stages, not here.
    """

    id: int | None = None
    repo_id: str
    title: str
    file: str
    line_start: int
    line_end: int
    citation_snippet: str
    source_lens: str | None = None
    source_tool: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    falsification_status: FalsificationStatus = FalsificationStatus.UNRESOLVED
    falsification_reason: str | None = None
    trust_boundary_id: int | None = None
    entity_id: int | None = None
    description: str | None = None
    corroborated_by: list[Corroboration] = Field(default_factory=list)

    @model_validator(mode="after")
    def _require_source_and_line_order(self) -> "Finding":
        if self.source_lens is None and self.source_tool is None:
            raise ValueError("finding must have a source_lens or a source_tool")
        if self.line_end < self.line_start:
            raise ValueError("line_end must be >= line_start")
        return self


class ValidationFailure(BaseModel):
    """A logged, exhausted parse/validation retry from `llm/client.py`.

    The structured-output reliability trail: which module called the model, which
    prompt version was in use, the truncated raw response, and the validation error.
    Nothing is silently retried into oblivion — an exhausted retry is a logged
    outcome, as much as a killed finding is.
    """

    id: int | None = None
    module: str
    prompt_version: str
    raw_response: str
    validation_error: str


class EvalRun(BaseModel):
    """One golden-harness execution, for closed-loop regression gating.

    Records the prompt versions used, precision/recall against the benchmark corpus,
    and whether this run regressed against the immediately prior run for the same
    lineage (`eval/regression.py` computes `regressed_from_prior`).
    """

    id: int | None = None
    lineage: str  # groups comparable runs (e.g. the fixture/corpus id)
    prompt_versions: dict[str, str] = Field(default_factory=dict)
    precision: float
    recall: float
    regressed_from_prior: bool = False


# --------------------------------------------------------------------------- #
# Triage stage (detect -> triage -> falsify): calibrated P(actionable) ranking
# --------------------------------------------------------------------------- #
class TriageLabel(BaseModel):
    """An analyst's ground-truth disposition on a past deterministic-tool finding.

    The cross-engagement label store the triage classifier learns from. Keyed by
    `rule_id` (the SAST rule that fired) and `engagement` (the repo/audit it came
    from); accumulates over time so per-rule historical FP rates and the calibrated
    P(actionable) model both improve as more audits are labelled. `actionable` is
    the label: True = a real, worth-fixing issue; False = a false positive.
    """

    id: int | None = None
    engagement: str  # repo_id / audit id the label was collected on
    rule_id: str  # SAST rule that produced the finding (e.g. "python.lang.security....")
    finding_fingerprint: str  # stable hash of (rule_id, file, line, snippet) — dedupe key
    actionable: bool  # analyst disposition: True = true positive, False = false positive
    note: str | None = None


class RulePrior(BaseModel):
    """Per-rule Beta-Binomial hyperparameters for cold-start P(actionable).

    `triage/priors.py` maintains a Beta(alpha, beta) prior over the actionable rate
    of each SAST rule. Cold-start rules use the weak global prior; as `TriageLabel`
    rows accumulate for a rule, the posterior mean shrinks from the prior toward the
    observed actionable fraction (Bayesian shrinkage). `alpha`/`beta` are the current
    posterior pseudo-counts; `observed_actionable`/`observed_total` record how many
    real labels back them (0/0 == pure prior, i.e. no evidence yet).
    """

    id: int | None = None
    rule_id: str
    alpha: float = Field(gt=0.0)  # prior + observed actionable pseudo-count
    beta: float = Field(gt=0.0)  # prior + observed non-actionable pseudo-count
    observed_actionable: int = 0
    observed_total: int = 0
    prior_source: str  # where the cold-start hyperparameters come from (no magic numbers)

    @property
    def posterior_mean(self) -> float:
        """Posterior mean actionable rate E[p] = alpha / (alpha + beta)."""
        return self.alpha / (self.alpha + self.beta)


class TriageResult(BaseModel):
    """The triage classifier's verdict on one finding: rank + calibrated P(actionable).

    Attached to an existing `Finding` (never replaces it). `suppressed` marks a finding
    demoted below the action threshold — it stays in the store, ranked and attributed,
    exactly like a killed falsification candidate. `attributions` are the top-3 feature
    contributions (SHAP where available, impurity importance otherwise).
    """

    id: int | None = None
    finding_id: int
    p_actionable: float = Field(ge=0.0, le=1.0)
    rank: int = Field(ge=1)
    suppressed: bool = False
    model_name: str  # winning model: "randomforest" | "xgboost"
    attributions: list[dict] = Field(default_factory=list)  # [{feature, value, contribution}]


# --------------------------------------------------------------------------- #
# Analyze stage — FAIR-style Monte Carlo risk quantification
# --------------------------------------------------------------------------- #
class PriorSource(BaseModel):
    """Provenance record for a single distribution parameter used in risk quant.

    Enforces the "no unsourced priors" rule at the persistence layer: every
    magnitude/frequency parameter that enters a simulation writes one of these,
    naming which dataset/method backs it (DBIR, IRIS, EPSS, KEV, or a calibrated
    SME estimate). `kind` is the parameter family; `param_path` is the key in
    `priors.yaml`; `source` is the human-readable citation copied from that file.
    """

    id: int | None = None
    kind: str  # "magnitude" | "frequency" | "sme_estimate"
    param_path: str  # dotted key into priors.yaml, e.g. "magnitude.data_breach"
    source: str  # citation string (dataset / method) from priors.yaml
    detail: str | None = None  # optional extra provenance (year, table, percentile basis)


class RiskScenario(BaseModel):
    """A FAIR-style loss scenario mapping one or more Findings to a modelled risk.

    Each scenario draws Loss Event Frequency ~ Poisson(lam) and Loss Magnitude ~
    Lognormal(mu, sigma). The frequency rate `lam` is derived from an exploitation-
    frequency prior *scaled by the triage P(actionable)* of the member findings —
    that scaling is the explicit seam between triage/ and analyze/. Distribution
    parameters are resolved from `priors.yaml`; each writes a `PriorSource` row.
    """

    id: int | None = None
    repo_id: str
    name: str
    finding_ids: list[int] = Field(default_factory=list)
    # Loss Event Frequency: Poisson rate (expected events/year).
    frequency_lambda: float = Field(ge=0.0)
    # Loss Magnitude: lognormal parameters (natural-log space).
    magnitude_mu: float
    magnitude_sigma: float = Field(gt=0.0)
    frequency_source: str  # PriorSource.param_path backing frequency_lambda
    magnitude_source: str  # PriorSource.param_path backing the magnitude params
    p_actionable: float | None = None  # triage signal folded into frequency_lambda


class SimulationRun(BaseModel):
    """One Monte Carlo run's persisted summary — the audit trail for a quantification.

    Records trial count and the loss distribution summary (never a single expected
    number: mean/median/p95 all persist so uncertainty survives to storage). The
    per-scenario exceedance data and the tornado sensitivity ranking are stored as
    JSON so the appendix artifact can be regenerated without re-simulating.
    """

    id: int | None = None
    repo_id: str
    trials: int
    mean_loss: float
    median_loss: float
    p95_loss: float
    scenario_summary: dict = Field(default_factory=dict)  # per-scenario mean/median/p95
    tornado: list[dict] = Field(default_factory=list)  # sensitivity ranking (param -> swing)
    seed: int | None = None


# --------------------------------------------------------------------------- #
# Review stage — human-in-the-loop checkpoint (maker-checker / four-eyes control)
# --------------------------------------------------------------------------- #
class ReviewDisposition(StrEnum):
    """A human reviewer's ruling on a held finding.

    `CONFIRM` releases the finding downstream (analyze/ may consume it); `DISMISS`
    keeps it in the store for the record but withholds it from analysis, exactly like
    a killed falsification candidate. The gate only opens on `CONFIRM`.
    """

    CONFIRM = "confirm"
    DISMISS = "dismiss"


class ReviewRequest(BaseModel):
    """A finding the automated pipeline could not resolve, held for human review.

    Raised by `review/checkpoint.py` for any finding written `unresolved` by falsify/
    or normalize/, or any triage result the classifier is too uncertain about. It
    carries everything a reviewer needs: the reason it is unresolved plus the gathered
    `evidence` (citation, trust-boundary context, and the stage's own reasoning trace —
    the falsification iterations, the adjudication debate, or the triage attribution).
    A request with no linked `ReviewDecision` blocks its finding from any analyze-style
    query (`db.list_analyzable_findings`) — a genuinely blocking checkpoint.
    """

    id: int | None = None
    repo_id: str
    finding_id: int
    stage: str  # which stage flagged the uncertainty: "falsify" | "normalize" | "triage"
    reason: str  # human-readable why-this-is-unresolved
    evidence: dict = Field(default_factory=dict)  # citation + trust boundary + stage trace


class ReviewDecision(BaseModel):
    """A reviewer's recorded ruling on a `ReviewRequest` — an append-only audit entry.

    Immutable by construction: nothing about a decision is ever edited. A correction is
    a *new* decision row that references the one it supersedes via `supersedes_id`, so
    the full history (who ruled what, when, and why it was later overridden) survives.
    The effective ruling for a request is its most recent decision row.
    """

    id: int | None = None
    review_request_id: int
    disposition: ReviewDisposition
    reviewer: str  # who ruled (name / id)
    rationale: str  # why — mandatory, same discipline as a killed-finding reason
    supersedes_id: int | None = None  # prior decision this one corrects (never an edit)
    created_at: str | None = None  # set by the store on insert


# --------------------------------------------------------------------------- #
# Normalize stage — debate framing for severity adjudication
# --------------------------------------------------------------------------- #
class DebatePosition(BaseModel):
    """One source's stance in a severity disagreement: its call *and its reasoning*.

    Debate framing gathers not just each source's severity value but the reasoning
    behind it, so the adjudicator (and, if it stays unresolved, a human reviewer) can
    see *why* the sources disagreed, not merely that they did.
    """

    source_type: SourceType
    source_name: str
    severity: Severity
    reasoning: str


class AdjudicationDebate(BaseModel):
    """The persisted trail of one severity-adjudication debate.

    Records every source's position (value + reasoning) alongside the outcome —
    either a synthesized `consensus` (with the resolved severity and the adjudicator's
    documented rationale) or an explicit `unresolved` that routes to review/. Persisted
    so the final severity is never the *only* thing kept: the disagreement itself is
    auditable.
    """

    id: int | None = None
    repo_id: str
    file: str
    line_start: int
    line_end: int
    positions: list[DebatePosition] = Field(default_factory=list)
    outcome: str  # "consensus" | "unresolved"
    resolved_severity: Severity | None = None
    synthesis_rationale: str | None = None


# --------------------------------------------------------------------------- #
# Falsify stage — bounded iteration trace (observe-think-act-reflect)
# --------------------------------------------------------------------------- #
class FalsificationIteration(BaseModel):
    """One round of the bounded falsification loop, logged for transparency.

    The challenger is an observe-think-act-reflect loop: each iteration gathers
    evidence, forms a verdict, then self-critiques that verdict against the evidence
    before deciding whether to commit. Every round is persisted — not just the final
    verdict — so a review/ reviewer can follow the reasoning trace, the same
    transparency principle as the adjudication debate trail.
    """

    id: int | None = None
    finding_id: int
    iteration: int = Field(ge=1)  # 1-based round number
    evidence: str  # summary of the reachability / mitigating-control context gathered
    verdict_status: FalsificationStatus
    verdict_rationale: str
    verdict_confidence: float
    critique_upholds: bool  # did the self-critique step uphold the verdict?
    critique_note: str
    committed: bool = False  # True on the round whose verdict was accepted (if any)

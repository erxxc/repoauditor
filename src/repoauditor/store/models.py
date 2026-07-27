"""Canonical pydantic models for the findings store.

These mirror the SQLite DDL in `ddl/` one-to-one and are the in-memory contract
every other stage speaks. Persistence lives in `db.py`; these are pure data shapes.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, model_validator


class IngestedRepo(BaseModel):
    """One immutable repository snapshot recorded by the ingest stage."""

    repo_id: str
    source: str
    commit_hash: str
    ingested_at: str | None = None


class RunStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class PipelineRun(BaseModel):
    """Durable status for one foreground pipeline orchestration."""

    id: int | None = None
    parent_run_id: int | None = None
    source: str
    repo_id: str | None = None
    commit_hash: str | None = None
    status: RunStatus = RunStatus.RUNNING
    started_at: str | None = None
    completed_at: str | None = None
    failed_stage: str | None = None
    failure_detail: str | None = None
    artifacts: list[str] = Field(default_factory=list)


class StageRun(BaseModel):
    """Latest durable attempt state for a stage within a pipeline run."""

    id: int | None = None
    pipeline_run_id: int
    stage: str
    status: RunStatus = RunStatus.RUNNING
    started_at: str | None = None
    completed_at: str | None = None
    summary: dict = Field(default_factory=dict)
    artifacts: list[str] = Field(default_factory=list)
    failure_detail: str | None = None


class ModelUsage(BaseModel):
    """Authoritative provider-reported usage for one model request attempt."""

    id: int | None = None
    pipeline_run_id: int | None = None
    stage: str
    module: str
    prompt_version: str
    provider: str
    model: str
    usage_available: bool
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_read_tokens: int | None = None
    cache_write_tokens: int | None = None
    latency_ms: int
    recorded_at: str | None = None


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
    # A candidate the falsify stage has not yet examined because it fell outside this
    # run's LLM budget. Distinct from UNRESOLVED (which means "examined, genuinely
    # ambiguous, route to human review"): DEFERRED is "not yet examined". A later
    # falsify run resumes it; the analyze gate excludes it; review ignores it (it keys
    # on UNRESOLVED). Never confuse it with a confirmed/killed verdict.
    DEFERRED = "deferred"


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
    """Another named lens/tool that also flagged a given finding.

    Agreement is not automatically independence: shared-model lenses are correlated.
    `score` and `match_basis` are populated by `analyze/corroboration.py`: `score` is the
    finding's mechanism-diversity-weighted agreement score in [0, 1] (the same aggregate is
    written on every corroboration row of a finding), and `match_basis` records *why* this
    source was judged to be flagging the same underlying issue (the matched signals, e.g.
    "line_overlap+cwe; cross-class(tool↔lens)"). Both are nullable: rows written by
    `normalize/adjudicate.py` before analyze runs (and pre-0007 rows) carry neither.
    """

    id: int | None = None
    finding_id: int | None = None
    source_type: SourceType
    source_name: str
    note: str | None = None
    score: float | None = None
    match_basis: str | None = None


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
    # Optional detector-supplied natural identity. SCA uses a canonical
    # ecosystem/package/version/advisory key because every manifest-level advisory is
    # otherwise anchored to the same synthetic line range.
    identity_key: str | None = None
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
    """A logged exhausted parse/schema retry or semantic citation failure.

    The reliability trail records which module raised the failure, which prompt or
    validator version was in use, the truncated raw response/candidate, and the error.
    Nothing is silently retried or rejected into oblivion.
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
class TriageLabelSource(StrEnum):
    """How a `TriageLabel` was obtained. Governs precedence when a finding is re-labelled.

    `MANUAL` — an analyst asserted it directly (`repoauditor triage-label`); ground truth
    that the derivation pass must never overwrite. `DERIVED_FALSIFY` / `DERIVED_REVIEW` —
    harvested automatically (the closed loop) from a downstream falsify verdict or human
    review decision respectively; a re-derivation may refresh these, a manual label caps them.
    """

    MANUAL = "manual"
    DERIVED_FALSIFY = "derived_falsify"
    DERIVED_REVIEW = "derived_review"


class TriageAssessmentOutcome(StrEnum):
    """An analyst assessment; UNCERTAIN is an explicit abstention, never a label."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"


class TriageDisposition(StrEnum):
    """Detailed analyst ground truth; projected to binary training or abstention."""

    CONFIRMED_ACTIONABLE = "confirmed_actionable"
    TOOL_INCORRECT = "tool_incorrect"
    UNREACHABLE = "unreachable"
    NOT_ATTACKER_CONTROLLED = "not_attacker_controlled"
    MITIGATED = "mitigated"
    DUPLICATE = "duplicate"
    VALID_NOT_ACTIONABLE = "valid_not_actionable"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"

    @property
    def outcome(self) -> TriageAssessmentOutcome:
        if self is TriageDisposition.CONFIRMED_ACTIONABLE:
            return TriageAssessmentOutcome.TRUE_POSITIVE
        if self is TriageDisposition.INSUFFICIENT_EVIDENCE:
            return TriageAssessmentOutcome.UNCERTAIN
        return TriageAssessmentOutcome.FALSE_POSITIVE


class TriageAssessment(BaseModel):
    """Append-only analyst evidence behind a label, correction, or abstention."""

    id: int | None = None
    finding_id: int
    engagement: str
    outcome: TriageAssessmentOutcome
    disposition: TriageDisposition | None = None
    rationale: str = Field(min_length=1)
    analyst: str = Field(min_length=1)
    dimensions: list[str] = Field(default_factory=list)
    created_at: str | None = None


class TriageLabel(BaseModel):
    """An analyst's ground-truth disposition on a past deterministic-tool finding.

    The cross-engagement label store the triage classifier learns from. Keyed by
    `rule_id` (the SAST rule that fired) and `engagement` (the repo/audit it came
    from); accumulates over time so per-rule historical FP rates and the calibrated
    P(actionable) model both improve as more audits are labelled. `actionable` is
    the label: True = a real, worth-fixing issue; False = a false positive. `source`
    records manual-vs-derived provenance (see `TriageLabelSource`); a directly-asserted
    label defaults to MANUAL and outranks any derived label for the same finding.
    """

    id: int | None = None
    engagement: str  # repo_id / audit id the label was collected on
    rule_id: str  # SAST rule that produced the finding (e.g. "python.lang.security....")
    finding_fingerprint: str  # stable hash of (rule_id, file, line, snippet) — dedupe key
    actionable: bool  # analyst disposition: True = true positive, False = false positive
    source: TriageLabelSource = TriageLabelSource.MANUAL
    note: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


class TriageFeatureRecord(BaseModel):
    """The exact feature vector triaged for a finding — the bridge to `TriageLabel`.

    Persisted per deterministic-tool finding at triage time so an accumulated label (keyed
    by `engagement` + `fingerprint`) can be rejoined to the numeric features the classifier
    trains on. `feature_names` is stored alongside the vector so a later change to the
    feature schema is *detected* (rows whose stored names don't match the current
    `FEATURE_NAMES` are skipped rather than silently column-misaligned), never guessed.
    """

    finding_id: int
    engagement: str
    rule_id: str
    fingerprint: str
    features: list[float]
    feature_names: list[str]


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
    triage_run_id: int | None = None
    scored_at: str | None = None


class TriageModelRun(BaseModel):
    """One auditable classifier fit/score pass; every new TriageResult links to it."""

    id: int | None = None
    repo_id: str
    model_name: str
    model_version: str
    feature_schema_version: str
    training_label_count: int
    evaluation_label_count: int
    label_source_counts: dict[str, int] = Field(default_factory=dict)
    synthetic_share: float
    synthetic_dropped: bool
    calibration: str
    evaluation_basis: str
    split_strategy: str
    split_detail: str
    evaluations: list[dict] = Field(default_factory=list)
    scanner_versions: dict[str, str] = Field(default_factory=dict)
    created_at: str | None = None


class ScoredTriageLabel(BaseModel):
    """A historical P(actionable) joined to its later authoritative label and cohort."""

    p_actionable: float
    actionable: bool
    engagement: str
    label_source: TriageLabelSource
    triage_run_id: int | None = None
    scored_at: str | None = None
    model_name: str | None = None
    model_version: str | None = None
    feature_schema_version: str | None = None
    calibration: str | None = None


# --------------------------------------------------------------------------- #
# Analyze stage — FAIR-style Monte Carlo risk quantification
# --------------------------------------------------------------------------- #
class PriorSource(BaseModel):
    """Provenance record for a single distribution parameter used in risk quant.

    Enforces the "no unsourced priors" rule at the persistence layer: every
    magnitude/frequency parameter that enters a simulation writes one of these,
    naming the exact publication, edition, table/figure, URL, and transformation.
    Historical rows that predate this contract are retained as `legacy_unverified`
    rather than assigned a false citation. `kind` is the parameter family; `param_path` is the key in
    `priors.yaml`; `source` is the human-readable citation copied from that file.
    """

    id: int | None = None
    kind: str  # "magnitude" | "frequency" | "sme_estimate"
    param_path: str  # dotted key into priors.yaml, e.g. "magnitude.data_breach"
    source: str  # citation string (dataset / method) from priors.yaml
    detail: str | None = None  # optional extra provenance (year, table, percentile basis)
    publication: str | None = None
    edition: str | None = None
    locator: str | None = None
    url: str | None = None
    transformation: str | None = None
    provenance_status: str = "verified"

    @model_validator(mode="after")
    def _verified_provenance_is_exact(self) -> "PriorSource":
        if self.provenance_status == "verified":
            required = (self.publication, self.edition, self.locator, self.url,
                        self.transformation)
            if not all(required):
                raise ValueError("verified prior sources require exact publication provenance")
        return self


class RiskScenario(BaseModel):
    """A FAIR-style loss scenario mapping one or more Findings to a modelled risk.

    Each member first draws finding validity ~ Bernoulli(p). Only valid members draw
    conditional Loss Event Frequency ~ Poisson(lam). Magnitude is lognormal. This keeps
    epistemic finding uncertainty separate from conditional event frequency.
    """

    id: int | None = None
    simulation_run_id: int | None = None
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
    p_actionable: float | None = None  # legacy summary only; never folded into lambda
    validity_probabilities: list[float] = Field(default_factory=list)
    validity_sources: list[str] = Field(default_factory=list)
    conditional_frequency_lambdas: list[float] = Field(default_factory=list)
    conditional_frequency_source: str | None = None
    threat_signal_labels: list[str] = Field(default_factory=list)
    exposure_factors: list[float] = Field(default_factory=list)
    control_strengths: list[float] = Field(default_factory=list)
    loss_scale: float = Field(default=1.0, gt=0.0)


class ScenarioInput(BaseModel):
    """Per-engagement FAIR input and whether it was derived, defaulted, or overridden."""

    id: int | None = None
    risk_scenario_id: int | None = None
    repo_id: str
    scenario_name: str
    input_name: str  # exposure | control_strength | loss_scale
    value: float
    origin: str  # derived | analyst_override | conservative_default
    source: str
    detail: str | None = None


class DealRisk(BaseModel):
    """Deal-relevant risk weighting for a finding, layered *alongside* technical severity.

    A sidecar annotation on an existing `Finding` (same discipline as `TriageResult`): it
    never overwrites the finding's `severity`. `weight` in [0, 1] is a diligence-facing
    re-weighting blended from four documented, config-sourced components — technical
    severity, production exposure (does the finding's trust boundary/entity touch a
    production or customer-data path, from the map stage), remediation burden (a *categorical*
    cost/timeline estimate by finding type — never a dollar figure, which is
    `risk_quant.py`'s job), and representation-&-warranty relevance (a config-driven lookup,
    not hardcoded logic). The component sub-scores are all persisted so the weight is fully
    reconstructable — no magic numbers. `band` is a coarse bucket of `weight` for reporting.
    """

    id: int | None = None
    finding_id: int
    weight: float = Field(ge=0.0, le=1.0)
    band: str  # low | elevated | high | critical (bucketed weight, config thresholds)
    production_exposure: str  # direct | indirect | internal | unknown
    remediation_category: str  # fast | moderate | major | redesign
    rep_warranty_category: str | None = None  # matched R&W category, if any
    rep_warranty_relevant: bool = False  # falls under a standard security rep
    # Component sub-scores (each in [0, 1]) — persisted so `weight` is auditable.
    severity_component: float
    exposure_component: float
    remediation_component: float
    rep_warranty_component: float
    rationale: str  # human-readable basis, same discipline as a killed-finding reason


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
    created_at: str | None = None


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
    stage: str  # "falsify" | "normalize" | "triage" | "triage-sample"
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


class ClaimVerificationStatus(StrEnum):
    """Structural verification outcome; never an exploitability verdict."""

    STRUCTURALLY_VERIFIED = "structurally_verified"
    STRUCTURALLY_REFUTED = "structurally_refuted"
    VERIFICATION_INCOMPLETE = "verification_incomplete"
    UNSUPPORTED = "unsupported"


class ClaimEvidence(BaseModel):
    """One exact source location supporting a structured security claim."""

    file: str
    line: int = Field(ge=1)
    source: str


class SecurityClaim(BaseModel):
    """A checkable structural claim derived from evidence, separate from a verdict."""

    id: int | None = None
    finding_id: int
    claim_version: str
    snapshot_commit: str | None = None
    mechanism: str
    entry_evidence: list[ClaimEvidence] = Field(default_factory=list)
    source_evidence: list[ClaimEvidence] = Field(default_factory=list)
    sink_evidence: ClaimEvidence | None = None
    path_nodes: list[ClaimEvidence] = Field(default_factory=list)
    path_predicates: list[str] = Field(default_factory=list)
    control_candidate: ClaimEvidence | None = None
    producer_type: str
    producer_name: str
    prompt_version: str | None = None
    created_at: str | None = None


class ClaimVerification(BaseModel):
    """An idempotent verifier record scoped to structural facts only."""

    id: int | None = None
    claim_id: int
    status: ClaimVerificationStatus
    verifier_name: str
    verifier_version: str
    checks: dict[str, bool] = Field(default_factory=dict)
    reason: str
    created_at: str | None = None

# Project priorities

Status: active execution backlog. Update this document when a gate is completed or when
new evidence changes the order; do not silently promote work past its prerequisite.

The methodology-specific detail remains authoritative in
[triage-accuracy-roadmap.md](triage-accuracy-roadmap.md),
[prior-scope-roadmap.md](prior-scope-roadmap.md), and
[agentic-escalation-gate.md](agentic-escalation-gate.md). This page records the cross-project
order so future sessions do not have to reconstruct it from conversation history.

## P0 — operational safety and test trust

- [x] Finish provider safeguards:
  - apply `[llm].timeout_seconds` to Anthropic as well as OpenAI-compatible requests;
  - disable hidden SDK retries so the shared reliability layer owns the retry count;
  - stop immediately on authentication, permission, invalid-model, quota, and other
    terminal client errors;
  - retain bounded retries only for plausibly transient connection/timeout/5xx failures;
  - complete usage, budget-stop, and `runs show` regression coverage.
  - protect guided `demo` with the same durable run scope; bound falsification against
    remaining provider-call capacity; preserve distinct manifest advisories with explicit
    natural identities; and block finalization while safely deferred work remains.
- [x] Re-check the suspected aggregate macOS exit-139 during repeated triage classifier
  training. It was a 30-second command-output yield being mistaken for process completion;
  polling the persistent session produced a clean exit (`26 passed` for the triage file).
  No classifier or native-runtime change was justified.
- [~] Calibrate the initial 75-call/250,000-token guardrails. Offline readiness is shipped:
  fixed evaluation roles, a zero-network corpus audit, and the fail-closed
  `usage-calibration` report. Paid evidence still requires one successful lightweight run
  and one protected independent pre/post pair after cache/provider access returns. Treat
  the limits as safety ceilings, not statistically calibrated defaults; never auto-raise.
- [ ] Add a budget-scoped deferred-queue continuation that reuses the immutable ingested
  snapshot and completed map/detect/triage evidence without paying to repeat those stages.
  Until then, rerunning the same source is safe and idempotent but operationally expensive;
  standalone model-backed stage commands also need the same durable usage scope before they
  are recommended as the continuation path.

## P1 — controlled real-world evidence

- [ ] Complete triage roadmap Phase 3: at least 40 usable human labels, both classes
  represented, across at least eight genuinely distinct engagements. Prefer 100–200 labels.
- [ ] Review high-ranked, reserved novel, and sampled low-ranked findings. Preserve
  `insufficient_evidence` as abstention and record evidence-based rationales.
- [~] Freeze a protected baseline. The serialize-javascript pre/post commits are explicitly
  designated as a protected holdout and checked offline; provider/model/prompt/configured
  result evidence remains pending the bounded online run. Keep fixtures/benchmarks separate
  from independent evidence and protected holdouts out of training.

## P2 — validation maturity

- [ ] At 40 real labels, publish descriptive threshold tradeoff tables.
- [ ] At 40 labels across eight engagements, activate repository-grouped validation with
  held-out repositories, class counts, sample size, and uncertainty disclosed.
- [ ] Add temporal validation only after adequate chronological depth exists.
- [ ] Characterize repeatability on identical inputs, separating sampling variance from
  retrieval-resolution sensitivity. Report verdict/citation/confidence/token/latency spread.
- [ ] Expand manufactured controls only where positive and negative mechanisms have
  independently checkable ground truth.

## P3 — nonstandard-finding optimization

- [ ] Improve language-specific slicing and authorization/source-to-sink context before
  changing the classifier.
- [ ] Expand independently checked `SecurityClaim` certificates for reachability, attacker
  control, sanitizer identity, and mitigating controls.
- [ ] Evaluate in-family/out-of-family novelty as an investigation-depth trigger. Do not
  train a novelty prioritizer until enough manually reviewed LLM findings exist.

## P4 — quantitative enrichment

- [ ] Add dated, cached EPSS and KEV enrichment only for real CVE-backed findings. Define
  stale/offline behavior and retain the labeled industry fallback when no signal exists.
- [ ] Audit EPSS, KEV, exposure, control strength, and loss-scale adjustments for double
  counting.
- [ ] Follow the prior-scope roadmap: inventory applicability, capture cohort metadata,
  establish data coverage, run prior-predictive/held-out checks, then consider versioned
  hierarchical priors. Never fabricate subgroup scaling.

## P5 — gated later capabilities

- [ ] Add dollar-cost reporting only with a dated, versioned provider/model price source;
  keep authoritative token observations separate from calculated cost.
- [ ] Keep agentic falsification opt-in and deferred until every escalation gate is met:
  protected evaluation, baseline comparison, recall safety, cohort breakdowns, read-only
  tools, and independent deterministic certificate verification.
- [ ] Remove or clearly retire the unused placeholder `report/templates/memo_v1.md`.

## Execution order

1. Finish P0 provider safeguards and merge authoritative usage accounting.
2. Diagnose native test instability.
3. Calibrate operational budgets.
4. Collect controlled human adjudications and freeze the protected baseline.
5. Activate validation gates only when their evidence floors are met.
6. Characterize repeatability, then improve slicing/checkable claims.
7. Add real EPSS/KEV enrichment.
8. Revisit hierarchical priors, cost calculation, and agentic escalation last.

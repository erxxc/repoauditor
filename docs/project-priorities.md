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
  `usage-calibration` report. The bounded lightweight and protected independent pair have
  now run; the formal persistent-store comparison is still outstanding. Treat
  the limits as safety ceilings, not statistically calibrated defaults; never auto-raise.
  - The first merged `live-lightweight` attempt (Actions run `30228015245`) qualified all
    four manufactured controls, then safely stopped with 18 deferred findings before
    normalize/scoring. It is safety evidence only: no accuracy score was produced and the
    failure artifact omitted partial usage totals.
  - [x] Persist usage totals, queue state, batch identity, and failure detail in paid-run
    artifacts on both success and failure.
  - [x] Drive live evaluation through the production run/resume continuation path (or one
    shared orchestration primitive), preserving linked batches and never repeating completed
    map/detect/triage work.
  - [x] Require a zero deferred backlog before normalize/scoring, aggregate linked-batch
    usage in the terminal artifact, and cover failure plus multi-batch success offline.
  - [x] Rerun `live-lightweight` under the unchanged ceilings and inspect its completed
    artifact before authorizing the protected pre/post pair.
- [x] Add a budget-scoped deferred-queue continuation that reuses the immutable ingested
  snapshot and completed map/detect/triage evidence without paying to repeat those stages.
  Continuation batches have fresh ceilings, durable parent links, and aggregate into one
  logical scan for calibration.
- [x] Put every standalone model-backed CLI path inside a durable usage scope: direct
  map/detect/falsify/normalize, doctor model checks, convergence evaluation, and
  manufactured-sentinel qualification now share the same ceilings as run/resume/demo.

## P1 — controlled real-world evidence

- [ ] Complete triage roadmap Phase 3: at least 40 usable human labels, both classes
  represented, across at least eight genuinely distinct engagements. Prefer 100–200 labels.
- [ ] Review high-ranked, reserved novel, and sampled low-ranked findings. Preserve
  `insufficient_evidence` as abstention and record evidence-based rationales.
- [~] Freeze a protected baseline. The serialize-javascript pre/post bounded run completed
  in Actions run `30230644266`. Corrected target-CVE scoring shows that the pre-fix target
  was detected but unresolved (confirmed recovery failed), while the post-fix target was
  absent (negative control passed). One unrelated post-fix confirmation remains
  unadjudicated because the fixture is not exhaustive; no project-wide precision is
  claimed. Keep fixtures/benchmarks separate from independent evidence and protected
  holdouts out of training.

## P2 — validation maturity

- [x] Ship descriptive threshold tradeoff tables that activate at 40 real labels. The
  mechanism is tested; publishing operational evidence still awaits the data gate.
- [x] Add the second adjudication reporting view promised by the taxonomy: operational
  actionability and technical validity must be reported separately. The latter treats
  `confirmed_actionable` and `valid_not_actionable` as technically positive while preserving
  abstentions and duplicate exclusions.
- [x] Ship repository-grouped validation that activates at 40 labels across eight
  engagements, with an explicit row-random fallback below the gate. Real held-out evidence
  still awaits the data gate; metric uncertainty remains open below.
- [ ] Keep vulnerability families, clones, and pre/post-fix pairs in one evaluation
  partition. Once the held-out repository count supports it, add repository-aware bootstrap
  ranges rather than presenting bare point metrics.
- [ ] Add temporal validation only after adequate chronological depth exists.
- [x] Add an adjudication audit for reassessment, independent-review coverage, and
  cross-analyst disagreement while retaining append-only evidence. Materiality is not
  inferred because it is not currently persisted; an enforced material-case second-review
  workflow remains a possible later schema change.
- [ ] Break evaluation out by language, mechanism, detector, and detailed disposition only
  when each cohort has enough observations; otherwise label it insufficient.
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
  hierarchical priors. Preserve effective dates and explicitly separate aleatory variability
  from epistemic uncertainty. Never fabricate subgroup scaling.

## P5 — gated later capabilities

- [ ] Add dollar-cost reporting only with a dated, versioned provider/model price source;
  keep authoritative token observations separate from calculated cost.
- [ ] Keep agentic falsification opt-in and deferred until every escalation gate is met:
  protected evaluation, baseline comparison, recall safety, cohort breakdowns, read-only
  tools, and independent deterministic certificate verification.
- [x] Retire the unused placeholder `report/templates/memo_v1.md`; memo generation remains
  on its single programmatic, benchmarked path.

## Execution order

Paid model calls and provider-backed tuning are intentionally deferred until the offline
backlog below is complete. Existing limits remain unchanged during that pause.

1. Retire the unused memo-template placeholder.
2. Add the actionability/technical-validity views and offline adjudication QA.
3. Collect controlled human adjudications and freeze the protected baseline.
4. Keep related-family evaluation partitions and cohort sufficiency gates ready to activate
   when collection volume supports them.
5. Audit quantitative input applicability and double-counting offline.
6. Resume paid work with the formal persistent-store usage comparison; do not raise limits
   automatically.
7. Then characterize repeatability and improve model-backed slicing/checkable claims.
8. Add live EPSS/KEV enrichment only after its offline cache/staleness contract is fixed.
9. Revisit hierarchical priors, cost calculation, and agentic escalation last.

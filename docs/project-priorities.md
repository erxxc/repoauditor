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
  now run, but their Actions artifacts used separate temporary stores; the formal
  same-persistent-store comparison is still outstanding. Do not merge those databases or
  match overlapping run ids. Treat the limits as safety ceilings, not statistically
  calibrated defaults; never auto-raise.
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
- [x] Freeze a protected baseline. The serialize-javascript pre/post bounded run completed
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
- [x] Ship evaluation-family-grouped validation that activates at 40 labels across eight
  families, with an explicit row-random fallback below the gate. Real held-out evidence
  still awaits the separate human-label/source-repository data gate; metric uncertainty
  remains open below.
- [x] Keep vulnerability families, clones, and pre/post-fix pairs in one evaluation
  partition through explicit `[triage.evaluation_family_overrides]`; the default remains
  the stable engagement id and the mapping affects validation grouping only.
- [ ] Once the held-out evaluation-family count supports it, add family-aware bootstrap
  ranges rather than presenting bare point metrics.
- [ ] Add temporal validation only after adequate chronological depth exists.
- [x] Add an adjudication audit for reassessment, independent-review coverage, and
  cross-analyst disagreement while retaining append-only evidence. Analyst-declared
  materiality is persisted and a matching disposition from a second distinct analyst is
  required before classifier training; materiality is never inferred.
- [x] Gate cohort views on adequate decided observations and both classes. Analyst-declared
  mechanism dimensions, detailed dispositions, and explicitly persisted SARIF
  language/detector cohorts are reported. Unavailable metadata remains visible and is never
  inferred from rule names or file extensions.
- [ ] Characterize repeatability on identical inputs, separating sampling variance from
  retrieval-resolution sensitivity. Report verdict/citation/confidence/token/latency spread.
- [x] Expand manufactured controls only where positive and negative mechanisms have
  independently checkable ground truth. Eight zero-token certificate controls now cover
  JS/TS SSRF, JS/TS command injection, Java SSRF, and authorization-versus-authentication
  semantics without expanding the paid weekly sentinel cohort.

## P3 — nonstandard-finding optimization

- [~] Improve language-specific slicing and authorization/source-to-sink context before
  changing the classifier. Python and bounded JS/TS SSRF paths now exist; broader mechanism,
  framework, and language coverage remains.
- [~] Expand independently checked `SecurityClaim` certificates. Version 10 now persists and
  checks local HTTP-entry syntax, request-input identity, control-candidate identity, and
  placement on the intraprocedural def-use chain, plus exact direct Python caller syntax
  and same-function authorization-candidate syntax independently reparsed from the snapshot.
  Authentication-only syntax is excluded. Flask blueprint registration calls are also tied
  back to their route subject and reparsed independently. Application startup,
  runtime/interprocedural reachability, deployed attacker control, authorization
  scope/effectiveness, and control effectiveness remain explicitly unverified.
  JavaScript/TypeScript SSRF now has a separate tree-sitter producer/checker for bounded
  local request-input chains into `fetch` or explicit global Axios URL-first methods.
  Command injection now supports exact `child_process.exec/execSync` with one direct local
  request-property input. Aliased/object-form Axios, child-process aliases/composition, and
  other JS/TS mechanisms remain unsupported/incomplete.
  Java SSRF now supports one direct `request.getParameter` to
  `new URL(...).openStream/openConnection` shape. Broader Java clients and mechanisms remain
  unsupported/incomplete.
- [ ] Evaluate in-family/out-of-family novelty as an investigation-depth trigger. Do not
  train a novelty prioritizer until enough manually reviewed LLM findings exist.

## P4 — quantitative enrichment

- [ ] Add dated, cached EPSS and KEV enrichment only for real CVE-backed findings. Define
  stale/offline behavior and retain the labeled industry fallback when no signal exists.
- [~] Audit EPSS, KEV, exposure, control strength, loss scale, and baseline applicability
  for double counting. The read-only `quant-audit` now exposes scope gaps and confirmed that
  the organization-level IRIS frequency baseline is repeated per finding within a scenario.
  The model correction is blocked pending a sourced allocation/decomposition decision.
- [x] Inventory current prior applicability through the read-only `quant-audit`.
- [ ] Continue the prior-scope roadmap: capture cohort metadata/effective dates, establish
  data coverage, run prior-predictive/held-out checks, then consider versioned hierarchical
  priors. Explicitly separate aleatory variability from epistemic uncertainty. Never
  fabricate subgroup scaling.

## P5 — gated later capabilities

- [ ] Add dollar-cost reporting only with a dated, versioned provider/model price source;
  keep authoritative token observations separate from calculated cost.
- [ ] Keep agentic falsification opt-in and deferred until every escalation gate is met:
  protected evaluation, baseline comparison, recall safety, cohort breakdowns, read-only
  tools, and independent deterministic certificate verification.
- [x] Retire the unused placeholder `report/templates/memo_v1.md`; memo generation remains
  on its single programmatic, benchmarked path.

## Consolidated remaining agenda

Paid model calls and provider-backed tuning are intentionally deferred until the offline
backlog below is exhausted. Existing limits remain unchanged during that pause.

### A — offline engineering available now

1. [x] Persist trustworthy language and detector cohort metadata with triage
   labels/features. SARIF detector identity and explicit artifact `sourceLanguage` now
   travel with the triaged feature/label join, and `triage-collection` reports their
   sufficiency. Missing metadata remains `unknown`; rule names and file extensions are
   never used as substitutes.
2. [x] Complete the bounded deterministic certificate expansion phase beyond the Python
   intraprocedural MVP. Direct Python callers, authorization candidates, and Flask blueprint
   registration are independently checked without being promoted to runtime facts. Bounded
   JS/TS SSRF and command-injection paths plus one Java SSRF shape prove the multi-language
   checker contract. Authorization effectiveness, non-Flask registration, further
   client/mechanism enumeration, cross-file data flow, and Ruby support are deferred until
   corpus results justify them; explicit unsupported/incomplete outcomes remain the default.
3. [x] Expand manufactured positive/negative controls only for mechanisms with independently
   checkable ground truth. Eight fast-lane, zero-token controls cover the bounded
   multi-language certificates and authorization/authentication distinction; live provider
   qualification remains separate and deferred.
4. [x] Persist prior target-population and temporal-scope fields without changing
   distributions. Aleatory representations and unquantified epistemic limitations are
   separate. Exact effective date/data vintage remain null—and visibly warned by
   `quant-audit`—because the configured citation does not establish them.
5. [x] Persist analyst-declared materiality and enforce a matching review by a second,
   distinct analyst before a material disposition enters classifier training. Materiality
   is never inferred; pending and disputed reviews remain visible in `triage-collection`.

### B — evidence/data gated

1. Collect at least 40 usable human labels, both classes, across eight genuine source
   repositories; prefer 100–200. Review high-ranked, reserved-novel, and sampled-low-ranked
   findings while retaining abstentions.
2. After adequate held-out family breadth exists, add family-aware bootstrap intervals.
3. Add temporal validation only after sufficient chronological depth exists.
4. Evaluate novelty as an investigation-depth trigger only after enough manually reviewed
   LLM findings exist; do not train a novelty prioritizer earlier.
5. Run prior-predictive and held-out loss checks only after applicable organization/incident
   data exists; hierarchical priors remain behind that gate.

### C — methodology blocked

1. Resolve the confirmed organization-frequency error before changing quantitative output:
   the IRIS organization-level annual rate is currently repeated per finding. Choose no
   allocation/decomposition until a defensible source or explicit model specification exists.

### D — paid/network deferred

1. Produce the formal three-run usage comparison in one persistent store; do not merge
   temporary databases or raise limits automatically.
2. Characterize repeatability on identical inputs, separating sampling variance from
   retrieval-resolution sensitivity.
3. Add dated/cached EPSS and KEV enrichment only with fixed stale/offline behavior and
   real-CVE-only matching.
4. Add provider dollar cost only from a dated, versioned provider/model price source.
5. Consider agentic falsification only after every gate in
   [agentic-escalation-gate.md](agentic-escalation-gate.md) is satisfied.

## Pre-tuning checkpoint

The current evidence-backed decision is recorded in
[pre-tuning-readiness.md](pre-tuning-readiness.md). Tuning is on hold: the local persistent
store has no usable human-label cohort or completed same-store three-run calibration,
repeatability is uncharacterized, and the organization-frequency defect remains
methodology-blocking. This hold is the priority-10 decision, not an incomplete tuning run.

## Large-repository detection safety

- [x] Project unbounded all-files × lens calls before paid map/detect work and fail when
  the configured bounded minimum cannot fit the pipeline call ceiling.
- [x] Cap live regions through explicit configuration, prioritize only scanner/map evidence,
  and reserve a stable ground-truth-blind coverage sample. Persist selected/omitted coverage.
- [x] Checkpoint every file+lens unit so a fresh standalone detect budget reuses completed
  units rather than repeating provider calls.
- [ ] Validate the bounded planner on independent projects without tuning its selection
  against advisory target locations. Treat missed omitted-region targets as coverage
  evidence, not false-negative model judgments.
- [x] Allow auditable human assessment of every canonical detector finding while explicitly
  withholding non-SARIF assessment-only evidence from the SAST classifier label/training
  gate. Never synthesize missing feature vectors to inflate the usable-label count.

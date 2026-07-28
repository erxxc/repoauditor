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

- [x] Complete the minimum triage roadmap Phase 3 activation floor: on 2026-07-27 the
  training-acquisition cohort reached 40 usable manual labels (11 positive, 29 negative)
  across eight genuinely distinct engagements, plus two explicit abstentions. The preferred
  100–200-label maturity target remains open.
- [~] Review high-ranked, reserved novel, and sampled low-ranked findings. The first
  ground-truth-blind tranche covered all eight engagements and retained
  `insufficient_evidence` as abstention. Coverage is not yet mature: nine of eleven positives
  are CI mutable-action findings, and no usable language cohort is available because the
  source SARIF did not persist explicit `sourceLanguage`.
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

1. [~] The minimum collection gate is met: 40 usable human labels, both classes, across
   eight genuine source repositories. Continue toward 100–200 with mechanism and positive
   diversity; review reserved-novel and sampled-low-ranked findings while retaining
   abstentions.
   - [x] Freeze a ground-truth-blind acquisition cohort before scanning: two independently
     authored projects each in Python, JavaScript, Java, and Ruby, pinned at exact commits
     with verified permissive licenses. It is explicitly excluded from evaluation and has
     no scanner-derived answer keys. Semgrep Community registry access was verified
     separately against an empty target (1,074 rules with Semgrep 1.170.0 on 2026-07-27).
   - [~] The cohort was materialized and scanned with Semgrep 1.170.0 Community
     `--config auto` on 2026-07-27. All eight scans completed and 127 SARIF candidates were
     imported through the normal triage/store path: Flask 16, Starlette 3, Express 45,
     Koa 7, Spark 7, Javalin 22, Sinatra 15, and Hanami 12. No human labels were created
     automatically; the initial human tranche is recorded below. Scanner yield must not
     retroactively change cohort membership.
   - [x] The first adjudication tranche produced 40 usable manual labels and two abstentions.
     The untouched retrospective threshold view shows no useful discrimination from the
     pre-label synthetic model: thresholds 0.0–0.6 select all 40 (precision 0.275,
     recall 1.0), while 0.7 selects 12 (precision 0.167, recall 0.182). This is baseline
     evidence, not a threshold recommendation. Do not overwrite it with an in-sample
     retrain; establish a new held-out scoring cohort before evaluating the real-label fit.
   - [x] Freeze that next prospective cohort before retraining. The mechanically selected
     19-candidate manifest is `docs/triage-prospective-holdout.json`: up to three lowest
     stable fingerprint hashes per engagement among unassessed classifier-eligible
     findings. It does not use existing score, rule outcome, or code verdict. Starlette had
     no remaining unassessed candidate and is disclosed rather than replaced selectively.
   - [x] Score the prospective cohort before adjudication. A first sequential pass exposed
     order-dependent feature refresh; after every engagement's feature rows were refreshed,
     runs 16–22 converged to identical fits and predictions. The converged grouped result
     (AP 1.0, Brier 0.054311 on 11 rows) is explicitly not accepted as broad generalization
     evidence because nine of eleven training positives share one mutable-action CI family.
     Predictions are frozen in `docs/triage-prospective-holdout.json` before review.
   - [x] Adjudicate the frozen predictions after scoring. At threshold 0.5 the 18 usable
     cases produced 7 TP, 0 FP, 11 TN, and 0 FN, with one abstention. All seven positives
     are the same mutable GitHub Actions family and every non-CI mechanism is negative.
     Treat this as narrow rule-family discrimination—not cross-mechanism generalization or
     permission to tune the operational threshold. The store now contains 58 usable manual
     labels (18 positive, 40 negative) plus three abstentions across eight engagements.
2. After adequate held-out family breadth exists, add family-aware bootstrap intervals.
3. Add temporal validation only after sufficient chronological depth exists.
4. Evaluate novelty as an investigation-depth trigger only after enough manually reviewed
   LLM findings exist; do not train a novelty prioritizer earlier.
5. Run prior-predictive and held-out loss checks only after applicable organization/incident
   data exists; hierarchical priors remain behind that gate.

### Current offline detector iteration

- [x] Run the first zero-token Juice Shop/lightweight detector round without importing new
  classifier labels. Semgrep 1.170.0 recovered the pinned Juice Shop login SQL injection
  (1/1 reviewed target; 50 other raw candidates remain unadjudicated). On the lightweight
  fixture it recovered SQL injection and SSRF, missed the planted IDOR, and raised both
  reviewed kill controls (fake secret and unreachable command injection). The SCA-only
  dependency case is excluded from the Semgrep denominator.
- [x] Run the separate secrets and SCA detector checks for their owned lightweight cases.
  Gitleaks raised exactly the planted Stripe-shaped placeholder, which remains an expected
  falsification kill rather than a confirmed secret. pip-audit and OSV-Scanner both
  recovered the designated requests 2.19.1 advisory through CVE-2018-18074's
  PYSEC/GHSA aliases. Their denominators remain separate from Semgrep.
- [x] Freeze a CVE-backed positive acquisition set before scanning. The four exact
  pre-fix/post-fix pairs cover PyJWT key confusion, simple-git command-execution/control
  bypass, Reposilite archive traversal, and ruby-saml signature wrapping across
  Python/TypeScript/Kotlin/Ruby. All have reviewed advisories and verified permissive
  licenses and are `evaluation_eligible=false`; existing evaluation pairs and the protected
  serialize-javascript holdout remain unavailable for training.
- [x] Materialize and scan the four frozen CVE-positive pairs with Semgrep Community
  1.170.0. It recovered 0/4 narrowly defined advisory targets; pre- and post-fix variants
  each produced 77 unrelated raw candidates in aggregate. This establishes a deterministic
  coverage gap for the nonstandard mechanisms, not finding invalidity or model performance.
  No scanner output was imported as a label.
- [~] Initialize bounded, human-reviewed LLM/falsification evaluation without tuning.
  The manual-only first pilot is PyJWT because it is the smallest pair and exercises
  semantic key confusion. It requires the exact `public-corpus-v2` cache, runs pre-fix
  before post-fix and has a 20-minute outer timeout. The first one-batch run
  (`30320579789`) used 33 calls and 156,800 known input/output tokens on pre-fix, then
  stopped with five deferred findings; post-fix did not start. The two-batch follow-up
  (`30322316600`) used 82 calls and 419,676 known input/output tokens, missed the pre-fix
  target because its file was not selected, and stopped post-fix with two deferred
  non-target findings. The next run is therefore evaluation-only and target-conditioned:
  it scans the frozen advisory file while separately recording whether the unchanged
  production planner selected it. Forced inclusion receives no production-coverage credit.
  Review that cheaper target-scoped artifact before enabling ruby-saml, simple-git, or
  Reposilite.
- [x] Record the PyJWT target-conditioned pre-tuning baseline. Run `30323666007`
  qualified 4/4 manufactured controls and completed both snapshots with 17 calls and
  164,537 known tokens. The pre-fix target was not raised even when its file was supplied;
  post-fix had no target signal. Context reconstruction showed that whole-file similarity
  added three same-file helper blocks while omitting the indexed `encode` and
  `_verify_signature` callers of `prepare_key`. PyJWT is development evidence after this
  diagnosis, not an untouched validation target for the resulting context change.
- [x] Implement the answer-key-independent context correction as
  `detection_context_v2`. Detection now ranks bounded external syntactic call-name matches
  ahead of whole-file similarity, excludes redundant same-file blocks, prefers production
  paths over tests, and gathers matches in one index pass. The version participates in
  detection checkpoint and evaluation provenance. Validate on a different frozen,
  untouched CVE pair; a PyJWT rerun may be used only as development confirmation.
- [x] Run and adjudicate the first untouched `detection_context_v2` validation on the frozen simple-git
  CVE-2026-28292 pair. The manual `cve-positive-simple-git` scope reuses the exact
  target-conditioned/production-selection split, two-batch ceiling, manufactured controls,
  and 20-minute timeout. Actions run `30325190074` passed 4/4 sentinels and completed both
  snapshots, but failed semantic validation: the production planner omitted the advisory
  file in both snapshots and the same-line candidates alleged a wildcard-dot mechanism,
  not the CVE's missing case-insensitive flag. The pre-fix target was therefore missed.
  The scorer now separates location evidence from human-adjudicated mechanism matches, and
  simple-git is development evidence rather than an untouched holdout.
- Evidence receipt: `docs/offline-detector-round-2026-07-27.json`. It reports target
  recovery and unmatched candidates, never project-wide precision from a partial answer key.
- CVE-positive acquisition receipt:
  `docs/cve-positive-acquisition-round-2026-07-27.json`. It preserves exact commits,
  target-scoped recovery, scanner bounds, and the Reposilite wrapper parse warning.
- Target-conditioned PyJWT receipt:
  `docs/pyjwt-target-conditioned-baseline-2026-07-28.json`.
- Target-conditioned simple-git receipt:
  `docs/simple-git-target-conditioned-baseline-2026-07-28.json`.

### Current falsification tuning

- [x] Require semantic human adjudication before a same-location candidate counts as a
  CVE target match. Location overlap remains visible but cannot silently stand in for
  mechanism agreement.
- [x] Add a zero-token manufactured case-sensitivity control and a small deterministic
  JavaScript regex-witness checker.
- [x] Gate confirmation of the supported regex-control bypass family on a concrete input,
  an exact control expression present in evidence, and a verified guard miss. Persist both
  the witness and checker result. This proves only the regex miss; application acceptance,
  path feasibility, and security effect remain separate evidence obligations.
- [ ] Measure production region selection independently on the next untouched project.
  Target-conditioned inclusion receives no production-coverage credit, and omitted target
  regions remain planner coverage evidence rather than semantic model false negatives.
- [x] Freeze Reposilite CVE-2024-36116 as that next untouched project. It has one localized
  Kotlin archive-traversal target and is lower-complexity than the remaining two-CVE
  ruby-saml pair. The manual `cve-positive-reposilite` workflow scope retains the exact
  corpus cache, sentinel gate, two-batch ceiling, and 20-minute timeout. Acceptance and
  prohibited post-result changes are frozen in
  `docs/reposilite-validation-plan-2026-07-28.json`.
- [x] Run `cve-positive-reposilite` once and retain the artifact/database. Actions run
  `30327552345` passed 4/4 manufactured falsification controls and completed both snapshots
  in one batch each, but failed validation: no pre-fix candidate was raised even with the
  complete target file forced into detection. Production selection also omitted the target
  because `.kt`/`.kts` were absent from the shared source inventory. There were no
  candidates to adjudicate. Reposilite is now development evidence; exact results are in
  `docs/reposilite-target-conditioned-baseline-2026-07-28.json`.
- [x] Add bounded Kotlin visibility to the shared source inventory. Map context remains
  capped at 40 files/its existing character budget, and detection remains capped by
  `[detect].max_llm_regions_per_run`; the work projection now reports Kotlin in the
  unbounded/omitted counts instead of silently excluding it. Retrieval uses its explicit
  logged lexical fallback until a Kotlin AST contract is independently tested.
- [x] Version the OWASP lens to `owasp_v2` with explicit path-traversal and unsafe
  archive-extraction obligations. Add external-answer-key, zero-token archive-containment
  controls that distinguish an accepted `../../` escape from normalized containment
  rejection without claiming attacker control or runtime sink execution.
- [x] Build a separate, budgeted `qualify-detection` command and manual
  `detection-sentinels` Actions scope. It calls only the OWASP lens once per manufactured
  archive case, requires semantic/location agreement for the vulnerable case, fails on any
  patched-control candidate, and retains authoritative usage in its JSON.
- [ ] Run that manufactured archive-detection qualification before spending on another
  independent project. Keep ruby-saml untouched until the instrument check passes.

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

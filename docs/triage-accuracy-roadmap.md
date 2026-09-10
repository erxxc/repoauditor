# Triage accuracy and nonstandard-finding roadmap

The persisted ground-truth meanings and evaluation-denominator rules are defined in
[adjudication-taxonomy.md](adjudication-taxonomy.md).
The separate [agentic escalation gate](agentic-escalation-gate.md) records why autonomous
tool-use remains deferred until usage accounting and recall-safe evaluation exist.
The [prior-scope roadmap](prior-scope-roadmap.md) separately records future quantitative
prior expansion; it does not change the current risk model.

There are no open lifecycle items. OPT-037 closed after Tier 0 exact-oracle coverage and a
Tier 1 descriptive reliability table over 104 temporally valid, model-compatible outcomes
across 15 evaluation families. Neither tier selected a threshold. Tier 2 remains
unavailable because predictive loss quantiles and estimator-confidence intervals answer
different questions and no independent-reference design was qualified.

Status: **post-MVP optimization roadmap**. The implemented safeguards remain authoritative,
but remaining maturity ideas are non-lifecycle future work described in
[`optimizations/optimization-register.md`](optimizations/optimization-register.md). Current
MVP execution is tracked only in [`poc-recovery-plan.md`](poc-recovery-plan.md).

Progress:

- [x] Phase 1.1 — bounded falsification queue fairness
- [x] Phase 1.2 — low-ranked review sampling
- [x] Phase 1.3 — provisional-model disclosure audit
- [x] Phase 1.4 — stable engagement identity audit
- [x] Phase 2 — score and label provenance
- [~] Phase 3 — collection infrastructure and the 40-label/eight-engagement activation
  floor are met; the preferred 100–200-label, broader-positive-family maturity target
  remains open
- [~] Phase 4 — threshold/grouped mechanisms, dual adjudication reporting, family-block
  uncertainty, and bounded train-before/evaluate-after temporal validation shipped;
  broader positive-family maturity and any production-threshold decision remain open
- [ ] Phase 5 — deferred optimization; see gates below

## Current baseline

- As of 2026-08-07, the store contains 104 usable human labels (37 positive, 67
  negative) across 15 source engagements and 404 unlabeled triaged findings. Only 36 labels
  have compatible stored triage scores (19 positive, 17 negative) across 7 engagements;
OPT-002 therefore remains below its 40-label/8-family activation gate. Language metadata
is unavailable for the existing human cohort; the Semgrep detector cohort has both classes.
The next evidence acquisition is frozen before source materialization in
[`optimizations/opt-002-independent-acquisition-protocol-2026-08-07.json`](optimizations/opt-002-independent-acquisition-protocol-2026-08-07.json).
It selects two independent deployable products plus one conditional reserve using public
product/repository metadata only, fixes exact commits and the compatible 3.3.0 scoring
identity, and requires scoring before an 8–12-entry blinded review packet is rendered. It
does not authorize scanning, provider calls, review outcomes, tuning, or store mutation.
- At the Phase 0 diagnostic that created this roadmap, real `TriageLabel` volume was
  0 true positives, 0 false positives, and 0 engagements. That is historical context, not a
  live counter; use `repoauditor triage-collection` for the current evidence volume.
- `suppressed` is a persisted annotation only. Falsify does not exclude suppressed findings;
  it orders triaged findings by P(actionable), applies its run budget, and resumes deferred
  findings later.
- `triage-stats` withholds threshold curves until 40 compatible real scored labels exist.
- Evaluation-family-grouped validation activates at 40 usable labels and 8 families. The
  separate collection gate still requires labels from 8 genuine source repositories.
  Before activation, evaluation explicitly reports its row-random or synthetic fallback.

## Phase 1 — Pre-UAT accuracy safeguards

Order and exit criteria:

1. **Falsification queue fairness** — reserve configurable bounded-run capacity for
   untriaged/novel findings while retaining highest-P(actionable) deterministic priority.
   Suppression remains soft. Tests must show both streams receive service and deferred work
   remains resumable.
2. **Low-ranked review sampling** — sample a small, auditable portion of low-ranked or
   suppressed findings for analyst review. The sample must be deterministic from a recorded
   seed/run identity and must never delete or silently promote a finding.
3. **Provisional-model disclosure** — CLI/UAT output must distinguish synthetic-basis,
   row-random-real, and engagement-grouped metrics.
4. **Stable engagement identity audit** — prove repeated snapshots of one source repository
   cannot cross grouped train/evaluation partitions under different IDs.

Exit: UAT cannot starve novel findings under a normal multi-finding budget, and collected
labels include an auditable low-ranked sample rather than only model-preferred examples.

## Phase 2 — Score and label provenance

Persist a triage/model run identifier, model and feature-schema versions, training-label
count, synthetic share, calibration/split strategy, scanner/rule version, and score time.
Keep manual, human-review, and falsification-derived labels separate. Evaluation defaults
to manual/review labels; derived labels may supplement training but are reported separately.
Expose label observation/correction times and provide cohort-aware `triage-stats` views.

Exit: every score can be compared only with compatible score cohorts, and evaluation label
origin is visible.

## Phase 3 — Controlled data collection

Activation floor: 40 usable manual/human-review labels across at least 8 genuinely distinct
source repositories. Falsification-derived labels may supplement training but do not advance
this human-evidence gate.
Preferred maturity target: 100–200 labels with both classes represented across multiple
repositories. Collect multiple languages/frameworks, business-logic and authorization
failures, tenant isolation, multi-service flows, CI/IaC, agent/tool boundaries, dependencies,
secrets, dead code, safe controls, and near-miss negatives. Review high-ranked findings,
reserved novel findings, and the low-ranked sample. Record rationale; never force genuinely
uncertain cases into binary labels.

Collection mechanism now available:

- `triage-label` requires a rationale and records an append-only analyst assessment.
- `--disposition uncertain` is an explicit abstention retained for audit but excluded from
  classifier training and activation counts.
- Repeatable `--dimension` values record analyst-verified coverage without inferring a
  vulnerability taxonomy from noisy rule names.
- `triage-collection [repo-id]` reports effective class/source counts, latest abstentions,
  unlabelled triaged findings, declared dimensions, explicit SARIF language/detector
  cohorts, and progress against both activation gates. Language is accepted only from
  artifact `sourceLanguage`; missing metadata remains visibly unavailable rather than being
  inferred from rule names or file extensions.

The activation floor was later met through 58 usable manual labels across eight genuine
engagements. Positive breadth remains narrow and does not establish broad classifier
generalization. The preferred 100–200-label maturity target is OPT-001, not a POC blocker.
The next training-acquisition tranche is frozen in
[`triage-review-acquisition-2026-07-29.json`](triage-review-acquisition-2026-07-29.json).
It selects least-reviewed rule families across engagements with stable hashes, excludes
families above the disclosed prior-label cap, and never uses candidate scores, predicted
classes, severity, verdicts, or code outcomes. It is not evaluation-eligible. Analysts must
review the cited code, retain abstentions, and declare coverage dimensions themselves.
`triage-review-packet` fails closed unless each frozen entry still matches its stored
finding/feature identity and resolves to exactly one immutable snapshot, then renders
bounded source context and a disposition-neutral command template.

The verified-scanner OPT-001 continuation is frozen separately in
[`triage-review-acquisition-2026-07-29-v2.json`](triage-review-acquisition-2026-07-29-v2.json).
It expands the unassessed pool with five previously selected CVE-positive vulnerable
snapshots, then prioritizes production source ahead of deployment/configuration and
supporting surfaces. The selected 11-entry tranche contains eight production and three
deployment candidates. Path class controls review order only; it is not a validity feature,
and scanner/advisory evidence still never becomes an automatic label. The corresponding
scanner receipt is
[`cve-positive-semgrep-acquisition-2026-07-29-v2.json`](cve-positive-semgrep-acquisition-2026-07-29-v2.json).

Human review of that tranche produced eleven additional negatives, bringing the usable
cohort to 80 labels (18 positive and 62 negative) across 12 engagements. The residual pool
was dominated by repeated controls and supporting surfaces, so the next OPT-001 expansion
was frozen before scanning in
[`opt-001-positive-mechanism-expansion-protocol-2026-07-29.json`](opt-001-positive-mechanism-expansion-protocol-2026-07-29.json).
Its acquisition-only OWASP anchors do not enter evaluation. The verified scan recovered all
three predeclared targets across JavaScript, Java, and Ruby; exact execution evidence is in
[`positive-mechanism-expansion-scan-2026-07-29.json`](positive-mechanism-expansion-scan-2026-07-29.json).
The resulting
[`12-entry review tranche`](triage-review-acquisition-2026-07-29-v3.json) starts with those
three declared production targets, then adds nine outcome-blind production candidates.
Benchmark metadata remains context rather than a label, and abstention remains available.

The v3 review added nine actionable positives and three negatives, producing 92 usable
labels (27 positive and 65 negative) across 15 engagements. A final production-only tranche
is frozen in
[`triage-review-acquisition-2026-07-29-v4.json`](triage-review-acquisition-2026-07-29-v4.json).
It selects 12 unsaturated anchor candidates across authorization, path/file handling,
redirects, token secrets, and template output, while explicitly excluding documentation,
bundled vendor code, CI, and package hygiene. Completing this tranche should cross OPT-001's
100-label maturity floor; it does not itself satisfy OPT-002's held-out family requirements.

The final tranche added ten actionable positives and two negatives. OPT-001 therefore
reached its lower maturity bound with 104 usable manual labels (37 positive and 67 negative)
across 15 engagements; three explicit abstentions remain excluded from training. This closes
the reviewed-label growth optimization without claiming held-out generalization. Only 36
real labels currently have compatible stored triage scores, below the existing 40-label
threshold-curve gate, and the benchmark acquisitions are not evaluation families. OPT-002
remains deferred pending additional evaluation-compatible scored evidence and adequate
held-out family breadth.

## Phase 4 — Validation maturity

The bounded OPT-003 temporal evaluation completed on 2026-08-12 with 40 prospective
decided outcomes across eight evaluation families and three prediction waves. All frozen
predictions preceded their first assessments. The aggregate Brier score was 0.1447 with a
broad 95% evaluation-family-block percentile range of 0.0452–0.2530. Fixed-threshold
precision and recall remain descriptive; no threshold was selected or recommended, and
wave two contained no positive outcomes. This closes temporal validation at its bounded
scope without authorizing tuning, recalibration, or production-policy changes.

At 40 labels, enable descriptive threshold tables. At 40 labels and 8 evaluation families,
activate grouped validation and report held-out repositories, class counts, sample size, and
metric uncertainty. Add train-before/evaluate-after validation only after chronological
depth exists.
Use repository-aware bootstrap ranges once the held-out repository count supports them.
Keep related vulnerability families, clones, and pre/post-fix pairs in one partition via
explicit `[triage.evaluation_family_overrides]`; this grouping is evaluation-only and never
becomes a classifier feature.
`triage-collection` reports both operational-actionability and technical-validity views,
excluding duplicates and abstentions from their decided denominators, plus observable
reassessment, independent-review, and cross-analyst-disagreement counts. It also withholds
analyst-declared dimension cohorts below 40 decided observations or without both classes.
Language and detector cohorts use the persisted triage-feature/label join and apply the same
40-decided-label/both-class descriptive sufficiency rule. Labels lacking explicit metadata
are reported as unavailable and never assigned by rule-name or file-extension inference.

## Phase 5 — Nonstandard-finding optimization

Expand unscripted live benchmarks by vulnerability family, language, trust boundary, and
single-file versus cross-service reasoning. Improve detection/retrieval and authorization
context before applying the SARIF-oriented classifier to LLM findings. Version-10 structural
certificates add independently reparsed direct Python caller and narrow same-function
authorization-candidate syntax, explicitly without claiming runtime/interprocedural
reachability or authorization effectiveness. Authentication-only syntax is excluded.
Flask blueprint registration syntax is now independently tied to its route subject without
claiming application startup or external reachability. Authorization scope/effectiveness,
non-Flask registration, cross-file data flow, and broader trusted non-Python coverage remain
open.
JavaScript/TypeScript now has separately parsed local SSRF certificates for `fetch` and
explicit global Axios URL-first methods. Aliased/object-form Axios remains incomplete;
exact `child_process.exec/execSync` command-injection chains are also supported for one
direct request property. Aliases, composition, other mechanisms/clients, and Java/Ruby
remain explicitly unsupported/incomplete. Java adds one separately parsed local
`request.getParameter` to `new URL(...).openStream/openConnection` SSRF shape.

This is the current deterministic-certificate phase boundary. Additional client/framework
enumeration and cross-file flow should resume only when corpus misses demonstrate a specific
coverage need; the active offline priority returns to manufactured controls.
The bounded OPT-009 semantic-novelty feasibility study is closed with a negative result:
neither the existing cohort nor two frozen prospective families supplied the predeclared
evaluation capacity, and the isolated instrument did not qualify. This establishes only
that OPT-009 was not justified or feasible at its evaluated scope, not that novelty
prioritization is universally impossible. Any future attempt is newly scoped work with a
new lifecycle identity and untouched evidence.

OPT-014 is likewise closed at a bounded evidence scope rather than held open indefinitely
behind unavailable data. Its deterministic prior-predictive report establishes internal
coherence of the configured anonymous neutral organization-year baseline, not predictive
validation, calibration, representativeness, or portfolio readiness. The bounded public and
controlled-access screens found no source meeting the frozen commercial-rights and full
organization-period contract; that result is not a universal data-impossibility claim.
SEC/EDGAR remains an inactive material-disclosure-context reserve, and non-filing periods
are not zero-incident observations. Any future observed-outcome or portfolio study is new
work with a separately frozen lifecycle, estimand, rights, data, and evaluation contract.

OPT-010 is closed at a bounded negative-feasibility scope. The isolated read-only tool
facade remains qualified, disabled, and disconnected, while the frozen prospective path
failed to assemble its exact 40-identity packet across four supported families. It therefore
did not proceed to paired G03b comparison, empirical G04 recall evaluation, thresholding, or
production activation. This establishes neither universal impossibility nor production
readiness. Any future agentic evaluation, scanner-policy change, verifier expansion, source
augmentation, packet, paired run, or activation is new work under a separate lifecycle.

OPT-036 is closed at its bounded Java syntactic weak-RNG and scanner-extension scope. The
detector is a first-class deterministic candidate producer behind a fail-closed,
package-local manifest seam. It does not execute or ingest the PRNG lattice lab and does not
establish trust-boundary crossing, state recovery, exploitability, or actionability.

## Explicit non-goals

- No automatic “optimal” P(actionable) threshold.
- No synthetic curve presented as operational evidence.
- No hard deletion or exclusion caused by triage suppression.
- No pooling incompatible model/feature cohorts without disclosure.
- No unified deterministic/LLM classifier without compatible features and real labels.

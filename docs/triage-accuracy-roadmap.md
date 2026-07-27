# Triage accuracy and nonstandard-finding roadmap

The persisted ground-truth meanings and evaluation-denominator rules are defined in
[adjudication-taxonomy.md](adjudication-taxonomy.md).
The separate [agentic escalation gate](agentic-escalation-gate.md) records why autonomous
tool-use remains deferred until usage accounting and recall-safe evaluation exist.
The [prior-scope roadmap](prior-scope-roadmap.md) separately records future quantitative
prior expansion; it does not change the current risk model.

Status: active. This document is the durable execution plan for improving triage accuracy
without presenting synthetic performance as real-world evidence.
The cross-project implementation order is tracked in
[project-priorities.md](project-priorities.md).

Progress:

- [x] Phase 1.1 — bounded falsification queue fairness
- [x] Phase 1.2 — low-ranked review sampling
- [x] Phase 1.3 — provisional-model disclosure audit
- [x] Phase 1.4 — stable engagement identity audit
- [x] Phase 2 — score and label provenance
- [~] Phase 3 — collection infrastructure shipped; real UAT gate not yet met
- [~] Phase 4 — threshold/grouped mechanisms and dual adjudication reporting shipped;
  real-data activation, uncertainty, and temporal depth remain open
- [ ] Phase 5 — see gates below

## Current baseline

- At the Phase 0 diagnostic that created this roadmap, real `TriageLabel` volume was
  0 true positives, 0 false positives, and 0 engagements. That is historical context, not a
  live counter; use `repoauditor triage-collection` for the current evidence volume.
- `suppressed` is a persisted annotation only. Falsify does not exclude suppressed findings;
  it orders triaged findings by P(actionable), applies its run budget, and resumes deferred
  findings later.
- `triage-stats` withholds threshold curves until 40 real scored labels exist.
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

This phase remains open until actual UAT data reaches the activation floor. The lightweight
fixture is one controlled engagement and cannot by itself satisfy repository diversity.

## Phase 4 — Validation maturity

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
context before applying the SARIF-oriented classifier to LLM findings. Version-6 structural
certificates add independently reparsed direct Python caller and narrow same-function
authorization-candidate syntax, explicitly without claiming runtime/interprocedural
reachability or authorization effectiveness. Authentication-only syntax is excluded.
Flask blueprint registration syntax is now independently tied to its route subject without
claiming application startup or external reachability. Authorization scope/effectiveness,
non-Flask registration, cross-file data flow, and trusted non-Python checkers remain open.
Consider a separate novelty prioritizer only after enough manually reviewed LLM findings
exist to show a held-out benefit.

## Explicit non-goals

- No automatic “optimal” P(actionable) threshold.
- No synthetic curve presented as operational evidence.
- No hard deletion or exclusion caused by triage suppression.
- No pooling incompatible model/feature cohorts without disclosure.
- No unified deterministic/LLM classifier without compatible features and real labels.

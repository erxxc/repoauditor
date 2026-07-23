# repoauditor — project scaffold

A personal CLI pipeline that ingests an unfamiliar acquired codebase, builds a
structured architecture/trust-boundary map, runs multi-lens AI-assisted
vulnerability detection with a falsification pass, normalizes deterministic
tool output alongside it, and produces two projections from one findings
store: an engineering remediation backlog and a leadership-facing risk memo.

Same architectural discipline as `semianalyst`: schema-first, thin CLI,
store owns the database, prompts are versioned artifacts, every finding
keeps its citation, severity is never asserted without corroborating
evidence.

---

## Pipeline stages

```
ingest -> map -> detect -> triage -> falsify -> normalize -> review -> analyze -> report
```

1. **ingest** — clone target repo, snapshot dependency manifests, hash-keyed
   idempotent storage (same pattern as semianalyst's `data/raw/`).
2. **map** — architecture recovery pass. Produces a structured domain map
   (entry points, trust boundaries, data stores, external integrations,
   auth boundaries) *before* any vulnerability hunting starts. This is the
   STRIDE-at-scale step — everything downstream is conditioned on it.
3. **detect** — multi-lens ensemble pass (OWASP Top 10 / supply-chain /
   agentic-surface framings) plus deterministic tools (SAST, SCA, secret
   scanners) run in parallel. Retrieval-augmented: candidate findings pull
   in callers/callees and similar patterns repo-wide before scoring.
4. **triage** — calibrated ML classifier (RandomForest/XGBoost, no LLM)
   re-ranks deterministic-tool findings by P(actionable), using code
   context, historical FP rates, and Beta-Binomial per-rule priors for
   cold start. Ranks and may suppress; never deletes. Determines how the
   falsify stage's LLM budget gets allocated.
5. **falsify** — every candidate finding gets a second pass whose only job
   is to try to disprove it (reachability, existing mitigating control,
   attacker-controlled input). Confirmed, killed, deferred, and unresolved
   outcomes remain in the store with explicit iteration evidence — nothing
   silently disappears.
6. **normalize** — LLM adjudicates conflicting severity calls between
   deterministic tools and the ensemble lenses, writes everything into the
   canonical finding schema.
7. **review** — a blocking human checkpoint for unresolved or low-confidence
   findings. Decisions require rationale and corrections append a superseding row;
   analysis cannot proceed while requests remain open.
8. **analyze** — FAIR-style Monte Carlo risk quantification: each scenario
   maps to one or more findings; P(actionable) from triage feeds a Bernoulli
   finding-validity gate, separate from the conditional loss-event frequency
   prior. Map-derived exposure scales threat-event frequency, falsification or
   analyst control strength modulates vulnerability, and engagement loss scale
   adjusts magnitude. Magnitude and conditional-frequency priors come from
   exactly cited industry loss data; revenue-band scaling remains neutral until
   an exact curve is verified.
   Outputs loss-exceedance curves and sensitivity analysis, not a single
   severity-weighted score.
9. **report** — two projections off the same `store/`: `--mode=engineering`
   (ticket backlog) and `--mode=memo` (leadership risk summary, now backed
   by the MC simulation appendix with sourced priors).

---

## Package layout

```
src/repoauditor/
  llm/
    client.py               # shared LLM call wrapper: schema validation, bounded
                              # retry on parse/validation failure, confidence
                              # threshold check, routes low-confidence results to
                              # a re-score-with-broader-context path or `unresolved`
    prompts/
      (no prompts live here — client is prompt-agnostic; each stage owns its
       own prompts/ dir as below)

  ingest/
    repo.py            # git clone/pull, idempotent by commit hash
    manifest.py         # dependency manifest snapshot (lockfiles, SBOM-ish)

  map/
    domain_map.py        # interface stub: raw repo -> structured architecture map
    schema.py             # TrustBoundary, EntryPoint, DataStore, Integration models
    prompts/
      architecture_recovery_v1.md

  detect/
    ensemble.py            # runs multiple framing lenses over a code region
    lenses/
      owasp_v1.md
      supply_chain_v1.md
      agentic_surface_v1.md
    deterministic/
      sast_adapter.py        # wraps external SAST tool output into canonical shape
      sca_adapter.py
      secrets_adapter.py
    retrieval/
      index.py                 # multi-language AST index, callers/callees +
                                 # similar-pattern lookup. Python via stdlib `ast`;
                                 # JS/TS/Java/Ruby via tree-sitter grammars; any other
                                 # language falls back to a logged lexical index (never a
                                 # silent gap). One public interface across all of them.

  triage/
    classifier.py                # RandomForest/XGBoost SAST finding triage,
                                   # tool-agnostic ingestion (SARIF/Semgrep first),
                                   # calibrated P(actionable), rank, SHAP attribution.
                                   # Persists each finding's feature vector so a label
                                   # collected later is rejoinable for real training.
    priors.py                      # Beta-Binomial per-rule cold-start priors +
                                     # Bayesian shrinkage as labels accumulate
    features.py                     # feature extraction: rule/CWE, severity, file
                                      # path, code churn (git history), sink/source
                                      # distance, dependency vs first-party, historical
                                      # FP rate, finding density
    synthetic.py                     # synthetic labeled dataset generator for
                                       # development/testing, clearly marked synthetic
    labels.py                         # ground-truth TriageLabel generation: DERIVED from
                                       # falsify verdicts + review decisions (closed loop,
                                       # review overrides falsify) and MANUAL analyst
                                       # override (triage-label CLI; manual wins over derived)
    training.py                        # assembles the training corpus: synthetic teacher
                                        # blended with real accumulated labels, synthetic's
                                        # share shrinking as real data grows (Beta-Binomial
                                        # shrinkage lifted to the corpus); marks real rows
                                        # for an honest real held-out PR/Brier split

  falsify/
    challenger.py               # interface stub: candidate finding -> confirmed | killed
    prompts/
      falsification_v1.md

  normalize/
    adjudicate.py                 # resolves conflicting severity across sources
    prompts/
      severity_adjudication_v1.md

  store/
    models.py                       # pydantic: Finding, Entity, TrustBoundary, Corroboration
    ddl/                              # numbered SQL migration files
    db.py                              # ONLY module allowed to touch SQLite

  analyze/
    corroboration.py                    # cross-lens/cross-tool agreement scoring
    risk_quant.py                        # FAIR-style Monte Carlo: Bernoulli finding validity
                                           # (P(actionable) unless confirmed), exposure-scaled
                                           # Poisson Threat Event Frequency, control-conditioned
                                           # Vulnerability, then lognormal Loss Magnitude with an
                                           # explicit loss scale; sourced priors; 10k-100k NumPy-
                                           # vectorized trials; loss exceedance curves,
                                           # mean/median/95th pct, tornado sensitivity chart

  eval/
    regression.py                          # tracks precision/recall per prompt
                                             # version over time; flags regressions
                                             # against the prior version before a
                                             # new prompt version is allowed into use

  report/
    engineering.py                        # backlog/ticket projection
    memo.py                                 # leadership risk memo projection —
                                              # composed PROGRAMMATICALLY (see below)
    templates/
      memo_v1.md                             # UNUSED placeholder (versioned artifact).
                                              # The memo's top-risks + embedded FAIR
                                              # appendix are variable-length generated
                                              # blocks a flat template can't hold, so
                                              # memo.py builds the markdown directly
                                              # (mirroring risk_quant._appendix_markdown).
                                              # Kept, not edited in place, per the
                                              # prompt/template-versioning rule; a future
                                              # memo_v2.md could supersede it.

  cli.py                                    # thin Typer app: stage commands plus run/finalize,
                                              # review, repos/runs, doctor, and db init

config.toml                                   # scan targets, model, rate limits, data paths
config.py                                       # single loader
priors.yaml                                       # sourced distribution parameters for
                                                    # risk_quant.py: exact IRIS magnitude and
                                                    # conditional-frequency baselines. Real EPSS/
                                                    # KEV enrichment is reserved for CVE-backed
                                                    # findings and is not fabricated when absent

tests/
  fixtures/
    <repo_id>/
      snapshot/            # known-CVE or intentionally-vulnerable repo snapshot
      expected_findings.json
  test_golden_harness.py     # runs full pipeline, diffs against expected
```

---

## Schema notes (store/models.py)

- **Finding** is the atomic unit (finding replaces semianalyst's *claim*):
  mandatory `file`, `line_range`, `citation_snippet`, `source_lens` or
  `source_tool`, `confidence`, `severity`, `falsification_status`
  (confirmed/killed/unresolved), `corroborated_by` (list of other
  lenses/tools that independently flagged it).
- LLM citations are semantically validated before a Finding is persisted: the
  verbatim snippet must resolve to repository source. A unique location
  canonicalizes an incorrect model-supplied file/range; absent or ambiguous
  snippets are logged as `ValidationFailure` records and rejected.
- Python SQLi/command-injection/SSRF falsification can consume a deterministic,
  intraprocedural def-use evidence slice. Its contract is deliberately non-authoritative:
  reachability, path feasibility, attacker control, and sanitizer effectiveness remain
  unproven; unsupported or dynamic dependencies are explicitly `incomplete`.
- **SecurityClaim / ClaimVerification** — an idempotent, structured audit trail for
  source/sink/path-node/control-candidate facts, pinned snapshot commit, and their
  verifier/version. The independently versioned checker reopens that snapshot rather than
  accepting the slicer's in-memory evidence. `structurally_verified` is narrowly structural
  and never means exploitable; `verification_incomplete` preserves missing or dynamic
  dependencies. These records are attached to unresolved review evidence but do not change
  the falsification verdict.
- **Convergence evaluation** — an opt-in, non-mutating solution-refinement experiment
  reruns a finding with artifact persistence disabled at coarse, standard, and refined
  retrieval/iteration resolution. It reports flips, citation overlap, confidence spread,
  and seed availability;
  non-convergence never becomes an automatic production verdict. See
  `docs/convergence-evaluation.md`.
- **TrustBoundary** / **EntryPoint** / **DataStore** / **Integration** —
  output of the `map/` stage, referenced by findings via foreign key so
  every finding is traceable back to *why it matters architecturally*, not
  just *what pattern matched*.
- Severity is never upgraded without independently produced corroboration or a
  falsification pass confirming reachability. Tool↔lens agreement and distinct
  deterministic-tool agreement qualify; shared-model multi-lens agreement remains visible
  but is correlated and cannot license an upgrade by itself. This is a direct carryover of
  semianalyst's "relative claims never converted to absolutes" rule.
- **ValidationFailure** — logs every exhausted parse/schema retry from
  `llm/client.py` and semantic citation failure from `detect/`: which module
  raised it, which prompt/validator version, the raw
  (truncated) response, and the validation error. This is the structured-
  output reliability trail — nothing gets silently retried into oblivion.
- **EvalRun** — one row per golden-harness execution: prompt versions used
  across all stages, precision/recall against the benchmark corpus, and a
  `regressed_from_prior` flag computed by `eval/regression.py`.
- **StageRun.summary** — descriptive funnel evidence captured at stage boundaries:
  raw/unique candidates and duplicate amplification, triage suppression/evaluation
  context, falsification outcomes, normalization abstentions, and review-request counts.
  It never changes a verdict. Model usage/cost remains explicitly unavailable until a
  backend returns authoritative provider usage rather than an estimate.
- **TriageLabel** — disposition (true/false positive) on a past finding, keyed
  by rule ID and engagement. Accumulates across engagements, not just within one
  — the label store the classifier learns from over time. `source` records
  provenance: `manual` (analyst, via `triage-label`) or `derived_falsify` /
  `derived_review` (harvested from downstream outcomes — the closed loop, review
  overriding falsify). Manual outranks derived. A sibling **triage_features** table
  persists each triaged finding's feature vector (+ column order), the bridge that
  turns an accumulated label into a real cross-engagement training row.
- **RulePrior** — per-rule Beta-Binomial hyperparameters (alpha, beta) for
  cold-start P(actionable); shrinks toward observed `TriageLabel` data as
  labels accumulate. Hyperparameter choices documented, not arbitrary.
- **RiskScenario** — maps one or more `Finding` rows to a FAIR-style risk
  scenario; carries validity, conditional frequency, exposure, control strength,
  and magnitude inputs. Persisted audit scenarios link to the `SimulationRun`
  that produced them; legacy/standalone rows may have no run link.
- **ScenarioInput** — per-scenario exposure, control-strength, and loss-scale
  provenance, explicitly labeled derived, analyst-overridden, or conservatively
  defaulted.
- **PriorSource** — the sourcing record `priors.yaml` maps to in the DB:
  which prior (magnitude/frequency), which document/dataset backs it
  (currently exact IRIS 2022 locations and transformations), so every number
  in the memo appendix is traceable. Future EPSS/KEV sources must be real,
  dated, and CVE-specific rather than severity proxies.
- **SimulationRun** — one row per Monte Carlo run: trial count, mean/
  median/95th percentile loss, and a reference to the tornado sensitivity
  output — the evidence layer behind the exec summary. Audited reruns are
  append-only and own distinct versioned `RiskScenario` rows.

---

## Eval / golden-fixture harness

Same backbone as semianalyst, adapted:

- Fixture corpus = known-vulnerable repos (OWASP Benchmark, a handful of
  CVE-tagged open source projects) with `expected_findings.json`.
- Metrics: precision/recall against ground truth per detect lens, plus
  falsification-pass effectiveness (how many false positives it correctly
  killed). This is what makes "detection precision on the benchmark corpus
  is X%" a defensible line in the leadership memo, instead of "the AI
  flagged this."
- Prompts under `prompts/` are versioned artifacts, never edited in place —
  a prompt change is a new file + a benchmark re-run, not a silent tweak.
- **Closed-loop, not one-shot.** Every harness run is persisted as an
  `EvalRun` (see schema notes). `eval/regression.py` compares a new run
  against the immediately prior run for the same stage; a regression in
  precision or recall is flagged before that prompt version is allowed
  into `map/`, `detect/`, `falsify/`, or `normalize/`. You don't have to
  remember to check — the harness catches it.

## Reliability layer

Formalizes what was already implicit in the pipeline's schema-first design,
so it's demonstrable rather than assumed:

- **Structured output, enforced.** Every LLM call across `map/`, `detect/`,
  `falsify/`, and `normalize/` goes through `llm/client.py`, which validates
  the response against the stage's Pydantic model and retries (bounded) on
  parse or validation failure. Exhausted retries are logged as a
  `ValidationFailure`, not swallowed. This is the difference between "the
  model usually returns valid JSON" and "invalid output is impossible to
  miss."
- **Confidence-gated fallback, not silent guessing.** A `Finding` or `map/`
  entity below the configured confidence threshold triggers one broader
  retrieval pass (more callers/callees/similar-pattern context) and a
  re-score, or is persisted as `unresolved`. Nothing low-confidence is
  quietly rounded up to a clean result — this is the same discipline as
  the falsification pass, applied one step earlier.
- **Eval as a gate, not a report.** Covered above — regressions block a
  prompt version from shipping rather than being discovered after the fact.

---

## CLI surface (thin, zero business logic)

```
repoauditor db init
repoauditor doctor [--check-model]
repoauditor ingest <repo-url>
repoauditor repos list [--all] [--format=human|json]
repoauditor run <repo-url> [--fresh] [--format=human|ndjson]
repoauditor runs list [--repo-id <repo-id>]
repoauditor runs show <run-id>
repoauditor map <repo-id>
repoauditor detect <repo-id>
repoauditor triage <repo-id>
repoauditor triage-label <finding-id> --disposition=true_positive|false_positive
repoauditor falsify <repo-id>
repoauditor normalize <repo-id>
repoauditor quantify <repo-id> [--record-audit]
repoauditor finalize <repo-id> [--record-audit] [--print-reports]
repoauditor report <repo-id> --mode=engineering
repoauditor report <repo-id> --mode=memo
```

---

## What's genuinely new vs. reused from semianalyst

- **Reused near-verbatim**: pyproject/uv layout, config loader shape,
  idempotent hash-keyed ingest, thin-CLI/store-owns-DB boundary, golden
  fixture harness structure, prompt-versioning discipline, CLAUDE.md
  pattern for cross-session architectural rules.
- **New**: the `map/` architecture-recovery stage, the `falsify/`
  challenger pass, multi-lens `detect/` ensemble, retrieval-augmented
  scoring, and the dual-projection `report/` split.
- **New (reliability layer)**: shared `llm/client.py` for schema
  validation + bounded retry, confidence-gated fallback instead of
  silent guessing, and closed-loop eval regression gating via `eval/`.
- **New (triage + risk quantification)**: `triage/` — a calibrated,
  non-LLM classifier (RandomForest/XGBoost) that pre-ranks deterministic
  findings before the expensive falsify pass, with Beta-Binomial cold-
  start priors and a cross-engagement label store; `analyze/risk_quant.py`
  — FAIR-style Monte Carlo simulation replacing heuristic severity
  weighting, with every prior sourced in `priors.yaml`. Deliberately no
  deep learning in either — tabular models and simulation, matching
  published FAIR methodology and exactly cited IRIS 2022 baselines rather
  than a novel or severity-derived threat model. EPSS/KEV are reserved for
  real, dated CVE-backed enrichment and are never inferred from severity.

Current implementation includes the review checkpoint, bounded falsification,
normalization debate trail, corrected two-layer validity/frequency model,
organization-specific exposure/control/loss-scale inputs, and versioned audited
simulation scenarios. Remaining enrichment work (such as live EPSS/KEV lookup or a
verified revenue-band scaling curve) must preserve the same provenance discipline.

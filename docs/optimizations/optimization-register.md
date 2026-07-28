# Optimization Register

Status: authoritative list of post-MVP work as of 2026-07-28.

I. Evaluation and classifier maturity

   A. OPT-001 — Grow the reviewed label cohort to 100–200 with broader positive mechanisms
      — in progress/evidence-gated — owner: AppSec adjudication — source:
      `../triage-accuracy-roadmap.md` and `../project-priorities.md` — activate after MVP
      items are closed; preserve abstentions and frozen holdouts — DoD impact: none.

   B. OPT-002 — Family-aware bootstrap ranges — deferred — owner: ML evaluation — source:
      `../triage-accuracy-roadmap.md` — activate after adequate held-out family breadth and
      both classes exist — DoD impact: none.

   C. OPT-003 — Temporal validation — deferred — owner: ML evaluation — source:
      `../triage-accuracy-roadmap.md` — activate after meaningful chronological depth exists
      — DoD impact: none.

   D. OPT-004 — Identical-input provider repeatability characterization — deferred/paid —
      owner: evaluation engineering — source: `../convergence-evaluation.md` and
      `../pre-tuning-readiness.md` — activate after a frozen repeat protocol and budget are
      approved — DoD impact: none.

II. Operations and cost

   A. OPT-005 — Formal same-store three-run usage calibration — deferred/paid — owner:
      reliability engineering — source: `../offline-readiness-runbook.md` — activate after
      MVP closure or if current hard ceilings block the POC walkthrough — DoD impact: none
      while limits remain fail-closed.

   B. OPT-006 — Provider dollar-cost reporting — deferred/source-gated — owner: reliability
      engineering — source: `../project-priorities.md` — activate only with dated,
      versioned provider/model pricing — DoD impact: none.

III. Detection and falsification depth

   A. OPT-007 — Improve production-region selection — evidence-ready, held until remaining
      MVP closure — owner: detection engineering — source:
      `../untouched-production-selection-plan-2026-07-28.json` and
      `../plotly-untouched-production-selection-2026-07-28.json` — the untouched Plotly.js
      measurement omitted the reviewed target in both variants, consistent with prior
      development-only aiohttp/Rack omissions. Activate only through a general path-blind
      design; never tune to any revealed target path — DoD impact: none because the current
      DoD requires measurement, not a passing selection outcome.

   B. OPT-008 — Expand slicing and deterministic certificates across additional clients,
      frameworks, languages, and cross-file flows — deferred/evidence-gated — owner: AppSec
      engineering — source: `../security-claim-certificates.md` and
      `../triage-accuracy-roadmap.md` — activate for specific corpus misses — DoD impact:
      none.

   C. OPT-009 — In-family/out-of-family novelty prioritization — deferred/data-gated —
      owner: AppSec/ML evaluation — source: `../project-priorities.md` — activate after
      enough manually reviewed LLM findings demonstrate held-out benefit — DoD impact: none.

   D. OPT-010 — Agentic falsification — deferred — owner: AppSec architecture — source:
      `../agentic-escalation-gate.md` — activate only after every documented safety and
      evaluation prerequisite passes — DoD impact: none.

IV. Quantitative enrichment

   A. OPT-011 — Sourced correction of organization-frequency allocation — methodology-gated
      — owner: quantitative-methodology — source: `../quantitative-integrity-audit.md` —
      long-term activation requires a defensible allocation/decomposition. The MVP separately
      gates affected output as experimental and not decision-grade — DoD impact: MVP
      presentation gate completed; richer model remains optimization.

   B. OPT-012 — Dated cached EPSS/KEV enrichment — deferred/network- and source-gated —
      owner: threat-data engineering — source: `../prior-scope-roadmap.md` — activate only
      for real CVEs with defined stale/offline behavior — DoD impact: none.

   C. OPT-013 — Prior temporal metadata and population applicability — deferred/source-gated
      — owner: quantitative-methodology — source: `../prior-scope-roadmap.md` — activate
      after exact source metadata is verified — DoD impact: none beyond current disclosure.

   D. OPT-014 — Prior-predictive checks, held-out validation, hierarchical priors,
      backtesting, and portfolio optimization — deferred/data-gated — owner:
      quantitative-methodology — source: `../prior-scope-roadmap.md` — activate only with
      applicable organization/incident data — DoD impact: none.

V. Intake

   A. OPT-015 — Preserve deterministic scanner failure detail — newly surfaced/deferred —
      owner: reliability engineering — source: the Plotly.js blind capture initially
      produced `semgrep_status=failed` when `--config auto` could not resolve through the
      restricted network sandbox, but the adapter artifact retained no root cause. Improve
      diagnostics without changing graceful degradation or scanner results — activation:
      after remaining MVP closure — DoD impact: none; the successful measurement reran the
      exact scanner with approved ruleset access and retained its SARIF digest.

   B. OPT-016 — Remove SHAP/Matplotlib pending-deprecation noise — newly surfaced/deferred
      — owner: test infrastructure — source: the 2026-07-28 fast-lane run completed with
      three warnings from SHAP's use of deprecated Matplotlib colormap mutation methods.
      Track the upstream dependency upgrade rather than patching third-party code; no
      correctness impact was observed — activation: routine dependency maintenance after
      MVP closure — DoD impact: none.

   C. Add the next proposed improvement as `OPT-017`; do not place it directly into the MVP
      recovery plan unless the project owner explicitly changes the DoD.

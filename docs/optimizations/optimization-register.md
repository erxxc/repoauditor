# Optimization Register

Status: authoritative post-MVP work list as of 2026-07-29. POC acceptance is complete.

Current execution priorities

1. **OPT-007 — production-region selection** is the next engineering iteration. Start with
   a frozen, path-blind design and replay it against the existing untouched-production
   artifacts before considering any live or paid validation.
2. **OPT-001 — reviewed-label growth** continues in parallel as an AppSec adjudication
   workstream. Prioritize non-CI positive-mechanism breadth; do not relax abstention,
   holdout, or evaluation-family controls merely to reach the numeric target.

OPT-002 remains gated on the family breadth produced by OPT-001. OPT-003 through OPT-006
and OPT-008 through OPT-014 remain behind their documented evidence, budget, safety, or
methodology gates. OPT-016 is routine dependency maintenance and does not displace the
ordered work above.

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

   A. OPT-007 — Improve production-region selection — evidence-ready/queued after OPT-021
      — owner: detection engineering — source:
      `../untouched-production-selection-plan-2026-07-28.json` and
      `../plotly-untouched-production-selection-2026-07-28.json` — the untouched Plotly.js
      measurement omitted the reviewed target in both variants, consistent with prior
      development-only aiohttp/Rack omissions. Begin only with a frozen, general path-blind
      design and offline replay against retained artifacts; never tune to any revealed
      target path. Live or paid validation requires a separately approved protocol and
      budget — DoD impact: none because the current DoD requires measurement, not a passing
      selection outcome.

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

   A. OPT-015 — Preserve deterministic scanner failure detail — implemented as an MVP
      acceptance correction —
      owner: reliability engineering — source: the Plotly.js blind capture initially
      produced `semgrep_status=failed` when `--config auto` could not resolve through the
      restricted network sandbox, but the adapter artifact retained no root cause. Improve
      diagnostics without changing graceful degradation. The failed POC walkthrough then
      demonstrated direct DoD impact: installed `pip-audit` failed at execution while
      preflight called the toolchain ready. Scanner execution status and attributable detail
      are now retained; an exact-direct-pin fallback is visibly partial rather than full
      transitive coverage.

   B. OPT-016 — Remove SHAP/Matplotlib pending-deprecation noise — newly surfaced/deferred
      — owner: test infrastructure — source: the 2026-07-28 fast-lane run completed with
      three warnings from SHAP's use of deprecated Matplotlib colormap mutation methods.
      Track the upstream dependency upgrade rather than patching third-party code; no
      correctness impact was observed — activation: routine dependency maintenance after
      MVP closure — DoD impact: none.

   C. OPT-017 — Diagnose the UAT IDOR selection/detection miss — completed diagnosis —
      owner: detection evaluation — source:
      `../poc-acceptance-attempt-2026-07-28.md` and
      `../poc-acceptance-walkthrough-2026-07-28.md` — the Anthropic rerun confirmed that
      `storefront/orders.py` was omitted by the bounded primary region plan while cross-file
      context still recovered and validly cited the IDOR. This is evidence that selected
      region scope and retrieval/citation scope differ, not grounds for target-path tuning.
      Feed the generalizable planner evidence into OPT-007 — DoD impact: none.

   D. OPT-018 — Support explicit requirements files in OSV-Scanner integration —
      implemented in the first post-MVP optimization PR — owner: deterministic detection —
      source: `../poc-acceptance-walkthrough-2026-07-28.md` — OSV-Scanner 2.4.0 returned
      “No package sources found” for recursive directory scanning even though a root
      `requirements.txt` existed; an explicit lockfile check parsed it successfully. Add a
      bounded manifest-discovery path with adapter regression coverage, preserving
      failure/partial-coverage disclosure. The adapter now retries a bounded set of explicit
      `requirements*.txt` files only after the attributable recursive-discovery failure and
      labels successful fallback coverage partial — DoD impact: none because pip-audit
      completed and the original degradation was disclosed.

   E. OPT-019 — Persist and expose rich per-stage summaries for demo/resume runs —
      implemented — owner: CLI/store observability — source:
      `../poc-acceptance-walkthrough-2026-07-28.md` — the region plan existed in
      `detection_region_run` but `runs show` did not expose it for the demo lineage, forcing
      a direct store query. Demo now records each executed stage, while `run`, `resume`, and
      direct map/detect/falsify/normalize commands share the same applicable summary
      projections. `runs show` exposes selected regions, scanner status/failure detail,
      model/prompt provenance, counts, and artifacts without a direct store query — DoD
      impact: none; live coverage was disclosed during acceptance.

   F. OPT-020 — Document and test bounded-plan versus cross-file retrieval scope —
      implemented in PR #59 (merge commit `5e07c58`) — owner: detection architecture — source:
      `../poc-acceptance-walkthrough-2026-07-28.md` — a valid IDOR citation referenced
      `storefront/orders.py` although that file was absent from the six selected primary
      regions. `../detection-context-provenance.md` now distinguishes architecture-based
      primary selection from the bounded syntactic caller/similarity context that may append
      an external file. Detection results and stage summaries retain only the expansions
      actually appended, with basis/file/line/symbol provenance. Generic path-blind
      regressions protect the behavior; no observed target path became a selection rule —
      DoD impact: none.

   G. OPT-021 — Generate a box-drawing/graphical architecture layout — implemented
      — owner: mapping presentation — source:
      `../poc-acceptance-walkthrough-2026-07-28.md` and the retained acceptance architecture
      artifact — the current text schematic is accurate and useful but renders each flow as
      a separate linear sentence. Add a deterministic, terminal-safe box-drawing projection
      that makes shared trust boundaries, entry points, datastores, and integrations
      visually scannable. Preserve the existing plain-text inventory and explicit
      “not recovered” limitations; do not infer new edges merely to improve layout. Consider
      an optional graphical format only if it can be generated offline without expanding
      mapping business logic — activation: satisfied by the merged OPT-018 through OPT-020
      sequence. The architecture artifact now opens with a deterministic terminal-safe
      projection that groups entry points under shared recovered trust boundaries, renders
      integration direction, and leaves datastores visibly unconnected. The original
      relationship and entity inventories remain intact, with focused presentation and CLI
      regressions — DoD impact: none.

   H. Add the next proposed improvement as `OPT-022`; do not place it directly into the MVP
      recovery plan unless the project owner explicitly changes the DoD.

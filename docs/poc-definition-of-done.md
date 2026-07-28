# POC Definition of Done

Status: **authoritative**, confirmed by the project owner on 2026-07-28.

I. Current statement

   A. A non-security user can install RepoAuditor, validate dependencies and model access,
      run an unattended scan against the lightweight UAT repository, clear review requests,
      and produce architecture, engineering, and leadership artifacts.

   B. The workflow completes within enforced call, token, batch, and time limits. It
      discloses scanner/model coverage, bounded source-region coverage, review exclusions,
      uncertainty, and known quantitative limitations. Required CI passes.

   C. Independently sourced pre-fix/post-fix evaluation demonstrates at least one
      human-adjudicated, falsification-confirmed semantic recovery with a clean patched
      control.

   D. Production-region selection is measured once on a genuinely untouched public project
      under a target-blind protocol. Selection and semantic detection are reported
      separately; the measurement does not need to show that the bounded planner selected
      the target.

II. Acceptance evidence

   A. Installation and workflow usability

      1. README quickstarts cover macOS dependencies, optional scanners, model configuration,
         missing-key behavior, guided menu operation, review, and finalization.
      2. The lightweight UAT fixture supports the bounded guided demo and known
         positive/negative checks.
      3. A final clean-environment walkthrough remains required before declaring the POC
         complete.

   B. Safety and transparency

      1. Durable per-stage/run records, bounded retry and usage scopes, resume behavior,
         scanner-coverage disclosure, and fail-closed review/finalization gates are present.
      2. Required fast CI and automatically enforced integration/live lanes are documented.
      3. Quantitative output affected by the known organization-frequency allocation defect
         must not be represented as decision-grade. Before POC completion, either resolve
         that defect from a defensible source/model specification or visibly gate the
         affected output as experimental and unsuitable for decision use.
      4. Satisfied for the POC by the owner-approved disclosure-only gate: a blocking
         read-only integrity audit labels affected CLI, memo, and appendix output
         experimental and not decision-grade. The underlying model is deliberately
         unchanged; sourced correction remains post-MVP work.

   C. Independent semantic evidence

      1. Satisfied by aiohttp CVE-2024-23334 Actions run `30387051690`.
      2. The frozen human `target_match` adjudication yields one confirmed pre-fix recovery.
      3. The patched control has no location or semantic signal.
      4. This is target-conditioned semantic evidence and receives no production-selection
         recall credit.

   D. Untouched production-selection evidence

      1. The target-blind capture/adjudication instrument is implemented and frozen.
      2. Satisfied by the Plotly.js CVE-2017-1000006 pre-fix/post-fix measurement recorded
         in
         [`plotly-untouched-production-selection-2026-07-28.json`](plotly-untouched-production-selection-2026-07-28.json).
      3. Both captures were written before target disclosure. The reviewed target was
         present in both source inventories but omitted by both bounded plans. This is
         production-selection evidence, not a semantic-detector false negative, and no
         target-aware rerun receives credit.

III. Explicitly outside the POC Definition of Done

   A. Broad or population-level real-world precision/recall claims.
   B. A tuned or automatically selected P(actionable) threshold.
   C. The preferred 100–200-label classifier maturity target.
   D. Family-aware confidence intervals or temporal validation.
   E. Provider repeatability characterization or formal same-store cost calibration.
   F. EPSS/KEV enrichment, hierarchical priors, backtesting, or portfolio optimization.
   G. Broad language/framework certificate coverage.
   H. Agentic falsification or autonomous repository tool execution.
   I. A guarantee that six bounded regions cover every security-relevant file.

IV. Scope control

   A. Completed work beyond this DoD remains valid evidence and is not reverted.
   B. New improvements that do not change this DoD are recorded in
      [`optimizations/optimization-register.md`](optimizations/optimization-register.md).
   C. An optimization becomes MVP-required only through an explicit owner-approved revision
      to this document and the recovery plan. It may not drift into the MVP implicitly.

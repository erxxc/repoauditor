# Documentation map

I. Authoritative project control

   A. [`poc-definition-of-done.md`](poc-definition-of-done.md) — the owner-confirmed POC
      commitment and acceptance boundary.
   B. [`documentation-status.md`](documentation-status.md) — authority/supersession rules
      and the current-state pointer.
   C. [`optimizations/optimization-status.json`](optimizations/optimization-status.json) —
      canonical machine-readable optimization lifecycle.
   D. [`optimizations/optimization-register.md`](optimizations/optimization-register.md) —
      narrative scope, owners, gates, and chronological outcomes.

II. Architecture and operating rules

   A. [`../CLAUDE.md`](../CLAUDE.md) — non-negotiable architectural constraints.
   B. [`../repoauditor-scaffold.md`](../repoauditor-scaffold.md) — design source of truth.
   C. [`offline-readiness-runbook.md`](offline-readiness-runbook.md) — offline and paid
      evaluation operations.
   D. [`adjudication-taxonomy.md`](adjudication-taxonomy.md) — evidence labels and evaluation
      denominators.
   E. [`detection-context-provenance.md`](detection-context-provenance.md) — distinction
      between bounded primary-region selection and external caller/similarity context.

III. Evidence and historical execution

   A. [`project-priorities.md`](project-priorities.md) — detailed historical execution and
      evidence ledger; superseded as the current priority authority by the optimization
      ledger/register.
   B. Dated JSON plans, diagnostics, qualification receipts, and baselines are immutable
      evidence for their named runs.
   C. [`poc-acceptance-walkthrough-2026-07-28.md`](poc-acceptance-walkthrough-2026-07-28.md)
      — sanitized evidence from the independent clean-environment POC walkthrough; raw
      operational evidence remains local and gitignored.
   D. Methodology documents describe implemented boundaries or deferred research; they do
      not silently expand the POC DoD.

IV. Documentation rule

   A. Update the DoD only after explicit project-owner approval.
   B. Update the recovery plan when an MVP item changes state.
   C. Record every new non-MVP improvement in `optimizations/` before implementation.
   D. Preserve completed evidence; correct stale status language with a dated supersession
      note rather than rewriting historical results.

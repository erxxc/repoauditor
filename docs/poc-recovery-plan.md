# POC Recovery Plan

Status: **historical MVP execution record — POC recovery completed 2026-07-28**.
Post-MVP outcomes below are reconciled through 2026-08-07; current lifecycle authority is
`optimizations/optimization-status.json` and narrative authority is
`optimizations/optimization-register.md`.

I. Validated Definition of Done

   A. Current statement

      1. Deliver the evidence-backed security POC defined in
         [`poc-definition-of-done.md`](poc-definition-of-done.md): accessible end-to-end
         operation, bounded and transparent execution, one confirmed independent semantic
         pre/post result, and one untouched production-selection measurement.

   B. Notable drift from original scope

      1. The project expanded from a one-stop CLI POC into stronger quantitative,
         classifier, corpus, falsification, certificate, and evaluation methodology.
      2. The project owner confirmed this work was useful and correct.
      3. It is not all required for POC completion. Treating every optimization as an MVP
         blocker was unapproved scope drift and is now stopped.
      4. There is no separate sponsor- or client-facing commitment.

II. Post-MVP status annotations (reconciled 2026-08-07)

   A. POC acceptance and operations

      1. Final clean-environment, non-security-user walkthrough — completed successfully,
         recorded in
         [`poc-acceptance-walkthrough-2026-07-28.md`](poc-acceptance-walkthrough-2026-07-28.md),
         and accepted by project owner `erxxc` — complete.
      2. Untouched public-pair production-selection measurement — completed on Plotly.js
         CVE-2017-1000006 under the frozen target-blind protocol — evaluation engineering
         plus AppSec reviewer.
      3. Known organization-frequency defect in quantitative output — POC gate completed:
         affected CLI, memo, and appendix output is conditionally labelled experimental and
         not decision-grade. OPT-011 later completed the sourced aggregate correction; this
         bullet records the narrower MVP-era presentation gate — quantitative-methodology
         owner plus product owner.

   B. Classifier and validation maturity (current outcome annotation)

      1. Grow from 58 usable labels toward 100–200 with broader positive mechanisms —
         completed at the lower bound with 104 usable labels; broader held-out family
         evidence remains OPT-002 — AppSec adjudication owner.
      2. Add family-aware bootstrap ranges — blocked on held-out family breadth — ML
         evaluation owner.
      3. Add temporal validation — blocked on chronological depth — ML evaluation owner.
      4. Characterize identical-input provider repeatability — completed at the approved
         two-subject/six-observation scope — evaluation engineering owner.

   C. Operational calibration

      1. Produce the formal same-store three-run usage comparison — completed; clean
         zero-provider comparison retained with current limits unchanged — reliability owner.
      2. Add provider dollar-cost reporting — completed from the dated 2026-08-01
         Anthropic price snapshot — reliability owner.

   D. Detection and falsification expansion

      1. Improve the planner after independent measurement identifies a generalizable miss —
         completed at OPT-007's approved production-region selection scope — detection owner.
      2. Expand slicing/certificates to additional clients, frameworks, languages, and
         cross-file flows — deferred pending specific corpus misses — AppSec engineering.
      3. Evaluate novelty as an investigation-depth trigger — blocked on reviewed LLM
         findings — AppSec/ML evaluation.
      4. Evaluate agentic falsification — blocked on all escalation gates — AppSec
         architecture owner.

   E. Quantitative enrichment

      1. Correct organization-frequency allocation — completed with one marked
         organization all-event stream and no finding/scenario allocation —
         quantitative-methodology owner.
      2. Add dated cached EPSS/KEV enrichment — completed with explicit refresh and offline
         current/stale/missing/invalid states — threat-data owner.
      3. Establish exact prior temporal metadata and broader applicability — exact source
         metadata completed; broader applicability remains data-gated — quantitative-
         methodology owner.
      4. Run prior-predictive, held-out, hierarchical-prior, and backtesting work — blocked
         on applicable organization/incident data — quantitative-methodology owner.

III. MVP — Required to Reach Done

   A. None. The owner-approved POC Definition of Done is complete.

IV. Deferred / Tuning (post-MVP)

   A. Classifier label growth and mechanism diversity — improves generalization but the
      validated POC does not claim production calibration.
   B. Bootstrap uncertainty and temporal validation — improves metric maturity but requires
      evidence not needed for the bounded POC claim.
   C. Repeatability and formal usage/cost calibration — improves operating guidance; current
      hard safety limits already fail closed.
   D. Planner improvement — measure first; changing selection is not required to complete
      the agreed measurement.
   E. Broader certificates, slicing, novelty, and agentic behavior — extend coverage beyond
      the POC and remain evidence-gated.
   F. EPSS/KEV, prior segmentation, hierarchy, backtesting, and portfolio optimization —
      quantitative enrichment beyond the POC; EPSS/KEV, exact prior metadata, and the
      aggregate frequency correction are complete, while OPT-014 remains data-gated.

V. Historical handoff (superseded)

   A. The July 28 handoff was to begin the post-MVP optimization workstream from
      [`optimizations/optimization-register.md`](optimizations/optimization-register.md),
      respecting each item's evidence and activation gate. Current next execution is in the
      lifecycle ledger and outstanding-work checkpoint.

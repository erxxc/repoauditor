# Documentation status and authority

Current as of **2026-08-07**.

Use this page to distinguish live project state from retained execution history. A dated
receipt or result is not stale merely because it says an authorization was pending or an
optimization was open at the time; those statements are immutable observations of that
step. They must not be interpreted as the current lifecycle state.

## Current authoritative state

- [`optimizations/optimization-status.json`](optimizations/optimization-status.json) is the
  machine-readable lifecycle authority: **30 closed, 5 open, 35 total**.
- [`optimizations/optimization-register.md`](optimizations/optimization-register.md) is the
  narrative authority for scope, owners, activation gates, and chronological outcomes.
- [`project-priorities.md`](project-priorities.md) records current work sequencing.
- [`optimizations/outstanding-work-checkpoint-2026-08-07.json`](optimizations/outstanding-work-checkpoint-2026-08-07.json)
  is the current derived checkpoint and must match the lifecycle ledger.

The five open optimizations are OPT-002, OPT-003, OPT-009, OPT-010, and OPT-014. No paid
provider execution is currently authorized. The outcome-blind, zero-provider OPT-002
[`acquisition protocol`](optimizations/opt-002-independent-acquisition-protocol-2026-08-07.json)
is frozen; its repository materialization, deterministic scan, scoring, and review packet
remain separately gated. The
[`primary execution receipt`](optimizations/opt-002-primary-execution-receipt-2026-08-07.json)
is pending review and explicit authorization; it permits exactly zero provider usage and
excludes the reserve and human review.

## Historical checkpoints

The following documents intentionally retain earlier counters or decisions and label their
observation date. Their historical sections are not current state:

- [`pre-tuning-readiness.md`](pre-tuning-readiness.md) — July 27 zero-label checkpoint,
  followed by a current-state reconciliation.
- [`poc-recovery-plan.md`](poc-recovery-plan.md) — final MVP recovery record as of July 28,
  with later optimization outcomes annotated.
- [`poc-acceptance-walkthrough-2026-07-28.md`](poc-acceptance-walkthrough-2026-07-28.md) —
  accepted POC walkthrough evidence.
- dated acquisition, scan, comparison, and optimization protocol/result documents — exact
  observations at their recorded dates.

## Immutable execution evidence

Files named `*receipt*.json`, `*result*.json`, dated protocols, and frozen review tranches
are audit evidence. Earlier phrases such as `authorization-pending`, `OPT-005 remains open`,
or `frequency defect unresolved` describe the state at creation. Do not edit them to mimic
today's state. Consult the lifecycle ledger and the later terminal result instead.

Notable supersessions:

- OPT-005's run-61 fail-closed comparison is superseded for qualification by the clean
  terminal comparison over runs 105/75/90; both records remain retained.
- OPT-011's pre-implementation threat-intel protocol boundary is superseded operationally
  by `organization_all_event_v1`; its EPSS/KEV non-quantitative boundary remains unchanged.
- Earlier label counts are superseded by 104 usable human labels, while the narrower
  evaluation-compatible scored cohort remains 36 labels across 7 engagements.

## Consistency policy

Current-state documents must state an `as of` date or point to the lifecycle ledger.
Historical counters must be introduced as historical observations and paired with a current
pointer when they can be mistaken for live status. Derived checkpoints must match the
ledger's summary and exact open-ID set. Tests enforce these invariants; receipts remain
immutable and are excluded from current-language assertions.

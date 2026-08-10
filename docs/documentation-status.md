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
was authorized and attempted. The retained
[`attempt result`](optimizations/opt-002-primary-execution-attempt-2026-08-07.json) records
a fail-closed scoring-identity mismatch after successful Documenso deterministic scanning;
Lobsters, the reserve, and human review were not started. OPT-002 remains open pending
duplicate derived-label/evaluation-family reconciliation. That reconciliation is now
implemented and recorded in
[`opt-002-duplicate-reconciliation-2026-08-07.json`](optimizations/opt-002-duplicate-reconciliation-2026-08-07.json):
historical rows remain immutable, exact aliases contribute once, and the read-only dry run
restores the frozen scoring identity. The pending
[`zero-provider continuation receipt`](optimizations/opt-002-zero-provider-continuation-receipt-2026-08-07.json)
froze retained Documenso re-triage and conditionally permitted frozen Lobsters acquisition
only after that identity passed. Its
[`continuation result`](optimizations/opt-002-zero-provider-continuation-result-2026-08-07.json)
records successful compatible scoring for both primaries, complete deterministic scanner
evidence, and exactly zero provider use. The two primaries yield 218 unique eligible
production/deployment candidates, so the reserve remains inactive. Packet selection,
candidate identity disclosure, human review, providers, tuning, and promotion remain gated.
The pending
[`packet-selection receipt`](optimizations/opt-002-packet-selection-receipt-2026-08-07.json)
freezes a balanced 12-entry offline selection and forbids score/outcome inputs. It does not
authorize execution until its exact approval statement is granted, and it authorizes no
source-context rendering, human review, labels, network/provider use, or promotion.
The subsequent
[`packet-selection result`](optimizations/opt-002-packet-selection-result-2026-08-07.json)
records 12 unique identities split evenly across the primary families. Selection was
offline and read-only; the store remained byte-identical and no source context, assessment,
or label was produced. OPT-002 now awaits a separately authorized bounded review.
The pending
[`bounded review receipt`](optimizations/opt-002-bounded-review-receipt-2026-08-08.json)
limits initial evidence to 20 adjacent lines around each citation and preserves explicit
abstention. It authorizes no execution until approved and no store import, provider use,
rescoring, tuning, reserve activation, or promotion.
The authorized review is now recorded in a separate
[`bounded review result`](optimizations/opt-002-bounded-review-result-2026-08-10.json): all
12 identities received explicit project-owner responses, yielding 11 decided projections
(five actionable and six non-actionable) and one preserved abstention. The store remained
byte-identical. Import, rescoring, tuning, reserve activation, and promotion remain
separately gated.
The pending
[`review import receipt`](optimizations/opt-002-review-import-receipt-2026-08-10.json)
freezes an atomic import of the 12 explicit assessments and only 11 decided manual labels,
followed by a read-only gate report. The abstention remains label-free, and status changes,
providers, rescoring, training, tuning, and production-policy changes remain excluded.

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

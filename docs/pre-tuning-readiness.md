# Pre-tuning readiness decision

Status: **historical 2026-07-27 checkpoint, reconciled to current state on 2026-08-07;
not authorized to tune**.

This file preserves the evidence available at that checkpoint. Its zero-label counters were
later superseded by the reviewed acquisition cohort and must not be read as current state.
Use [`documentation-status.md`](documentation-status.md) for current authority and
[`optimizations/optimization-register.md`](optimizations/optimization-register.md) for the
still-deferred tuning prerequisites. The recovery plan is a historical MVP record. The
decision to hold tuning remains in force.

## Current reconciliation — 2026-08-07

The live persistent store now has 104 usable human labels (37 positive, 67 negative) across
15 source engagements. The narrower compatible scored cohort has only 36 labels (19 positive,
17 negative) across 7 engagements, below the existing 40-label/8-family activation gate.
There are 404 unlabeled triaged findings, but volume alone is not held-out family evidence.
The same-store usage calibration, bounded repeatability characterization, and OPT-011
aggregate frequency correction are complete. Current blockers are evaluation-compatible
family breadth, chronological depth, reviewed LLM-origin novelty evidence, and applicable
organization/incident data for OPT-014. See
[`documentation-status.md`](documentation-status.md) and the optimization ledger for current
authority.

This checkpoint separates implementation verification from empirical validation. Passing
tests and manufactured controls show that bounded code paths execute as specified; they do
not establish classifier calibration, real-world accuracy, provider repeatability, or
quantitative-model validity.

## Evidence observed

The local persistent store used for this checkpoint reports:

- 0 usable human triage labels (0 positive, 0 negative) against the 40-label minimum;
- 0 represented engagements against the eight-engagement minimum;
- no independently reviewed or material-review-complete findings;
- two ingested lightweight snapshots; and
- one pipeline run, which failed in `falsify`.

At that checkpoint, grouped validation, threshold tradeoff curves, family-aware intervals,
temporal validation, novelty training, and classifier tuning remained evidence-gated.
Fixture answer keys, manufactured controls, and model-generated labels must not be
substituted for the missing human cohort.

The formal provider-usage calibration is now available in this store. The retained clean
comparison over terminal runs 105/75/90 qualifies all three distinct logical scan chains
with zero unknown usage and zero deferred findings. It observed peak per-batch utilization
of 38.67% of the current call ceiling and 46.59% of the current token ceiling. This removes
the OPT-005 calibration blocker without recommending or applying a limit change. The earlier
run-61 comparison remains retained as fail-closed historical evidence.

The repeated organization-frequency defect is resolved by `organization_all_event_v1`,
which consumes the IRIS annual rate once per modeled organization-year. Findings remain
non-allocating audit context, historical rows retain their legacy marker, and category
attribution/remediation deltas remain unavailable. Quantitative expansion is still blocked
on applicable organization/incident data under OPT-014; the configured priors continue to
preserve target-population and uncertainty limitations.

OPT-004 now provides a bounded initial provider-repeatability characterization. Across three
byte-identical standard-profile observations per frozen subject, finding 295 was confirmed
three times and finding 300 was killed three times; every pairwise citation-set Jaccard was
1.0. Confidence varied only for finding 295 (range 0.05). The provider exposes no sampling
seed, and two subjects do not establish universal stability, but this separates an observed
identical-input baseline from the existing retrieval-resolution experiment.

## Current required order before tuning

1. Add at least four usable evaluation-compatible scored labels and an eighth genuine
   evaluation family, preserving abstentions and both outcome classes; do not treat benchmark
   acquisition as held-out evidence.
2. Activate family-aware descriptive/bootstrap evaluation only after the 40-label/8-family
   gate is actually satisfied.
3. Accumulate meaningful observation/correction chronology before temporal validation.
4. Obtain applicable organization/incident data before adding category allocation,
   prior-predictive checks, or remediation-effect modeling under OPT-014.
5. Tune one bounded component at a time against a frozen evaluation cohort only after its
   specific gate passes; do not tune on the UAT answer key.

The correct priority-10 outcome is therefore a documented **hold**, not a parameter change.

# Pre-tuning readiness decision

Status as of 2026-07-27: **historical checkpoint; not authorized to tune**.

This file preserves the evidence available at that checkpoint. Its zero-label counters were
later superseded by the reviewed acquisition cohort and must not be read as current state.
Use [`poc-recovery-plan.md`](poc-recovery-plan.md) for current MVP work and
[`optimizations/optimization-register.md`](optimizations/optimization-register.md) for the
still-deferred tuning prerequisites. The decision to hold tuning remains in force.

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

Therefore grouped validation, threshold tradeoff curves, family-aware intervals, temporal
validation, novelty training, and classifier tuning remain evidence-gated. Fixture answer
keys, manufactured controls, and model-generated labels must not be substituted for this
missing human cohort.

The formal provider-usage calibration is now available in this store. The retained clean
comparison over terminal runs 105/75/90 qualifies all three distinct logical scan chains
with zero unknown usage and zero deferred findings. It observed peak per-batch utilization
of 38.67% of the current call ceiling and 46.59% of the current token ceiling. This removes
the OPT-005 calibration blocker without recommending or applying a limit change. The earlier
run-61 comparison remains retained as fail-closed historical evidence.

Quantitative tuning is independently blocked. `quant-audit` correctly identifies that the
IRIS organization-level annual frequency baseline is repeated per finding and summed within
a scenario. No cited source currently supports that allocation. The configured priors
persist target-population and uncertainty-role metadata. OPT-013 later verified the source's
July 2022 Advisen feed release and 2012–2021 study window; this temporal metadata removes
that warning without changing the still-blocked frequency allocation.

OPT-004 now provides a bounded initial provider-repeatability characterization. Across three
byte-identical standard-profile observations per frozen subject, finding 295 was confirmed
three times and finding 300 was killed three times; every pairwise citation-set Jaccard was
1.0. Confidence varied only for finding 295 (range 0.05). The provider exposes no sampling
seed, and two subjects do not establish universal stability, but this separates an observed
identical-input baseline from the existing retrieval-resolution experiment.

## Required order before tuning

1. Collect human adjudications across genuine repositories until both label and engagement
   gates are met, preserving abstentions and both outcome classes.
2. Run the three bounded calibration scans in one persistent store when paid work resumes;
   keep current call/token/time ceilings in force until that report is complete.
3. Repeat identical provider/model/prompt/snapshot evaluations enough to describe verdict,
   citation, confidence, token, and latency variability separately from resolution changes.
4. Obtain a sourced frequency allocation/decomposition—or change the scenario model through
   an explicit methodology decision—before treating quantitative output as decision-grade.
5. Only then activate grouped validation and threshold/family analysis. Tune one bounded
   component at a time against a frozen evaluation cohort; do not tune on the UAT answer key.

The correct priority-10 outcome is therefore a documented **hold**, not a parameter change.

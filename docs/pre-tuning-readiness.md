# Pre-tuning readiness decision

Status as of 2026-07-27: **not authorized to tune**.

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

The formal provider-usage calibration also remains unavailable in this store. It requires
one completed lightweight run and a completed independent pre/post pair, including linked
continuations and authoritative token metadata, in the same persistent store. Workflow
artifacts from temporary CI databases are useful safety observations but must not be merged
or represented as that calibration cohort.

Quantitative tuning is independently blocked. `quant-audit` correctly identifies that the
IRIS organization-level annual frequency baseline is repeated per finding and summed within
a scenario. No cited source currently supports that allocation. The configured priors now
persist target-population and uncertainty-role metadata, but exact effective dates and data
vintages remain unknown and visibly warned rather than fabricated.

Provider repeatability is also uncharacterized. The current convergence experiment varies
retrieval/decomposition resolution, while Anthropic and the OpenAI-compatible transport do
not expose a configured sampling seed. Until identical-input repeats exist, sampling
variance cannot be separated from resolution sensitivity.

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

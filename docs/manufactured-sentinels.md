# Manufactured-solution instrument controls

Status: active instrument qualification; not production scan input.

Repoauditor keeps four fixed falsification sentinels: exploitable SQL injection and SSRF
paths plus parameterized-query and hostname-allowlisted negative controls. Their human-authored
answer key is outside the scanned snapshot. The model receives the candidate and source
context, never the expected disposition.

Run the control explicitly:

```sh
uv run repoauditor qualify-instrument
uv run repoauditor qualify-instrument --format json
```

This makes multiple live model calls and may incur provider cost. It never ingests the
sentinels into a customer repository and disables finding, claim, iteration, and verdict
persistence. Shared reliability-layer validation failures remain auditable.

## Qualification rule

The run reports positive recovery, negative-control recovery, and total recovery. Because
the cohort has only four fixed cases, qualification is intentionally fail-closed: every
case must match its declared `confirmed` or `killed` answer. An unresolved result is a miss,
not silently credited as correct. A miss exits nonzero and disqualifies that instrument run.

Passing means only that the configured provider/model/prompt recovered these manufactured
knowns at that time. It is not an estimate of precision, recall, or calibration on unknown
or independently authored repositories. The existing public corpus and UAT lanes remain
the evidence for those separate questions.

## Automatic cadence

The protected paid live workflow runs the controls every Tuesday, publishes the structured
result in the job summary, and retains it for 30 days. Manual dispatch defaults to
`sentinels-only`; choose `full-live` explicitly for the broader corpus/golden sweep. The
broader sweep remains automatically enforced on the first day of each month. The same
control is not repeated inside that pytest selection, preventing duplicate API cost.

Current Anthropic and OpenAI-compatible transports do not provide a configured sampling
seed, so the result explicitly reports repeatability as unisolated. Gauge/repeatability
characterization remains a later phase.

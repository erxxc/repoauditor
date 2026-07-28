# Manufactured-solution instrument controls

Status: active instrument qualification; not production scan input.

Repoauditor keeps four fixed falsification sentinels: exploitable SQL injection and SSRF
paths plus parameterized-query and fixed-target/redirect-disabled negative controls. Their
human-authored answer key and ground-truth basis are outside the scanned snapshot. The model
receives the candidate and source context, never the expected disposition.

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
Qualification scores the declared disposition; it does not certify every incidental claim
in the model's freeform rationale. Rationale accuracy is reviewed separately.

## Automatic cadence

The protected paid live workflow runs the controls every Tuesday, publishes the structured
result in the job summary, and retains it for 30 days. Manual dispatch defaults to
`sentinels-only`. `live-lightweight` evaluates only the 12-file UAT fixture, while
`bounded-independent` evaluates one pinned independent pre/post pair. The latter runs
automatically on the first day of each month. Paid corpus evaluation stops on its first
failure and has a 20-minute hard timeout; there is no monolithic hosted-model corpus sweep.
The same manufactured control is not repeated inside a bounded pytest selection,
preventing duplicate API cost.

Current Anthropic and OpenAI-compatible transports do not provide a configured sampling
seed, so the result explicitly reports repeatability as unisolated. Gauge/repeatability
characterization remains a later phase.

## Zero-token deterministic certificate controls

The separate `manufactured_certificate_controls` fixture runs in the required fast lane and
does not call a provider. Its eight externally labelled controls cover:

- JS/TS Axios SSRF request input versus a fixed target;
- JS/TS `child_process.exec` request input versus a fixed command;
- Java `request.getParameter` SSRF versus a fixed URL; and
- ownership authorization versus authentication-only syntax.

The answer key remains outside the scanned snapshot. These controls qualify only the narrow
structural producer/checker contracts and do not estimate real-world accuracy or prove
control effectiveness. Keeping them separate also prevents this offline expansion from
silently increasing the four-case weekly paid sentinel cohort.

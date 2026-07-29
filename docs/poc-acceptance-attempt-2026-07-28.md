# POC Acceptance Attempt — 2026-07-28

Status: **not accepted; offline corrections in progress**.

Source: [assistant-operated walkthrough and attached scorecard](https://gist.github.com/brock6g/6ca0fe0cf2c983a0dc951aefd3ec0ad6)
against merge commit `a3ce0d56bac54e9c61addb6b1b3ecb073a26d299`.

## What passed

- Installation, SQLite initialization, missing-key behavior, and live endpoint validation.
- Bounded execution and durable continuation without repeating map/detect.
- Human review decisions and rationales.
- Architecture, engineering, leadership, quantitative, and scorecard artifacts.
- Durable terminal run records.

## Acceptance blockers

1. The walkthrough was assistant-operated, not completed by an independent non-security
   reviewer.
2. After `resume` cleared the bounded backlog, the CLI did not guide the user through demo
   review/finalization/scorecard generation.
3. Scanner preflight reported installed executables as ready even though `pip-audit` failed
   during execution; the failure was discarded and the vulnerable-dependency case received
   no candidate.

## Score interpretation correction

The original demo scorecard reported 4/10. Case-level evidence showed:

- genuine passes: cases 1, 2, 4, and 6;
- genuine detection misses: case 3 (IDOR) and case 5 (dependency);
- safe negative outcomes with unexercised mechanisms: cases 7, 8, and 9;
- a safe duplicate outcome with partial source coverage: case 10 (two killed candidates,
  zero countable findings, one observed source).

Therefore final security outcome, detection coverage, falsification-mechanism coverage, and
source coverage must be reported separately. No historical artifact is overwritten; a new
scorecard is generated after the correction.

## Rerun boundary

No prompt tuning or target-aware model change is licensed by this attempt. Complete the
offline scorer, scanner-health, and demo-continuation corrections first. Then inspect the
recorded region plan for case 3 and rerun acceptance with the Anthropic baseline and an
independent non-security reviewer.

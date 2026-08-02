# Falsification convergence evaluation

Status: evaluation-only; it does not change production verdicts.

The convergence check applies solution refinement from computational verification and
validation: perturb the resolution of the instrument while holding the subject fixed. A
finding that changes disposition as retrieval breadth and decomposition depth increase is
evidence of method sensitivity, not automatically evidence about the target repository.

Run it for one persisted finding:

```sh
uv run repoauditor falsify-convergence <finding-id>
uv run repoauditor falsify-convergence <finding-id> --format json
```

The command makes multiple provider calls and may incur API cost. It retains the persisted
finding identity for attributable model-call context while explicitly disabling evaluation
artifact writes; it does not write findings, falsification iterations, claims, or verdicts.

## Controlled variables

Every profile holds constant the repository commit, finding, architecture map, prompt
versions, provider/model, confidence thresholds, and self-critique policy. It varies:

| Profile | Iterations | Local context | Related-result base | Module context | Evidence cap |
|---|---:|---:|---:|---:|---:|
| coarse | 1 | 6 lines | 1 | 12 lines | 6,000 chars |
| standard | 2 | 10 lines | 2 | 18 lines | 12,000 chars |
| refined | 3 | 18 lines | 5 | 30 lines | 24,000 chars |

Unlike production's early-exit behavior, an evaluation profile reaches its declared
iteration tier before its result is compared. This prevents a confident tier-one result
from being mislabeled as a refined measurement.

## Interpretation

Output reports verdict flip rate, adjacent citation-set Jaccard similarity, confidence
spread, and the earliest resolution from which the verdict remains stable. Classifications
are descriptive:

- `stable` — the same decided verdict at every measured resolution;
- `unresolved` — every resolution abstained;
- `oscillating` — the verdict changed and later returned to its initial value;
- `non_convergent` — other disposition changes across resolution.

These labels do not prescribe a production action. Unstable and unresolved findings remain
reviewable; the harness never kills or confirms them.

Anthropic calls and the current OpenAI-compatible transport do not expose a configured
sampling seed. Their output explicitly says seed reproducibility is unavailable. A live
result therefore combines resolution sensitivity with possible model repeatability noise;
repeatability/measurement-system characterization is a separate future phase.

That phase now has a frozen initial protocol in
[`optimizations/opt-004-repeatability-protocol-2026-08-01.json`](optimizations/opt-004-repeatability-protocol-2026-08-01.json).
It holds the existing standard profile byte-identical for three fresh observations of each
of two predeclared human-reviewed subjects. No calls are authorized by the protocol itself;
execution still requires an explicit calls, tokens, and USD budget plus immutable subject
digests.

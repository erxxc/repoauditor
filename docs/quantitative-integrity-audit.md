# Quantitative input integrity audit

Status: read-only audit implemented; the repeated organization-frequency defect is fixed
for methodology-marked aggregate runs.
The audit never changes a scenario, prior, or simulation result.

Run it against a repository whose findings have cleared review:

```sh
uv run repoauditor quant-audit <repo-id>
```

## Current factor map

| Input | FAIR/model role | Current source | Double-counting assessment |
|---|---|---|---|
| Finding validity | Epistemic Bernoulli gate: whether the issue exists | Falsification/review confirmation or triage `P(actionable)` | Structurally separate from event rate |
| Conditional frequency | Organization loss-event rate | IRIS 2022 Figure 4 organization-level annual loss-event baseline | Consumed once by `organization_all_event_v1`; malformed or legacy repeated streams remain blocking |
| EPSS/KEV | CVE-specific threat evidence | Explicitly refreshed FIRST/CISA cache; current/stale state and source dates are labeled | Informational only; no proxy, severity inference, or quantitative multiplier is active |
| Exposure | Threat contact-frequency modifier | Existing map/deal-risk production-exposure signal or analyst override | Used in deal ranking and quantification, but those are separate outputs rather than one repeated equation |
| Control strength | Vulnerability/success modifier | Conservative zero unless explicitly overridden | Separate from validity; no inferred control credit |
| Loss scale | Loss-magnitude modifier | Conservative 1.0 unless explicitly overridden | Applied only to magnitude |
| Magnitude | Per-event loss distribution | IRIS 2022 Table 3 all-event/all-sector baseline | Reused across scenario names; no category-specific calibration is claimed |

## Resolved frequency structure

The cited input remains an organization-level probability for organizations over $10M
revenue. New runs convert it once to a Poisson rate and consume one stream per modeled
organization-year. Findings retain membership, validity provenance, and informational threat
labels but cannot multiply or allocate frequency. The audit blocks a marked aggregate run
unless it contains exactly one `organization_all_event` unit and one frequency stream. It
also retains the earlier repeated-frequency check for historical/legacy shapes.

## Applicability gaps

- Both IRIS priors now record the source-exact July 2022 Advisen feed snapshot and
  2012–2021 study window. This removes the temporal-metadata warning but does not broaden
  the population or resolve the frequency structure.
- The frequency population is organizations over $10M revenue. An unknown revenue band is
  reported as unverified; a configured band below $10M is reported as a mismatch.
- The magnitude distribution is all-event and all-sector. It is not evidence for different
  category medians merely because findings are assigned different scenario names.
- Analyst overrides are engagement evidence, not published population priors. Their
  rationale and sensitivity require separate review.
- No language, industry, geography, architecture, control-maturity, or time-vintage
  adjustment is currently supported beyond the provenance already attached to the baseline.

Category allocation and remediation-effect modeling remain unavailable. Adding either is
OPT-014/data-gated and must not use an intuitive equal split or severity weighting.

# Quantitative input integrity audit

Status: read-only audit implemented; one blocking model-structure issue remains unresolved.
The audit never changes a scenario, prior, or simulation result.

Run it against a repository whose findings have cleared review:

```sh
uv run repoauditor quant-audit <repo-id>
```

## Current factor map

| Input | FAIR/model role | Current source | Double-counting assessment |
|---|---|---|---|
| Finding validity | Epistemic Bernoulli gate: whether the issue exists | Falsification/review confirmation or triage `P(actionable)` | Structurally separate from event rate |
| Conditional frequency | Threat/loss-event rate | IRIS 2022 Figure 4 organization-level annual loss-event baseline | **Blocking:** currently repeated once per finding and summed within a scenario |
| EPSS/KEV | CVE-specific threat evidence | Inactive; industry fallback is explicitly labeled | No proxy or severity-derived value is active |
| Exposure | Threat contact-frequency modifier | Existing map/deal-risk production-exposure signal or analyst override | Used in deal ranking and quantification, but those are separate outputs rather than one repeated equation |
| Control strength | Vulnerability/success modifier | Conservative zero unless explicitly overridden | Separate from validity; no inferred control credit |
| Loss scale | Loss-magnitude modifier | Conservative 1.0 unless explicitly overridden | Applied only to magnitude |
| Magnitude | Per-event loss distribution | IRIS 2022 Table 3 all-event/all-sector baseline | Reused across scenario names; no category-specific calibration is claimed |

## Blocking frequency issue

The cited frequency input is an organization-level probability of at least one annual loss
event for organizations over $10M revenue. Scenario construction currently converts that
probability to a Poisson rate, assigns the full rate to every finding, and sums those rates.
Consequently, the estimated event rate rises mechanically with finding count even though the
source does not publish a per-finding conditional rate.

The audit flags multi-finding scenarios but does not choose a replacement. A correction
requires a sourced modeling decision: for example, whether the baseline is allocated once
per portfolio, once per scenario, or decomposed through calibrated threat-event categories.
Until then, affected quantitative output is conditionally gated in the CLI, leadership memo,
and quantitative appendix as **experimental and not decision-grade** whenever the read-only
integrity audit returns a blocking issue. The simulation and stored inputs are unchanged;
the gate preserves figures for method evaluation while prohibiting deal, budget, or
risk-acceptance use.

## Applicability gaps

- The frequency population is organizations over $10M revenue. An unknown revenue band is
  reported as unverified; a configured band below $10M is reported as a mismatch.
- The magnitude distribution is all-event and all-sector. It is not evidence for different
  category medians merely because findings are assigned different scenario names.
- Analyst overrides are engagement evidence, not published population priors. Their
  rationale and sensitivity require separate review.
- No language, industry, geography, architecture, control-maturity, or time-vintage
  adjustment is currently supported beyond the provenance already attached to the baseline.

The next model change remains gated on a sourced resolution of the organization-frequency
allocation problem. Do not replace it with an intuitive equal split or severity weighting.

# Organization-frequency methodology

Status: **OPT-011 methodology approved for implementation; runtime behavior is unchanged.**

## Decision

Repoauditor will model the cited IRIS frequency as one organization-year, all-event
baseline. A repository's countable findings are evidence attached to that modeled
organization; they are not independent organizations or loss-event generators.

For an in-population organization, the annual event count is:

```text
lambda_org = -ln(1 - 0.129)
N_org ~ Poisson(lambda_org * exposure_org * (1 - control_strength_org))
loss_i ~ Lognormal(IRIS_all_event_mu, IRIS_all_event_sigma) * loss_scale_org
annual_loss = sum(loss_i for i in 1..N_org)
```

The published probability and transformation remain exactly those recorded in
`priors.yaml`. The model consumes `lambda_org` once per simulation trial. Finding count,
severity, validity probability, rule family, scenario label, EPSS, and KEV do not multiply
or allocate it.

This is an explicit model specification, not a claim that IRIS publishes vulnerability-
conditioned frequency. It estimates an organization-level industry baseline when the
source population is applicable. It does not estimate incremental loss caused by a
finding, avoided loss from remediation, or scenario-specific loss.

## Why this option

IRIS Figure 4 supplies an organization-level probability of at least one annual loss
event for organizations over $10M revenue. IRIS Table 3 supplies an all-event, all-sector
loss magnitude distribution. Those inputs support one all-event organization model. They
do not support any of the following alternatives, which remain prohibited:

- one full organization rate per finding or per scenario;
- equal allocation across findings or scenario names;
- severity-, confidence-, EPSS-, KEV-, or deal-risk-weighted allocation;
- treating scenario labels as calibrated event categories; or
- summing several organization-level scenario simulations into a portfolio total.

Using one aggregate modeling unit removes the known count-multiplication error without
inventing a decomposition. It also makes the limitation visible: finding-level attribution
is unavailable rather than encoded through arbitrary weights.

## Input and provenance contract

- The modeling unit is named `organization_all_event` and has one frequency draw stream.
- All countable finding IDs and their validity provenance remain attached for audit and
  review, but validity is not folded into the organization event rate.
- Cached EPSS and KEV remain informational labels only.
- Production-exposure scores derived per finding are not promoted to organization-level
  frequency evidence. PR 2 will use the neutral defaults `exposure_org=1.0`,
  `control_strength_org=0.0`, and `loss_scale_org=1.0` unless an analyst supplies an
  engagement-wide `*` override with the existing persisted provenance.
- Scenario-specific overrides are invalid for this aggregate model. They must fail closed
  rather than being averaged or silently ignored.
- The existing revenue-population checks remain: unknown is unverified, below $10M is a
  mismatch, and neither condition becomes decision-grade merely because allocation is fixed.
- Historical simulation rows remain immutable and retain their earlier methodology. New
  runs must identify the aggregate methodology version; they must not reinterpret old rows.

## Output claim boundary

CLI, memo, appendix, charts, persisted summaries, and tornado output may describe the
result only as an **organization-level all-event industry baseline**. They must not display
per-finding or per-scenario frequency contributions, remediation savings, or a ranking of
scenario risk. Finding membership and threat labels may appear as non-quantitative context.

The current `EXPERIMENTAL / NOT DECISION-GRADE` disclosure may be removed only for the
specific repeated-frequency blocker after PR 2 proves the new invariant. Population,
parameter-uncertainty, and applicability warnings remain independently active.

## PR 2 acceptance contract

Implementation is complete only when all of the following are enforced by tests:

1. One, two, or many countable findings resolve to exactly one aggregate modeling unit and
   exactly one base `lambda_org`; adding a finding cannot increase that base rate.
2. Findings in several current scenario categories still produce one all-event unit.
3. The Monte Carlo engine draws one Poisson event count per organization trial, not one per
   finding, while preserving the fitted all-event magnitude distribution.
4. A repository with no countable findings continues to produce no modeled output.
5. Per-finding exposure and validity values cannot numerically alter the aggregate rate;
   engagement-wide analyst overrides remain explicit and persisted.
6. Scenario-specific overrides fail closed with a message naming the aggregate-only model.
7. Integrity audit no longer reports `organization_frequency_repeated_per_finding` for new
   aggregate runs and adds a blocker for any new run that contains multiple full-rate
   streams or lacks the methodology marker.
8. CLI, memo, appendix, persistence, reruns, charts, and sensitivity output use the same
   aggregate semantics and claim boundary.
9. Existing versioned historical rows are readable without mutation and are not relabeled.
10. No production threshold, triage verdict, prior value, or operational provider limit
    changes as part of OPT-011.

OPT-014 remains data-gated. Organization/incident data would be required to add calibrated
category allocation, prior-predictive checks, or remediation-effect modeling later.

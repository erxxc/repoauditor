# Prior-scope roadmap

Status as of 2026-08-07: applicability inventory, exact source temporal metadata, persisted
scope/uncertainty metadata, dated cached EPSS/KEV evidence, and the aggregate organization-
frequency correction are implemented. OPT-014 expansion remains data-gated.

Open enrichment work is post-MVP and tracked in
[`optimizations/optimization-register.md`](optimizations/optimization-register.md). The
POC's narrower presentation gate was satisfied, and OPT-011 later corrected the frequency
structure with `organization_all_event_v1`.

The first applicability inventory is now executable through
`repoauditor quant-audit <repo-id>` and documented in
[quantitative-integrity-audit.md](quantitative-integrity-audit.md). It deliberately reports
unsupported scope rather than changing priors. It now verifies the single marked aggregate
stream and continues to report population and uncertainty limitations.

Repoauditor's current priors are industry baselines with explicit publication provenance,
plus separately identified engagement inputs and CVE-specific EPSS/KEV signals where those
signals actually exist. They should not be treated as universally representative of every
organization, architecture, geography, or time period.

Before expanding their scope, preserve these gates:

- Define the target population for each prior: industry, organization size/revenue band,
  geography/regulatory environment, technology/architecture, exposure, control maturity,
  and source-data vintage.
- Prefer hierarchical partial pooling when sufficiently diverse observations exist, so
  sparse cohorts borrow strength without being silently collapsed into a global baseline.
- Keep organization-specific empirical inputs and analyst overrides distinct from published
  population priors, with origin and effective date visible in scenario provenance.
- Use prior-predictive checks, sensitivity analysis, and backtesting against held-out
  incident/loss observations before enabling a narrower cohort prior by default.
- Separate aleatory variability from epistemic uncertainty and keep both visible as ranges.
- Audit EPSS, KEV, exposure, control strength, and loss-scale adjustments for double counting.
- Do not invent scaling curves or subgroup adjustments when source data cannot support them;
  retain and label the broader conservative baseline instead.

The configured priors now persist target-population descriptions and separate the aleatory
representation used by the simulation from epistemic limitations that remain unquantified.
IRIS 2022's methodology identifies the July 2022 Advisen data-feed release and its exact
2012–2021 study window. The configured magnitude and frequency priors therefore record
`2022-07` as the effective source snapshot and `2012-01-01/2021-12-31` as data vintage.
These are source-exact metadata, not values inferred from the edition, and they do not alter
either configured distribution.

OPT-012 adds explicit `repoauditor threat-enrich <repo-id> --refresh` acquisition from FIRST
EPSS and CISA KEV. Quantification reads the repo-bound cache offline and labels it current,
stale, missing, or invalid. These signals remain informational: they do not modify validity,
frequency, magnitude, severity, or deal-risk weight. OPT-011's completion does not convert
these informational signals into model inputs.

Remaining implementation order is: establish adequate real-data coverage, run prior-
predictive and held-out checks, then introduce versioned hierarchical priors behind an
explicit compatibility boundary.

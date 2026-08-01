# Prior-scope roadmap

Status: applicability inventory, persisted scope/uncertainty metadata, and dated cached
EPSS/KEV evidence are implemented; quantitative-model changes remain gated.

Open enrichment work is post-MVP and tracked in
[`optimizations/optimization-register.md`](optimizations/optimization-register.md). The
current POC has one narrower requirement: affected quantitative output must be corrected or
visibly gated as experimental/non-decision-grade while the organization-frequency defect
remains unresolved.

The first applicability inventory is now executable through
`repoauditor quant-audit <repo-id>` and documented in
[quantitative-integrity-audit.md](quantitative-integrity-audit.md). It deliberately reports
unsupported scope rather than changing priors. The confirmed organization-frequency
repetition issue remains unresolved pending a sourced decomposition.

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
The cited edition is not relabeled as an effective date or data vintage: those fields remain
null and `quant-audit` reports that missing temporal scope explicitly. This metadata change
does not alter either configured distribution.

OPT-012 adds explicit `repoauditor threat-enrich <repo-id> --refresh` acquisition from FIRST
EPSS and CISA KEV. Quantification reads the repo-bound cache offline and labels it current,
stale, missing, or invalid. These signals remain informational: they do not modify validity,
frequency, magnitude, severity, or deal-risk weight while the frequency-allocation defect is
unresolved.

Remaining implementation order is: establish exact temporal metadata from a verified source
or source dataset, establish adequate real-data coverage, run prior-predictive and held-out
checks, then introduce versioned hierarchical priors behind an explicit compatibility
boundary.

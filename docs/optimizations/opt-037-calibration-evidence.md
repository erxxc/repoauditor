# OPT-037 — Calibration evidence

## I. Intake

- Proposed: 2026-09-09 from local proposal commit
  `fd179aeb25da1ff88c4070bd02159f8f40c1f66a`.
- Status: gated; admission does not transfer lab evidence or implement calibration.
- Owner: project governance / quantitative assurance.

## II. Ordered scope

### Tier 0 — exact-oracle coverage utility

Add a pure calibration utility only after a separately authorized static aggregate fixture
is exported from lattice-lab merge `c248eea5c2bd25b7dfcf077049a060ac6aa435d2` with its
command, seed, schema, and SHA-256 provenance. This is bounded evidence ingestion, not a
runtime dependency: RepoAuditor must not import or execute the lab. The known aggregate
target is 48/49 covered cells for the 49-cell odd-bound grid and 31/31 covered scored cells
for the 42-cell bit-length grid; the sole odd-bound miss is at the analytic edge. Tests must
report rather than hide unscored, underdetermined, or infeasible cells.

The utility may implement Wilson intervals, predicted-versus-observed coverage by frozen
regime, and reliability tables. Passing establishes that the coverage machinery reproduces
a boundary with independently known truth. It does not calibrate RepoAuditor findings,
triage scores, loss priors, or production decisions.

### Tier 1 — triage reliability against realized outcomes

Reuse the existing authoritative score-to-later-label join and 40-real-label gate. Every
score must strictly precede its first assessment, and pooled rows must share the compatible
model name/version, feature-schema version, and calibration identity already enforced by
the threshold-statistics path. Reliability bins must disclose row counts and uncertainty;
sparse or one-class cohorts remain unavailable. Results are descriptive and select no
threshold.

### Tier 2 — simulator estimator-coverage design

Tier 2 is not implementation-ready. The reported p5/median/p95 loss distribution values are
predictive quantiles, not confidence intervals for a Monte Carlo estimator. A future design
must name the estimator, interval construction, nominal coverage, seed and batch schedule,
and independent reference. Analytic zero-event mass and expectations may be exact
references. Compound-distribution quantiles or fixed-threshold exceedance probabilities may
be used only with a separately qualified independent numerical oracle; existing simulated
point estimates must not be called analytic truth.

## III. Reporting and integrity boundary

A future memo may disclose each tier as available or unavailable. Missing calibration evidence is informational
unless a later policy explicitly makes it required. No tier may
claim predictive validity, representativeness, accuracy of the IRIS priors, portfolio
readiness, or an optimal threshold. No fitting, refitting, prior change, model selection,
backtesting against loss data, or production-policy change is in scope.

## IV. Activation gates

1. Tier 0 requires a separately authorized sanitized aggregate fixture transfer and
   exact-oracle qualification.
2. Tier 1 requires separate authorization plus the existing temporal, cohort-size,
   two-class, family, and score-compatibility gates.
3. Tier 2 requires a separately reviewed protocol correcting its interval semantics and
   reference construction.
4. Each tier produces its own immutable receipt and result. OPT-037 remains open until a
   separately authorized bounded closure decision.

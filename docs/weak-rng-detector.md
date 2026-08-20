# Weak-RNG detector (OPT-036)

`weak_rng` is repoauditor's own deterministic source detector for the taxonomy's
middle branch: a **shared/predictable generator crossing a trust boundary**. Unlike
SAST/SCA/secrets it wraps no external tool — it scans the tree-sitter retrieval index
for predictable-RNG idioms. This class is invisible to SAST rule packs, dependency
scanning, and CVE feeds because it is a correct-looking use of a standard-library API,
which is precisely why it is worth a first-class detector.

## Mechanism

Java idioms located syntactically over the retrieval index
(`detect/deterministic/weak_rng_adapter.py`, `detect_in_source`):

- unseeded / fully-qualified `new java.util.Random(` — a 48-bit truncated LCG whose full
  internal state is recoverable from a few outputs (the Randar attack; demonstrated in
  the standalone `prng-lattice-lab` harness);
- `Math.random(` — backed by the same shared `java.util.Random`;
- Apache Commons `RandomStringUtils.random*` (the elttam case), excluding the `secure()`
  variants.

Comments and test sources (`sourcefiles.is_test_source`) are skipped; `SecureRandom` is
never matched. Each finding carries a concrete location, a stable `identity_key` (the
enclosing symbol + idiom, for matching/dedup), and a per-idiom confidence.

## Status: standalone detector; framework integration SHELVED

This change ships **only the detector**: `weak_rng_adapter.py` (`detect_in_source` +
`WeakRngAdapter`, which already implements the OPT-022 `ScannerExecution` contract) and
its unit tests. It imports the existing `ScannerExecution` / `CandidateFinding` shapes
read-only and touches no other file — a purely additive module.

Registering it as a live first-class scanner — adding it to `DETERMINISTIC_SCANNERS`
(`execution.py`), a deployment canary (`canaries.py`), the ensemble runner
(`ensemble.py`), and the OPT-030 capability matrix — is **deliberately shelved**. Every
one of those integration points is digest-frozen by *closed* optimization instruments:
`ensemble.py` by OPT-009 (2026-08-13), and `execution.py` + `canaries.py` by OPT-010's
instrument-qualification receipt (2026-08-19), whose digest sits at the root of a ~20-deep
tamper-evident hash chain across the closed OPT-010 lifecycle. Editing any of them would
invalidate preserved evidence, and there is no non-frozen seam to register a scanner
through (those files are both the definition and the consumption points for the roster).

So repoauditor's deterministic-scanner extension surface is, as of the OPT-010 closure,
frozen shut for new scanners. Reopening it — via an owner-authorized re-qualification of
the affected instruments, or a re-architected registration seam — is its own scoped piece
of work; the live wiring of `weak_rng` waits on it. Until then this detector is available
as a module and exercised by its tests, but is not part of a live detect pass.

## Claim boundary

Matching is **syntactic**, so findings are **review candidates, never automatic
actionable findings**. The adapter proposes a conservative **initial `MEDIUM` severity**
only; `normalize/adjudicate` owns any upgrade, and the corroborating source that licenses
one is a reproducible state-recovery demonstration (built in the harness), not a prior.

## Execution contract

`WeakRngAdapter` already implements the OPT-022 `ScannerExecution` contract, ready for
the shelved registration. Applicability is the presence of Java source; `target_count` is
the number of `.java` files considered, basis `scanner-reported-files`. So `empty` (Java
present, no idioms) is distinguishable from `not-applicable` (no Java) and from `failed`,
per OPT-022. A deployment canary (isolated positive `new java.util.Random()` vs. clean
`SecureRandom`-only control, no external binary) is written and ships with the shelved
integration, not in this detector-only change.

## Blind spots

- Syntactic matching only: obfuscated construction, reflection, or a `Random` reached
  through a wrapper/factory can be missed; a matched idiom may be seeded securely or used
  outside a trust boundary.
- Java only in this first pass; `nextInt(oddBound)` bias modelling and other languages are
  follow-ups.
- No claim of exhaustive recall.

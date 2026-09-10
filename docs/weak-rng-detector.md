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

## Status: integrated deterministic detector

`WeakRngAdapter` is registered in `DETERMINISTIC_SCANNERS`, the ensemble runner,
deployment canaries, CLI summaries, execution evidence, and the capability matrix. The
historical OPT-010 receipt digests remain receipt-time evidence and are tested separately
from the current extended scanner surface.

The standalone `prng-lattice-lab` remains corroboration context only. RepoAuditor does
not import it, execute it, ingest its artifacts, or make detector results contingent on
its availability.

## Claim boundary

Matching is **syntactic**, so findings are **review candidates, never automatic
actionable findings**. The adapter proposes a conservative **initial `MEDIUM` severity**
only; `normalize/adjudicate` owns any upgrade, and the corroborating source that licenses
one is a reproducible state-recovery demonstration (built in the harness), not a prior.

## Execution contract

`WeakRngAdapter` implements the OPT-022 `ScannerExecution` contract. Applicability is the
presence of Java source; `target_count` is
the number of `.java` files considered, basis `scanner-reported-files`. So `empty` (Java
present, no idioms) is distinguishable from `not-applicable` (no Java) and from `failed`,
per OPT-022. Its deployment canary uses an isolated positive `new java.util.Random()` and
clean `SecureRandom`-only control without an external binary.

## Blind spots

- Syntactic matching only: obfuscated construction, reflection, or a `Random` reached
  through a wrapper/factory can be missed; a matched idiom may be seeded securely or used
  outside a trust boundary.
- Java only in this first pass; `nextInt(oddBound)` bias modelling and other languages are
  follow-ups.
- No claim of exhaustive recall.

## Python random plugin (`weak_rng_py`)

The additive package-local `weak_rng_py` plugin detects direct textual calls to selected
Python `random` APIs. It reports deterministic, snapshot-bound candidates at initial
`MEDIUM` severity, excludes canonical test paths from findings and target counts, and uses
`random.getrandbits` plus `secrets.token_hex` as synthetic canary controls. It does not
import, execute, or ingest PRNG lattice-lab.

This is substring-only coverage. Aliased or `from random import ...` calls may be missed;
shadowed `random` identifiers and string literals can match. `secrets` and
`random.SystemRandom` are excluded, but a match still does not establish security-sensitive
use, attacker observation, state recovery, exploitability, actionability, or exhaustive
recall. Those limitations are frozen in focused tests rather than inferred away.

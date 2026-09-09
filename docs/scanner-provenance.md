# Scanner Configuration and Provenance

Status: implemented for deterministic scanner execution evidence.

Every official or supplemental Semgrep, gitleaks, pip-audit, OSV-Scanner, and weak-RNG execution now
retains the binary version when available, a normalized invocation, configuration identity
and resolution outcome, and applicable ruleset or advisory-source metadata. Normalized
invocations use placeholders such as `$SNAPSHOT`, `$MANIFEST`, and `$REPORT` so temporary
host paths do not make otherwise equivalent evidence differ.

## Semgrep baseline

Production Semgrep execution no longer uses mutable `--config auto`. RepoAuditor vendors a
compressed snapshot of the official default registry payload, identifies it as
`p/default@sha256:<digest>`, and verifies the decompressed SHA-256 before invoking Semgrep
with a temporary local file. Execution works offline and fails with attributable
configuration detail if the packaged payload is absent or corrupted. There is no fallback
to an unverified or mutable registry ruleset.

The current snapshot was retrieved from `https://semgrep.dev/c/p/default` on 2026-07-29. Its
decompressed digest is
`e1fb774d43b23f8265ae07566a5e325763244df9ba6eb8cbefe51e3ce05540c4` and it contains 1,073
rules. Per-rule source, license, and registry-version metadata remain embedded in the
vendored YAML.

The execution record retains:

- the Semgrep binary version reported by the target metadata;
- the logical pinned configuration identity;
- the SHA-256 and parsed rule count;
- `pinned-verified` or the attributable failed/unavailable outcome; and
- the normalized scanner invocation.

Refreshing the vendored payload and retained digest is a scanner-rules release. It should be
evaluated against the deployment canaries and frozen corpus controls before promotion.

## RepoAuditor supplemental Semgrep pass

The owned supplemental pack is a separate versioned YAML asset and is never concatenated
with the official baseline. Production detection invokes it through a second `SastAdapter`
pass and retains its own `repoauditor-supplemental@sha256:<digest>` configuration identity,
rule count, execution status, SARIF artifact, and `semgrep-supplemental` candidate count.
Language-inapplicable snapshots report `not-applicable` rather than a clean or failed zero.

The initial pack contains one reviewed JavaScript/TypeScript dynamic shell-execution rule.
Its matches are unadjudicated review candidates, not automatic command-injection findings.
Every required deployment-gate run exercises the exact packaged rule against a positive
variable-command control and a clean argument-vector control.

## Other scanners

Gitleaks uses rules embedded in its pinned binary. Its execution evidence records the binary
version, `gitleaks embedded default`, and `embedded-default`; the binary pin therefore also
pins its default detector configuration.

Pip-audit records its binary version, effective primary or direct-pin fallback invocation,
the PyPI vulnerability service, and the UTC time at which that service was queried.
OSV-Scanner records equivalent evidence for the OSV.dev live API.

The live PyPI and OSV scan responses do not expose an immutable advisory-database release
version. RepoAuditor therefore leaves `advisory_database_version` null rather than inventing
one, while retaining the authoritative database identity and query timestamp. This makes the
evidence boundary explicit: replay with the same binary and manifest can still change when
the upstream advisory service changes.

CI installs exact scanner binary versions in both the test and bounded-UAT workflows.
OPT-025 promotes the provenance assertions and deployment canaries into a required,
fail-closed scanner gate.

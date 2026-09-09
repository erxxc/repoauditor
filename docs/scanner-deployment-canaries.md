# Scanner Deployment Canaries

Status: implemented for the official and RepoAuditor supplemental Semgrep passes, gitleaks,
pip-audit, OSV-Scanner, and the embedded weak-RNG detector.

Run the isolated deployment check with:

```console
repoauditor scanner-canaries
repoauditor scanner-canaries --output scanner-canaries.json
```

The command exits successfully only when every scanner passes both controls. It does not
run model preflight, open the product finding store, ingest a repository, create classifier
labels, or contribute to evaluation and acquisition metrics. Temporary controls are deleted
after the run; the optional output contains execution-health metadata and counts, not the
generated candidate findings.

## Controls

| Scanner | Positive control | Non-positive control |
| --- | --- | --- |
| Semgrep | Python shell invocation matched by a local canary rule | Safe argument-vector invocation with no match |
| Semgrep supplemental | Variable JavaScript command passed to `execSync` | `execFileSync` argument-vector invocation with the shell disabled |
| gitleaks | Synthetic Stripe-shaped credential | Environment-placeholder text |
| pip-audit | Exact pin of a known vulnerable package | Applicable, deliberately empty requirements file |
| OSV-Scanner | Exact pin of a known vulnerable package | Root with no supported manifest (`not-applicable`) |
| Weak RNG | Java `new Random()` token generation | Java `SecureRandom` construction |

Each positive control must produce validated output, at least one applicable target, and at
least one finding. Each clean control must produce validated empty output over at least one
target. The OSV non-applicable control instead proves that absence of a supported manifest is
reported distinctly from a clean scan.

All controls travel through the production adapter subprocess and parser paths. The official
Semgrep control intentionally uses a repository-local rule so the canary itself does not
depend on mutable registry resolution. The supplemental control uses the exact packaged
owned ruleset and therefore also verifies its digest, rule count, positive behavior, clean
behavior, separate execution identity, and candidate attribution.
The weak-RNG control uses the production in-process adapter and verifies its embedded
configuration and snapshot-bound retrieval path without starting a subprocess.
Likewise, advisory counts may change as vulnerability databases change; the check requires a
nonzero positive result rather than an exact count. Pinning and retaining scanner
configuration and advisory provenance is tracked separately in OPT-024.

## Report interpretation

The JSON report uses schema version 2 and includes one result per scanner. `passed` is
fail-closed at both scanner and report level, and `provenance_passed` discloses the
scanner-specific OPT-024 check. Each probe embeds the common
`ScannerExecution` evidence: status, applicability, output validity, finding and target
counts, count basis, available version/configuration, and attributable failure detail.

`persisted_findings` is constrained to zero. This is an explicit invariant of the report,
not a count obtained by querying product storage: the canary orchestration has no storage or
ingestion dependency.

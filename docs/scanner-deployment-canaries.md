# Scanner Deployment Canaries

Status: implemented for Semgrep, gitleaks, pip-audit, and OSV-Scanner.

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
| gitleaks | Synthetic Stripe-shaped credential | Environment-placeholder text |
| pip-audit | Exact pin of a known vulnerable package | Applicable, deliberately empty requirements file |
| OSV-Scanner | Exact pin of a known vulnerable package | Root with no supported manifest (`not-applicable`) |

Each positive control must produce validated output, at least one applicable target, and at
least one finding. Each clean control must produce validated empty output over at least one
target. The OSV non-applicable control instead proves that absence of a supported manifest is
reported distinctly from a clean scan.

All controls travel through the production adapter subprocess and parser paths. The Semgrep
control intentionally uses a repository-local rule so the canary itself does not depend on
mutable registry resolution. It therefore verifies the binary, target submission, parser,
and adapter contract, but does not establish the provenance of the production ruleset.
Likewise, advisory counts may change as vulnerability databases change; the check requires a
nonzero positive result rather than an exact count. Pinning and retaining scanner
configuration and advisory provenance is tracked separately in OPT-024.

## Report interpretation

The JSON report uses schema version 1 and includes one result per scanner. `passed` is
fail-closed at both scanner and report level. Each probe embeds the common
`ScannerExecution` evidence: status, applicability, output validity, finding and target
counts, count basis, available version/configuration, and attributable failure detail.

`persisted_findings` is constrained to zero. This is an explicit invariant of the report,
not a count obtained by querying product storage: the canary orchestration has no storage or
ingestion dependency.

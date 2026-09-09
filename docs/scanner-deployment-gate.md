# Required Scanner Deployment Gate

Status: implemented in `.github/workflows/tests.yml`.

The `scanner deployment / required` job runs on every pull request, every push to `main`,
and manual test-workflow dispatch. Repository branch protection should require that exact
check name.

The job installs the same exact scanner binary versions used by bounded UAT and runs:

```console
repoauditor scanner-canaries --output scanner-canaries.json
```

The command exits nonzero unless all six scanner passes satisfy their positive,
clean/not-applicable, target-count, producer-schema, and scanner-specific provenance
controls. Provenance qualification requires:

- a version and normalized invocation for every positive and non-positive execution;
- a verified digest and nonzero rule count for the local Semgrep canary configuration;
- a verified digest, nonzero rule count, and separate execution identity for the
  RepoAuditor supplemental Semgrep pass;
- the binary-embedded default identity for gitleaks;
- live-service identity and UTC advisory query time for applicable pip-audit and OSV runs;
  and
- an explicit OSV `not-applicable` result where the negative root has no manifest.
- the embedded `weak_rng@v1` identity and its Java positive/clean controls.

The workflow publishes the JSON report to the GitHub step summary and retains it with the raw
binary-version output for 30 days, including failed runs when those files were produced.
Canary orchestration remains isolated from ingestion and product storage, with
`persisted_findings` constrained to zero.

The larger public-corpus scanner matrix remains manual in `bounded-corpus-uat`. It is not
part of the required pull-request gate because it depends on a separately validated corpus
cache and measures broader detector behavior rather than deployment health.

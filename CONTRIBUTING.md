# Contributing and test lanes

Repoauditor separates fast pipeline checks from tests that intentionally invoke external
scanners, full-size calibration, chart rendering, or paid model APIs. Assertions are not
removed from slower lanes; the markers make their runtime and operating requirements
explicit.

## Required pull-request lane

```sh
uv sync --python 3.12
uv run pytest -m "not integration and not live"
```

This deterministic lane runs on every pull request and push to `main`. It includes the
scripted golden pipeline, per-stage `EvalRun` recording, and regression gates. Scripted
pipeline fixtures return fixed empty scanner output through the real ensemble adapter seam;
they do not launch scanner subprocesses whose behavior is covered in the integration lane.
The expected runtime is under 60–90 seconds on a typical CI runner.

Repository administrators must make the GitHub check named `fast / required` a required
branch-protection check for `main`; workflow files cannot set repository branch protection.

## Integration lane

```sh
uv run pytest -m "integration and not live"
```

This lane retains real Semgrep, pip-audit/OSV-Scanner, and gitleaks verification, the
full-size 2,000-row triage calibration, and real matplotlib chart generation. CI installs
pinned scanner versions and runs the lane after every merge/push to `main`, as well as on a
manual dispatch. A failure therefore blocks a healthy `main` signal even though scanner
startup is not duplicated on each pull request.

## Live-model lane

```sh
REPOAUDITOR_LLM=live ANTHROPIC_API_KEY=... uv run pytest -m live
```

This paid/provider lane runs automatically every Tuesday and can also be dispatched
manually. It exercises the golden and benchmark corpora against the configured live model.
Configure `ANTHROPIC_API_KEY` as an Actions environment secret in the
`live-model-tests` environment; do not store it in repository variables, workflow YAML, or
test output. The workflow checks only whether the secret is non-empty and never prints its
value. For automatic scheduled execution, do not configure required reviewers on that
environment. A missing secret fails clearly rather than silently presenting an unexecuted
live check as coverage.

The three lane commands are intentionally mutually clear: `integration` covers local,
deterministic external tools and expensive local computation; `live` covers real model API
calls; the default PR lane excludes both.

## Public-corpus cache lane

The `public corpus cache` workflow runs every Sunday and on manual dispatch. It restores an
immutable cache of the 19 acquisition-only public snapshots, or fetches and archives their
exact pinned commits on a cache miss. Its key is derived from the materializer plus every
independent/OWASP corpus metadata file, so a pin or acquisition-code change cannot silently
reuse stale source. There is deliberately no broad restore key.

This lane runs only provenance, pre/post-pair, citation, and negative-control integrity tests.
It never imports or executes acquired source, invokes a scanner, or calls a hosted model.
The small JUnit result is retained for 30 days; the roughly 231 MB source corpus remains an
Actions cache rather than a repository artifact. GitHub controls cache eviction, and the
weekly cadence keeps an actively used cache warm. If a cache is suspected to be corrupt,
delete that exact key in **Actions → Caches** and rerun the workflow; caches are immutable.

For a local cold materialization (network access is explicit):

```sh
python tests/fixtures/materialize_public_corpus.py /tmp/repoauditor-corpus-clones --fetch
uv run pytest tests/test_benchmark_corpus.py -m "not integration and not live"
```

## Bounded corpus UAT

The manual `bounded corpus UAT` workflow has two deliberately separate modes:

- `deterministic` restores the exact validated corpus cache and runs Semgrep, pip-audit,
  OSV-Scanner, and gitleaks over Django, Lodash, Commons Text, and Rack pre/post pairs,
  plus the Juice Shop anchor. It emits JSON with target-CVE hits, patched-target
  persistence, tool counts, and candidates awaiting analyst adjudication.
- `live-lightweight` runs the real Anthropic-backed pipeline only on the 12-file
  purpose-built UAT fixture. It requires the `live-model-tests` environment secret and an
  explicit paid-run acknowledgement. It does not install scanners, so the result isolates
  the model path and says so in the artifact.

The independent-project metadata documents one historical CVE per project; it is not an
exhaustive vulnerability inventory. Therefore the deterministic mode does **not** call every
unmatched scanner candidate a false positive or publish a project-level precision number.
Analysts must adjudicate those candidates first. Likewise, the lightweight fixture result is
reported as fixture-derived calibration, never as independent real-world performance.

Both modes retain their JSON/JUnit evidence for 30 days. UAT artifacts are evaluation
evidence, not training labels: to add a reviewed outcome to the triage corpus, scan the
repository as a persistent engagement and use `repoauditor triage-label` with an analyst and
rationale. Use `uncertain` when the evidence does not support TP or FP.

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

The manufactured-sentinel control runs automatically every Tuesday. On the first day of
each month, the live lane runs only the pinned `serialize-javascript` pre/post pair. Manual
dispatch defaults to `sentinels-only`; `live-lightweight` selects only the 12-file UAT
fixture and `bounded-independent` selects that same small independent pre/post pair.
There is deliberately no monolithic paid full-corpus option: one Juice Shop evaluation
exhausted the configured provider allowance before producing a result.
Configure `ANTHROPIC_API_KEY` as an Actions environment secret in the
`live-model-tests` environment; do not store it in repository variables, workflow YAML, or
test output. The workflow checks only whether the secret is non-empty and never prints its
value. For automatic scheduled execution, do not configure required reviewers on that
environment. A missing secret fails clearly rather than silently presenting an unexecuted
live check as coverage.

The three lane commands are intentionally mutually clear: `integration` covers local,
deterministic external tools and expensive local computation; `live` covers real model API
calls; the default PR lane excludes both.

Detection reliability includes semantic citation integrity in addition to schema validation.
Every LLM citation must occur verbatim in indexed repository source. A unique match
canonicalizes the file and line range with provenance; zero or multiple unresolved matches
produce a `detect.citation` validation-failure record and no Finding. Regression fixtures
must cover relocation as well as absent/ambiguous rejection.

Repository text is adversarial model input. Detect and falsify compose their stage prompts
with the shared versioned policy under `src/repoauditor/llm/prompts/` and delimit all
candidate and retrieval evidence. Changes to that policy require a new artifact version,
provenance update, adversarial boundary tests, and the same golden-harness regression gate
as any other prompt change.

The Python slicing MVP under `falsify/slicing.py` is evidence construction, not a verdict
engine. Tests must preserve its explicit limitations and incomplete states. A slice may add
source/assignment/sink or sanitizer-candidate context for SQLi, command injection, and SSRF;
it must never independently confirm or kill a finding.

`falsify/claims.py` translates supported slices into versioned structural claims and a
separately versioned verifier result. Keep claim and verifier writes idempotent, preserve
their exact evidence and pinned snapshot commit in `store/`, and keep the verifier independent
of the slicer's in-memory result. Never interpret `structurally_verified` as proof of
exploitability, end-to-end reachability, control effectiveness, or risk.

## Public-corpus cache lane

The generated `independent_*/snapshot/` and `anchor_owasp_*/snapshot/` directories are
gitignored acquisition artifacts; never force-add them. The `public corpus cache` workflow
runs every Sunday and on manual dispatch. It restores an
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

The human-label acquisition cohort is separate from that evaluation cache. Materialize its
eight pinned, permissively licensed projects without touching the evaluation snapshots:

```sh
python tests/fixtures/materialize_public_corpus.py \
  /tmp/repoauditor-training-clones \
  --training-acquisition-only \
  --fetch
```

The generated `acquisition_*/snapshot/` directories are ignored and must not be committed.
They contain no expected-finding keys and are never evaluation evidence. Verify Community
ruleset access separately, before scanning any cohort member:

```sh
mkdir -p /tmp/repoauditor-semgrep-ruleset-probe
semgrep scan --config auto --json --metrics auto --disable-version-check \
  /tmp/repoauditor-semgrep-ruleset-probe
```

The probe is intentionally empty: it verifies registry/ruleset resolution without letting
scanner yield influence cohort selection. Semgrep's `auto` resolver currently refuses
`--metrics off`; operators who cannot permit that behavior must use a separately reviewed,
explicitly pinned ruleset instead of silently claiming `auto` coverage.

The mechanism-diverse CVE-positive training cohort is also acquisition-only:

```sh
python tests/fixtures/materialize_public_corpus.py \
  /tmp/repoauditor-cve-positive-clones \
  --cve-positive-acquisition-only \
  --fetch
```

This produces exact pre-fix/post-fix pairs but does not make them evaluation fixtures or
automatically label scanner output. Do not execute acquired source.

## Bounded corpus UAT

The manual `bounded corpus UAT` workflow has two deliberately separate modes:

- `deterministic` restores the exact validated corpus cache and runs Semgrep, pip-audit,
  OSV-Scanner, and gitleaks over Django, Lodash, Commons Text, and Rack pre/post pairs,
  plus the Juice Shop anchor. It emits JSON with target-CVE hits, patched-target
  persistence, Semgrep run status, binary availability, pre/post deltas, tool counts,
  and candidates awaiting analyst adjudication. Raw candidates remain in the artifact;
  pair-stable signals are also collapsed into a realistic review-workload count.
- `live-lightweight` runs the real Anthropic-backed pipeline only on the 12-file
  purpose-built UAT fixture. It requires the `live-model-tests` environment secret and an
  explicit paid-run acknowledgement. It does not install scanners, so the result isolates
  the model path and says so in the artifact. Its version-2 scorer measures only
  falsification-confirmed, deduplicated issues. The scanner-only dependency case is excluded
  from model recall; killed, unresolved, and deferred findings are disclosed separately;
  and severity agreement is reported separately from finding identity. Each JSON result
  includes case-level matching evidence and unmatched confirmed groups for review.
  Negative controls distinguish an end-to-end pass (absent or correctly killed) from a
  falsification exercise (raised and killed), and unavailable expected scanner sources are
  reported as partial coverage rather than silently treated as tested.

The independent-project metadata documents one historical CVE per project; it is not an
exhaustive vulnerability inventory. Therefore the deterministic mode does **not** call every
unmatched scanner candidate a false positive or publish a project-level precision number.
Analysts must adjudicate those candidates first. Likewise, the lightweight fixture result is
reported as fixture-derived calibration, never as independent real-world performance.
Version-1 and version-2 lightweight scores are not directly comparable because version 2
corrects the evaluated population and denominator; its EvalRun lineage is
`corpus-v2::uat_lightweight_app`.

Both modes retain their JSON/JUnit evidence for 30 days. UAT artifacts are evaluation
evidence, not training labels: to add a reviewed outcome to the triage corpus, scan the
repository as a persistent engagement and use `repoauditor triage-label` with an analyst and
rationale. Use `uncertain` when the evidence does not support TP or FP.

The application also enforces the `[llm]` per-pipeline call and provider-reported token
ceilings in `config.toml`. These complement the Actions wall-clock timeouts: the call limit
terminates fast provider-error/retry storms, while the token limit stops before the next
request after the recorded total reaches its ceiling. Provider calls without returned usage
metadata count toward the call ceiling and remain explicitly unknown in token totals.

The `live model tests` workflow's `bounded-independent` scope restores the same exact
validated public-corpus cache before making any paid calls. It fails before evaluation when
that cache is unavailable; it never silently skips acquisition-only entries or fetches a
floating revision. Paid corpus execution is constrained to one declared cohort, stops on
the first test/provider failure (`pytest -x`), and is terminated after 20 minutes
(`timeout`, with a 30-second forced-kill grace). The step has a 22-minute Actions ceiling
and the whole job a 30-minute ceiling. During the run, each completed fixture is named in
verbose pytest output and appended to
`live-corpus-results.json`, and pytest writes `live-corpus-junit.xml`. Both are uploaded
even when a later fixture fails, so a long paid run retains its partial evidence rather than
collapsing to a final traceback. Scanner-dependent fixtures are absent from these
model-only cohorts. Large OWASP anchors remain available to the free retrieval/scanner
lanes, but are not submitted to the hosted model by this workflow.

The cache workflow and paid independent lane also run the zero-network corpus-readiness
audit. Metadata must identify exactly one protected independent pre/post holdout, and the
paid lane additionally requires both pinned snapshots to be materialized before it
qualifies the model or begins corpus evaluation. See
`docs/offline-readiness-runbook.md`.

For native retrieval failures, manually dispatch `live model tests` with
`retrieval-diagnostic`. This scope restores and requires the exact public-corpus cache, then
runs only the Juice Shop retrieval smoke test with flushed per-file diagnostics. It skips
the API-key check, manufactured controls, and all live corpus tests, so it makes no model
calls. The final `retrieval diagnostic: indexing ...` log entry identifies the file active
at a native crash. It is the cache-backed parser check for the large Juice Shop anchor and
does not unlock a paid full-corpus sweep.

The July 2026 Juice Shop diagnostic isolated a native failure in
`data/datacreator.ts`: `tree-sitter 0.26.0` returned corrupted TypeScript coordinates and
then exited 139, while 0.25.2 extracted the same pinned file with valid locations. The
runtime is therefore constrained to `>=0.25,<0.26` until a later release is independently
verified against this cache-backed smoke test; do not relax that bound based only on unit
fixtures.

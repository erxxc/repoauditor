# Offline readiness and paid calibration runbook

This runbook separates zero-network preparation from the later provider/cache-dependent
steps. Do not collapse the two: metadata readiness is not evidence that a live model works,
and a paid run is not permission to train on the protected holdout.

## What can run offline

Audit corpus provenance, roles, and local materialization:

```sh
uv run python tests/fixtures/audit_corpus_readiness.py \
  --output data/corpus-readiness.json
```

The audit performs no network access. `metadata_ready=true` means the checked-in manifests
have the required independent-project provenance and exactly one protected pre/post pair.
`online_execution_ready=false` means a pinned snapshot cache still must be restored; it is
not an evaluation failure and must not be silently skipped.

Run the required default tests:

```sh
uv run pytest -m "not integration and not live"
```

Inspect controlled adjudication progress and unrepresented target dimensions:

```sh
uv run repoauditor triage-collection
```

The dimension view is descriptive. Merely declaring a dimension does not advance the
40-label/eight-engagement activation gate, and uncertain assessments remain abstentions.

## Fixed evaluation roles

- `uat_lightweight_app` is `calibration_fixture`: useful for operational consumption and
  regression checks, never independent real-world evidence.
- `independent_serialize_javascript_pre` and
  `independent_serialize_javascript_post` are one `protected_holdout` pair. Do not use their
  findings, verdicts, or labels for training, prompt development, threshold selection, or
  ground-truth generation.
- Every finding label remains human-reviewed advisory/patch evidence; repoauditor output
  never becomes its own ground truth.

Changing a checked-in expectation manifest changes the trusted corpus-cache key. Any such
change requires the public-corpus cache workflow to rebuild the exact pinned cache before a
bounded independent live run. Never weaken the cache-miss failure.

## Later online sequence

Only after the provider allowance and protected cache are available:

1. Run the public-corpus cache workflow and confirm both protected snapshots materialize at
   their declared commits.
2. Run one fresh foreground pipeline over the lightweight snapshot. Stop and inspect its
   status and authoritative usage before authorizing the protected pair; do not queue all
   three paid runs blindly.
3. Run one fresh foreground pipeline over each protected pre/post snapshot only if the
   lightweight run completed within the existing ceilings.
4. If a run stops with a deferred backlog, use `repoauditor resume <repo-id>` until the
   backlog reaches zero. Record the **terminal run id** for each logical scan. Linked
   continuation batches are aggregated automatically; review/finalize is not required.
5. Produce the offline comparison:

```sh
uv run repoauditor usage-calibration \
  --lightweight-run-id <id> \
  --independent-pre-run-id <id> \
  --independent-post-run-id <id> \
  --format json
```

The command makes no provider calls. It fails closed unless the terminal batch completed,
the terminal falsify stage has no deferred findings, the logical scan recorded provider
calls, and every call returned token metadata. Intermediate recovered-failure statuses
remain disclosed in the chain and their usage is retained. The report shows total chain
usage plus peak single-batch utilization of the current 75-call/250,000-token ceilings, but
never recommends or applies a new limit.

The scheduled/manual live-test workflow is a separate model-capability lane. It uses the same
call/token scope and writes authoritative usage totals into its uploaded result, but its
pytest store is temporary. Use those artifacts for workflow safety and accuracy review; use
three foreground runs in one persistent local store when producing the formal
`usage-calibration` comparison above.

For a large repository, inspect `run`'s detection preflight before authorizing provider
work. The output distinguishes the unbounded call projection from the configured bounded
region plan. If a bounded detect pass stops, run `repoauditor detect <repo-id>` again under a
fresh budget; persisted file+lens checkpoints prevent completed units from being re-billed.
If the original pipeline run already exhausted its total budget, continue through standalone
`triage`, `falsify`, and `normalize` operations rather than reusing that exhausted run id.
Never raise a limit merely to approximate all-files × all-lenses coverage, and never
describe omitted regions as model-reviewed.

### Lightweight observations and completed harness corrections

Actions run `30228015245` on 2026-07-27 passed all four manufactured controls, then stopped
before normalize/scoring because 18 findings remained deferred. That is a successful
fail-closed safety observation, not a completed accuracy or capacity result. Its failure
artifact retained JUnit evidence but not partial authoritative usage, so it cannot justify a
limit change or the protected-pair run.

The following harness corrections were completed before the later successful runs:

1. usage, queue state, batch identity, and failure detail are emitted on terminal paths;
2. deferred work continues through linked, freshly bounded batches without rerunning
   map/detect/triage;
3. the complete batch chain is aggregated and zero deferred findings are required before
   normalize/scoring; and
4. failure artifacts and multi-batch completion retain offline regression coverage.

Keep the 75-call/250,000-token per-batch ceilings unchanged while making this correction.
The first continuation run drained four findings per continuation batch and stopped at the
four-batch cap with eight remaining, after 74 calls and 238,555 known tokens. Based on that
observed queue rate, the approved rerun caps each fixture at six total linked batches and
retains its 20-minute process timeout. Its conservative outer bounds are therefore 450 calls
and 1,500,000 provider-reported tokens, although the measured projection is roughly 90 calls
plus normalization and about 280,000 tokens plus normalization; the wall-clock timeout
remains an independent stop.
Reaching any bound produces a failure artifact rather than a partial score. The completed
lightweight run (`30229939662`) used 108 calls and 357,170 known input/output tokens across
six linked batches with zero deferred findings. These are observations, not justification
for changing the ceilings. The protected pair was authorized only after that artifact was
reviewed.

### Protected-pair observation

Actions run `30230644266` completed both serialize-javascript snapshots with no deferred
findings. The pre-fix scan used 28 calls and 121,403 known input/output tokens across two
batches; the post-fix scan used 18 calls and 97,018 known tokens in one batch. These are
operational observations, not permission to raise a limit.

The original artifact's legacy precision/recall fields are invalid for this protected pair:
the ground truth covers one reviewed historical CVE, not every possible finding in the
repository, and the legacy scorer treated unresolved findings as countable. Offline
rescoring against the retained database gives the defensible interpretation:

- pre-fix: the CVE-2019-16769 target was raised but remained `unresolved`; this is an
  abstention, so confirmed target recovery failed;
- post-fix: no confirmed or unresolved signal matched CVE-2019-16769; the negative control
  passed; and
- one different post-fix confirmation is `unadjudicated`, not an automatic false positive.

Protected-pair evaluation therefore reports target recovery/persistence and unadjudicated
confirmed groups, never project-wide precision. Only falsification-confirmed target matches
count as recovery; unresolved matches remain visible abstentions.

### CVE-positive semantic pilot

The manual `cve-positive-pyjwt` scope in the `live model tests` workflow is the first
evaluation initialized from `cve_positive_acquisition_cohort.json`. It is intentionally not
scheduled and cannot expand to the other three pairs automatically. Run the `public corpus
cache` workflow first; the live workflow fails before provider use unless the exact
`public-corpus-v2` cache contains every frozen pre/post snapshot.

The pilot always runs PyJWT pre-fix before post-fix, stops on the first failure, allows at
most two linked batches per snapshot, and retains the existing 75-call/250,000-token
per-batch circuit breakers plus a 20-minute outer timeout. Its paid semantic evaluation is
now restricted to the frozen advisory target file. Before substituting that file, the
harness records the unchanged production planner's ground-truth-blind region selection.
The artifact labels these as `target-conditioned` semantic evidence and production
retrieval coverage respectively; forced target inclusion never receives coverage credit.
This is evaluation-harness behavior only and does not alter production detection planning.

The first one-batch pilot (Actions run `30320579789`) qualified all four manufactured
controls, then stopped after the PyJWT pre-fix snapshot with five deferred findings. Its
single batch used 33 calls, 149,952 input tokens, and 6,848 output tokens with no unknown
usage. No post-fix work or target score ran. The two-batch cap is therefore an
evidence-based continuation allowance for this same pair, not permission to expand the
cohort or raise the underlying per-batch circuit breakers.

The two-batch follow-up (Actions run `30322316600`) again qualified all four controls. It
used 82 calls, 403,365 input tokens, and 16,311 output tokens across the pair. The pre-fix
target was not detected, but `jwt/algorithms.py` was absent from the production region plan,
so this is a retrieval-coverage miss rather than a valid semantic-detector measurement.
The post-fix snapshot stopped with two deferred non-target findings. That result motivated
the target-conditioned harness above; rerunning the unchanged whole-repository pilot would
spend more without resolving the confound.

The target-conditioned baseline (Actions run `30323666007`) completed both snapshots in
one batch each with no deferred findings. All four manufactured controls passed. The pair
used 17 calls and 164,537 known tokens. The pre-fix target was not raised even with
`jwt/algorithms.py` supplied explicitly; post-fix had no target signal. The structured
receipt is
[`pyjwt-target-conditioned-baseline-2026-07-28.json`](pyjwt-target-conditioned-baseline-2026-07-28.json).
It also records the separate production-selection outcome and the context diagnostic.
Because that diagnostic now informs development, PyJWT is not an untouched validation
target for subsequent context-construction changes.

`detection_context_v2` is the resulting generic correction. It retrieves bounded external
syntactic call-name matches for functions defined in the primary file before falling back
to external similar-pattern matches; same-file blocks already present in the primary region
are not repeated. Production paths rank ahead of test paths, and candidates matching more
primary definitions rank higher within each class. The version is part of detection
checkpoint/evaluation provenance. Validate it on another frozen pair that did not motivate
the change. A later PyJWT rerun is development confirmation only, never an unbiased gate.

### Completed simple-git validation

The manual `cve-positive-simple-git` scope was the first independent validation of
`detection_context_v2`. Its commits, target, and acceptance criteria were frozen in
`cve_positive_acquisition_cohort.json` before the context change:

- pre-fix `f8cb7df3feb3c135d2e10803586d64dfe6a2bfe9`: a
  falsification-confirmed match for CVE-2026-28292 is recovery; unresolved is an abstention;
- post-fix `f7042088aa2dac59e3c49a84d7a2f4b26048a257`: any matching signal is disclosed and
  confirmed persistence fails the negative control; and
- confirmed non-target findings remain unadjudicated because the project answer key is not
  exhaustive.

Actions run `30325190074` completed both target-conditioned snapshots and passed all four
manufactured sentinels. It used 31 calls, 141,839 input tokens, 10,473 output tokens, and
195,273 ms of recorded model latency. The production planner omitted the target file in
both snapshots. At the advisory line, the model raised candidates about wildcard-dot
matching; manual adjudication found those to be a different mechanism from the missing
case-insensitive flag in CVE-2026-28292. The pre-fix target was therefore not recovered,
and same-line post-fix output was not a persisted target signal. The exact receipt is
[`simple-git-target-conditioned-baseline-2026-07-28.json`](simple-git-target-conditioned-baseline-2026-07-28.json).

This exposed a scoring defect: location overlap had been treated as target matching without
semantic adjudication. The scorer now reports location candidates separately and counts a
target only after a human marks its mechanism `target_match`. Missing adjudication remains
pending, never an inferred match. The supported regex-control bypass family also now
requires a concrete, checkable witness before a confirmation can commit. These corrections
make simple-git development evidence; it is no longer an untouched validation target.

The paid run was target-conditioned on
`simple-git/src/lib/plugins/block-unsafe-operations-plugin.ts` while separately recording
the unchanged production region plan. The next pair must retain this separation: forced
inclusion measures semantic handling, while unchanged production selection measures
planner coverage.

Acceptance is target-scoped and was frozen before execution:

- pre-fix: a semantically adjudicated, falsification-confirmed match is recovery;
  unresolved is an abstention;
- post-fix: any matching signal is disclosed, and confirmed persistence fails the negative
  control; and
- confirmed findings outside CVE-2026-28292 remain unadjudicated rather than becoming
  automatic false positives.

Review the JSON artifact, JUnit result, and retained SQLite usage evidence before enabling
another CVE-positive pair. Do not change prompts, thresholds, target locations, or budgets
from the pilot result; that would turn this acquisition check into tuning on its answer key.

### Completed validation: Reposilite

Reposilite CVE-2024-36116 is the next pair. It was selected before ruby-saml because it
has one localized Kotlin archive-traversal target, while ruby-saml combines two CVEs, an
XML parser differential, signature wrapping, and a seven-file patch. The previous Semgrep
partial-parse warning came from a Gradle wrapper script, not the target Kotlin file.

Actions run `30327552345` passed all four falsification sentinels and completed both
snapshots, but the validation gate failed. The target-conditioned detector raised zero
findings pre-fix and post-fix, so no finding reached falsification or human semantic
adjudication. The unchanged production planner also omitted the target in both variants.
The pair itself used 10 calls, 177,789 input tokens, and 8,982 output tokens; qualification
usage was not retained in its JSON and is therefore not fabricated. The structured receipt
is
[`reposilite-target-conditioned-baseline-2026-07-28.json`](reposilite-target-conditioned-baseline-2026-07-28.json).

The production omission was structural rather than merely a ranking miss: `.kt` and `.kts`
were absent from the shared source inventory, so map/retrieval/planning could not select the
Kotlin target. The forced semantic miss exposed a separate lens gap: OWASP v1 did not
explicitly cover path traversal or unsafe archive extraction, while the other two lenses
exclude or do not apply to this application mechanism.

The offline correction adds bounded Kotlin visibility without changing the existing map
file/character budgets or detection region cap. Kotlin retrieval initially uses the
explicit logged lexical fallback rather than an untested AST inference. `owasp_v2` assigns
path traversal and unsafe archive extraction to the OWASP lens, and a zero-token
manufactured pair checks a concrete escaping archive entry against vulnerable and
normalized-containment shapes. Qualification usage is now included in the structured
`qualify-instrument --format json` output.

The manual Actions scope was `cve-positive-reposilite`. It required the exact validated
public-corpus cache and a passing manufactured-instrument qualification, then ran the
pre-fix commit before the post-fix control. It retains the existing two-batch maximum per
snapshot, provider call/token ceilings, and 20-minute outer timeout. Target-conditioned
semantic evaluation and unchanged production-planner selection remain separate.

Scoring now requires human semantic adjudication. A same-file or same-line alert is only a
location candidate. Pre-fix recovery requires `target_match` plus a falsification-confirmed
verdict; unresolved is an abstention. Post-fix confirmed persistence of a semantically
matched target fails the negative control. Non-target findings remain unadjudicated because
the answer key is intentionally not exhaustive.

The exact commits, target, acceptance criteria, ceilings, and prohibited post-result changes
are frozen in
[`reposilite-validation-plan-2026-07-28.json`](reposilite-validation-plan-2026-07-28.json).
Reposilite is development evidence after this diagnosis. Do not use a rerun as an untouched
gate. Qualify the new archive-detection prompt on manufactured controls first; preserve
ruby-saml as the next independent validation target.

## Analyst decision after collection

Keep the current limits unless the three-run evidence demonstrates a specific operational
problem. If a change is proposed, record:

- the exact three run IDs and snapshot commits;
- provider/model and prompt versions;
- calls, input/output/cache tokens, unknown-usage count, and latency per run;
- whether a ceiling stopped a run;
- why the proposed ceiling still bounds unattended loss if the provider fails quickly.

One lightweight fixture and one independent pair are calibration evidence, not a universal
capacity model for every large repository. Any larger operating profile remains an explicit
analyst-approved configuration, never an automatic escalation.

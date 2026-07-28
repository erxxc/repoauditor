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

The pilot always runs PyJWT pre-fix before post-fix, stops on the first failure, allows
exactly one bounded batch per snapshot, and retains the existing 75-call/250,000-token
per-batch circuit breakers plus a 20-minute outer timeout. Thus its conservative ceiling is
150 calls and 500,000 provider-reported tokens across both snapshots, although a timeout
or earlier pipeline stop should end it first. These are safety limits, not spending targets.

Acceptance is target-scoped and was frozen before execution:

- pre-fix: a falsification-confirmed match is recovery; unresolved is an abstention;
- post-fix: any matching signal is disclosed, and confirmed persistence fails the negative
  control; and
- confirmed findings outside CVE-2022-29217 remain unadjudicated rather than becoming
  automatic false positives.

Review the JSON artifact, JUnit result, and retained SQLite usage evidence before enabling
another CVE-positive pair. Do not change prompts, thresholds, target locations, or budgets
from the pilot result; that would turn this acquisition check into tuning on its answer key.

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

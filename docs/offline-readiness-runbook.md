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

Changing a checked-in expectation manifest changes the trusted corpus-cache key. After this
offline-readiness change merges, the public-corpus cache workflow must rebuild the exact
pinned cache before a bounded independent live run. Never weaken the cache-miss failure.

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

# POC Acceptance Walkthrough — 2026-07-28

Status: **accepted**, signed off by project owner `erxxc` on 2026-07-28.

This is the sanitized, durable record of the clean-environment walkthrough. Raw logs, the
review-session SQLite store, generated reports, and scorecards remain locally under
`data/acceptance/2026-07-28/` and are excluded from version control.

## Evaluation boundary

- Reviewer: independent alternate reviewer agent operating as a non-security user.
- Source: clean clone of commit `442b07682a65709443707c39ded617f32b07bf22`.
- Platform: macOS, Python 3.12.
- Provider/model: Anthropic / `claude-opus-4-8`.
- Elapsed time: approximately 40 minutes.
- The reviewer did not inspect the fixture answer key or planted-source annotations before
  the pipeline produced its scorecard.
- No code, prompt, configuration, fixture, or expected-result data was changed during the
  evaluation.

## Acceptance results

The walkthrough demonstrated the documented new-user path:

1. A clean install completed successfully.
2. `doctor` initialized the SQLite schema and reported scanner availability.
3. With no API key, `demo` stopped before scanning, exited nonzero, and printed actionable
   environment-variable guidance without persisting a key.
4. `doctor --check-model` verified Anthropic authentication, model access, and structured
   output.
5. `demo` completed ingest through its bounded falsification checkpoint.
6. Eight documented `resume` operations cleared the deferred falsification backlog.
7. Twelve review requests were decided from CLI-presented evidence with recorded rationales.
   Because the evaluator had no interactive TTY, it used the README-documented
   `review list`/`review decide` path instead of the equivalent interactive prompts.
8. `demo --continue` produced the architecture map, engineering backlog, leadership memo,
   quantitative appendix, and Markdown/JSON UAT scorecards.
9. All eleven recorded operations completed; none failed.

The generated architecture artifact was retained with the local acceptance evidence as
`data/acceptance/2026-07-28/architecture-d5f8bf9e856c.txt` (42 lines, SHA-256
`a2de2d0116762575b0b2da4531347b69f1bfd821d3612701c68e997dd5c23823`). It contains the
recovered entry-point/trust-boundary associations, datastore inventory, outbound
integrations, and explicit completeness limitations. It remains gitignored with the raw
acceptance evidence.

The scorecard reported:

- 10/10 final security outcomes passed.
- 8/10 expected mechanisms exercised.
- Cases 7 and 8 were safe negative outcomes for which detection raised no candidate, so the
  intended falsification mechanism could not be exercised. The scorecard disclosed their
  zero source coverage separately rather than treating absence as demonstrated
  falsification.

The run used 148 model calls and 413,352 processed tokens across the model check, initial
demo, and eight bounded resume operations. The largest individual operation used 27 calls
and 94,833 tokens, below the configured per-run limits of 75 calls and 250,000 tokens.

## Coverage and quantitative disclosures

- gitleaks completed with one redacted finding.
- pip-audit completed through full transitive resolution.
- Semgrep completed successfully with zero matches.
- OSV-Scanner failed because version 2.4.0 did not discover the fixture's bare
  `requirements.txt` through the adapter's recursive directory invocation. The failure and
  attributable detail were disclosed; pip-audit provided SCA coverage for this run.
- The bounded LLM plan selected 6 of 12 candidate files and completed 18 file/lens units.
- The quantitative integrity audit reported five blocking
  `organization_frequency_repeated_per_finding` issues. CLI, memo, and appendix output all
  carried the required experimental/not-decision-grade warning.

## Region-plan finding

The selected region plan did not include `storefront/orders.py`. Nevertheless, cross-file
context surfaced a confirmed IDOR finding with a citation that passed citation-integrity
validation against that file. This resolves the earlier UAT IDOR investigation: the prior
zero-candidate result was not enough to establish a stable semantic miss, while this run
shows that bounded selection and retrieved citation scope are not identical.

The complete plan was stored in `detection_region_run`, but `runs show` did not expose it for
the demo/resume lineage. The reviewer needed a direct read-only store query. This is a
traceability improvement, not a blocker under the current POC Definition of Done.

## Acceptance decision

The reviewer recommends **ACCEPTED** against
[`poc-definition-of-done.md`](poc-definition-of-done.md). Installation, missing-key
behavior, bounded execution, review/finalization, artifacts, coverage disclosure, and
quantitative gating were demonstrated in a clean environment. The independently sourced
semantic and untouched-selection requirements remain satisfied by their separately frozen
aiohttp and Plotly.js evidence.

Project owner `erxxc` explicitly accepted the independently operated reviewer agent as
satisfying the intended “non-security user” acceptance boundary on 2026-07-28. The POC
Definition of Done is complete. A future human usability study may improve the product, but
it is not retroactively added to the completed POC acceptance criteria.

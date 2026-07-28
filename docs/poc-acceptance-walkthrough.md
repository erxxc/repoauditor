# POC Acceptance Walkthrough

Status: **ready to execute after the quantitative-output gate merges**.

This is the final POC acceptance check. It is intentionally written for a reviewer without
a security background. The reviewer should use a clean checkout and the README only; project
engineering may observe, but should not translate commands or make review decisions for them.

## Reviewer and environment

- Reviewer:
- Date/time:
- Operating system:
- Clean checkout commit:
- Model/provider:
- Start time:
- End time:

Do not record an API key in this document, terminal history, screenshots, or artifacts.

## Acceptance procedure

1. Follow `README.md` from **New to the command line? Start here** through installation.
2. Run `uv run repoauditor doctor`.
3. Before providing a credential, run `./demo` and confirm it stops before scanning with:
   - `Demo cannot start: no API key present`
   - the exact environment-variable command needed
   - a statement that the key is not written to the repository.
4. Set the provider key only in the current terminal and run
   `uv run repoauditor doctor --check-model`. Confirm the command warns that the request may
   incur a charge and reports endpoint/auth/model/structured-output readiness.
5. Run `./demo`.
6. At the review checkpoint, read the evidence without an engineer interpreting it. Record a
   `confirm` or `dismiss` decision and a short rationale when prompted.
7. Confirm the demo finishes or pauses safely within its documented usage limits; it must not
   loop or continue spending after a terminal failure.
8. Confirm the artifact recap identifies:
   - the architecture map,
   - engineering report,
   - leadership memo,
   - quantitative appendix,
   - Markdown and JSON UAT scorecards.
9. Open the memo and quantitative appendix. Confirm any blocking quantitative-integrity
   finding is visibly labelled experimental and not decision-grade.
10. Run `uv run repoauditor runs list --repo-id uat_lightweight_app` and verify the run is
    recorded with a terminal status.

## Evidence record

- Dependency preflight: pass / fail
- Missing-key behavior: pass / fail
- Live model check: pass / fail
- Guided scan: pass / fail
- Human review: pass / fail / not reached
- Finalization and artifacts: pass / fail / not reached
- Quantitative limitation disclosure: pass / fail / not applicable
- Durable terminal run record: pass / fail
- Total elapsed time:
- UAT score:
- Artifact paths:
- Reviewer confusion or intervention required:

## Acceptance rule

The POC is accepted only when every applicable item above passes and the independent reviewer
can complete the workflow from the README without undocumented engineering intervention. A
failed or confusing item is recorded as either:

- an MVP blocker when it prevents the validated Definition of Done; or
- the next numbered entry in `optimizations/optimization-register.md` when the core workflow
  remains complete and the change is usability tuning.

Reviewer sign-off:

Project-owner sign-off:

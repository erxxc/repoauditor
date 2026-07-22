# CLAUDE.md — architectural rules for repoauditor

These rules are non-negotiable and cross-session. The design source of truth is
[`repoauditor-scaffold.md`](repoauditor-scaffold.md). If a change appears to require
breaking one of these, stop and ask before proceeding.

## Pipeline

```
ingest -> map -> detect -> triage -> falsify -> normalize -> review -> analyze -> report
```

The `map` stage runs **before** any detection. Vulnerability hunting is conditioned
on the architecture/trust-boundary map — every finding must trace back to a trust
boundary (foreign key), so it is clear *why it matters architecturally*, not just
*what pattern matched*.

The `triage` stage runs **after** `detect` and **before** `falsify`. It re-ranks
deterministic-tool findings by P(actionable) using a calibrated classifier (not an
LLM) so the expensive LLM-driven falsification pass spends its budget on the
findings most likely to matter first. Triage is a ranking/prioritization layer,
never a deletion layer — see below.

## Boundaries

- **Thin CLI.** `cli.py` only parses arguments and calls library functions. It
  contains zero business logic. This boundary is architectural, not stylistic.
- **`store/` owns the database.** It is the *only* module allowed to touch SQLite.
  No other module opens a connection, writes SQL, or knows the DB file path.
- **Schema-first.** Pydantic models and SQLite DDL are the contract. Schema changes
  are new numbered migrations in `store/ddl/`, never edits to already-applied ones.

## Findings & evidence

- A **Finding** is the atomic unit. It always carries its citation: mandatory
  `file`, `line_range`, and `citation_snippet`, plus a `source_lens` or `source_tool`.
  No finding without a citation.
- **Severity is never upgraded** without a corroborating source (another lens/tool
  independently flagging it) or a falsification pass that confirms reachability.
  Relative claims are never silently converted to absolutes.
- The **falsify** stage tries to *disprove* each candidate (reachability, mitigating
  control, attacker-controlled input). Confirmed, killed, deferred, and unresolved
  outcomes remain in the store with their evidence trail — nothing silently disappears.
- The **triage** stage ranks and may suppress (demote priority on) deterministic-
  tool findings by calibrated P(actionable). It never deletes a finding — a
  suppressed finding remains in `store/` with its rank and feature attribution
  visible, same discipline as a killed falsification candidate.
- **No unsourced priors.** Every distribution parameter or per-rule prior used by
  `triage/` or `analyze/`'s risk quantification must declare its source (industry
  loss data, a real dated CVE-specific EPSS/KEV signal, or a calibrated SME estimate)
  in a priors config file. Severity-derived EPSS/KEV proxies are prohibited. No magic
  numbers.

## Prompts & templates are versioned artifacts

- Every file under a `prompts/` or `templates/` directory is a versioned artifact.
  **Never edit one in place.** A prompt change is a *new* file (e.g. `..._v2.md`)
  plus a benchmark re-run on the golden fixtures — never a silent tweak. The eval
  harness (`tests/`) is the precision/recall backbone that makes benchmark numbers
  defensible; treat it as such.

## Reliability layer

- **Every LLM call is schema-validated.** No module calls a model and trusts the
  raw output. All calls go through the shared `llm/` client, which validates the
  response against its expected Pydantic model, retries on parse/validation
  failure (bounded retry count, never infinite), and writes a `ValidationFailure`
  row to `store/` on exhaustion. Validation failures are never silently swallowed
  — they are as much a logged outcome as a killed finding.
- **No guessing under low confidence.** Any stage producing a `Finding` or a
  `map/` entity below the configured confidence threshold must not assert it
  outright. It either triggers a broader retrieval pass (more callers/callees/
  similar-pattern context) and re-scores once, or is written with status
  `unresolved` — never silently rounded up to a confident result.
- **Eval results are tracked over time, not just per-run.** The golden harness
  records precision/recall per prompt version to `store/` (or a sibling eval
  log), not just stdout. A prompt version change that regresses precision/recall
  against the prior version on the benchmark corpus must be flagged before that
  version is used in `map/`, `detect/`, `falsify/`, or `normalize/` — this is a
  gate, not an FYI.

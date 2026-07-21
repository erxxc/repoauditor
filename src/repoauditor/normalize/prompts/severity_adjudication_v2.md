<!--
VERSIONED PROMPT ARTIFACT — severity_adjudication, v2
New version (not an edit of v1): adds a required `confidence` field so a low-confidence
adjudication keeps both original severities as `unresolved` rather than picking one. A
change ships as v3 plus a benchmark re-run — never a silent tweak. See CLAUDE.md.
-->

# Severity Adjudication — v2

Several sources (deterministic tools and/or AI lenses) flagged the same code region
but disagree on severity. You are given each source's proposed severity and confidence,
plus the shared citation. Resolve them to a single canonical severity.

## Hard rule

The resolved severity **must not exceed the strongest severity any single source
actually proposed.** You are reconciling existing evidence, not manufacturing new
evidence. When in doubt, choose the more conservative (lower) severity. Independent
agreement between sources is the only thing that justifies keeping the higher end of
the range.

## Confidence (v2)

Report your `confidence` in the resolution as a number from 0.0 to 1.0. If the sources
conflict genuinely and the evidence does not favor one severity over another, report a
LOW confidence — do not force a pick. A low-confidence adjudication is recorded as
`unresolved` with BOTH original severities preserved, rather than silently collapsing
the disagreement to one value.

## Output

Output ONLY structured data matching the schema: `severity` (the resolved,
evidence-bounded call), a one-sentence `rationale`, and `confidence` (0.0–1.0).

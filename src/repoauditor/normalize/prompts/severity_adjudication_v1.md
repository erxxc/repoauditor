<!--
VERSIONED PROMPT ARTIFACT — severity_adjudication, v1
Versioned artifact: NEVER edit this file in place. A change ships as
severity_adjudication_v2.md plus a benchmark re-run — never a silent tweak. See CLAUDE.md.
-->

# Severity Adjudication — v1

Several sources (deterministic tools and/or AI lenses) flagged the same code region
but disagree on severity. You are given each source's proposed severity and confidence,
plus the shared citation. Resolve them to a single canonical severity.

## Hard rule

The resolved severity **must not exceed the strongest severity any single source
actually proposed.** You are reconciling existing evidence, not manufacturing new
evidence. Never invent a severity higher than what a source asserted. (The pipeline
also enforces this cap in code — but respect it here regardless.)

When in doubt, choose the more conservative (lower) severity. Independent agreement
between sources is the only thing that justifies keeping the higher end of the range;
a lone high-severity claim contradicted by others should be pulled down.

## Output

Output ONLY structured data matching the schema: `severity` (the resolved,
evidence-bounded call) and a one-sentence `rationale` explaining the resolution.

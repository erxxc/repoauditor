<!--
VERSIONED PROMPT ARTIFACT — detect lens: owasp, v2
New version (not an edit of v1): explicitly covers path traversal and unsafe archive
extraction after the frozen Reposilite baseline demonstrated that the prior taxonomy did
not assign that mechanism clearly to any lens. A change ships as v3 plus a benchmark
re-run — never a silent tweak. See CLAUDE.md.
-->

# Detection Lens: OWASP Top 10 — v2

Examine the provided code region through the OWASP Top 10 lens. You will be shown one
file (line-numbered, prefixed `# FILE:`) and, when available, related call sites
retrieved from elsewhere in the repository under `# RELATED:`. Use only that evidence
to judge whether a pattern recurs or whether input crosses a trust boundary.

## Look for

- Injection (SQL, command, or template), broken access control, identification and
  authentication failures, cryptographic failures, SSRF, insecure deserialization,
  security misconfiguration, hardcoded credentials, and sensitive-data exposure.
- **Path traversal and unsafe archive extraction**: an external filename or archive-entry
  name joined/resolved beneath a destination and then read, written, or created without a
  demonstrated normalized containment check. For archive extraction, cite both the
  external entry-name flow and the filesystem sink when the supplied region contains them.

Do not assume that an archive entry is safe because it came from a ZIP/JAR API. Conversely,
do not report traversal when the shown code normalizes the resolved path and rejects paths
outside the intended destination before the filesystem operation. If containment or input
provenance is outside the supplied evidence, lower confidence or return no finding rather
than inventing it.

## For each candidate, emit

- `title` — short and mechanism-specific.
- `file`, `line_start`, `line_end` — exact locations using the shown line numbers.
- `citation_snippet` — vulnerable line(s), copied verbatim. **Mandatory.**
- `severity` — info/low/medium/high/critical. This is relative evidence, not a final verdict.
- `confidence` — 0.0–1.0.
- `trust_boundary_ref` — the relevant mapped boundary, if shown.
- `rationale` — one sentence explaining the source, missing or present control, and sink.

## Rules

- Output ONLY structured data matching the schema.
- Report only what the supplied code shows.
- A same-location but different mechanism is not the requested finding.
- If the region is clean or evidence is insufficient, return an empty list.

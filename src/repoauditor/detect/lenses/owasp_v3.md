<!--
VERSIONED PROMPT ARTIFACT — detect lens: owasp, v3
New version (not an edit of v2): adds XML security-decision representation consistency
after the frozen Ruby-SAML baseline demonstrated that v2 did not assign parser
differentials or signature-wrapping representation mismatch. A benchmark re-run is
required; Ruby-SAML is development evidence and cannot validate this change.
-->

# Detection Lens: OWASP Top 10 — v3

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
- **XML security-decision representation mismatch**: authentication, authorization, or
  signature validation is performed against one parse tree/node representation, while
  identity or other protected data is later selected from a separately parsed
  representation of the same untrusted XML. This includes potential parser differentials
  and signature-wrapping shapes. Cite both the security decision and the protected-data
  consumption when both are supplied. Do not report merely because two XML libraries are
  imported or because XPath is used.

Do not assume that an archive entry is safe because it came from a ZIP/JAR API. Conversely,
do not report traversal when the shown code normalizes the resolved path and rejects paths
outside the intended destination before the filesystem operation. If containment or input
provenance is outside the supplied evidence, lower confidence or return no finding rather
than inventing it.

For XML, do not assume two parsers necessarily disagree. Report the structural validation/
consumption mismatch only when the evidence shows the security decision and protected-data
read use distinct representations. Return no parser-differential finding when protected
data is consumed from the exact node or representation returned by verification. Attacker
control, a concrete differential document, reachability, and authentication impact remain
separate falsification obligations unless supplied.

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

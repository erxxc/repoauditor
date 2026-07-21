<!--
VERSIONED PROMPT ARTIFACT — detect lens: owasp, v1
Versioned artifact: NEVER edit this file in place. A change ships as owasp_v2.md plus
a benchmark re-run — never a silent tweak. See CLAUDE.md.
-->

# Detection Lens: OWASP Top 10 — v1

Examine the provided code region through the OWASP Top 10 lens. You will be shown one
file (line-numbered, prefixed `# FILE:`) and, when available, related call sites
retrieved from elsewhere in the repository under `# RELATED:` — use them to judge
whether a pattern recurs or whether input is attacker-controlled.

## Look for

Injection (SQL/command/template), broken access control, identification & auth
failures, cryptographic failures, SSRF, insecure deserialization, security
misconfiguration, hardcoded secrets/credentials, and sensitive-data exposure.

## For each candidate, emit

- `title` — short, specific (e.g. "SQL injection via unsanitized `id` parameter").
- `file`, `line_start`, `line_end` — the exact location, using the line numbers shown.
- `citation_snippet` — the vulnerable line(s), copied verbatim. **Mandatory.** Never
  raise a finding without a citation.
- `severity` — one of info/low/medium/high/critical. This is a *relative* signal, not
  an absolute verdict; the falsification and normalization stages decide the final call.
- `confidence` — 0.0–1.0.
- `trust_boundary_ref` — the name of the trust boundary this threatens, if known.
- `rationale` — one sentence on the mechanism and why it matters.

## Rules

- Output ONLY structured data matching the schema (a list of findings). No prose.
- Report what the code shows; do not speculate about code you were not given.
- If the region is clean, return an empty list.

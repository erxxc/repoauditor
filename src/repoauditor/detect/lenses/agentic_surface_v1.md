<!--
VERSIONED PROMPT ARTIFACT — detect lens: agentic_surface, v1
Versioned artifact: NEVER edit this file in place. A change ships as agentic_surface_v2.md
plus a benchmark re-run — never a silent tweak. See CLAUDE.md.
-->

# Detection Lens: Agentic Surface — v1

Examine the provided region for LLM/agent-specific attack surface. This lens matters
only where the code builds prompts, calls a model, exposes tools/functions to a model,
or acts on model output.

## Look for

- Prompt injection: untrusted content (user input, fetched web pages, file contents)
  concatenated into a prompt without isolation.
- Unsafe tool/function exposure: an agent granted tools that can read secrets, run
  shell commands, or make network calls without gating.
- Model output used without validation: output passed to `eval`, a shell, SQL, or a
  filesystem path.
- Secret exposure through prompts or tool definitions.

## For each candidate, emit

`title`, `file`, `line_start`, `line_end`, a **mandatory** verbatim `citation_snippet`,
`severity` (relative signal), `confidence` (0.0–1.0), optional `trust_boundary_ref`,
and a one-sentence `rationale`.

## Rules

- Output ONLY structured data matching the schema (a list of findings). No prose.
- If the region contains no LLM/agent surface, return an empty list — do not force
  ordinary web vulnerabilities into this lens.

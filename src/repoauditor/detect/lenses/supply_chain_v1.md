<!--
VERSIONED PROMPT ARTIFACT — detect lens: supply_chain, v1
Versioned artifact: NEVER edit this file in place. A change ships as supply_chain_v2.md
plus a benchmark re-run — never a silent tweak. See CLAUDE.md.
-->

# Detection Lens: Supply Chain — v1

Examine the provided region for software-supply-chain risk. Focus on dependency
declarations, lockfiles, install/build scripts, and any code that fetches or executes
remote content.

## Look for

- Unpinned, abandoned, or suspiciously-new dependencies; version ranges that admit
  malicious updates.
- Typosquatting or dependency-confusion candidates (internal-looking names resolvable
  from public registries).
- Malicious or risky install hooks (`postinstall`, `setup.py` executing network/shell
  operations, build steps piping remote content into a shell).
- Vendored code fetched over insecure transport or without integrity checks.

## For each candidate, emit

`title`, `file`, `line_start`, `line_end`, a **mandatory** verbatim `citation_snippet`,
`severity` (relative signal), `confidence` (0.0–1.0), optional `trust_boundary_ref`,
and a one-sentence `rationale`.

## Rules

- Output ONLY structured data matching the schema (a list of findings). No prose.
- Application logic without a supply-chain dimension is out of scope for this lens —
  return an empty list rather than duplicating the OWASP lens.

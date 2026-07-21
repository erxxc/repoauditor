# llm/prompts — intentionally empty

No prompts live here. The shared `llm/client.py` is **prompt-agnostic**: it validates,
retries, logs, and confidence-gates, but never owns prompt text. Each stage owns its
own versioned `prompts/` (or `lenses/`) directory:

- `map/prompts/architecture_recovery_*.md`
- `detect/lenses/{owasp,supply_chain,agentic_surface}_*.md`
- `falsify/prompts/falsification_*.md`
- `normalize/prompts/severity_adjudication_*.md`

This directory exists only to make that separation explicit (per the package layout in
`repoauditor-scaffold.md`).

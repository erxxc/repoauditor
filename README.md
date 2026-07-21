# repoauditor

`repoauditor` is a personal CLI pipeline for auditing an unfamiliar acquired codebase: it ingests the repo (hash-keyed, idempotent snapshots), recovers a structured architecture / trust-boundary map, runs multi-lens AI-assisted vulnerability detection with a falsification pass that tries to disprove each candidate, normalizes deterministic tool output alongside the AI findings into one canonical store, and projects that single findings store two ways — an engineering remediation backlog (`--mode=engineering`) and a leadership-facing risk memo (`--mode=memo`). See [`repoauditor-scaffold.md`](repoauditor-scaffold.md) for the design source of truth and [`CLAUDE.md`](CLAUDE.md) for the architectural rules.

## Getting started

```sh
uv sync                          # install deps into a local .venv
uv run repoauditor db init       # create the SQLite schema (data/repoauditor.db)
uv run repoauditor ingest <repo-url>   # clone + snapshot a target, keyed by commit hash
```

`db init` applies the numbered migrations in `src/repoauditor/store/ddl/` and is safe to re-run. `ingest` is idempotent: re-ingesting an unchanged commit is a no-op. The downstream stages (`map`, `detect`, `falsify`, `report`) are stubbed interfaces in this scaffold and will raise until their logic lands.

# ⚠️ Intentionally insecure — do not deploy or run against real data

`storefront/` is a **deliberately vulnerable web application** used as a static-analysis
test fixture. It contains real, exploitable security flaws on purpose. It exists to be
**read and analyzed by tooling**, not to be operated as a service.

## Rules

- **Do not deploy it.** Never run it on a shared host, a public interface, or anything
  reachable from a network you don't fully control.
- **Do not point it at real data.** The database it expects holds customer PII by design;
  only ever use throwaway, synthetic data.
- **It will not self-serve.** `python wsgi.py` refuses to start. A local-only instance
  requires the explicit `STOREFRONT_ALLOW_RUN=1` opt-in, and even then it binds to
  `127.0.0.1` only with the debugger disabled.

## What is safe

- **Importing / static analysis is safe.** Building the app object has no side effects
  (no sockets, no database writes). Copying, reading, parsing, or scanning these files is
  the intended use.
- One command-execution code path exists only in a **retired, unregistered** module
  (`storefront/legacy.py`) that the app never wires in; it cannot be reached at runtime.

The specific planted issues, their expected dispositions, and the sourced CVE are
documented in the fixture's top-level `README.md` (one directory up, outside this
snapshot) — deliberately kept out of the app itself so a detector still has to find them.

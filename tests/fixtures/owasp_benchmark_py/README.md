# Fixture: `owasp_benchmark_py` — OWASP Benchmark for Python (subset)

A representative **25-case slice** of the OWASP Benchmark for Python, used as the
detection precision/recall corpus for the golden harness.

## Sourcing (no unsourced fixtures)

| | |
|---|---|
| Project | OWASP Benchmark for Python |
| Upstream | https://github.com/OWASP-Benchmark/BenchmarkPython |
| Pinned commit | `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` (2026-05-19) |
| Benchmark version | 0.1 |
| Ground truth | the project's own `expectedresults-0.1.csv` — **authoritative, not hand-labelled** |
| License | GNU GPL v3 (OWASP Benchmark) |

`snapshot/` contains the selected `testcode/BenchmarkTest*.py` files verbatim from that
commit, plus the `helpers/` package and `requirements.txt` they import (so the slice is a
coherent, self-consistent app fragment, not orphaned files).

## Why *these* cases

The full suite is 1,230 cases across 14 categories — too large and too repetitive to
iterate on. We picked a **balanced slice across the five categories the session called for**
(the exact CWE families a diligence audit cares about most), rather than one category
repeated:

| Category | CWE | real=true (recall) | real=false (precision trap) |
|---|---|---|---|
| `sqli` | CWE-89 | 00099, 00283, 00284 | 00011, 00012 |
| `xss` | CWE-79 | 00096, 00097, 00098 | 00082, 00083 |
| `pathtraver` | CWE-22 | 00001, 00002, 00003 | 00004, 00005 |
| `cmdi` | CWE-78 | 00165, 00166, 00167 | 00350, 00512 |
| `hash` (weak crypto) | CWE-327/328 | 00054, 00057, 00058 | 00055, 00056 |

- **15 real=true** cases are the **recall** ground truth — listed in `expected_findings.json`.
- **10 real=false** cases are **precision traps**: safe code that *looks* like the vulnerable
  variant in the same category. They are deliberately **omitted** from `findings`, so under the
  existing scorer any finding the pipeline raises on them is unmatched and counts as a false
  positive — which is exactly how the OWASP Benchmark measures a tool's FP rate. They are
  listed under `precision_traps` for auditability. Selection within each category is the first
  N true / first N false by test-id (deterministic, reproducible from the CSV).

## Scoring is deferred (by design)

These cases are detected by the **owasp LLM lens** and/or **semgrep** — neither of which runs
in a bare CI environment (no `ANTHROPIC_API_KEY`; semgrep not installed). So this fixture is
**not** run by the deterministic scripted golden test (it has no `FIXTURE_LLM` scripted
responses, and scripting them would make the precision/recall circular). It is scored by the
**turnkey deferred harness** — see `../README.md` — under `REPOAUDITOR_LLM=live` and/or with
semgrep installed. `severity` is category-canonical and, per the harness convention, an
approximate anchor; `source_lens` is omitted so a case matches whether flagged by the lens or
by semgrep.

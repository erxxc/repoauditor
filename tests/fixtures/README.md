# Golden / benchmark fixture corpus

Two tiers of *vulnerability* fixtures live here. The split exists because the golden harness
runs a **scripted** model by default, and scripting canned answers for a large corpus would
make its precision/recall *circular* (you'd be scoring hand-written answers against
hand-written ground truth). So the honest numbers are separated from the deterministic ones.

> Not every dir here is a vuln fixture. A **benchmark-corpus** fixture is identified by
> carrying an `expected_findings.json` (its ground truth) — that's how `conftest.py`
> discovers them. Non-vuln fixtures without one are ignored by the corpus harness:
> - `multilang_retrieval/` — JS/TS, Java, Ruby (+ a Go file for the lexical fallback) source
>   files exercising caller→callee relationships for `detect/retrieval`'s tree-sitter index
>   (`tests/test_retrieval.py`). No `expected_findings.json`; it isn't a vuln corpus.

## Tier 1 — scripted golden fixtures (deterministic, run in CI)

| Fixture | What it exercises |
|---|---|
| `example_vuln_repo` | SQLi / SSRF / hardcoded secret + a planted false positive + an ambiguous→`unresolved` candidate |
| `command_injection_svc` | command injection + hardcoded DB password + a planted false positive |

These have canned model output in `conftest.py::FIXTURE_LLM`, so the deterministic golden
test (`test_golden_harness.py`) and `test_ingest.py` run them with **no network, key, or
cost**. Discovery of these is gated on `FIXTURE_LLM` (not "every dir here"), which is what
lets Tier 2 live alongside them without breaking the scripted harness.

## Tier 2 — benchmark corpus (real, documented; scored by the live model / real tools)

| Fixture | Source | CWE / CVE | Detection path |
|---|---|---|---|
| `owasp_benchmark_py` | OWASP Benchmark for Python v0.1 subset (25 cases) — see its `README.md` | CWE-89/79/22/78/327-328 | owasp LLM lens / semgrep |
| `cve_gunicorn_smuggling` | Gunicorn `gunicorn/http/message.py` @ 21.2.0 (real file) | CVE-2024-1135 (CWE-444) | LLM lens / semgrep |
| `cve_vulnerable_deps` | requirements.txt pinning real CVE-affected versions | CVE-2020-14343 (PyYAML 5.3.1), CVE-2018-1000656 (Flask 0.12.2) | SCA (pip-audit / OSV) |

Every fixture's `expected_findings.json` carries a `source` block with the upstream repo,
pinned commit/version, and advisory IDs (verified via `https://api.osv.dev`), so nothing
here is an unsourced or fabricated vulnerability. These are **not** scripted — they are
detected by the live LLM lens and/or the deterministic SAST/SCA tools.

## What actually produces a number, and when

Run the corpus harness with `pytest tests/test_benchmark_corpus.py`.

| Number | Lineage (EvalRun) | Status in a bare CI env |
|---|---|---|
| **Secrets adapter** precision/recall | `secrets_adapter` | **Runs now** — real gitleaks. Honest baseline: **precision 1.00 / recall 0.50** (catches the strong-pattern Stripe token; misses the plain-text password — a real gitleaks limitation, deliberately not rigged to 1.0). |
| Scripted detect / falsify / normalize | `<repo>::{detect,falsify,normalize}` | **Runs now** — deterministic **pipeline-logic** P/R (1.0/1.0 post-falsify; `severity_adjudication_v3` confirmed non-regressing end-to-end). *Not* a model-capability number. |
| Live OWASP + CVE precision/recall | `corpus::<repo>` | **Deferred / turnkey.** Needs `REPOAUDITOR_LLM=live` (LLM lens + falsify + normalize) and, for the SAST/SCA fixtures, `semgrep` / `pip-audit` / `osv-scanner` installed. |

### Producing the deferred live baseline (the memo's methodology number)

```bash
export ANTHROPIC_API_KEY=...            # required for the LLM stages
# optional, for the SAST/SCA fixtures:  pipx install semgrep pip-audit ; brew install osv-scanner
REPOAUDITOR_LLM=live pytest tests/test_benchmark_corpus.py::test_corpus_live_baseline -s
```

Each fixture records one `EvalRun` (lineage `corpus::<repo>`); `eval/regression.py` then
gates future prompt-version changes against that recorded number. **This is the honest,
model-driven precision/recall that belongs in the leadership memo's methodology note** —
until it is produced against this corpus, the memo should not quote a broader-corpus figure.

> Environment note (this build): `ANTHROPIC_API_KEY` is unset and only `gitleaks` of the
> deterministic tools is installed, so only the "Runs now" rows above are populated. The
> corpus and harness are in place so the live baseline is a one-command run once a key /
> the tools are available.

# Golden / benchmark fixture corpus

Three evidence kinds live here. The split exists because the golden harness
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

The metadata field `source.kind` is authoritative:

- `independent` — independently authored, mature public software used for the primary
  real-world cohort. Pre/post snapshots share one `project_id` and count as one repository.
- `benchmark` — deliberately vulnerable or benchmark-authored calibration anchor. It never
  advances the independent-repository gate.
- `fixture` — purpose-built or minimal-slice test material. It never advances that gate.

## Independent real-world cohort

Eight projects are pinned as vulnerable/patched pairs using acquisition metadata rather than
vendored source trees. The patched commit is a same-codebase negative control; advisories and
diffs are reviewer evidence, never labels inferred from a repoauditor run.

| Project | Language | CVE | Provenance | License |
|---|---|---|---|---|
| Lodash | JavaScript | CVE-2020-8203 | OpenSSF CVE Benchmark + OSV | MIT |
| Parse Server | JavaScript | CVE-2020-5251 | OpenSSF CVE Benchmark + OSV | BSD-3-Clause |
| serialize-javascript | JavaScript | CVE-2019-16769 | OpenSSF CVE Benchmark + OSV | BSD-3-Clause |
| Django | Python | CVE-2021-31542 | CVEfixes scope + OSV + upstream diff | BSD-3-Clause |
| aiohttp | Python | CVE-2024-23334 | CVEfixes v1.0.8 scope + OSV + upstream diff | Apache-2.0 |
| Apache Commons Text | Java | CVE-2022-42889 | CVEfixes scope + GHSA/GHSL + upstream diff | Apache-2.0 |
| Apache JSPWiki | Java | CVE-2019-10090 | OpenSSF CVE Benchmark/CVEfixes scope + OSV | Apache-2.0 |
| Rack | Ruby | CVE-2023-27539 | ruby-advisory-db + OSV/GHSA + upstream diff | MIT |

The exact pre/post hashes, upstream URL, license, and verification links are repeated in each
fixture's `expected_findings.json` and README. `materialize_public_corpus.py` materializes from
verified local clones without network access by default; `--fetch` is an explicit opt-in to
clone/fetch the public upstreams. Source and license files exist only in the generated local
snapshot and are not redistributed by this repository.

CI materializes these snapshots in the scheduled/manual `public corpus cache` workflow. The
cache key hashes this materializer and all acquisition metadata; an exact hit is reused and a
miss reacquires every pinned commit. No fallback key is used, acquired code is never executed,
and the integrity result is retained for 30 days. See `CONTRIBUTING.md` for cache invalidation.

The manual `bounded corpus UAT` workflow consumes that exact cache. Its free scanner matrix is
limited to Django, Lodash, Commons Text, and Rack pre/post pairs plus Juice Shop. Because each
independent project has one advisory-derived target rather than exhaustive labels, its JSON
reports unmatched findings as `unadjudicated_candidate_count`, never as false positives. The
separate paid mode runs only `uat_lightweight_app` and labels its metrics fixture-derived.

## Public vulnerable application anchors

OWASP Juice Shop, WebGoat, and RailsGoat are pinned acquisition-only known-positive anchors.
They are `benchmark`, not independent evidence. Juice Shop and RailsGoat are MIT; WebGoat is
GPL-2.0-or-later. None of their source trees is redistributed in this repository.

Every fixture's `expected_findings.json` carries a `source` block with the upstream repo,
pinned commit/version, and advisory IDs (verified via `https://api.osv.dev`), so nothing
here is an unsourced or fabricated vulnerability. These are **not** scripted — they are
detected by the live LLM lens and/or the deterministic SAST/SCA tools.

All corpus sources currently selected are public. This does not create permission to add or
transmit proprietary code: future additions must record authorization explicitly, and no
proprietary content may be sent to a hosted model merely because this harness supports one.

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

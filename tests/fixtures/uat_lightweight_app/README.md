# `uat_lightweight_app` — purpose-built vulnerable fixture (UAT)

A small, **intentionally vulnerable** Flask storefront authored from scratch to serve as a
fast, repeatable UAT fixture for the repoauditor pipeline. It is a controlled **10-case
test matrix**, not an adaptation of an existing project (OWASP Juice Shop is too large and
its vulnerabilities aren't calibrated as a controlled matrix). The app is deliberately
compact — 12 Python source files, one framework, one dependency manifest — so an
`ingest → … → report` cycle is quick to run over and over during UAT.

- **App source (ground truth-free):** `snapshot/`
- **Machine-readable expectations:** `expected_findings.json`
- **Safety notice shipped with the app:** `snapshot/SECURITY.md`

## ⚠️ Safety — this is a vulnerable web app (VWA), inert by default

The snapshot contains **real, exploitable** flaws on purpose. It is meant to be **read and
statically analyzed**, never operated as a service.

- **The pipeline never runs it.** `ingest` copies files; `map`/`detect` read them
  statically. Nothing in repoauditor imports or executes the app. (Proven this session:
  isolated ingest of the 12 source files + `requirements.txt` discovery succeeds.)
- **It will not self-serve.** `python wsgi.py` prints a refusal and exits non-zero. A
  local instance requires the explicit `STOREFRONT_ALLOW_RUN=1` opt-in, and even then binds
  `127.0.0.1` only with the Werkzeug debugger **disabled** — no public interface, no
  interactive console.
- **Importing is side-effect free.** `create_app()` opens no sockets and writes no files.
- **The one command-exec sink is dead code.** It lives in `storefront/legacy.py`, a
  blueprint the app factory never registers, additionally guarded by a permanently-`False`
  flag — it cannot run even if the app is started (this is case 8 by design).

The per-finding "answer key" is kept **out of the snapshot** (here and in
`expected_findings.json`) so a detector still has to find each issue — `snapshot/SECURITY.md`
warns that the app is insecure without disclosing where the planted issues are.

## Framework choice and rationale

**Chosen: Python 3 + Flask 3.0.3.** Rationale (this is a fixture whose job is to exercise
*this pipeline's* tooling reliably and cheaply):

- **Native tool coverage.** `requirements.txt` is the SCA adapter's first-class manifest;
  Python has first-class AST support in `detect/retrieval`; `gitleaks`, `semgrep`, and
  `pip-audit`/`osv-scanner` are all first-class on this stack. A different ecosystem would
  push one or more stages onto a weaker path (e.g. the retrieval index's lexical fallback).
- **Clean map-stage recovery.** Flask's `@app.route` entry points and a SQLite datastore
  are exactly the shapes the `map/` architecture-recovery stage recovers well, which is what
  gives the production-exposure and trust-boundary checks (cases 3, 6) something real to
  resolve.
- **Compactness + realism.** A public catalog, signed-in order/invoice history, an admin
  tool, and account settings map cleanly onto all 10 case types in ~12 small files.
- **Corpus comparability.** It keeps this fixture on the same stack as the existing corpus,
  so UAT numbers are comparable rather than confounded by a language switch.

The choices the spec delegated: **case 2 = SSRF** (admin link-preview), **case 3 = IDOR**
(order-by-id), and **case 10 rides on case 4** (the hardcoded secret, flagged by two
sources).

## The real, verified CVE (case 5)

| Field | Value |
|---|---|
| Package / pin | `requests==2.19.1` (`requirements.txt`) |
| CVE | **CVE-2018-18074** |
| Aliases | GHSA-x84v-xcm2-53pg · PYSEC-2018-28 |
| CWE | CWE-522 (Insufficiently Protected Credentials) |
| Affected / fixed | `< 2.20.0` / fixed in `2.20.0` |
| Summary | Requests < 2.20.0 sends the HTTP `Authorization` header to an `http` URI on a same-hostname `https→http` redirect, leaking credentials to a network sniffer. |
| Verification | Queried live against `https://api.osv.dev/v1/query` (package `requests`, version `2.19.1`) — the advisory and the affected range were confirmed, not approximated. |

`requests` is also the HTTP client at the SSRF sink (case 2), so the vulnerable dependency
is genuinely wired into the app. No EPSS/KEV numbers are asserted (none are real+dated here),
per CLAUDE.md.

## The two flagged dependency gaps

1. **No live model key in a bare environment.** `ANTHROPIC_API_KEY` is unset /
   `REPOAUDITOR_LLM` is not `live`, so the LLM-lens `detect`, `falsify`, and `normalize`
   stages don't run. Every case whose detection **or disposition** depends on the model —
   the SQLi/SSRF/IDOR confirmations, the mitigating-control kill (7), the unreachable kill
   (8), the ambiguous→review routing (9), and the LLM half of the duplicate (10) — is scored
   only under a live run. Turnkey: `export ANTHROPIC_API_KEY=… ; REPOAUDITOR_LLM=live pytest
   tests/test_benchmark_corpus.py::test_corpus_live_baseline`.
2. **Deterministic SAST/SCA tools not installed.** Only `gitleaks` (secrets) is present in a
   bare CI env; `semgrep` (SAST) and `pip-audit`/`osv-scanner` (SCA) are not. So the SAST
   corroboration and the **case-5 dependency CVE path** are deferred to a tooled run
   (`pipx install semgrep pip-audit ; brew install osv-scanner`). What runs **now**: real
   gitleaks confirms the case-4/10 secret (rule `stripe-access-token`, the only leak it
   reports — precision clean), and the ingest is well-formed.

A knock-on note on pinning: `requests==2.19.1` is old enough that real SCA tools will surface
**additional** real, OSV-verified `requests` advisories beyond CVE-2018-18074; those are
acceptable, not fabricated. And as of ingest, even current `Flask`/`Werkzeug` carry freshly
published advisories, so the fixture does **not** try to hold a moving CVE-clean baseline for
them — the designated, stable case-5 CVE is CVE-2018-18074.

## The 10 planted cases

| # | Case | Where | Expected disposition | Kill/route basis |
|---|---|---|---|---|
| 1 | SQL injection (public route) | `catalog.py` `GET /products/search` | **confirmed** | attacker-controlled param concatenated into SQL |
| 2 | SSRF | `integrations.py` `GET /admin/link-preview` | **confirmed** | caller-controlled URL fetched server-side |
| 3 | IDOR (broken object-level authz) | `orders.py` `GET /orders/<id>` | **confirmed** | authenticated but no ownership check |
| 4 | Hardcoded secret (fake credential) | `config.py` `STRIPE_SECRET_KEY` | **confirmed** | `sk_live_` fake, gitleaks-detectable |
| 5 | Vulnerable dependency (real CVE) | `requirements.txt` `requests==2.19.1` | **confirmed** | CVE-2018-18074 via SCA |
| 6 | Production-like customer datastore | `db.py` `customers` (PII) | **architecture-exposure** | map recovers it; deal_risk scores exposure=direct |
| 7 | Genuine mitigating control | `invoices.py` `GET /invoices/<id>` | **killed** | `@owns_resource` ownership gate found by falsify |
| 8 | Unreachable candidate | `legacy.py` `legacy_import` | **killed** | unregistered blueprint + always-`False` flag |
| 9 | Ambiguous, needs review | `account.py` `POST /account/return-target` | **requires-review** | no redirect sink in-repo + uncorroborated → unresolved |
| 10 | Duplicate across sources | `config.py` (same line as case 4) | **confirmed, collapses to 1** | gitleaks + owasp lens → matching → one countable finding |

Cases 7–9 are the discrimination tests: 7 and 8 must be **correctly killed** (not surviving
false positives, not silently dropped — the killed verdict + reason persist), and 9 must
**route to `review/` as unresolved** rather than being guessed either way.

## `expected_findings.json` — schema (extends the corpus convention)

It keeps the existing keys (`repo_id`, `source`, `findings`, `expected_unresolved`; findings
carry `file` + `citation_contains` with approximate line anchors) so
`test_corpus_fixture_is_well_formed` accepts it, and adds:

- **`expected_killed`** — candidates falsify must kill, each with a `kill_basis`
  (`mitigating_control` | `unreachable`). (Cases 7, 8.)
- **`expected_map`** — the trust boundaries / data stores / integrations `map/` should
  recover; the `customers` datastore entry is the case-6 production-exposure ground truth.
- **`planted_cases`** — the per-case matrix required by the UAT spec: category + location
  (file/route/line), an acceptable **`severity_range`** (a range, not a point, per the
  project's uncertainty discipline), `expected_disposition`, expected **trust boundary +
  exposure**, expected **scanner/model source(s)**, and the **collapse** flags for case 10.
- **`field_provenance`** — maps the `exposure` field names to the current risk-quant
  **session B** shapes so they are directly validatable: `production_exposure_label` ←
  `DealRisk.production_exposure`; `exposure_component_range` ← `DealRisk.exposure_component`
  (= `RiskScenario.exposure_factors[]`); `control_strength_expected` ←
  `RiskScenario.control_strengths[]`; `scenario_input_origin_expected` ←
  `ScenarioInput.origin`; `entity_kind` ← `store.EntityKind`; dispositions ←
  `FalsificationStatus`.

## Validation status — all ten goals are validatable now

Both risk-quant **session B** (organization exposure/control-strength/loss-scale inputs +
versioned audited simulation scenarios) and the **CLI maturity resume** work are complete, so
every validation goal below has real machinery behind it — including exposure/control-strength
provenance (`RiskScenario` + `ScenarioInput`) and **resumed / repeated audited runs**
(`quantify --record-audit`, append-only `SimulationRun` + versioned `RiskScenario`). What's
deferred is only *tool/model availability* (the two gaps above), not the checks themselves.

| Goal (case) | Validated by | Runs now? |
|---|---|---|
| SQLi / SSRF / IDOR confirmed (1,2,3) | live detect→falsify; `findings` ground truth | live |
| Hardcoded secret (4) | gitleaks `secrets` + owasp lens | **secret half now** (gitleaks) |
| Vulnerable dep CVE (5) | SCA (pip-audit/osv) vs `source.advisories` | tooled run |
| Production datastore exposure (6) | `map/` entities + `deal_risk` exposure_component + `RiskScenario.exposure_factors` | live map |
| Mitigating control killed (7) | falsify mitigating-control search → `killed` | live falsify |
| Unreachable killed (8) | falsify reachability check → `killed` | live falsify |
| Ambiguous → review (9) | reliability layer → `unresolved` → `review/` request | live |
| Duplicate collapses to 1 (10) | `matching.py` + `db.list_countable_findings` | live (both sources) |
| Exposure/control provenance | `ScenarioInput.origin` + `PriorSource` | live analyze |
| Resumed/repeated audited runs | `quantify --record-audit`, `SimulationRun` history | now |

### Producing the live UAT baseline

For the guided, one-stop demonstration from the repository root:

```bash
export ANTHROPIC_API_KEY=…
./demo
```

This path checks the live model, scans only `snapshot/` (never this answer key), prompts for
the human review decision, records an audited quantification, writes both reports, and emits
Markdown plus JSON scorecards for all ten cases.

During early UAT, triage may report `synthetic_row_random`. That is a cold-start generator
check, not measured real-world precision. Do not cite it as model accuracy. After analyst
decisions accumulate, use `repoauditor triage-stats` to inspect observed threshold tradeoffs;
the command withholds the table until 40 real scored labels exist and never recommends a
threshold. Grouped validation remains unavailable until eight distinct engagements exist.

For benchmark development or lower-level diagnosis:

```bash
export ANTHROPIC_API_KEY=…                              # LLM stages (gap 1)
pipx install semgrep pip-audit ; brew install osv-scanner   # SAST/SCA (gap 2)
REPOAUDITOR_LLM=live pytest tests/test_benchmark_corpus.py::test_corpus_live_baseline -s
# or drive the pipeline directly against the snapshot for an iterative UAT run:
#   repoauditor ingest tests/fixtures/uat_lightweight_app/snapshot
#   repoauditor run   tests/fixtures/uat_lightweight_app/snapshot
```

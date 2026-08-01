# Deterministic scanner capability and applicability matrix

Status: OPT-030 implemented from production adapters and retained evidence as of
2026-07-31. The machine-readable companion is
[`scanner-capability-matrix.json`](scanner-capability-matrix.json).

## Claim boundary

Deployment health and detection capability are different claims. A passing execution
contract or canary proves that a configured adapter ran, evaluated disclosed targets, and
returned validated output. It does not prove exhaustive recall, exploitability,
actionability, or repository-wide security. Every emitted match remains an unadjudicated
candidate until repository evidence supports a disposition.

## Matrix

| Scanner | Implemented capability | Production applicability and inputs | Expected strengths | Known blind spots |
| --- | --- | --- | --- | --- |
| **Semgrep official** (`semgrep`) | Security patterns and rule-defined data flows across source, frameworks, configuration, CI/IaC, and secret patterns represented by the pinned 1,073-rule official default pack. | The verified local pack must select at least one non-symlink file. Target count comes from Semgrep's target report; zero targets is `failed`, not `empty`. | Broad offline multi-language coverage; normalized SARIF citations; independently verified targets and configuration digest. | Public rules demonstrably miss some advisory mechanisms. A match does not establish attacker control, reachability, mitigation state, or actionability. Cross-service and business-logic coverage is not exhaustive. |
| **Semgrep supplemental** (`semgrep-supplemental`) | One qualified JavaScript/TypeScript rule for variable or concatenated commands passed to Node.js `child_process.exec` or `execSync`. | At least one `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, or `.tsx` file must exist. The owned pack runs separately with its own digest, SARIF, target report, count, and producer. | Vulnerable-only recovery on the frozen codecov-node target; packaged positive and safe argument-vector controls. | Only one mechanism is qualified. A shell sink match is not automatically command injection. SQL, SSRF, archive, and traversal rules are not yet implemented. |
| **pip-audit** (`pip-audit`) | Known PyPI advisories for package versions declared in submitted Python requirements files. | Current production code submits root-level `requirements*.txt`. Exact direct pins may use a visibly `partial` no-transitive-resolution fallback. | Python-specific resolution; package/version/advisory/fix evidence; explicit partial fallback. | The adapter does **not** currently submit `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `pyproject.toml`, or nested requirements files. Matches do not prove vulnerable-code use. Live advisory results can change. |
| **OSV-Scanner** (`osv-scanner`) | Known OSV advisories for packages discovered from source and lockfile formats supported by the pinned binary. | Recursively scans the submitted root. If discovery reports no sources, up to 100 discovered `requirements*.txt` files are tried explicitly and reported `partial`; no supported source is `not-applicable`. | Multi-ecosystem discovery; canonical package/advisory identity; clean versus no-source distinction. | Coverage follows the pinned binary's supported formats. The explicit fallback covers requirements files only. Advisory matches do not prove reachability; the live database can change. |
| **gitleaks** (`gitleaks`) | Embedded-rule detection of credential-, token-, key-, and secret-like patterns in repository content. | Every submitted snapshot is applicable when the binary exists. It scans the working tree with `--no-git`, not repository history. | Language-independent patterns; secret values redacted before persistence; validated clean JSON. | History, runtime stores, and external secret managers are outside scope. Placeholders, examples, tests, and revoked values can match. |

## Status semantics

| Status | Meaning |
| --- | --- |
| `complete` | Applicable, validated output over at least one target, with one or more candidates. |
| `empty` | Applicable, validated output over at least one target, with zero candidates. This is not a vulnerability-free claim. |
| `not-applicable` | Zero inputs satisfy that adapter's production applicability policy. |
| `partial` | Validated results cover a disclosed subset or fallback mode; `failure_detail` identifies missing coverage. |
| `unavailable` | The scanner executable/capability is absent; no coverage claim is made. |
| `failed` | Execution, target verification, or output validation failed with attributable detail. |
| `disabled` | Deterministic scanning was explicitly disabled; no coverage claim is made. |

## Controls and evidence

- The common typed contract and clean-zero rules are defined in
  [`scanner-execution-contract.md`](scanner-execution-contract.md).
- Versions, invocations, configuration identities, rule digests/counts, advisory sources,
  and query timestamps are defined in [`scanner-provenance.md`](scanner-provenance.md).
- All five production scanner identities have positive and clean/not-applicable controls in
  [`scanner-deployment-canaries.md`](scanner-deployment-canaries.md), enforced by the
  [`required deployment gate`](scanner-deployment-gate.md).
- The corrected bounded deployment audit ran nine fixtures with no failed, partial,
  unavailable, or unexplained-zero result and retained 1,941 raw candidates. This is
  execution and candidate-volume evidence, not precision or recall evidence:
  [`deterministic-tool-deployment-audit-2026-07-29.json`](deterministic-tool-deployment-audit-2026-07-29.json).
- Historical remeasurement verified 3,862 Semgrep targets and 571 unadjudicated candidates:
  [`OPT-026 results`](optimizations/opt-026-historical-scanner-remeasurement-results-2026-07-29.json).
- Supplemental qualification covers exactly one rule and one frozen advisory target:
  [`OPT-027/028 results`](optimizations/opt-027-028-supplemental-differential-results-2026-07-29.json).

## Applicability correction disclosed by OPT-030

The 2026-07-29 deployment audit's narrative listed several Python lockfile names for
`pip-audit` applicability. Current production adapter behavior is narrower: it glob-selects
only root-level `requirements*.txt`. The historical audit is retained unchanged; this
matrix follows executable behavior and records the discrepancy. Broader Python manifest
support would be a new optimization rather than an undocumented capability claim.

OPT-031 subsequently bound this correction to scanner-specific constants consumed by the
adapter and added a behavioral regression for the root-only pip-audit boundary. It did not
expand pip-audit inputs or alter the historical audit.

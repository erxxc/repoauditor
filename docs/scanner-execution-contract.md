# Scanner execution contract

Status: OPT-022 implementation contract, hardened by OPT-032 through OPT-034 on 2026-08-01.

Every production deterministic adapter emits one typed execution record in the detect-stage
summary. The record is evidence about scanner deployment and coverage; it is not a
vulnerability finding and never enters triage, classifier labels, or evaluation ground truth.

Fields:

- `scanner`, `status`, and `applicable` identify the tool and whether the snapshot contains
  input the adapter can evaluate.
- `output_valid` means the producer-specific JSON or SARIF schema was successfully validated.
- `finding_count` is the number of normalized candidates returned by that producer.
- `target_count` and `target_count_basis` disclose what was actually counted. Semgrep reports
  selected files; pip-audit reports submitted manifests; gitleaks reports the submitted
  snapshot root. OSV-Scanner reports the submitted root for recursive discovery and the
  submitted manifests when its bounded explicit fallback is used.
- `version`, `configuration`, normalized `invocation`, configuration
  digest/rule-count/resolution fields, and advisory database identity/version/query time
  retain the OPT-024 execution provenance described in
  [`scanner-provenance.md`](scanner-provenance.md).
- `applicability_detail` is mandatory for `not-applicable` records and states which
  production input prerequisite was absent.
- `failure_detail` is mandatory for `failed` records.

The model rejects a clean `empty` or `complete` status unless the run was applicable, output
was valid, and at least one target was scanned or submitted. `complete` requires at least one
finding; `empty` requires zero findings. `not-applicable` requires zero applicable targets.
Known scanner identities are also restricted to their executable target-count bases; the
machine-readable capability matrix is tested against the same runtime allowlist.
`partial`, `unavailable`, `failed`, and `disabled` remain explicit rather than collapsing to
an empty result.

The records are persisted through the existing versioned stage-summary JSON and restored
when a pipeline resumes after detect. This avoids a database migration while preserving the
evidence in `runs show`, audit records, and downstream report projections. Historical
summaries without `scanner_executions` remain readable; absence is unavailable historical
evidence, never reconstructed as a clean scan.

OPT-023 adds isolated positive and clean deployment canaries that exercise this same adapter
path. Canary results do not enter product findings.

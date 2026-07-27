# Deterministic security-claim certificates

`SecurityClaim` separates an untrusted evidence producer from a small deterministic checker.
The producer may retrieve and slice broadly; the checker reopens the immutable snapshot,
parses it independently, and accepts only narrowly defined structural facts.

Current certificate version: `security_claim_v4`
Current verifier: `python_local_certificate_checker_v4`

## Checked facts

- Snapshot commit equality and snapshot-contained file paths.
- Exact source text for entry, source, path, sink, and control-candidate evidence.
- A supported Python sink call at the claimed line.
- Intraprocedural backward def-use closure from sink arguments.
- Local HTTP-entry syntax: a recognized Flask-style route/method decorator on the enclosing
  function, backed by persisted entry evidence.
- Local request-input syntax: `request`/`flask_request` input containers such as `args`,
  `form`, `json`, or a function parameter bound by a route placeholder.
- Control-candidate identity: an independently recognized sanitizer/validator/allowlist/
  parameterization/ownership call at the claimed line.
- Whether that control candidate lies on the reconstructed local def-use chain before the
  sink.
- Exact direct Python call-site syntax for persisted caller evidence. The checker reparses
  each caller file independently and confirms that the claimed line invokes the sliced
  function.

## Explicit non-claims

Structural verification does **not** establish:

- runtime route or framework registration;
- interprocedural or cross-service reachability;
- that a syntactically verified direct caller executes, is externally reachable, or reaches
  the callee under feasible runtime conditions;
- that a recognized input is attacker-controlled in the deployed environment;
- path feasibility or predicate satisfaction;
- sanitizer or mitigating-control effectiveness;
- exploitability, severity, or real-world risk.

A plain function parameter is not treated as attacker-controlled unless the same local
function has a checked route placeholder for that parameter. A control-like function name
is identity evidence only; it cannot kill a finding without separate evidence of
effectiveness.

The local source-to-sink proof remains intraprocedural. Direct Python callers are separate
context facts, not extensions of that def-use proof. Unsupported caller languages,
cross-file data-flow paths, path predicates, missing immutable snapshots, or incomplete
certificates remain incomplete/unsupported rather than being guessed.

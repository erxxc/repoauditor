# Deterministic security-claim certificates

`SecurityClaim` separates an untrusted evidence producer from a small deterministic checker.
The producer may retrieve and slice broadly; the checker reopens the immutable snapshot,
parses it independently, and accepts only narrowly defined structural facts.

Current certificate version: `security_claim_v8`
Current verifier: `deterministic_structural_certificate_checker_v8`

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
- Same-function Python authorization-candidate syntax from a deliberately narrow checker
  vocabulary, including ownership, role, and permission guards. The checker independently
  matches the exact snapshot text and AST location.
- Flask blueprint-registration syntax tied to the blueprint symbol on the local route
  decorator. The checker independently reparses the registration file and requires an exact
  `register_blueprint(...)` argument match.
- For JavaScript and TypeScript SSRF only: one local `req`/`request`
  `query`/`body`/`params`/`headers` expression, optionally assigned to a local variable,
  flowing into exactly one cited `fetch(...)` URL argument or the first URL argument of
  `axios.get/post/put/patch/delete/head/options(...)`. The checker loads its own tree-sitter
  grammar and independently reconstructs this local chain and client identity.

## Explicit non-claims

Structural verification does **not** establish:

- that syntactically verified framework registration executes during application startup;
- interprocedural or cross-service reachability;
- that a syntactically verified direct caller executes, is externally reachable, or reaches
  the callee under feasible runtime conditions;
- that a recognized input is attacker-controlled in the deployed environment;
- path feasibility or predicate satisfaction;
- sanitizer or mitigating-control effectiveness;
- whether an authorization candidate authenticates the right principal, protects the right
  object/action, executes in the deployed framework, or is effective;
- exploitability, severity, or real-world risk.
- that a JavaScript/TypeScript `req` or `request` object is actually framework-provided,
  attacker-controlled, or unsanitized in the deployed application.

A plain function parameter is not treated as attacker-controlled unless the same local
function has a checked route placeholder for that parameter. A control-like function name
is identity evidence only; it cannot kill a finding without separate evidence of
effectiveness.

The local source-to-sink proof remains intraprocedural. Direct Python callers are separate
context facts, not extensions of that def-use proof. Unsupported caller languages,
cross-file data-flow paths, path predicates, missing immutable snapshots, or incomplete
certificates remain incomplete/unsupported rather than being guessed.

Authentication-only syntax such as `login_required` or `current_customer_id()` is not
classified as authorization evidence. Conversely, a recognized authorization-like name is
only a candidate identity—not grounds to kill a finding without separately checked control
semantics and effectiveness.

Blueprint registration is similarly a syntax fact. It does not prove that the application
factory runs, that deployment selects that factory, or that a reverse proxy/network path
exposes the route. Direct `@app.route` endpoints do not receive a separate blueprint-
registration claim.

JavaScript/TypeScript support is intentionally mechanism-bounded. SSRF through `fetch` and
the explicit global `axios` URL-first methods above is supported. Generic property calls
such as `client.get(...)`, aliased Axios instances, bare `get(...)`, Axios interceptors, and
object-form `axios.request({url: ...})` are not inferred and remain incomplete. Other
mechanisms and HTTP clients are unsupported. Missing grammars, parse errors,
multiple/ambiguous sinks, and unresolved URL assignments remain incomplete rather than
falling back to lexical guesses.

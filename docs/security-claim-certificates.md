# Deterministic security-claim certificates

`SecurityClaim` separates an untrusted evidence producer from a small deterministic checker.
The producer may retrieve and slice broadly; the checker reopens the immutable snapshot,
parses it independently, and accepts only narrowly defined structural facts.

Falsification also has one deliberately smaller, separate certificate:
`verify_javascript_regex_guard_witness` checks whether a concrete string makes an exact
JavaScript `/pattern/flags.test(...)` expression from the supplied evidence miss. A
supported regex-control bypass cannot be confirmed without that witness and a verified
guard miss. The witness and checker result are stored with the falsification iteration.

Current certificate version: `security_claim_v11`
Current verifier: `deterministic_structural_certificate_checker_v11`

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
- For JavaScript and TypeScript command injection: one direct local `req`/`request`
  property, optionally assigned once, flowing into the first argument of the exact
  `child_process.exec(...)` or `child_process.execSync(...)` member call. The independent
  checker requires the literal `child_process` object identity.
- For Java SSRF: one literal-key `request.getParameter(...)`/`req.getParameter(...)`
  expression, optionally assigned once to a local variable, flowing into the constructor
  argument of the exact `new URL(...).openStream()` or `openConnection()` shape. The checker
  independently loads the Java grammar and reconstructs the same local chain.
- For Ruby unsafe deserialization: one literal-symbol `params[:key]` expression passed
  directly to exact `Marshal.load(...)`, optionally through one exact
  `Base64.decode64(...)` wrapper. The checker independently loads the Ruby grammar and
  reconstructs the receiver, method, argument count, wrapper, and params source.

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
- for a verified regex guard miss, that the application accepts the concrete string, that
  the relevant path executes, or that the claimed security effect occurs.

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

Command-injection support is similarly narrow. Destructured imports (`exec(...)`), aliases
such as `cp.exec(...)`, `spawn`/`spawnSync`, dynamic member access, helper wrappers, and
composed command expressions remain incomplete/unsupported. In particular, seeing request
data somewhere inside string concatenation or a template literal is not treated as a
closed local certificate.

Java support is intentionally one-shape evidence, not a general Java taint engine. URL
variables (`url.openConnection()`), `URI` conversion chains, `HttpClient`, Spring clients,
composed URL expressions, non-literal parameter keys, and other vulnerability mechanisms
remain incomplete/unsupported. Servlet binding and the deployed provenance of the
`request` object are not established.

Ruby support is likewise one reviewed shape, not general Rails taint analysis. String-key
params, local-variable aliases, alternate Base64 helpers, YAML or other object loaders,
composed expressions, and generic `.load` receivers remain incomplete. The certificate does
not establish route exposure, authentication state, gadget availability, or code execution.

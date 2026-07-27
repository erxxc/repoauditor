# Agentic falsification escalation gate

Status: deferred pending measurement prerequisites.

Repoauditor already runs a bounded observe → retrieve → verdict → self-critique loop. A
tool-using agent that autonomously requests more context is not automatically a correctness
improvement: it adds correlated model judgments, wider exposure to untrusted repository
text, and potentially material latency/cost. It must remain opt-in until the following
evidence exists.

## Activation prerequisites

1. **Authoritative usage accounting — implemented for current paths.** All model-backed CLI
   entry points persist provider-reported input/output/cache tokens and latency per attempt;
   deferred batches carry durable parent links, and linked batches are aggregated as one
   logical scan.
   Calls whose failure response omits usage metadata remain counted and explicitly unknown.
   Dollar cost stays unavailable until a dated, provider/model-specific price source exists.
2. **Protected evaluation cohort — partial.** The frozen serialize-javascript pair remains
   outside prompt development and training, but one pair is not a broad real-world cohort.
3. **Baseline comparison — open/paid.** Compare the current bounded falsifier against the
   proposed agent on unique issues, reporting precision, recall, abstention coverage,
   latency, token use, and cost per uniquely validated issue.
4. **Recall safety — open/evidence-gated.** Aggressive false-positive reduction must not
   silently suppress true vulnerabilities. Any unresolved case remains reviewable.
5. **Cohort breakdown — partial/evidence-gated.** Family, analyst-declared mechanism, and
   explicitly sourced SARIF language/detector gates exist; adequate real cohort sizes do
   not yet exist. Missing metadata stays unavailable rather than inferred. Pooled gains
   cannot hide a weak subgroup.
6. **Read-only tools — design only.** The agent may request indexed source, slices, callers,
   references, and stored architecture evidence. It may not execute repository code, invoke
   repository tools, access arbitrary networks, or mutate the checkout.
7. **Independent verification — partial.** Agent-produced claims use the persisted
   `SecurityClaim` contract, bind to an immutable snapshot commit, and are checked by a
   separately versioned deterministic verifier that reopens the snapshot and reconstructs
   supported facts without consuming the producer's evidence object. Version 3 additionally
   checks persisted local HTTP-entry evidence, request-input identity, and control-candidate
   identity/def-use placement. These remain syntax facts—not runtime reachability, attacker
   control, or control effectiveness. The agent never verifies its own claim.

## Proposed eligibility

An experiment should evaluate only findings that remain unresolved after the normal bounded
loop and whose deterministic claim is `incomplete` or absent. “High impact” must come from
recorded architecture/exposure evidence, not raw severity alone. Eligibility, iteration
budget, context budget, and tool allowlist must be configuration-driven and recorded in run
provenance.

Until these gates are satisfied, human review is the safer escalation path.

# Agentic falsification escalation gate

Status: deferred pending measurement prerequisites.

Repoauditor already runs a bounded observe → retrieve → verdict → self-critique loop. A
tool-using agent that autonomously requests more context is not automatically a correctness
improvement: it adds correlated model judgments, wider exposure to untrusted repository
text, and potentially material latency/cost. It must remain opt-in until the following
evidence exists.

## Activation prerequisites

1. **Authoritative usage accounting** — provider-reported input/output/cache tokens and
   latency per call are persisted. Dollar cost may be calculated only from a dated,
   provider/model-specific price source; otherwise report tokens and leave cost unavailable.
2. **Protected evaluation cohort** — independently authored, human-adjudicated repositories
   remain outside prompt development and training.
3. **Baseline comparison** — compare the current bounded falsifier against the proposed
   agent on unique issues, reporting precision, recall, abstention coverage, latency, token
   use, and cost per uniquely validated issue.
4. **Recall safety** — aggressive false-positive reduction must not silently suppress true
   vulnerabilities. Any unresolved case remains reviewable.
5. **Cohort breakdown** — results are separated by mechanism/CWE, language, provider/model,
   and repository family; pooled gains cannot hide a weak subgroup.
6. **Read-only tools** — the agent may request indexed source, slices, callers, references,
   and stored architecture evidence. It may not execute repository code, invoke repository
   tools, access arbitrary networks, or mutate the checkout.
7. **Independent verification** — agent-produced claims use the persisted `SecurityClaim`
   contract, bind to an immutable snapshot commit, and are checked by a separately versioned
   deterministic verifier that reopens the snapshot and reconstructs supported facts without
   consuming the producer's evidence object. The agent never verifies its own claim.

## Proposed eligibility

An experiment should evaluate only findings that remain unresolved after the normal bounded
loop and whose deterministic claim is `incomplete` or absent. “High impact” must come from
recorded architecture/exposure evidence, not raw severity alone. Eligibility, iteration
budget, context budget, and tool allowlist must be configuration-driven and recorded in run
provenance.

Until these gates are satisfied, human review is the safer escalation path.

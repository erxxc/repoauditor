<!--
VERSIONED PROMPT ARTIFACT — falsification self-critique, v1
The reflect step of the bounded challenger loop (observe-think-act-REFLECT). A change
ships as v2 plus a benchmark re-run — never a silent edit. See CLAUDE.md.
-->

# Falsification self-critique — v1

You have just produced a verdict (`confirmed` / `killed` / `unresolved`) on a candidate
finding. Before that verdict is committed, **audit your own reasoning against the
evidence you actually had.** You are your own adversary now: look for the reason the
verdict is wrong, not the reason it is right.

## Check your verdict against the evidence

- Did you actually establish **reachability**, or assume it? If the context never
  showed the sink being reached from an entry point, a `confirmed` is over-reach.
- Did you actually establish **attacker control** of the input?
- For a `killed` verdict: did you find a *specific* mitigating control in the provided
  context, or infer one that isn't shown? Killing on an assumed control is over-reach.
- Is there context you would need but were not given? If so the honest verdict is
  `unresolved`, and this verdict does not hold.

## Output

Output ONLY structured data matching the schema:

- `upholds` — `true` only if the verdict is fully supported by the evidence you were
  given; `false` if it over-reached in either direction.
- `concern` — the specific weakness you found, or, if it holds, why it holds.
- `confidence` — 0.0–1.0 in this self-assessment. Report LOW confidence rather than
  rubber-stamping; a low-confidence critique does not license committing the verdict.

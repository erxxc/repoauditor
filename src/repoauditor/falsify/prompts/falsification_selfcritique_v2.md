<!--
VERSIONED PROMPT ARTIFACT — falsification self-critique, v2
New version (not an edit of v1): audits concrete counterexample evidence and the small
deterministic check separately from reachability and security effect. See CLAUDE.md.
-->

# Falsification self-critique — v2

You have just produced a verdict (`confirmed` / `killed` / `unresolved`) on a candidate
finding. Before it is committed, audit your reasoning against the evidence and any
deterministic counterexample check. Look for the reason the verdict is wrong.

## Check the verdict

- Did the evidence actually establish reachability and attacker control?
- For a `killed` verdict, is the specific mitigating control shown rather than assumed?
- For a `confirmed` JavaScript regex-control bypass, is there a concrete witness using
  the exact cited control expression? If it is absent, malformed, or the deterministic
  result does not say `verified_guard_miss`, the confirmation does not hold.
- A verified regex guard miss proves only that narrow fact. Did evidence independently
  establish application acceptance, path feasibility, and the security effect? If not,
  the confirmation does not hold.
- Did the verdict confuse a different weakness at the same line with the candidate's
  claimed mechanism?
- If necessary context is absent, the honest result is `unresolved`.

## Output

Output ONLY structured data matching the schema:

- `upholds` — true only when the verdict is fully supported.
- `concern` — the specific weakness, or why the verdict holds.
- `confidence` — 0.0–1.0. Low-confidence critique cannot license a verdict.

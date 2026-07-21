<!--
VERSIONED PROMPT ARTIFACT — severity_adjudication, v3
New version (not an edit of v2): adds DEBATE FRAMING. The adjudicator now sees each
source's *reasoning*, not just its severity value, and either synthesizes a documented
consensus or returns an explicit non-consensus (routed to human review). Adds a
`consensus` flag alongside the v2 `confidence` field. A change ships as v4 plus a
benchmark re-run — never a silent tweak. See CLAUDE.md.
-->

# Severity Adjudication (debate framing) — v3

Several sources (deterministic tools and/or AI lenses) flagged the same code region
but disagree on severity. You are given, for EACH source, its proposed severity **and
the reasoning behind it**, plus the shared citation. The sources' arguments are laid
out together so you can weigh them against each other — this is a debate you are
adjudicating, not a vote you are tallying.

## Your task

Read every source's reasoning. Then do exactly one of:

1. **Synthesize a consensus.** If the arguments reconcile — one is clearly stronger, or
   they agree once their reasoning is compared — set `consensus = true`, give the
   resolved `severity`, and document *why* in `rationale`: which argument prevailed and
   what the weaker ones missed.
2. **Declare no consensus.** If the sources genuinely conflict and the evidence does not
   favor one reading over another, set `consensus = false`. Do not force a pick — a
   non-consensus is routed to a human reviewer with the full debate attached.

## Hard rule (unchanged from v2)

The resolved severity **must not exceed the strongest severity any single source
actually proposed.** You are reconciling existing evidence, not manufacturing new
evidence. When in doubt, choose the more conservative (lower) severity. Independent
agreement between sources is the only thing that justifies keeping the higher end of
the range.

## Confidence

Report your `confidence` (0.0–1.0) in the resolution. A low-confidence consensus is
also routed to review rather than committed — do not inflate confidence to force a
resolution through.

## Output

Output ONLY structured data matching the schema: `severity` (the resolved,
evidence-bounded call), `consensus` (true/false), a one-sentence `rationale` naming
which argument prevailed, and `confidence` (0.0–1.0).

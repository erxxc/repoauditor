# Analyst adjudication taxonomy and evaluation protocol

This taxonomy separates “the analyzer was wrong” from “the issue is technically real but
not worth acting on.” It is append-only analyst evidence. The triage classifier remains
binary for now; the detailed disposition is retained so future evaluation does not erase
why a row became actionable, non-actionable, or an abstention.

| Disposition | Meaning | Current `P(actionable)` label |
|---|---|---:|
| `confirmed_actionable` | Real, exploitable, and remediation-worthy | true |
| `tool_incorrect` | The claimed mechanism is not present | false |
| `unreachable` | The cited sink/path cannot be reached | false |
| `not_attacker_controlled` | The relevant value is not attacker-controlled | false |
| `mitigated` | A specific effective control blocks exploitation | false |
| `duplicate` | Same issue as another adjudicated finding | false; exclude from unique counts |
| `valid_not_actionable` | Technically valid, but accepted/immaterial/policy-suppressed | false |
| `insufficient_evidence` | Evidence cannot support a decision | no label; abstention |

Legacy `true_positive`, `false_positive`, and `uncertain` inputs remain accepted and map to
`confirmed_actionable`, `tool_incorrect`, and `insufficient_evidence`.

## Evidence and review

Every assessment records analyst identity, rationale, engagement, finding, and optional
coverage dimensions. Rationales should identify observable source/sink/path evidence, the
disproving condition or control where relevant, and any deployment assumption. A tool or
model must not adjudicate its own output. Ambiguous cases remain `insufficient_evidence`;
they are not converted to negatives to improve apparent precision.

For disputed cases, use a second human reviewer and retain corrections as later assessment
rows. Never rewrite the earlier assessment.

Materiality is analyst-declared with `triage-label --material`; it is never inferred from
severity or modeled loss. A binary material assessment is withheld from classifier training
until a second, distinct analyst records the same detailed disposition. Repeated review by
the same analyst does not satisfy the gate, and cross-analyst disagreement remains withheld.
The append-only assessments remain the audit record while the effective binary label is only
projected after agreement. `triage-collection` reports confirmed, pending, and disputed
material-review counts.

## Reporting views

Report at least two views:

1. **Operational actionability** — only `confirmed_actionable` is positive. This is the
   current triage training target.
2. **Technical validity** — `confirmed_actionable` and `valid_not_actionable` are positive.
   Other decided mechanism/path/control outcomes are negative.

`duplicate` is reported as amplification and excluded from unique-issue denominators.
`insufficient_evidence` is reported as abstention/coverage and excluded from precision and
recall denominators. Report selective performance against decided coverage.

## Split and contamination discipline

- Split by configured evaluation family once the existing volume/diversity gate is met;
  family defaults to stable repository identity and explicit overrides bind clones,
  renamed repositories, and pre/post pairs.
- Prefer temporal evaluation for model/prompt revisions when timestamps support it.
- Keep vulnerability families, clones, and pre/post-fix pairs in one split.
- Keep purpose-built fixtures separate from independently authored real-world evidence.
- Do not train on protected UAT holdouts or derive ground truth from repoauditor's verdicts.
- Break results down by language, mechanism, detector, and disposition when sample sizes
  support it; otherwise label the cohort insufficient.

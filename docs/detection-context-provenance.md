# Detection Context Provenance

Status: implemented as part of OPT-020.

## Scope boundary

A detection **primary region** is a source file selected by the bounded, ground-truth-blind
planner. Its `selection_basis` records why the file received live lens calls:
deterministic-tool evidence, architecture-map evidence, or the stable coverage sample.

The prompt for that primary region may also contain up to three external code blocks from
the syntactic retrieval index:

1. External functions that call a function name defined in the primary file, ordered ahead
   of other context.
2. External similar-pattern functions filling any remaining slots.

These blocks are context expansions, not additional selected regions. Their presence does
not mean the planner selected the related file, the call-name match is type-resolved, or a
runtime/data-flow edge was proven. Architecture-map records affect primary selection; they
are not silently converted into retrieval edges.

## Durable record

`DetectionRun.context_expansions` records only blocks actually appended to a prompt. The
detect stage summary retained by `runs show` uses this shape:

```json
{
  "primary_file": "component_a.py",
  "related": [
    {
      "basis": "call-name-match",
      "file": "component_b.py",
      "line_start": 3,
      "symbol": "dispatch"
    }
  ]
}
```

The supported bases are `call-name-match` and `similar-pattern`. The record contains
location and selection provenance, not the source excerpt itself. Repository evidence
continues to be citation-validated before a finding is persisted.

## Interpretation

- `region_plan.selected` answers which primary files consumed bounded lens capacity.
- `context_expansions` answers which external files contributed bounded prompt context.
- A finding may validly cite an expansion file even when that file is absent from the
  primary selection list, provided the normal citation-integrity check anchors it to the
  repository.
- Missing expansion provenance means no external block was appended; it does not prove that
  no cross-file relationship exists.

This separation is observability only. It does not alter planner ranking, retrieval order,
prompt text, candidate confidence, citation correction, or verdict behavior.

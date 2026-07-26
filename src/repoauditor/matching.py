"""Cross-source finding matching — the single "are these the same underlying issue?" call.

This is deliberately a package-level primitive (like `sourcefiles.py`), not owned by any one
stage, because it is used at **two** points in the pipeline and must give the *same* answer
at both:

  * `normalize/adjudicate.py` — to license a severity upgrade before a finding reaches
    `review/`. Two independently produced signals flagging the same issue is one of the two
    things that license keeping the higher end of a severity range (the other being a
    falsification pass confirming reachability, per CLAUDE.md).
  * `analyze/corroboration.py` — to score cross-source agreement *downstream* of review, for
    the confidence narrative. It never changes severity.

Extracting matching here (rather than leaving it in `analyze/` and importing a stage from a
later stage) is what makes those two uses provably consistent: one heuristic, one place.

The heuristic is **conservative** — a false match is worse than a missed match, because a
false match would license an unwarranted severity upgrade. It matches on:
  * overlapping `line_range` on the same file; and/or
  * a shared CWE class (only counted when *both* sources carry one); and/or
  * a shared map linkage (same `entity_id` / `trust_boundary_id`).
with two guards:
  * a **CWE-conflict veto** — if both sources classified the issue but to *different* CWEs,
    they are two co-located issues, never a match (surfaced as a `Divergence`); and
  * a **cross-file bar** — with no line overlap, a match needs the strong signal (same CWE
    *and* same concrete entity); same trust boundary alone is too coarse (the map's
    primary-boundary fallback makes many findings share one), so it only ever *strengthens*
    an existing match, never creates one.

Matching is intentionally **source-agnostic**: it answers "same issue?", not "corroborating?".
Whether a matched group is *corroboration* (≥2 distinct sources) or a *duplicate* (one source
reported twice) is a caller-side interpretation via `MatchGroup.distinct_sources` — so the
same grouping serves normalize's licensing and analyze's scoring without either re-deciding
what "the same issue" means.

Different prompts executed by the shared LLM ensemble are distinct lenses, but not
independent producers: they share the same provider/model, retrieval context, and calling
path. `has_independent_corroboration` therefore requires either a tool↔lens combination or
two distinct deterministic tools. Lens↔lens agreement remains useful and visible as
multi-lens agreement, but cannot by itself license a severity upgrade.

Pure logic, no I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .store.models import Finding, SourceType

_CWE_RE = re.compile(r"cwe[-_ ]?(\d+)", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Signal extraction
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SourceRef:
    """One distinct detection source (a lens or a tool)."""

    source_type: SourceType
    source_name: str

    def __str__(self) -> str:
        return f"{self.source_name}({self.source_type})"


def source_of(finding: Finding) -> SourceRef:
    if finding.source_tool is not None:
        return SourceRef(SourceType.TOOL, finding.source_tool)
    return SourceRef(SourceType.LENS, finding.source_lens or "unknown")


def has_independent_corroboration(sources: set[SourceRef]) -> bool:
    """Whether a source set spans independently produced evidence.

    All LLM lenses belong to one producer family even when their prompt names differ.
    Distinct deterministic tools are treated as separate producers, as is a tool↔lens pair.
    """
    tools = {source.source_name for source in sources if source.source_type is SourceType.TOOL}
    has_lens = any(source.source_type is SourceType.LENS for source in sources)
    return len(tools) >= 2 or (bool(tools) and has_lens)


def cwes_of(finding: Finding) -> set[str]:
    """CWE ids a finding carries (from its title/description), normalized to bare digits."""
    text = f"{finding.title} {finding.description or ''}"
    return {m.group(1) for m in _CWE_RE.finditer(text)}


def line_overlap(a: Finding, b: Finding) -> bool:
    return a.file == b.file and a.line_start <= b.line_end and b.line_start <= a.line_end


# --------------------------------------------------------------------------- #
# Pairwise decision
# --------------------------------------------------------------------------- #
@dataclass
class MatchDecision:
    """The outcome of comparing two findings: matched, or a surfaced divergence, or neither."""

    matched: bool
    basis: list[str]
    divergence: bool = False
    reason: str = ""


def same_issue(a: Finding, b: Finding) -> MatchDecision:
    """Do two findings point at the same underlying issue? Conservative; source-agnostic."""
    # A detector-supplied natural identity is stronger than a display location. In
    # particular, SCA advisories all anchor to manifest line 1: different keys must not
    # collapse merely because they share that synthetic line, and an unkeyed neighbor
    # must not transitively bridge two distinct advisories.
    if a.identity_key is not None or b.identity_key is not None:
        if a.identity_key is not None and a.identity_key == b.identity_key:
            return MatchDecision(
                matched=True, basis=["natural_identity"],
                reason=f"same detector natural identity {a.identity_key}",
            )
        return MatchDecision(
            matched=False, basis=["natural_identity_conflict"],
            reason="distinct or unavailable detector natural identities",
        )

    cw_a, cw_b = cwes_of(a), cwes_of(b)
    shared_cwe = cw_a & cw_b
    both_classified = bool(cw_a) and bool(cw_b)
    line = line_overlap(a, b)
    same_entity = a.entity_id is not None and a.entity_id == b.entity_id
    same_boundary = a.trust_boundary_id is not None and a.trust_boundary_id == b.trust_boundary_id

    # Veto: both classified the issue but disagree on class -> co-located but distinct.
    if both_classified and not shared_cwe:
        return MatchDecision(
            matched=False, basis=["cwe_conflict"], divergence=True,
            reason=f"co-located but distinct CWE classes {sorted(cw_a)} vs {sorted(cw_b)}",
        )

    if line:
        basis = ["line_overlap"]
        if shared_cwe:
            basis.append(f"cwe:{','.join(sorted(shared_cwe))}")
        if same_entity:
            basis.append("entity")
        if same_boundary:
            basis.append("trust_boundary")
        return MatchDecision(matched=True, basis=basis,
                             reason="overlapping lines from independent sources")

    # No line overlap: only a strong class+locus signal justifies a cross-region match.
    # Same trust boundary ALONE is too coarse (primary-boundary fallback) -> insufficient.
    if shared_cwe and same_entity:
        return MatchDecision(
            matched=True, basis=[f"cwe:{','.join(sorted(shared_cwe))}", "entity"],
            reason="same CWE class at the same architectural entity (different lines)",
        )

    return MatchDecision(matched=False, basis=[], reason="insufficient shared signal to match")


# --------------------------------------------------------------------------- #
# Grouping
# --------------------------------------------------------------------------- #
@dataclass
class Divergence:
    """A surfaced (not hidden) disagreement between sources."""

    kind: str  # "cwe_conflict" | "uncorroborated"
    finding_ids: list[int]
    detail: str


@dataclass
class MatchGroup:
    """A set of findings judged to be the same underlying issue."""

    findings: list[Finding]

    @property
    def representative(self) -> Finding:
        """The finding that speaks for the group — the highest-confidence member."""
        return max(self.findings, key=lambda f: f.confidence)

    @property
    def distinct_sources(self) -> set[SourceRef]:
        return {source_of(f) for f in self.findings}

    @property
    def is_corroborated(self) -> bool:
        """True iff ≥2 named sources agree (including correlated multi-lens agreement)."""
        return len(self.distinct_sources) >= 2

    @property
    def has_independent_corroboration(self) -> bool:
        """True only when agreement spans independently produced evidence."""
        return has_independent_corroboration(self.distinct_sources)

    def corroborating_sources(self) -> set[SourceRef]:
        """Distinct sources other than the representative's own."""
        return self.distinct_sources - {source_of(self.representative)}

    def basis_for(self, member: Finding) -> str:
        """Why `member` is in the group — the basis of its edge to the representative."""
        decision = same_issue(self.representative, member)
        return "+".join(decision.basis) if decision.matched else "transitive-via-group"


@dataclass
class MatchResult:
    """Grouped findings plus the structural divergences found while grouping."""

    groups: list[MatchGroup]
    divergences: list[Divergence] = field(default_factory=list)


def find_matches(findings: list[Finding]) -> MatchResult:
    """Cluster findings by transitive `same_issue`, collecting CWE-conflict divergences.

    Order-stable and deterministic in the finding set: the same rows always produce the same
    groups — which is exactly what lets normalize and analyze rely on identical matching.
    """
    parent = list(range(len(findings)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        parent[find(i)] = find(j)

    divergences: list[Divergence] = []
    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            decision = same_issue(findings[i], findings[j])
            if decision.matched:
                union(i, j)
            elif decision.divergence:
                divergences.append(Divergence(
                    kind="cwe_conflict",
                    finding_ids=[findings[i].id, findings[j].id],
                    detail=decision.reason,
                ))

    clusters: dict[int, list[Finding]] = {}
    for idx, finding in enumerate(findings):
        clusters.setdefault(find(idx), []).append(finding)
    return MatchResult(groups=[MatchGroup(f) for f in clusters.values()],
                       divergences=divergences)

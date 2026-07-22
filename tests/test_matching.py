"""Tests for the shared matcher (repoauditor.matching) — the single 'same issue?' decision
used by both normalize/ (licensing) and analyze/ (scoring). Pure logic, no store needed.
"""

from __future__ import annotations

from repoauditor.matching import (
    SourceRef,
    cwes_of,
    find_matches,
    line_overlap,
    same_issue,
    source_of,
)
from repoauditor.store.models import Finding, SourceType


def _f(*, id=None, lens=None, tool=None, sev="high", conf=0.8, desc="", file="app.py",
       start=10, end=10, entity=None, tb=None):
    if lens is None and tool is None:
        lens = "owasp"  # Finding requires a source; default to a lens for source-agnostic tests
    return Finding(
        id=id, repo_id="r", title="issue", file=file, line_start=start, line_end=end,
        citation_snippet="code", source_lens=lens, source_tool=tool, confidence=conf,
        severity=sev, description=desc, entity_id=entity, trust_boundary_id=tb,
    )


# --------------------------------------------------------------------------- #
# Signal extraction
# --------------------------------------------------------------------------- #
def test_source_and_cwe_and_overlap_primitives():
    assert source_of(_f(tool="sast")) == SourceRef(SourceType.TOOL, "sast")
    assert source_of(_f(lens="owasp")) == SourceRef(SourceType.LENS, "owasp")
    assert cwes_of(_f(desc="sqli [CWE-89] and CWE-78")) == {"89", "78"}
    assert line_overlap(_f(start=10, end=20), _f(start=15, end=25))
    assert not line_overlap(_f(start=10, end=12), _f(start=13, end=15))
    assert not line_overlap(_f(file="a.py"), _f(file="b.py"))


# --------------------------------------------------------------------------- #
# same_issue — the conservative pairwise decision
# --------------------------------------------------------------------------- #
def test_overlapping_lines_match():
    d = same_issue(_f(lens="owasp", start=10, end=10), _f(tool="secrets", start=10, end=10))
    assert d.matched and "line_overlap" in d.basis


def test_conflicting_cwe_on_same_lines_is_a_divergence_not_a_match():
    d = same_issue(_f(lens="owasp", desc="[CWE-89]"), _f(tool="sast", desc="[CWE-78]"))
    assert not d.matched and d.divergence and d.basis == ["cwe_conflict"]


def test_cross_file_needs_shared_cwe_and_same_entity():
    a = _f(tool="sca", file="requirements.txt", start=1, end=1, desc="[CWE-1104]", entity=7)
    b = _f(lens="owasp", file="app.py", start=5, end=5, desc="[CWE-1104]", entity=7)
    d = same_issue(a, b)
    assert d.matched and "entity" in d.basis and any(x.startswith("cwe:") for x in d.basis)
    # Same CWE but different entity (no line overlap) is below the conservative bar.
    b2 = _f(lens="owasp", file="app.py", start=5, end=5, desc="[CWE-1104]", entity=9)
    assert not same_issue(a, b2).matched


def test_trust_boundary_alone_does_not_create_a_cross_file_match():
    # Same boundary, no shared CWE, no line overlap, no shared entity => not a match
    # (the primary-boundary fallback makes trust boundary too coarse to match on alone).
    a = _f(tool="sca", file="requirements.txt", start=1, end=1, tb=3)
    b = _f(lens="owasp", file="app.py", start=5, end=5, tb=3)
    assert not same_issue(a, b).matched


# --------------------------------------------------------------------------- #
# find_matches — grouping + MatchGroup helpers
# --------------------------------------------------------------------------- #
def test_grouping_and_corroboration_flags():
    lens = _f(id=1, lens="owasp", conf=0.9)
    tool = _f(id=2, tool="secrets", conf=0.6)
    result = find_matches([lens, tool])
    assert len(result.groups) == 1
    g = result.groups[0]
    assert g.is_corroborated                        # two distinct sources
    assert g.representative.id == 1                  # highest confidence
    assert g.distinct_sources == {SourceRef(SourceType.LENS, "owasp"),
                                  SourceRef(SourceType.TOOL, "secrets")}
    assert g.corroborating_sources() == {SourceRef(SourceType.TOOL, "secrets")}
    assert "line_overlap" in g.basis_for(tool)


def test_same_source_group_is_not_corroborated():
    g = find_matches([_f(id=1, tool="sast"), _f(id=2, tool="sast")]).groups[0]
    assert not g.is_corroborated                    # one distinct source == duplicate
    assert len(g.distinct_sources) == 1


def test_matching_is_deterministic_on_the_finding_set():
    findings = [_f(id=1, lens="owasp", conf=0.9), _f(id=2, tool="secrets", conf=0.6),
                _f(id=3, lens="crypto", file="other.py", start=1, end=1)]
    a = find_matches(findings)
    b = find_matches(list(reversed(findings)))
    # Same rows => same grouping (order-independent), which is what lets normalize and
    # analyze rely on identical matching at their two pipeline points.
    assert {frozenset(f.id for f in g.findings) for g in a.groups} == \
           {frozenset(f.id for f in g.findings) for g in b.groups}

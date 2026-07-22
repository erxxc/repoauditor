"""Tests for analyze/corroboration.py — conservative cross-source matching + scoring.

The bias under test is: a *false* match is worse than a *missed* match (a false match would
license an unwarranted severity upgrade). So the suite pins down what does NOT match
(same-source duplicates; co-located-but-different-CWE) as much as what does, plus the
independence-weighted score and the fact that severity is never touched here.
"""

from __future__ import annotations

import pytest

from repoauditor.analyze.corroboration import (
    SourceRef,
    agreement_score,
    corroborate,
)
from repoauditor.store import db
from repoauditor.store.models import Finding, SourceType


def _finding(cfg, *, title, line, source_lens=None, source_tool=None, desc="",
             sev="high", conf=0.8, tb=None, entity=None, file="app.py"):
    return db.insert_finding(Finding(
        repo_id="r", title=title, file=file, line_start=line, line_end=line,
        citation_snippet="code", source_lens=source_lens, source_tool=source_tool,
        confidence=conf, severity=sev, description=desc,
        trust_boundary_id=tb, entity_id=entity,
    ), cfg)


# --------------------------------------------------------------------------- #
# Matching — the positive case and the conservative vetoes.
# --------------------------------------------------------------------------- #
def test_cross_source_overlap_matches_and_scores_cross_class(tmp_config):
    db.init_db(tmp_config)
    lens_id = _finding(tmp_config, title="Hardcoded token", line=16, source_lens="owasp")
    tool_id = _finding(tmp_config, title="Secret", line=16, source_tool="secrets")

    results, _ = corroborate("r", tmp_config)
    assert len(results) == 1
    res = results[0]
    # Representative is the higher-confidence finding; the *other* source is the corroborator.
    assert res.representative_id in (lens_id, tool_id)
    assert {(c.source_type, c.source_name) for c in res.corroborations} != set()
    # One tool + one lens => independence 1.0, breadth 0.5 => 0.5.
    assert res.score == pytest.approx(0.5)
    assert all(c.score == pytest.approx(0.5) for c in res.corroborations)
    assert any("line_overlap" in (c.match_basis or "") for c in res.corroborations)


def test_merged_group_is_reported_once_not_per_member(tmp_config):
    """corroborate reuses the shared matcher, so a group of N members yields ONE result
    (keyed to the representative) — it never double-reports the same issue per member."""
    db.init_db(tmp_config)
    rep = _finding(tmp_config, title="token", line=16, source_lens="owasp", conf=0.9)
    dup = _finding(tmp_config, title="secret", line=16, source_tool="secrets", conf=0.6)

    results, _ = corroborate("r", tmp_config)
    assert len(results) == 1
    assert results[0].representative_id == rep
    assert sorted(results[0].member_finding_ids) == sorted([rep, dup])


def test_same_source_is_not_corroboration(tmp_config):
    """Two findings from the SAME tool at the same spot are duplicates, not agreement."""
    db.init_db(tmp_config)
    _finding(tmp_config, title="dup a", line=16, source_tool="sast")
    _finding(tmp_config, title="dup b", line=16, source_tool="sast")

    results, divergences = corroborate("r", tmp_config)
    assert results == []  # no multi-source group
    # Both are surfaced as uncorroborated rather than silently collapsed.
    assert {d.kind for d in divergences} == {"uncorroborated"}
    assert db.list_findings("r", tmp_config)[0].corroborated_by == []


def test_cwe_conflict_is_a_divergence_not_a_match(tmp_config):
    """Overlapping lines but different CWE classes => two distinct issues, never a match."""
    db.init_db(tmp_config)
    _finding(tmp_config, title="SQLi", line=24, source_lens="owasp", desc="sqli [CWE-89]")
    _finding(tmp_config, title="Cmd inj", line=24, source_tool="sast", desc="os cmd [CWE-78]")

    results, divergences = corroborate("r", tmp_config)
    assert results == []  # the veto fired — no corroboration written
    conflicts = [d for d in divergences if d.kind == "cwe_conflict"]
    assert len(conflicts) == 1
    assert "89" in conflicts[0].detail and "78" in conflicts[0].detail


def test_cross_file_match_requires_cwe_and_same_entity(tmp_config):
    """No line overlap => match only on the strong signal (shared CWE at the same entity)."""
    db.init_db(tmp_config)
    # Same entity id, same CWE, different files/lines — a manifest hit vs an import-site hit.
    from repoauditor.store.models import Entity, EntityKind, TrustBoundary
    tb_id = db.insert_trust_boundary(TrustBoundary(repo_id="r", name="edge"), tmp_config)
    ent = db.insert_entity(Entity(repo_id="r", kind=EntityKind.INTEGRATION, name="dep",
                                  trust_boundary_id=tb_id), tmp_config)
    _finding(tmp_config, title="Vuln dep", line=1, file="requirements.txt",
             source_tool="sca", desc="flask CVE [CWE-1104]", tb=tb_id, entity=ent)
    _finding(tmp_config, title="Unsafe import", line=5, file="app.py",
             source_lens="owasp", desc="uses vulnerable flask [CWE-1104]", tb=tb_id, entity=ent)

    results, _ = corroborate("r", tmp_config)
    assert len(results) == 1
    assert results[0].score == pytest.approx(0.5)
    assert any("entity" in (c.match_basis or "") for c in results[0].corroborations)


def test_cross_file_without_entity_does_not_match(tmp_config):
    """Same CWE but no shared entity and no line overlap => below the conservative bar."""
    db.init_db(tmp_config)
    _finding(tmp_config, title="a", line=1, file="requirements.txt", source_tool="sca",
             desc="[CWE-1104]")
    _finding(tmp_config, title="b", line=5, file="app.py", source_lens="owasp",
             desc="[CWE-1104]")
    results, _ = corroborate("r", tmp_config)
    assert results == []


# --------------------------------------------------------------------------- #
# Agreement scoring — independence dominates raw count.
# --------------------------------------------------------------------------- #
def test_agreement_score_independence_weighting():
    lens_a = SourceRef(SourceType.LENS, "owasp")
    lens_b = SourceRef(SourceType.LENS, "secure-design")
    lens_c = SourceRef(SourceType.LENS, "crypto")
    tool = SourceRef(SourceType.TOOL, "semgrep")

    assert agreement_score({lens_a}) == 0.0                     # single source: no agreement
    cross_pair = agreement_score({lens_a, tool})                # tool+lens
    same_pair = agreement_score({lens_a, lens_b})               # lens+lens
    same_trio = agreement_score({lens_a, lens_b, lens_c})       # lens+lens+lens
    assert cross_pair == pytest.approx(0.5)
    assert same_pair == pytest.approx(0.25)
    # Independence dominates count: a cross-class *pair* beats a same-class *trio*.
    assert cross_pair > same_trio
    assert same_trio > same_pair


# --------------------------------------------------------------------------- #
# Discipline: corroboration records the agreement but never upgrades severity.
# --------------------------------------------------------------------------- #
def test_corroboration_persists_score_and_leaves_severity_untouched(tmp_config):
    db.init_db(tmp_config)
    lens_id = _finding(tmp_config, title="token", line=16, source_lens="owasp",
                       sev="medium", conf=0.9)
    _finding(tmp_config, title="secret", line=16, source_tool="secrets",
             sev="high", conf=0.6)

    corroborate("r", tmp_config)

    # Re-read through the store: the corroboration + score is hydrated onto the finding,
    # and the representative's severity is exactly what it was — no upgrade happened here.
    rep = next(f for f in db.list_findings("r", tmp_config) if f.id == lens_id)
    assert rep.severity == "medium"                    # unchanged
    assert rep.corroborated_by                          # corroboration recorded
    assert rep.corroborated_by[0].score == pytest.approx(0.5)
    assert rep.corroborated_by[0].match_basis

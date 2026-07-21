"""Tests for the normalize stage — severity adjudication across conflicting sources."""

from __future__ import annotations

from repoauditor.llm import LLMClient, ScriptedBackend
from repoauditor.normalize import Adjudication, adjudicate
from repoauditor.store import db
from repoauditor.store.models import FalsificationStatus, Finding, Severity, SourceType


def _finding(source_lens=None, source_tool=None, severity="high", confidence=0.8,
             description=None):
    return Finding(
        repo_id="r",
        title="overlapping issue",
        file="app.py",
        line_start=24,
        line_end=25,
        citation_snippet='conn.execute("SELECT * FROM users WHERE id = " + user_id)',
        source_lens=source_lens,
        source_tool=source_tool,
        confidence=confidence,
        severity=severity,
        description=description,
    )


def _client(resolution: Severity, tmp_config, confidence: float = 1.0,
            consensus: bool = True) -> LLMClient:
    def handler(system, user, schema, context):
        assert schema is Adjudication
        return Adjudication(severity=resolution, rationale="scripted resolution",
                            consensus=consensus, confidence=confidence)

    return LLMClient(ScriptedBackend(handler), tmp_config)


def test_adjudicates_conflicting_sources_and_records_corroboration(tmp_config):
    db.init_db(tmp_config)
    tool_finding = _finding(source_tool="sast", severity="high", confidence=0.7)
    lens_finding = _finding(source_lens="owasp", severity="critical", confidence=0.9)

    resolved = adjudicate([tool_finding, lens_finding], config=tmp_config,
                          llm=_client(Severity.HIGH, tmp_config))

    assert len(resolved) == 1
    finding = resolved[0]
    assert finding.severity is Severity.HIGH
    assert finding.source_lens == "owasp"  # highest-confidence representative
    assert [(c.source_type, c.source_name) for c in finding.corroborated_by] == [
        (SourceType.TOOL, "sast")
    ]


def test_resolved_severity_is_capped_at_the_evidence_ceiling(tmp_config):
    db.init_db(tmp_config)
    a = _finding(source_tool="sast", severity="medium", confidence=0.6)
    b = _finding(source_lens="owasp", severity="high", confidence=0.9)

    # Even if the model returns critical, the code caps at the ceiling (high).
    resolved = adjudicate([a, b], config=tmp_config, llm=_client(Severity.CRITICAL, tmp_config))

    assert resolved[0].severity is Severity.HIGH


def test_low_confidence_adjudication_keeps_both_severities_unresolved(tmp_config):
    db.init_db(tmp_config)
    a = _finding(source_tool="sast", severity="medium", confidence=0.6)
    b = _finding(source_lens="owasp", severity="high", confidence=0.9)

    # Model resolves, but with confidence below threshold -> don't pick a winner.
    resolved = adjudicate([a, b], config=tmp_config,
                          llm=_client(Severity.HIGH, tmp_config, confidence=0.3))

    f = resolved[0]
    assert f.falsification_status is FalsificationStatus.UNRESOLVED
    # Both original severities are preserved rather than collapsed to one.
    notes = {(c.source_name, c.note) for c in f.corroborated_by}
    assert ("sast", "medium") in notes
    assert ("owasp", "high") in notes


def test_single_source_finding_passes_through_unchanged(tmp_config):
    lone = _finding(source_lens="owasp", severity="medium")

    def boom(*a, **k):  # must not be called for a single-source group
        raise AssertionError("adjudication should not run without a conflict")

    resolved = adjudicate([lone], config=tmp_config,
                          llm=LLMClient(ScriptedBackend(boom), tmp_config))

    assert len(resolved) == 1
    assert resolved[0].severity is Severity.MEDIUM
    assert resolved[0].corroborated_by == []


# --------------------------------------------------------------------------- #
# Debate framing: the full trail (positions + outcome) is persisted, not just severity
# --------------------------------------------------------------------------- #
def test_debate_sees_each_sources_reasoning_and_persists_a_consensus_trail(tmp_config):
    db.init_db(tmp_config)
    tool = _finding(source_tool="sast", severity="high", confidence=0.7,
                    description="pattern matched an unsanitized concat")
    lens = _finding(source_lens="owasp", severity="critical", confidence=0.9,
                    description="reachable from an unauthenticated endpoint")

    captured = {}

    def handler(system, user, schema, context):
        captured["user"] = user  # what the adjudicator actually saw
        return Adjudication(severity=Severity.HIGH, rationale="tool's concat argument prevailed",
                            consensus=True, confidence=0.9)

    resolved = adjudicate([tool, lens], config=tmp_config,
                          llm=LLMClient(ScriptedBackend(handler), tmp_config))

    # The adjudicator was shown BOTH sources' reasoning, not just their severities.
    assert "pattern matched an unsanitized concat" in captured["user"]
    assert "reachable from an unauthenticated endpoint" in captured["user"]
    assert resolved[0].severity is Severity.HIGH

    # The full debate trail is persisted with the consensus outcome.
    debates = db.list_adjudication_debates("r", tmp_config)
    assert len(debates) == 1
    debate = debates[0]
    assert debate.outcome == "consensus"
    assert debate.resolved_severity is Severity.HIGH
    assert {p.severity for p in debate.positions} == {Severity.HIGH, Severity.CRITICAL}
    assert {p.reasoning for p in debate.positions} == {
        "pattern matched an unsanitized concat",
        "reachable from an unauthenticated endpoint",
    }


def test_no_consensus_routes_to_unresolved_and_persists_the_disagreement(tmp_config):
    db.init_db(tmp_config)
    a = _finding(source_tool="sast", severity="medium", confidence=0.6,
                 description="only a heuristic match")
    b = _finding(source_lens="owasp", severity="high", confidence=0.9,
                 description="looks reachable but unconfirmed")

    # Model is confident, but declares NO consensus -> route to review as unresolved.
    resolved = adjudicate([a, b], config=tmp_config,
                          llm=_client(Severity.HIGH, tmp_config, confidence=0.9,
                                      consensus=False))

    f = resolved[0]
    assert f.falsification_status is FalsificationStatus.UNRESOLVED
    # Both severities preserved (not collapsed to one).
    notes = {(c.source_name, c.note) for c in f.corroborated_by}
    assert ("sast", "medium") in notes and ("owasp", "high") in notes
    assert "no consensus" in (f.description or "")

    debate = db.get_adjudication_debate_for_region("r", "app.py", 24, 25, tmp_config)
    assert debate is not None
    assert debate.outcome == "unresolved"
    assert debate.resolved_severity is None       # nothing forced
    assert len(debate.positions) == 2             # the disagreement itself is auditable

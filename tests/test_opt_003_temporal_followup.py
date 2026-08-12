"""OPT-003 follow-up is one-symbol, bounded, score-blind, and non-mutating."""

from __future__ import annotations

import inspect

from repoauditor.eval import temporal_followup, temporal_followup_corrected


def test_followup_binds_one_abstention_and_exact_symbol():
    assert temporal_followup.FINDING_ID == 2036
    assert temporal_followup.ASSESSMENT_ID == 159
    assert temporal_followup.SYMBOL == "requireFileOwner"
    assert temporal_followup.MAX_MATCHED_FILES == 10
    assert temporal_followup.MAX_RENDERED_FILES == 2
    assert temporal_followup.MAX_MATCHES == 4
    assert temporal_followup.CONTEXT_LINES == 20


def test_followup_store_query_reads_no_scores_or_outcomes():
    source = inspect.getsource(temporal_followup._assert_store)
    for forbidden in ("p_actionable", "rank", "suppressed", "confidence"):
        assert forbidden not in source
    assert "insufficient_evidence" in source


def test_followup_renderer_is_local_bounded_and_refuses_overwrite():
    render_source = inspect.getsource(temporal_followup.render_followup)
    main_source = inspect.getsource(temporal_followup.main)
    assert "root.rglob" in render_source
    assert "MAX_MATCHED_FILES" in render_source
    assert "MAX_RENDERED_FILES" in render_source
    assert "MAX_MATCHES" in render_source
    assert "CONTEXT_LINES" in render_source
    assert "refusing to overwrite" in main_source


def test_corrected_renderer_selects_only_first_four_stable_matches():
    source = inspect.getsource(temporal_followup_corrected.render_followup)
    assert 'sorted(root.rglob("*"))' in source
    assert "matches[:MAX_MATCHES]" in source
    assert "MAX_RENDERED_FILES" in source
    assert "CONTEXT_LINES" in source
    assert "p_actionable" not in source

"""The OPT-002 selector uses only frozen identity inputs."""

from __future__ import annotations

from dataclasses import replace

import pytest

from repoauditor.eval.independent_packet import (
    EligibleCandidate,
    SOURCES,
    _candidate_key,
    select_balanced,
)


def _candidate(repo_id: str, index: int) -> EligibleCandidate:
    source = SOURCES[repo_id]
    fingerprint = f"fp-{repo_id}-{index:03d}"
    return EligibleCandidate(
        finding_id=index,
        repo_id=repo_id,
        evaluation_family=source["family"],
        finding_fingerprint=fingerprint,
        rule_id="rule",
        file=f"app/{index}.rb",
        line_start=index,
        line_end=index,
        title="title",
        producer="semgrep",
        candidate_key=_candidate_key(source["family"], fingerprint),
        source_commit=source["commit"],
        triage_model_run_id=source["model_run"],
        normalized_sink="sink",
    )


def test_selector_is_balanced_and_stable_without_score_fields(monkeypatch):
    monkeypatch.setitem(SOURCES["opt002-documenso"], "eligible", 7)
    monkeypatch.setitem(SOURCES["opt002-lobsters"], "eligible", 8)
    candidates = [
        *(_candidate("opt002-documenso", index) for index in range(7)),
        *(_candidate("opt002-lobsters", index) for index in range(8)),
    ]

    selected = select_balanced(candidates)

    assert len(selected) == 12
    assert [item.repo_id for item in selected[::2]] == ["opt002-documenso"] * 6
    assert [item.repo_id for item in selected[1::2]] == ["opt002-lobsters"] * 6
    assert not hasattr(selected[0], "p_actionable")
    assert not hasattr(selected[0], "rank")
    assert not hasattr(selected[0], "severity")
    assert select_balanced(list(reversed(candidates))) == selected


def test_selector_fails_closed_on_family_inventory_drift(monkeypatch):
    monkeypatch.setitem(SOURCES["opt002-documenso"], "eligible", 1)
    monkeypatch.setitem(SOURCES["opt002-lobsters"], "eligible", 1)
    candidates = [
        _candidate("opt002-documenso", 1),
        _candidate("opt002-lobsters", 1),
    ]

    with pytest.raises(RuntimeError, match="cannot supply"):
        select_balanced(candidates)


def test_non_ordering_metadata_does_not_change_selection(monkeypatch):
    monkeypatch.setitem(SOURCES["opt002-documenso"], "eligible", 6)
    monkeypatch.setitem(SOURCES["opt002-lobsters"], "eligible", 6)
    candidates = [
        *(_candidate("opt002-documenso", index) for index in range(6)),
        *(_candidate("opt002-lobsters", index) for index in range(6)),
    ]
    changed = [replace(item, title="changed", file="elsewhere.rb") for item in candidates]

    assert [item.candidate_key for item in select_balanced(changed)] == [
        item.candidate_key for item in select_balanced(candidates)
    ]

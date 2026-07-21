"""Tests for the AST retrieval index (deterministic — no LLM)."""

from __future__ import annotations

from pathlib import Path

from repoauditor.detect.retrieval import RetrievalIndex

SOURCE = '''\
import sqlite3


def run_query(user_id):
    conn = sqlite3.connect("app.db")
    return conn.execute("SELECT * FROM users WHERE id = " + user_id)


def handler(user_id):
    return run_query(user_id)


def other():
    conn = sqlite3.connect("x.db")
    return conn.execute("SELECT 1")
'''


def _index(tmp_path: Path) -> RetrievalIndex:
    (tmp_path / "app.py").write_text(SOURCE)
    return RetrievalIndex().build(tmp_path)


def test_find_callers(tmp_path):
    index = _index(tmp_path)
    callers = index.find_callers("run_query")
    assert [c.symbol for c in callers] == ["handler"]


def test_find_callees(tmp_path):
    index = _index(tmp_path)
    callees = {c.symbol for c in index.find_callees("handler")}
    assert "run_query" in callees


def test_find_similar_patterns(tmp_path):
    index = _index(tmp_path)
    # Both run_query and other call `connect` + `execute`; a snippet using them
    # should surface both, most-overlapping first.
    hits = index.find_similar_patterns('conn.execute("SELECT * FROM t WHERE x=" + y)')
    symbols = {h.symbol for h in hits}
    assert {"run_query", "other"} <= symbols

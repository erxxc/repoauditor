"""Tests for the AST retrieval index (deterministic — no LLM)."""

from __future__ import annotations

import logging
from pathlib import Path

from repoauditor.detect.retrieval import RetrievalIndex

MULTILANG = Path(__file__).parent / "fixtures" / "multilang_retrieval" / "snapshot"

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


# --------------------------------------------------------------------------- #
# Multi-language AST indexing (tree-sitter): JS / TS / Java / Ruby share the
# exact find_callers/find_callees/find_similar_patterns interface as Python.
# --------------------------------------------------------------------------- #
def _callers_in(index: RetrievalIndex, symbol: str, file_suffix: str) -> set[str]:
    """Caller symbols of `symbol` restricted to one source file (avoids cross-language
    symbol-name collisions in the shared name index)."""
    return {c.symbol for c in index.find_callers(symbol) if c.file.endswith(file_suffix)}


def test_javascript_ast_caller_callee():
    index = RetrievalIndex().build(MULTILANG)
    # function_declaration + arrow-assigned const both call runQuery.
    assert _callers_in(index, "runQuery", "svc.js") == {"handler", "helper"}
    callees = {c.symbol for c in index.find_callees("handler")}
    assert "runQuery" in callees
    # member-call `conn.execute(...)` is stored under the method name.
    run_query = next(f for f in index.find_callers("runQuery") if f.symbol == "handler")
    assert run_query.language == "javascript"


def test_typescript_ast_caller_callee():
    index = RetrievalIndex().build(MULTILANG)
    assert _callers_in(index, "lookup", "svc.ts") == {"fetchUser"}
    fetch = next(c for c in index.find_callers("lookup") if c.file.endswith("svc.ts"))
    assert fetch.language == "typescript"


def test_java_ast_caller_callee():
    index = RetrievalIndex().build(MULTILANG)
    assert _callers_in(index, "runQuery", "Svc.java") == {"handle"}


def test_ruby_ast_caller_callee():
    index = RetrievalIndex().build(MULTILANG)
    assert _callers_in(index, "run_query", "svc.rb") == {"handler"}
    callees = {c.symbol for c in index.find_callees("handler") if c.language == "ruby"}
    assert "run_query" in callees


def test_unsupported_language_falls_back_to_lexical_and_is_logged(tmp_path, caplog):
    (tmp_path / "svc.go").write_text(
        "package main\nfunc handler(id string) string { return runQuery(id) }\n"
        "func runQuery(id string) string { return db.Execute(id) }\n"
    )
    with caplog.at_level(logging.INFO, logger="repoauditor.detect.retrieval.index"):
        index = RetrievalIndex().build(tmp_path)
    # Explicit, logged fallback — not a silent gap.
    assert any("lexical fallback" in r.message and ".go" in r.message for r in caplog.records)
    # The .go file is still retrievable via lexical tokens rather than dropped.
    hits = index.find_similar_patterns("x = runQuery(id)")
    assert any(h.file.endswith("svc.go") for h in hits)
    assert any(f.language == "lexical" for f in index.find_callers("runQuery"))


def test_similar_patterns_span_languages():
    index = RetrievalIndex().build(MULTILANG)
    # `execute(` appears in the JS, Java, and Ruby fixtures — one snippet surfaces all.
    hits = index.find_similar_patterns('conn.execute("SELECT " + x)')
    langs = {h.language for h in hits}
    assert {"javascript", "java", "ruby"} <= langs

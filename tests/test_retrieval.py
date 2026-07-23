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


def test_find_enclosing_includes_decorators_and_local_source(tmp_path):
    (tmp_path / "routes.py").write_text(
        'from flask import Blueprint, request\n'
        'bp = Blueprint("catalog", __name__)\n\n'
        '@bp.route("/search")\n'
        'def search():\n'
        '    term = request.args.get("q", "")\n'
        '    sql = "SELECT * FROM products WHERE name = \'" + term + "\'"\n'
        '    return sql\n'
    )
    index = RetrievalIndex().build(tmp_path)

    enclosing = index.find_enclosing("routes.py", 7, 7)

    assert [item.symbol for item in enclosing] == ["search"]
    assert enclosing[0].line_start == 4
    assert '@bp.route("/search")' in enclosing[0].source
    assert 'request.args.get("q"' in enclosing[0].source


def test_file_excerpt_and_text_references_include_module_level_evidence(tmp_path):
    (tmp_path / "legacy.py").write_text(
        'ENABLE_LEGACY = False\n\n'
        'def legacy_import():\n'
        '    if not ENABLE_LEGACY:\n'
        '        return None\n'
        '    dangerous()\n'
    )
    (tmp_path / "app.py").write_text(
        'def create_app():\n'
        '    # legacy_import is intentionally not registered\n'
        '    register(active_handler)\n'
    )
    index = RetrievalIndex().build(tmp_path)

    excerpt = index.file_excerpt("legacy.py", 6, context_lines=6)
    references = index.find_text_references("legacy_import")

    assert excerpt is not None and "ENABLE_LEGACY = False" in excerpt.source
    assert any(item.file == "app.py" and "register(active_handler)" in item.source
               for item in references)


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


def test_javascript_ast_walk_handles_nesting_beyond_python_recursion_limit(tmp_path):
    depth = 1_500
    nested = "(" * depth + "userInput" + ")" * depth
    (tmp_path / "deep.js").write_text(
        f"function deeplyNested() {{ return sink({nested}); }}\n"
    )

    index = RetrievalIndex().build(tmp_path)

    callers = index.find_callers("sink")
    assert any(item.symbol == "deeplyNested" for item in callers)


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

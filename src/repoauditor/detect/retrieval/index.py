"""Repo-wide multi-language retrieval index.

Deterministic caller/callee and similar-pattern lookup over an ingested snapshot
(preferred over embeddings here: no infra, reproducible). Before a lens scores a
candidate, the ensemble pulls in related call sites; the falsify stage uses the same
index to look for mitigating controls elsewhere in the codebase.

The query interface includes callers, callees, similar patterns, enclosing functions,
bounded file excerpts, and literal repo-wide references. The latter three let falsification
retrieve source-to-sink, decorator, module-config, and registration evidence even when a
finding snippet contains no call token. Indexing is AST-based per language:

  * Python           via the stdlib `ast` module (dependency-free, exact).
  * JS / TS / Java /  via tree-sitter grammars (`tree_sitter_language_pack`), walking
    Ruby              each grammar's function-definition and call nodes.
  * everything else   falls back to a lexical (regex) index — an explicit, *logged*
                      degrade ("no AST support for .go files, using lexical fallback"),
                      never a silent gap, so a `.go`/`.php`/`.rs` file still participates
                      in similar-pattern retrieval instead of vanishing.

The public interface is identical regardless of how a file was indexed, so
`falsify/`'s mitigating-control search and `detect/`'s pattern-repetition detection
benefit from the new languages without any change to their calling code.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from ...sourcefiles import iter_source_files

logger = logging.getLogger(__name__)


@dataclass
class FunctionInfo:
    """One indexed function: where it lives, its source, and the names it calls.

    For lexically-indexed (non-AST) files there is one `FunctionInfo` per file whose
    `symbol` is the file path and whose `calls` are the call-like tokens found by regex —
    enough to keep the file visible to `find_similar_patterns`/`find_callers`.
    """

    symbol: str
    file: str  # relative to snapshot root
    line_start: int
    line_end: int
    source: str
    calls: set[str] = field(default_factory=set)
    language: str = "python"


@dataclass(frozen=True)
class CitationLocation:
    """One exact occurrence of a verbatim citation in the indexed snapshot."""

    file: str
    line_start: int
    line_end: int


# --------------------------------------------------------------------------- #
# Language dispatch
# --------------------------------------------------------------------------- #
# Suffix -> tree-sitter language name in tree_sitter_language_pack. Python is handled
# separately by the stdlib `ast` path; anything not here and not `.py` is lexical.
_TS_LANG_BY_SUFFIX: dict[str, str] = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "tsx",
    ".java": "java",
    ".rb": "ruby",
}

# Grammars share an extraction "family" (JS/TS/TSX parse to the same node shapes).
_FAMILY_BY_LANG: dict[str, str] = {
    "javascript": "js", "typescript": "js", "tsx": "js",
    "java": "java",
    "ruby": "ruby",
}

# Per-family node types: which nodes are function definitions (mapped to the field
# holding the symbol name) and which are calls. Verified against the installed grammars.
_DEF_TYPES: dict[str, dict[str, str]] = {
    "js": {
        "function_declaration": "name",
        "generator_function_declaration": "name",
        "method_definition": "name",
    },
    "java": {"method_declaration": "name", "constructor_declaration": "name"},
    "ruby": {"method": "name", "singleton_method": "name"},
}
_CALL_TYPES: dict[str, set[str]] = {
    "js": {"call_expression"},
    "java": {"method_invocation"},
    "ruby": {"call"},
}


class RetrievalIndex:
    """AST index over a snapshot for callers/callees + similar-pattern lookup.

    Storage is a flat list of `FunctionInfo` plus a name->defs index, so several files
    defining the same symbol are all retained (the earlier Python-only index kept only
    the last definition of a colliding name — a real limitation once multiple languages
    and files are in play).
    """

    def __init__(self) -> None:
        self._functions: list[FunctionInfo] = []
        self._by_name: dict[str, list[FunctionInfo]] = {}
        self._file_texts: dict[str, str] = {}
        self._lexical_logged: set[str] = set()  # extensions already warned about
        self._built = False
        self._snapshot_path: Path | None = None

    # ------------------------------------------------------------------ build
    def build(self, snapshot_path: Path) -> "RetrievalIndex":
        """Index the snapshot. Idempotent per instance; returns self for chaining."""
        snapshot_path = Path(snapshot_path)
        self._snapshot_path = snapshot_path.resolve()
        for path in iter_source_files(snapshot_path):
            rel = path.relative_to(snapshot_path).as_posix()
            text = path.read_text(errors="replace")
            self._file_texts[rel] = text
            suffix = path.suffix.lower()
            if suffix == ".py":
                infos = _index_python(text, rel)
            elif suffix in _TS_LANG_BY_SUFFIX:
                infos = self._index_treesitter(text, rel, _TS_LANG_BY_SUFFIX[suffix], suffix)
            else:
                infos = self._index_lexical(text, rel, suffix)
            self._add(infos)
        self._built = True
        return self

    @property
    def snapshot_path(self) -> Path | None:
        """Root used to build this index; independent checkers may reopen it."""
        return self._snapshot_path

    def _add(self, infos: list[FunctionInfo]) -> None:
        for info in infos:
            self._functions.append(info)
            self._by_name.setdefault(info.symbol, []).append(info)

    def _index_treesitter(
        self, text: str, rel: str, ts_lang: str, suffix: str
    ) -> list[FunctionInfo]:
        """AST-index a supported non-Python file, degrading to lexical if the grammar
        can't be loaded (so a missing optional grammar is a logged fallback, not a crash)."""
        parser = _get_ts_parser(ts_lang)
        if parser is None:
            if suffix not in self._lexical_logged:
                logger.warning(
                    "tree-sitter grammar for %s unavailable; using lexical fallback for %s files",
                    ts_lang, suffix,
                )
                self._lexical_logged.add(suffix)
            return self._index_lexical(text, rel, suffix)
        return _index_treesitter_source(text, rel, ts_lang, parser)

    def _index_lexical(self, text: str, rel: str, suffix: str) -> list[FunctionInfo]:
        """Lexical (regex) fallback for a language with no AST support. Logged once/ext."""
        if suffix not in self._lexical_logged:
            logger.info("no AST support for %s files, using lexical fallback", suffix)
            self._lexical_logged.add(suffix)
        calls = _call_tokens(text)
        if not calls:
            return []
        lines = text.splitlines()
        # One file-level pseudo-function so the file stays retrievable by shared tokens.
        return [FunctionInfo(
            symbol=rel, file=rel, line_start=1, line_end=max(len(lines), 1),
            source=text, calls=calls, language="lexical",
        )]

    # ------------------------------------------------------------------ query
    def find_callers(self, symbol: str) -> list[FunctionInfo]:
        """Functions whose body calls `symbol`, ordered by (file, line)."""
        hits = [f for f in self._functions if symbol in f.calls]
        return sorted(hits, key=lambda f: (f.file, f.line_start))

    def find_callees(self, symbol: str) -> list[FunctionInfo]:
        """Functions that `symbol` calls (those we have indexed), deduped + ordered.

        Unions the call sets of every indexed definition named `symbol` (a symbol can be
        defined in more than one file/language), then resolves each callee name to its
        indexed definitions.
        """
        called: set[str] = set()
        for info in self._by_name.get(symbol, []):
            called |= info.calls
        resolved: list[FunctionInfo] = []
        seen: set[tuple[str, int, str]] = set()
        for name in called:
            for info in self._by_name.get(name, []):
                key = (info.file, info.line_start, info.symbol)
                if key not in seen:
                    seen.add(key)
                    resolved.append(info)
        return sorted(resolved, key=lambda f: (f.file, f.line_start))

    def find_similar_patterns(self, snippet: str, limit: int = 5) -> list[FunctionInfo]:
        """Functions that share call-name usage with `snippet`, ranked by overlap.

        Lets detection catch "the same bad pattern in N places": a snippet calling
        `execute`/`requests.get` surfaces every other function doing the same, across
        every indexed language (the snippet's call tokens are extracted language-
        agnostically, and call *names* are stored the same way in every indexer).
        """
        wanted = _call_tokens(snippet)
        if not wanted:
            return []
        scored: list[tuple[int, FunctionInfo]] = []
        for info in self._functions:
            overlap = len(wanted & info.calls)
            if overlap:
                scored.append((overlap, info))
        scored.sort(key=lambda pair: (-pair[0], pair[1].file, pair[1].line_start))
        return [info for _, info in scored[:limit]]

    def find_enclosing(
        self, file: str, line_start: int, line_end: int | None = None
    ) -> list[FunctionInfo]:
        """Functions overlapping a cited range, smallest enclosing region first."""
        rel = self._resolve_file(file)
        if rel is None:
            return []
        end = line_end if line_end is not None else line_start
        hits = [
            info for info in self._functions
            if info.file == rel and info.line_start <= end and line_start <= info.line_end
        ]
        return sorted(
            hits,
            key=lambda info: (info.line_end - info.line_start, info.line_start, info.symbol),
        )

    def file_excerpt(
        self, file: str, line_start: int, line_end: int | None = None, context_lines: int = 8
    ) -> FunctionInfo | None:
        """A bounded source excerpt around a citation, including module-level evidence."""
        rel = self._resolve_file(file)
        if rel is None:
            return None
        lines = self._file_texts[rel].splitlines()
        end = line_end if line_end is not None else line_start
        start_idx = max(0, line_start - context_lines - 1)
        end_idx = min(len(lines), end + context_lines)
        return FunctionInfo(
            symbol=f"{rel}:context",
            file=rel,
            line_start=start_idx + 1,
            line_end=max(end_idx, start_idx + 1),
            source="\n".join(lines[start_idx:end_idx]),
            language="context",
        )

    def source_text(self, file: str) -> tuple[str, str] | None:
        """Return `(canonical_relative_path, text)` for deterministic analysis helpers."""
        rel = self._resolve_file(file)
        if rel is None:
            return None
        return rel, self._file_texts[rel]

    def find_text_references(
        self, token: str, limit: int = 5, context_lines: int = 6
    ) -> list[FunctionInfo]:
        """Repo-wide literal references, including module-level config/registration code."""
        if not token:
            return []
        hits: list[FunctionInfo] = []
        for rel, text in sorted(self._file_texts.items()):
            lines = text.splitlines()
            for index, line in enumerate(lines):
                if token not in line:
                    continue
                start = max(0, index - context_lines)
                end = min(len(lines), index + context_lines + 1)
                hits.append(FunctionInfo(
                    symbol=f"reference:{token}",
                    file=rel,
                    line_start=start + 1,
                    line_end=end,
                    source="\n".join(lines[start:end]),
                    language="reference",
                ))
                if len(hits) >= limit:
                    return hits
        return hits

    def locate_citation(self, citation: str) -> list[CitationLocation]:
        """Locate every exact occurrence of a verbatim citation in source files."""
        needle = citation.strip().replace("\r\n", "\n").replace("\r", "\n")
        if not needle:
            return []
        locations: list[CitationLocation] = []
        for rel, text in sorted(self._file_texts.items()):
            start = 0
            while True:
                offset = text.find(needle, start)
                if offset < 0:
                    break
                line_start = text.count("\n", 0, offset) + 1
                locations.append(CitationLocation(
                    file=rel,
                    line_start=line_start,
                    line_end=line_start + needle.count("\n"),
                ))
                start = offset + max(len(needle), 1)
        return locations

    def _resolve_file(self, file: str) -> str | None:
        normalized = file.replace("\\", "/")
        if normalized in self._file_texts:
            return normalized
        matches = [
            rel for rel in self._file_texts
            if normalized.endswith(rel) or rel.endswith(normalized)
        ]
        return min(matches, key=len) if matches else None


# --------------------------------------------------------------------------- #
# Python indexer (stdlib ast — exact, dependency-free)
# --------------------------------------------------------------------------- #
def _index_python(text: str, rel: str) -> list[FunctionInfo]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    lines = text.splitlines()
    infos: list[FunctionInfo] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end = getattr(node, "end_lineno", node.lineno)
        decorator_lines = [
            decorator.lineno for decorator in node.decorator_list
            if hasattr(decorator, "lineno")
        ]
        start = min([node.lineno, *decorator_lines])
        infos.append(FunctionInfo(
            symbol=node.name,
            file=rel,
            line_start=start,
            line_end=end,
            source="\n".join(lines[start - 1 : end]),
            calls=_called_names(node),
            language="python",
        ))
    return infos


def _called_names(func: ast.AST) -> set[str]:
    """Set of callable names invoked inside a function (e.g. `execute`, `get`)."""
    names: set[str] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                names.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                names.add(fn.attr)
    return names


# --------------------------------------------------------------------------- #
# tree-sitter indexer (JS / TS / TSX / Java / Ruby)
# --------------------------------------------------------------------------- #
_TS_PARSERS: dict[str, object] = {}
_TS_UNAVAILABLE: set[str] = set()


def _get_ts_parser(ts_lang: str):
    """Return a cached tree-sitter parser for a language, or None if unavailable.

    The grammar pack is an ordinary dependency, but load failures degrade to the lexical
    fallback (same graceful-degradation discipline as `triage.features.git_churn`) rather
    than breaking a whole detect run.
    """
    if ts_lang in _TS_PARSERS:
        return _TS_PARSERS[ts_lang]
    if ts_lang in _TS_UNAVAILABLE:
        return None
    try:
        from tree_sitter_language_pack import get_parser

        parser = get_parser(ts_lang)
    except Exception:
        _TS_UNAVAILABLE.add(ts_lang)
        return None
    _TS_PARSERS[ts_lang] = parser
    return parser


def _ts_text(node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _index_treesitter_source(text: str, rel: str, ts_lang: str, parser) -> list[FunctionInfo]:
    src = text.encode("utf-8", errors="replace")
    tree = parser.parse(src)
    family = _FAMILY_BY_LANG[ts_lang]
    def_types = _DEF_TYPES[family]
    infos: list[FunctionInfo] = []

    def visit(node) -> None:
        name: str | None = None
        body = node
        if node.type in def_types:
            name = _ts_def_name(node, def_types[node.type], src)
        elif family == "js" and node.type == "variable_declarator":
            # `const foo = (x) => ...` / `const foo = function () {}` — the symbol is on
            # the declarator, the callable body is the assigned value.
            value = node.child_by_field_name("value")
            if value is not None and value.type in ("arrow_function", "function", "function_expression"):
                name = _ts_def_name(node, "name", src)
                body = value
        if name:
            infos.append(FunctionInfo(
                symbol=name,
                file=rel,
                line_start=node.start_point.row + 1,
                line_end=node.end_point.row + 1,
                source=_ts_text(node, src),
                calls=_ts_collect_calls(body, family, src),
                language=ts_lang,
            ))
        for child in node.children:
            visit(child)

    visit(tree.root_node)
    return infos


def _ts_def_name(node, field_name: str, src: bytes) -> str | None:
    name_node = node.child_by_field_name(field_name)
    return _ts_text(name_node, src) if name_node is not None else None


def _ts_collect_calls(body, family: str, src: bytes) -> set[str]:
    """Callee names invoked anywhere inside `body` (including nested closures — parity
    with the Python indexer's `ast.walk`)."""
    call_types = _CALL_TYPES[family]
    names: set[str] = set()
    stack = [body]
    while stack:
        node = stack.pop()
        if node.type in call_types:
            callee = _ts_callee_name(node, family, src)
            if callee:
                names.add(callee)
        stack.extend(node.children)
    return names


def _ts_callee_name(node, family: str, src: bytes) -> str | None:
    if family == "js":
        fn = node.child_by_field_name("function")
        if fn is None:
            return None
        if fn.type == "member_expression":
            prop = fn.child_by_field_name("property")
            return _ts_text(prop, src) if prop is not None else None
        if fn.type in ("identifier", "property_identifier"):
            return _ts_text(fn, src)
        return None
    if family == "java":
        name = node.child_by_field_name("name")
        return _ts_text(name, src) if name is not None else None
    if family == "ruby":
        method = node.child_by_field_name("method")
        return _ts_text(method, src) if method is not None else None
    return None


# --------------------------------------------------------------------------- #
# Lexical helpers (shared by the fallback index + similar-pattern token extraction)
# --------------------------------------------------------------------------- #
def _call_tokens(snippet: str) -> set[str]:
    """Best-effort set of call names in an arbitrary snippet (Python-parses, else regex).

    Cross-language by construction: the regex extracts every `name(` occurrence, and for a
    member call `obj.method(` it captures `method` — the same identity every indexer stores
    a callee under — so a snippet in one language matches indexed functions in another.
    """
    try:
        tree = ast.parse(snippet)
        return _called_names(tree)
    except SyntaxError:
        return set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", snippet))

"""Repo-wide AST retrieval index.

Deterministic, AST-based caller/callee and similar-pattern lookup over an ingested
snapshot (preferred over embeddings here: no infra, reproducible). Before a lens
scores a candidate, the ensemble pulls in related call sites; the falsify stage uses
the same index to look for mitigating controls elsewhere in the codebase.

Narrow interface — `find_callers`, `find_callees`, `find_similar_patterns` — plus
`build`. Currently indexes Python (via `ast`); other languages fall through to the
similar-pattern text heuristic, so the interface holds as more parsers are added.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from ...sourcefiles import iter_source_files


@dataclass
class FunctionInfo:
    """One indexed function: where it lives, its source, and the names it calls."""

    symbol: str
    file: str  # relative to snapshot root
    line_start: int
    line_end: int
    source: str
    calls: set[str] = field(default_factory=set)


class RetrievalIndex:
    """AST index over a snapshot for callers/callees + similar-pattern lookup."""

    def __init__(self) -> None:
        self._functions: dict[str, FunctionInfo] = {}
        self._built = False

    # ------------------------------------------------------------------ build
    def build(self, snapshot_path: Path) -> "RetrievalIndex":
        """Index the snapshot. Idempotent per instance; returns self for chaining."""
        snapshot_path = Path(snapshot_path)
        for path in iter_source_files(snapshot_path):
            if path.suffix != ".py":
                continue
            rel = path.relative_to(snapshot_path).as_posix()
            self._index_python(path, rel)
        self._built = True
        return self

    def _index_python(self, path: Path, rel: str) -> None:
        text = path.read_text(errors="replace")
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return
        lines = text.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            end = getattr(node, "end_lineno", node.lineno)
            info = FunctionInfo(
                symbol=node.name,
                file=rel,
                line_start=node.lineno,
                line_end=end,
                source="\n".join(lines[node.lineno - 1 : end]),
                calls=_called_names(node),
            )
            # Last definition wins on name collision — good enough for retrieval.
            self._functions[node.name] = info

    # ------------------------------------------------------------------ query
    def find_callers(self, symbol: str) -> list[FunctionInfo]:
        """Functions whose body calls `symbol`."""
        return [f for f in self._functions.values() if symbol in f.calls]

    def find_callees(self, symbol: str) -> list[FunctionInfo]:
        """Functions that `symbol` calls (those we have indexed)."""
        info = self._functions.get(symbol)
        if info is None:
            return []
        return [self._functions[c] for c in info.calls if c in self._functions]

    def find_similar_patterns(self, snippet: str, limit: int = 5) -> list[FunctionInfo]:
        """Functions that share call-name usage with `snippet`, ranked by overlap.

        Lets detection catch "the same bad pattern in N places": a snippet calling
        `execute`/`requests.get` surfaces every other function doing the same.
        """
        wanted = _call_tokens(snippet)
        if not wanted:
            return []
        scored: list[tuple[int, FunctionInfo]] = []
        for info in self._functions.values():
            overlap = len(wanted & info.calls)
            if overlap:
                scored.append((overlap, info))
        scored.sort(key=lambda pair: (-pair[0], pair[1].file, pair[1].line_start))
        return [info for _, info in scored[:limit]]


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


def _call_tokens(snippet: str) -> set[str]:
    """Best-effort set of call names in an arbitrary snippet (parses, else regex)."""
    try:
        tree = ast.parse(snippet)
        return _called_names(tree)
    except SyntaxError:
        import re

        return set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", snippet))

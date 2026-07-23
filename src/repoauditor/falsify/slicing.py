"""Bounded Python def-use evidence slices for falsification context.

This is not a path-feasibility engine. It extracts an intraprocedural chain from a supported
sink backward through simple assignments to observable request inputs or function
parameters. It never confirms reachability, attacker control, or sanitizer effectiveness.
Unsupported languages, missing sinks, dynamic name construction, and unresolved dependencies
produce an explicit `incomplete` result rather than guessed evidence.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from ..detect.retrieval import RetrievalIndex
from ..store.models import Finding

SLICE_VERSION = "python_local_slice_v1"

_MECHANISM_TERMS = {
    "sql_injection": ("sql injection", "sqli", "cwe-89"),
    "command_injection": ("command injection", "os command", "cwe-78"),
    "ssrf": ("ssrf", "server-side request forgery", "cwe-918"),
}
_SINKS = {
    "sql_injection": {"execute", "executemany", "query", "raw"},
    "command_injection": {"system", "popen", "run", "call", "check_output", "Popen"},
    "ssrf": {"get", "post", "put", "delete", "request", "urlopen"},
}
_SANITIZER_HINT = re.compile(
    r"(?:saniti[sz]e|escape|quote|allowlist|validate|urlparse|parameteri[sz])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SliceLine:
    line: int
    source: str


@dataclass
class PythonSliceEvidence:
    mechanism: str
    status: str
    file: str
    function: str | None = None
    entry_evidence: list[SliceLine] = field(default_factory=list)
    source_evidence: list[SliceLine] = field(default_factory=list)
    assignments: list[SliceLine] = field(default_factory=list)
    sink: SliceLine | None = None
    sanitizer_candidates: list[SliceLine] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [
            f"# DETERMINISTIC PYTHON SLICE: {SLICE_VERSION}",
            f"mechanism={self.mechanism}; status={self.status}; "
            f"file={self.file}; function={self.function or '(none)'}",
        ]
        for label, evidence in (
            ("entry", self.entry_evidence),
            ("source", self.source_evidence),
            ("assignment", self.assignments),
            ("sanitizer-candidate", self.sanitizer_candidates),
        ):
            lines.extend(f"{label} L{item.line}: {item.source}" for item in evidence)
        if self.sink:
            lines.append(f"sink L{self.sink.line}: {self.sink.source}")
        lines.extend(f"limitation: {item}" for item in self.limitations)
        lines.append(
            "interpretation: evidence only; reachability, attacker control, path feasibility, "
            "and sanitizer effectiveness are not established by this slice"
        )
        return "\n".join(lines)


def _mechanism(finding: Finding) -> str | None:
    text = " ".join(
        part for part in (finding.title, finding.description, finding.citation_snippet) if part
    ).lower()
    for mechanism, terms in _MECHANISM_TERMS.items():
        if any(term in text for term in terms):
            return mechanism
    return None


def _call_name(call: ast.Call) -> str:
    fn = call.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        return fn.attr
    return ""


def _line(lines: list[str], node: ast.AST) -> SliceLine:
    number = getattr(node, "lineno", 1)
    end = getattr(node, "end_lineno", number)
    return SliceLine(number, "\n".join(lines[number - 1:end]).strip())


def _loaded_names(node: ast.AST) -> set[str]:
    return {
        child.id for child in ast.walk(node)
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
    }


def _is_request_source(node: ast.AST) -> bool:
    return any(
        isinstance(child, ast.Name) and child.id in {"request", "flask_request"}
        for child in ast.walk(node)
    )


def build_python_slice(
    index: RetrievalIndex, finding: Finding
) -> PythonSliceEvidence | None:
    """Build a conservative local slice for one supported Python finding."""
    mechanism = _mechanism(finding)
    if mechanism is None:
        return None
    source = index.source_text(finding.file)
    if source is None:
        return PythonSliceEvidence(
            mechanism, "incomplete", finding.file,
            limitations=["cited file is not present in the retrieval index"],
        )
    rel, text = source
    if not rel.endswith(".py"):
        return PythonSliceEvidence(
            mechanism, "incomplete", rel,
            limitations=["language is not supported by the Python slicing MVP"],
        )
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return PythonSliceEvidence(
            mechanism, "incomplete", rel,
            limitations=["Python source could not be parsed"],
        )
    lines = text.splitlines()
    functions = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= finding.line_end
        and finding.line_start <= getattr(node, "end_lineno", node.lineno)
    ]
    if not functions:
        return PythonSliceEvidence(
            mechanism, "incomplete", rel,
            limitations=["citation is not enclosed by a Python function"],
        )
    function = min(functions, key=lambda node: getattr(node, "end_lineno", 0) - node.lineno)
    result = PythonSliceEvidence(mechanism, "local", rel, function.name)
    result.limitations.append("intraprocedural slice only; callers and runtime registration are not proven")

    for decorator in function.decorator_list:
        result.entry_evidence.append(_line(lines, decorator))

    calls = [
        node for node in ast.walk(function)
        if isinstance(node, ast.Call) and _call_name(node) in _SINKS[mechanism]
    ]
    if not calls:
        result.status = "incomplete"
        result.limitations.append("no supported sink call was found in the enclosing function")
        return result
    sink = min(calls, key=lambda node: abs(node.lineno - finding.line_start))
    result.sink = _line(lines, sink)

    assignments: dict[str, list[tuple[ast.AST, ast.AST, bool]]] = {}
    for node in ast.walk(function):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = (
                node.targets if isinstance(node, ast.Assign)
                else [node.target]
            )
            value = getattr(node, "value", None)
            if value is None or getattr(node, "lineno", 0) > sink.lineno:
                continue
            for target in targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append(
                        (node, value, isinstance(node, ast.AugAssign))
                    )
    for records in assignments.values():
        records.sort(key=lambda item: item[0].lineno)

    parameters = {
        arg.arg for arg in (
            [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
        )
    }
    dependencies: list[tuple[str, int]] = []
    for argument in [*sink.args, *(keyword.value for keyword in sink.keywords)]:
        dependencies.extend((name, sink.lineno) for name in _loaded_names(argument))
    ignored = {"db", "requests", "httpx", "urllib", "os", "subprocess"}
    dependencies = [(name, before) for name, before in dependencies if name not in ignored]
    visited: set[tuple[str, int]] = set()
    unresolved: set[str] = set()
    while dependencies:
        name, before_line = dependencies.pop()
        key = (name, before_line)
        if key in visited:
            continue
        visited.add(key)
        if name in parameters:
            result.source_evidence.append(
                SliceLine(function.lineno, f"function parameter: {name}")
            )
            continue
        candidates = [
            record for record in assignments.get(name, [])
            if record[0].lineno < before_line
        ]
        if not candidates:
            unresolved.add(name)
            continue
        assignment, value, includes_previous = candidates[-1]
        result.assignments.append(_line(lines, assignment))
        if _is_request_source(value):
            result.source_evidence.append(_line(lines, assignment))
        for call in (child for child in ast.walk(value) if isinstance(child, ast.Call)):
            if _SANITIZER_HINT.search(_call_name(call)):
                result.sanitizer_candidates.append(_line(lines, call))
        dependencies.extend(
            (dependency, assignment.lineno)
            for dependency in (_loaded_names(value) - ignored - {"request", "flask_request"})
        )
        if includes_previous:
            dependencies.append((name, assignment.lineno))

    if unresolved:
        result.status = "incomplete"
        result.limitations.append(
            "unresolved local dependencies: " + ", ".join(sorted(unresolved))
        )
    if any(
        isinstance(node, (ast.Call, ast.Subscript))
        for node in ast.walk(sink)
        if node is not sink
    ):
        result.limitations.append("sink arguments contain dynamic calls/subscripts")

    for values in (
        result.entry_evidence,
        result.source_evidence,
        result.assignments,
        result.sanitizer_candidates,
    ):
        values[:] = sorted(set(values), key=lambda item: (item.line, item.source))
    return result

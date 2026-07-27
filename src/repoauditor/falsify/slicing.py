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

SLICE_VERSION = "python_local_slice_v4"

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
_AUTHORIZATION_HINT = re.compile(
    r"^(?:owns_resource|require_(?:admin|role|permission)|authorize|"
    r"check_(?:permission|access|ownership)|enforce_(?:permission|access|ownership)|"
    r"has_permission)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SliceLine:
    line: int
    source: str


@dataclass(frozen=True)
class CallerSliceLine:
    file: str
    line: int
    source: str


@dataclass(frozen=True)
class RegistrationSliceLine:
    file: str
    line: int
    source: str


@dataclass
class StructuralSliceEvidence:
    mechanism: str
    status: str
    file: str
    function: str | None = None
    language: str = "python"
    entry_evidence: list[SliceLine] = field(default_factory=list)
    caller_evidence: list[CallerSliceLine] = field(default_factory=list)
    authorization_candidates: list[SliceLine] = field(default_factory=list)
    registration_evidence: list[RegistrationSliceLine] = field(default_factory=list)
    source_evidence: list[SliceLine] = field(default_factory=list)
    assignments: list[SliceLine] = field(default_factory=list)
    sink: SliceLine | None = None
    sanitizer_candidates: list[SliceLine] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [
            f"# DETERMINISTIC {self.language.upper()} SLICE: {SLICE_VERSION}",
            f"mechanism={self.mechanism}; status={self.status}; "
            f"file={self.file}; function={self.function or '(none)'}",
        ]
        for label, evidence in (
            ("entry", self.entry_evidence),
            ("authorization-candidate", self.authorization_candidates),
            ("source", self.source_evidence),
            ("assignment", self.assignments),
            ("sanitizer-candidate", self.sanitizer_candidates),
        ):
            lines.extend(f"{label} L{item.line}: {item.source}" for item in evidence)
        lines.extend(
            f"caller {item.file}:L{item.line}: {item.source}"
            for item in self.caller_evidence
        )
        lines.extend(
            f"registration {item.file}:L{item.line}: {item.source}"
            for item in self.registration_evidence
        )
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


def _callable_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _call_name(node)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
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


def _direct_python_callers(
    index: RetrievalIndex, symbol: str
) -> list[tuple[str, SliceLine]]:
    """Return exact direct-call syntax from AST-indexed Python files only."""
    evidence: list[tuple[str, SliceLine]] = []
    seen: set[tuple[str, int, str]] = set()
    for caller in index.find_callers(symbol):
        if caller.language != "python":
            continue
        source = index.source_text(caller.file)
        if source is None:
            continue
        relative, text = source
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        lines = text.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _call_name(node) != symbol:
                continue
            item = _line(lines, node)
            key = (relative, item.line, item.source)
            if key not in seen:
                seen.add(key)
                evidence.append((relative, item))
    return sorted(evidence, key=lambda pair: (pair[0], pair[1].line, pair[1].source))


def _route_subjects(function: ast.AST) -> set[str]:
    """Blueprint symbols used by local Flask-style route decorators."""
    subjects: set[str] = set()
    for decorator in function.decorator_list:
        if (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr in {"route", "get", "post", "put", "patch", "delete"}
            and isinstance(decorator.func.value, ast.Name)
        ):
            subjects.add(decorator.func.value.id)
    return subjects


def _blueprint_registrations(
    index: RetrievalIndex, subjects: set[str]
) -> list[RegistrationSliceLine]:
    """Find exact Python ``register_blueprint(subject)`` syntax for route subjects."""
    evidence: list[RegistrationSliceLine] = []
    seen: set[tuple[str, int, str]] = set()
    files = {
        reference.file
        for subject in subjects
        for reference in index.find_text_references(subject, limit=50)
    }
    for file in sorted(files):
        source = index.source_text(file)
        if source is None or not file.endswith(".py"):
            continue
        relative, text = source
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        lines = text.splitlines()
        for node in ast.walk(tree):
            if (
                not isinstance(node, ast.Call)
                or _call_name(node) != "register_blueprint"
                or not any(
                    isinstance(argument, ast.Name) and argument.id in subjects
                    for argument in node.args
                )
            ):
                continue
            item = _line(lines, node)
            key = (relative, item.line, item.source)
            if key not in seen:
                seen.add(key)
                evidence.append(RegistrationSliceLine(relative, item.line, item.source))
    return sorted(evidence, key=lambda item: (item.file, item.line, item.source))


def build_python_slice(
    index: RetrievalIndex, finding: Finding
) -> StructuralSliceEvidence | None:
    """Build a conservative local slice for one supported Python finding."""
    mechanism = _mechanism(finding)
    if mechanism is None:
        return None
    source = index.source_text(finding.file)
    if source is None:
        return StructuralSliceEvidence(
            mechanism, "incomplete", finding.file,
            limitations=["cited file is not present in the retrieval index"],
        )
    rel, text = source
    if not rel.endswith(".py"):
        return StructuralSliceEvidence(
            mechanism, "incomplete", rel,
            limitations=["language is not supported by the Python slicing MVP"],
        )
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return StructuralSliceEvidence(
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
        return StructuralSliceEvidence(
            mechanism, "incomplete", rel,
            limitations=["citation is not enclosed by a Python function"],
        )
    function = min(functions, key=lambda node: getattr(node, "end_lineno", 0) - node.lineno)
    result = StructuralSliceEvidence(mechanism, "local", rel, function.name)
    result.limitations.append(
        "local def-use slice only; direct caller syntax does not prove runtime reachability"
    )

    for decorator in function.decorator_list:
        result.entry_evidence.append(_line(lines, decorator))
        if _AUTHORIZATION_HINT.fullmatch(_callable_name(decorator)):
            result.authorization_candidates.append(_line(lines, decorator))
    for call in (
        node for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and _AUTHORIZATION_HINT.fullmatch(_call_name(node))
    ):
        result.authorization_candidates.append(_line(lines, call))
    # SliceLine has no file field because most evidence is local. Caller file identity is
    # carried separately when the certificate is constructed.
    result.caller_evidence = [
        CallerSliceLine(relative, item.line, item.source)
        for relative, item in _direct_python_callers(index, function.name)
    ]
    result.registration_evidence = _blueprint_registrations(
        index, _route_subjects(function)
    )

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
        result.authorization_candidates,
    ):
        values[:] = sorted(set(values), key=lambda item: (item.line, item.source))
    return result


def _ts_parser(language: str):
    try:
        from tree_sitter_language_pack import get_parser

        return get_parser(language)
    except Exception:
        return None


def _ts_source(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _ts_walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _js_call_name(node, source: bytes) -> str:
    function = node.child_by_field_name("function")
    if function is None:
        return ""
    if function.type == "identifier":
        return _ts_source(function, source)
    if function.type == "member_expression":
        prop = function.child_by_field_name("property")
        return _ts_source(prop, source) if prop is not None else ""
    return ""


def _js_request_source(node, source: bytes) -> bool:
    text = _ts_source(node, source)
    return bool(
        re.search(r"\b(?:req|request)\s*\.\s*(?:query|body|params|headers)\b", text)
    )


def build_javascript_ssrf_slice(
    index: RetrievalIndex, finding: Finding
) -> StructuralSliceEvidence | None:
    """Build a bounded JS/TS SSRF slice with explicit unsupported-mechanism evidence."""
    mechanism = _mechanism(finding)
    if mechanism is None:
        return None
    source_record = index.source_text(finding.file)
    if source_record is None:
        return StructuralSliceEvidence(
            "ssrf", "incomplete", finding.file, language="javascript",
            limitations=["cited file is not present in the retrieval index"],
        )
    relative, text = source_record
    suffix = relative.rsplit(".", 1)[-1].lower()
    language = "typescript" if suffix in {"ts", "tsx"} else "javascript"
    if suffix not in {"js", "jsx", "mjs", "cjs", "ts", "tsx"}:
        return None
    if mechanism != "ssrf":
        return StructuralSliceEvidence(
            mechanism, "unsupported", relative, language=language,
            limitations=["JavaScript/TypeScript certificate checker supports SSRF only"],
        )
    parser = _ts_parser("tsx" if suffix == "tsx" else language)
    if parser is None:
        return StructuralSliceEvidence(
            "ssrf", "incomplete", relative, language=language,
            limitations=[f"tree-sitter grammar unavailable for {language}"],
        )
    source = text.encode("utf-8", errors="replace")
    tree = parser.parse(source)
    if tree.root_node.has_error:
        return StructuralSliceEvidence(
            "ssrf", "incomplete", relative, language=language,
            limitations=[f"{language} source could not be parsed without errors"],
        )
    calls = [
        node for node in _ts_walk(tree.root_node)
        if node.type == "call_expression"
        and _js_call_name(node, source) == "fetch"
        and node.start_point.row + 1 <= finding.line_end
        and finding.line_start <= node.end_point.row + 1
    ]
    result = StructuralSliceEvidence(
        "ssrf", "incomplete", relative, language=language,
        limitations=[
            "local JavaScript/TypeScript SSRF slice only; runtime reachability and "
            "request-object provenance are not proven"
        ],
    )
    if len(calls) != 1:
        result.limitations.append("exactly one cited fetch(...) sink was not found")
        return result
    sink = calls[0]
    result.sink = SliceLine(
        sink.start_point.row + 1, _ts_source(sink, source)
    )
    arguments = sink.child_by_field_name("arguments")
    argument_nodes = [
        child for child in (arguments.named_children if arguments is not None else [])
    ]
    if len(argument_nodes) != 1:
        result.limitations.append("fetch sink must have exactly one URL argument")
        return result
    argument = argument_nodes[0]
    if _js_request_source(argument, source):
        result.source_evidence.append(
            SliceLine(argument.start_point.row + 1, _ts_source(argument, source))
        )
    elif argument.type == "identifier":
        name = _ts_source(argument, source)
        declarations = []
        for node in _ts_walk(tree.root_node):
            if node.type != "variable_declarator" or node.start_byte >= sink.start_byte:
                continue
            declared = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if (
                declared is not None and value is not None
                and _ts_source(declared, source) == name
                and _js_request_source(value, source)
            ):
                declarations.append(node)
        if declarations:
            declaration = max(declarations, key=lambda item: item.start_byte)
            statement = (
                declaration.parent
                if declaration.parent is not None
                and declaration.parent.type in {"lexical_declaration", "variable_declaration"}
                else declaration
            )
            evidence = SliceLine(
                statement.start_point.row + 1, _ts_source(statement, source)
            )
            result.source_evidence.append(evidence)
            result.assignments.append(evidence)
    if not result.source_evidence:
        result.limitations.append("fetch URL was not tied to a local request input")
        return result
    result.status = "local"
    return result


def build_structural_slice(
    index: RetrievalIndex, finding: Finding
) -> StructuralSliceEvidence | None:
    """Dispatch to a trusted language/mechanism producer without guessing support."""
    suffix = finding.file.rsplit(".", 1)[-1].lower()
    if suffix == "py":
        return build_python_slice(index, finding)
    if suffix in {"js", "jsx", "mjs", "cjs", "ts", "tsx"}:
        return build_javascript_ssrf_slice(index, finding)
    return None

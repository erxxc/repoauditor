"""Certificate construction and independent, structurally scoped checking.

The slicer is an untrusted certificate producer. The checker accepts only the persisted
claim plus a pinned snapshot, reopens the source, reparses its AST, and reconstructs a small
local def-use closure. It never consumes `PythonSliceEvidence`.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from ..store.models import (
    ClaimEvidence,
    ClaimVerification,
    ClaimVerificationStatus,
    SecurityClaim,
)
from .slicing import PythonSliceEvidence, SLICE_VERSION

CLAIM_VERSION = "security_claim_v3"
VERIFIER_NAME = "python-local-certificate-checker"
VERIFIER_VERSION = "python_local_certificate_checker_v3"

# Intentionally separate from the slicer's rule table: this is the small checker policy.
_CHECKER_SINKS = {
    "sql_injection": {"execute", "executemany", "query", "raw"},
    "command_injection": {"system", "popen", "run", "call", "check_output", "Popen"},
    "ssrf": {"get", "post", "put", "delete", "request", "urlopen"},
}
_IGNORED_NAMES = {
    "db", "requests", "httpx", "urllib", "os", "subprocess",
    "request", "flask_request",
}
_HTTP_DECORATORS = {"route", "get", "post", "put", "patch", "delete"}
_REQUEST_INPUT_CONTAINERS = {
    "args", "form", "values", "json", "files", "headers", "cookies",
}
_CONTROL_NAME = re.compile(
    r"(?:saniti[sz]e|escape|quote|allowlist|validate|parameteri[sz]|owns_resource)",
    re.IGNORECASE,
)


def _evidence(file: str, item) -> ClaimEvidence:
    return ClaimEvidence(file=file, line=item.line, source=item.source)


def claim_from_slice(
    finding_id: int,
    evidence: PythonSliceEvidence,
    snapshot_commit: str | None,
) -> SecurityClaim:
    """Translate slicer output into a certificate; this function does not verify it."""
    sources = [_evidence(evidence.file, item) for item in evidence.source_evidence]
    assignments = [_evidence(evidence.file, item) for item in evidence.assignments]
    sink = _evidence(evidence.file, evidence.sink) if evidence.sink else None
    controls = [_evidence(evidence.file, item) for item in evidence.sanitizer_candidates]
    return SecurityClaim(
        finding_id=finding_id,
        claim_version=CLAIM_VERSION,
        snapshot_commit=snapshot_commit,
        mechanism=evidence.mechanism,
        entry_evidence=[_evidence(evidence.file, item) for item in evidence.entry_evidence],
        source_evidence=sources,
        sink_evidence=sink,
        path_nodes=[*sources, *assignments, *([sink] if sink else [])],
        path_predicates=[],
        control_candidate=controls[0] if controls else None,
        producer_type="deterministic",
        producer_name=SLICE_VERSION,
    )


def _call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""


def _loaded_names(node: ast.AST) -> set[str]:
    return {
        child.id for child in ast.walk(node)
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
    }


def _safe_file(root: Path, relative: str) -> Path | None:
    root = root.resolve()
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def _matches_line(lines: list[str], evidence: ClaimEvidence) -> bool:
    expected = evidence.source.strip().replace("\r\n", "\n")
    count = max(1, expected.count("\n") + 1)
    actual = "\n".join(lines[evidence.line - 1:evidence.line - 1 + count]).strip()
    return actual == expected


def _parameter_name(evidence: ClaimEvidence) -> str | None:
    prefix = "function parameter: "
    return evidence.source[len(prefix):].strip() if evidence.source.startswith(prefix) else None


def _attribute_chain(node: ast.AST) -> tuple[str, ...]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return tuple(reversed(parts))


def _http_entry_decorators(function) -> list[ast.AST]:
    return [
        decorator for decorator in function.decorator_list
        if isinstance(decorator, ast.Call)
        and _call_name(decorator) in _HTTP_DECORATORS
    ]


def _route_parameter_names(decorators: list[ast.AST]) -> set[str]:
    names: set[str] = set()
    for decorator in decorators:
        if not isinstance(decorator, ast.Call) or not decorator.args:
            continue
        route = decorator.args[0]
        if not isinstance(route, ast.Constant) or not isinstance(route.value, str):
            continue
        names.update(
            item.rsplit(":", 1)[-1]
            for item in re.findall(r"<([^>]+)>", route.value)
        )
    return names


def _request_input_at_line(function, line: int) -> bool:
    for node in ast.walk(function):
        if getattr(node, "lineno", None) != line:
            continue
        chain = _attribute_chain(node)
        if (
            len(chain) >= 2
            and chain[0] in {"request", "flask_request"}
            and chain[1] in _REQUEST_INPUT_CONTAINERS
        ):
            return True
    return False


def _recognized_control_at_line(function, line: int) -> bool:
    return any(
        isinstance(node, ast.Call)
        and node.lineno == line
        and bool(_CONTROL_NAME.search(_call_name(node)))
        for node in ast.walk(function)
    )


def _enclosing_function(tree: ast.AST, line: int):
    functions = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= line <= getattr(node, "end_lineno", node.lineno)
    ]
    return min(
        functions,
        key=lambda node: getattr(node, "end_lineno", node.lineno) - node.lineno,
    ) if functions else None


def _local_closure(function, sink: ast.Call) -> tuple[set[int], set[str]]:
    """Reconstruct assignment/parameter lines reachable backward from sink arguments."""
    assignments: dict[str, list[tuple[ast.AST, ast.AST, bool]]] = {}
    for node in ast.walk(function):
        if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = getattr(node, "value", None)
        if value is None or node.lineno > sink.lineno:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                assignments.setdefault(target.id, []).append(
                    (node, value, isinstance(node, ast.AugAssign))
                )
    for records in assignments.values():
        records.sort(key=lambda record: record[0].lineno)

    parameters = {
        arg.arg for arg in (
            [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
        )
    }
    pending = [
        (name, sink.lineno)
        for argument in [*sink.args, *(item.value for item in sink.keywords)]
        for name in _loaded_names(argument) - _IGNORED_NAMES
    ]
    lines = {sink.lineno}
    reached_parameters: set[str] = set()
    visited: set[tuple[str, int]] = set()
    while pending:
        name, before = pending.pop()
        if (name, before) in visited:
            continue
        visited.add((name, before))
        if name in parameters:
            reached_parameters.add(name)
            lines.add(function.lineno)
            continue
        candidates = [
            record for record in assignments.get(name, [])
            if record[0].lineno < before
        ]
        if not candidates:
            continue
        node, value, includes_previous = candidates[-1]
        lines.add(node.lineno)
        pending.extend(
            (dependency, node.lineno)
            for dependency in _loaded_names(value) - _IGNORED_NAMES
        )
        if includes_previous:
            pending.append((name, node.lineno))
    return lines, reached_parameters


def verify_structural_claim(
    claim: SecurityClaim,
    snapshot_path: Path | None,
    expected_commit: str | None,
) -> ClaimVerification:
    """Independently check a certificate against a pinned snapshot.

    `structurally_verified` means only that exact source, sink, and local def-use facts
    close under this checker. It never validates exploitability or real-world risk.
    """
    checks = {
        "snapshot_bound": bool(claim.snapshot_commit and expected_commit),
        "snapshot_matches": bool(
            claim.snapshot_commit and expected_commit
            and claim.snapshot_commit == expected_commit
        ),
        "supported_mechanism": claim.mechanism in _CHECKER_SINKS,
        "certificate_complete": bool(
            claim.source_evidence and claim.sink_evidence and claim.path_nodes
        ),
        "evidence_matches_snapshot": False,
        "supported_sink_present": False,
        "local_def_use_closes": False,
        "http_entrypoint_present": False,
        "attacker_input_source_present": False,
        "control_candidate_present": False,
        "control_on_local_def_use": False,
    }
    status = ClaimVerificationStatus.VERIFICATION_INCOMPLETE
    reason = "Certificate verification could not complete."

    if not checks["supported_mechanism"]:
        status = ClaimVerificationStatus.UNSUPPORTED
        reason = f"Checker does not support mechanism {claim.mechanism!r}."
    elif not checks["snapshot_bound"]:
        reason = "Claim or verification request lacks an immutable snapshot commit."
    elif not checks["snapshot_matches"]:
        status = ClaimVerificationStatus.STRUCTURALLY_REFUTED
        reason = "Claim snapshot commit does not match the snapshot being checked."
    elif not checks["certificate_complete"]:
        reason = "Certificate lacks required source, sink, or path-node evidence."
    elif snapshot_path is None:
        reason = "No pinned snapshot path was available to the independent checker."
    elif claim.path_predicates:
        reason = "Path predicates are not supported by the local certificate checker."
    else:
        files = {
            item.file for item in [
                *claim.entry_evidence,
                *claim.source_evidence,
                *claim.path_nodes,
                *([claim.sink_evidence] if claim.sink_evidence else []),
                *([claim.control_candidate] if claim.control_candidate else []),
            ]
        }
        if len(files) != 1:
            reason = "The local checker accepts exactly one Python source file."
        else:
            relative = next(iter(files))
            path = _safe_file(snapshot_path, relative)
            if path is None or path.suffix != ".py":
                reason = "Claimed Python source file is absent or escapes the snapshot."
            else:
                text = path.read_text(errors="replace")
                lines = text.splitlines()
                try:
                    tree = ast.parse(text)
                except SyntaxError:
                    reason = "Claimed Python source cannot be parsed."
                else:
                    ordinary = [
                        item for item in [
                            *claim.entry_evidence,
                            *claim.source_evidence,
                            *claim.path_nodes,
                            *([claim.sink_evidence] if claim.sink_evidence else []),
                            *([claim.control_candidate] if claim.control_candidate else []),
                        ]
                        if _parameter_name(item) is None
                    ]
                    checks["evidence_matches_snapshot"] = all(
                        _matches_line(lines, item) for item in ordinary
                    )
                    sink_calls = [
                        node for node in ast.walk(tree)
                        if isinstance(node, ast.Call)
                        and node.lineno == claim.sink_evidence.line
                        and _call_name(node) in _CHECKER_SINKS[claim.mechanism]
                    ]
                    checks["supported_sink_present"] = len(sink_calls) == 1
                    if not checks["evidence_matches_snapshot"]:
                        status = ClaimVerificationStatus.STRUCTURALLY_REFUTED
                        reason = "Certificate text does not match the pinned snapshot."
                    elif not checks["supported_sink_present"]:
                        status = ClaimVerificationStatus.STRUCTURALLY_REFUTED
                        reason = "Certificate sink is not a supported AST call at that line."
                    else:
                        sink = sink_calls[0]
                        function = _enclosing_function(tree, sink.lineno)
                        if function is None:
                            reason = "Supported sink is not enclosed by a Python function."
                        else:
                            closure_lines, parameters = _local_closure(function, sink)
                            entry_decorators = _http_entry_decorators(function)
                            entry_lines = {item.line for item in claim.entry_evidence}
                            checks["http_entrypoint_present"] = bool(
                                entry_decorators
                                and all(
                                    decorator.lineno in entry_lines
                                    for decorator in entry_decorators
                                    if _call_name(decorator) in _HTTP_DECORATORS
                                )
                            )
                            route_parameters = _route_parameter_names(entry_decorators)
                            checks["attacker_input_source_present"] = any(
                                (
                                    (name := _parameter_name(item)) is not None
                                    and name in route_parameters
                                )
                                or (
                                    _parameter_name(item) is None
                                    and _request_input_at_line(function, item.line)
                                )
                                for item in claim.source_evidence
                            )
                            if claim.control_candidate is not None:
                                checks["control_candidate_present"] = (
                                    _recognized_control_at_line(
                                        function, claim.control_candidate.line
                                    )
                                )
                                checks["control_on_local_def_use"] = (
                                    checks["control_candidate_present"]
                                    and claim.control_candidate.line in closure_lines
                                    and claim.control_candidate.line <= sink.lineno
                                )
                            parameter_ok = all(
                                name in parameters and item.line == function.lineno
                                for item in claim.source_evidence
                                if (name := _parameter_name(item)) is not None
                            )
                            claimed_lines = {
                                item.line for item in claim.path_nodes
                                if _parameter_name(item) is None
                            }
                            checks["local_def_use_closes"] = (
                                parameter_ok and claimed_lines <= closure_lines
                            )
                            if not checks["local_def_use_closes"]:
                                status = ClaimVerificationStatus.STRUCTURALLY_REFUTED
                                reason = (
                                    "Claimed path nodes do not close under independent "
                                    "local def-use reconstruction."
                                )
                            else:
                                status = ClaimVerificationStatus.STRUCTURALLY_VERIFIED
                                reason = (
                                    "Structurally verified against the pinned snapshot: exact "
                                    "certificate text, supported sink AST, and local def-use "
                                    "closure match. Exploitability, end-to-end reachability, "
                                    "attacker control, control effectiveness, and real-world "
                                    "risk are not validated. Entry-point, request-input, and "
                                    "control checks identify local syntax only."
                                )
    return ClaimVerification(
        claim_id=claim.id or 0,
        status=status,
        verifier_name=VERIFIER_NAME,
        verifier_version=VERIFIER_VERSION,
        checks=checks,
        reason=reason,
    )

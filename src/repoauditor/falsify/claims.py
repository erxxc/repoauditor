"""Certificate construction and independent, structurally scoped checking.

The slicer is an untrusted certificate producer. The checker accepts only the persisted
claim plus a pinned snapshot, reopens the source, reparses its AST, and reconstructs a small
local def-use closure. It never consumes the producer's `StructuralSliceEvidence`.
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
from .slicing import StructuralSliceEvidence, SLICE_VERSION

CLAIM_VERSION = "security_claim_v9"
VERIFIER_NAME = "deterministic-structural-certificate-checker"
VERIFIER_VERSION = "deterministic_structural_certificate_checker_v9"

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
_AUTHORIZATION_NAME = re.compile(
    r"^(?:owns_resource|require_(?:admin|role|permission)|authorize|"
    r"check_(?:permission|access|ownership)|enforce_(?:permission|access|ownership)|"
    r"has_permission)$",
    re.IGNORECASE,
)
_CHECKER_AXIOS_URL_METHODS = {
    "get", "post", "put", "patch", "delete", "head", "options",
}
_CHECKER_CHILD_PROCESS_METHODS = {"exec", "execSync"}


def _evidence(file: str, item) -> ClaimEvidence:
    return ClaimEvidence(file=file, line=item.line, source=item.source)


def claim_from_slice(
    finding_id: int,
    evidence: StructuralSliceEvidence,
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
        language=evidence.language,
        entry_evidence=[_evidence(evidence.file, item) for item in evidence.entry_evidence],
        caller_evidence=[
            ClaimEvidence(file=item.file, line=item.line, source=item.source)
            for item in evidence.caller_evidence
        ],
        authorization_evidence=[
            _evidence(evidence.file, item)
            for item in evidence.authorization_candidates
        ],
        registration_evidence=[
            ClaimEvidence(file=item.file, line=item.line, source=item.source)
            for item in evidence.registration_evidence
        ],
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


def _callable_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _call_name(node)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
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


def _route_registration_subjects(decorators: list[ast.AST]) -> set[str]:
    """Blueprint names referenced by independently parsed HTTP decorators."""
    return {
        decorator.func.value.id
        for decorator in decorators
        if isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and isinstance(decorator.func.value, ast.Name)
    }


def _registration_at_line(tree: ast.AST, line: int, subjects: set[str]) -> bool:
    return any(
        isinstance(node, ast.Call)
        and node.lineno == line
        and _call_name(node) == "register_blueprint"
        and any(
            isinstance(argument, ast.Name) and argument.id in subjects
            for argument in node.args
        )
        for node in ast.walk(tree)
    )


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


def _recognized_authorization_at_line(
    tree: ast.AST, function: ast.AST, line: int
) -> bool:
    """Recognize only checker-owned authorization candidate syntax on this function."""
    decorator_match = any(
        getattr(node, "lineno", None) == line
        and bool(_AUTHORIZATION_NAME.fullmatch(_callable_name(node)))
        for node in function.decorator_list
    )
    call_match = any(
        isinstance(node, ast.Call)
        and node.lineno == line
        and bool(_AUTHORIZATION_NAME.fullmatch(_call_name(node)))
        and _enclosing_function(tree, line) is function
        for node in ast.walk(function)
    )
    return decorator_match or call_match


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


def _verify_javascript_claim(
    claim: SecurityClaim,
    snapshot_path: Path | None,
    expected_commit: str | None,
) -> ClaimVerification:
    """Independently check one local JS/TS request-input→supported-sink certificate."""
    checks = {
        "snapshot_bound": bool(claim.snapshot_commit and expected_commit),
        "snapshot_matches": bool(
            claim.snapshot_commit and expected_commit
            and claim.snapshot_commit == expected_commit
        ),
        "supported_mechanism": claim.mechanism in {"ssrf", "command_injection"},
        "certificate_complete": bool(
            claim.source_evidence and claim.sink_evidence and claim.path_nodes
        ),
        "evidence_matches_snapshot": False,
        "supported_sink_present": False,
        "local_def_use_closes": False,
        "request_input_source_present": False,
    }
    status = ClaimVerificationStatus.VERIFICATION_INCOMPLETE
    reason = "JavaScript/TypeScript certificate verification could not complete."
    if not checks["supported_mechanism"]:
        status = ClaimVerificationStatus.UNSUPPORTED
        reason = "The JS/TS checker supports SSRF and command injection only."
    elif not checks["snapshot_bound"]:
        reason = "Claim or verification request lacks an immutable snapshot commit."
    elif not checks["snapshot_matches"]:
        status = ClaimVerificationStatus.STRUCTURALLY_REFUTED
        reason = "Claim snapshot commit does not match the snapshot being checked."
    elif not checks["certificate_complete"]:
        reason = "Certificate lacks required source, sink, or path-node evidence."
    elif snapshot_path is None:
        reason = "No pinned snapshot path was available to the independent checker."
    else:
        files = {
            item.file for item in [
                *claim.source_evidence,
                *claim.path_nodes,
                *([claim.sink_evidence] if claim.sink_evidence else []),
            ]
        }
        if len(files) != 1:
            reason = "The JS/TS checker accepts exactly one source file."
        else:
            relative = next(iter(files))
            path = _safe_file(snapshot_path, relative)
            suffix = path.suffix.lower() if path is not None else ""
            if path is None or suffix not in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
                reason = "Claimed JS/TS source file is absent or escapes the snapshot."
            else:
                try:
                    from tree_sitter_language_pack import get_parser

                    parser = get_parser(
                        "tsx" if suffix == ".tsx"
                        else "typescript" if suffix == ".ts"
                        else "javascript"
                    )
                except Exception:
                    reason = "Required tree-sitter grammar is unavailable."
                else:
                    text = path.read_text(errors="replace")
                    source = text.encode("utf-8", errors="replace")
                    tree = parser.parse(source)
                    if tree.root_node.has_error:
                        reason = "Claimed JS/TS source cannot be parsed without errors."
                    else:
                        lines = text.splitlines()
                        evidence = [
                            *claim.source_evidence,
                            *claim.path_nodes,
                            *([claim.sink_evidence] if claim.sink_evidence else []),
                        ]
                        def node_text(node) -> str:
                            return source[node.start_byte:node.end_byte].decode(
                                "utf-8", errors="replace"
                            )

                        stack = [tree.root_node]
                        nodes = []
                        while stack:
                            node = stack.pop()
                            nodes.append(node)
                            stack.extend(reversed(node.children))
                        checks["evidence_matches_snapshot"] = all(
                            any(
                                node.start_point.row + 1 == item.line
                                and node_text(node).strip() == item.source.strip()
                                for node in nodes
                            )
                            for item in evidence
                        )
                        sink_calls = []
                        sink_kinds: dict[int, str] = {}
                        for node in nodes:
                            if (
                                node.type != "call_expression"
                                or node.start_point.row + 1 != claim.sink_evidence.line
                            ):
                                continue
                            function = node.child_by_field_name("function")
                            kind = None
                            if (
                                claim.mechanism == "ssrf"
                                and function is not None
                                and node_text(function) == "fetch"
                            ):
                                kind = "fetch"
                            elif function is not None and function.type == "member_expression":
                                obj = function.child_by_field_name("object")
                                prop = function.child_by_field_name("property")
                                if (
                                    claim.mechanism == "ssrf"
                                    and obj is not None and prop is not None
                                    and obj.type == "identifier"
                                    and node_text(obj) == "axios"
                                    and node_text(prop) in _CHECKER_AXIOS_URL_METHODS
                                ):
                                    kind = "axios." + node_text(prop)
                                elif (
                                    claim.mechanism == "command_injection"
                                    and obj is not None and prop is not None
                                    and obj.type == "identifier"
                                    and node_text(obj) == "child_process"
                                    and node_text(prop)
                                    in _CHECKER_CHILD_PROCESS_METHODS
                                ):
                                    kind = "child_process." + node_text(prop)
                            if kind is not None:
                                sink_calls.append(node)
                                sink_kinds[id(node)] = kind
                        checks["supported_sink_present"] = len(sink_calls) == 1
                        valid_source = False
                        if checks["supported_sink_present"]:
                            arguments = sink_calls[0].child_by_field_name("arguments")
                            args = (
                                list(arguments.named_children)
                                if arguments is not None else []
                            )
                            sink_kind = sink_kinds[id(sink_calls[0])]
                            if args and (sink_kind != "fetch" or len(args) == 1):
                                argument = args[0]
                                argument_text = node_text(argument)
                                request_pattern = (
                                    r"^(?:req|request)\s*\.\s*"
                                    r"(?:query|body|params|headers)\s*\.\s*"
                                    r"[A-Za-z_$][A-Za-z0-9_$]*$"
                                )
                                if re.fullmatch(request_pattern, argument_text):
                                    valid_source = any(
                                        item.source == argument_text
                                        for item in claim.source_evidence
                                    )
                                elif argument.type == "identifier":
                                    for node in nodes:
                                        if (
                                            node.type != "variable_declarator"
                                            or node.start_byte >= sink_calls[0].start_byte
                                        ):
                                            continue
                                        name = node.child_by_field_name("name")
                                        value = node.child_by_field_name("value")
                                        if (
                                            name is not None and value is not None
                                            and node_text(name) == argument_text
                                            and re.fullmatch(
                                                request_pattern, node_text(value)
                                            )
                                            and any(
                                                item.line == node.start_point.row + 1
                                                and item.source == node_text(
                                                    node.parent
                                                    if node.parent is not None
                                                    and node.parent.type in {
                                                        "lexical_declaration",
                                                        "variable_declaration",
                                                    }
                                                    else node
                                                )
                                                for item in claim.source_evidence
                                            )
                                        ):
                                            valid_source = True
                        checks["request_input_source_present"] = valid_source
                        checks["local_def_use_closes"] = (
                            checks["evidence_matches_snapshot"]
                            and checks["supported_sink_present"]
                            and valid_source
                        )
                        if not checks["evidence_matches_snapshot"]:
                            status = ClaimVerificationStatus.STRUCTURALLY_REFUTED
                            reason = "Certificate text does not match the pinned snapshot."
                        elif not checks["supported_sink_present"]:
                            status = ClaimVerificationStatus.STRUCTURALLY_REFUTED
                            reason = (
                                "Certificate sink is not one exact supported fetch/Axios "
                                "member call."
                            )
                        elif not valid_source:
                            status = ClaimVerificationStatus.STRUCTURALLY_REFUTED
                            reason = (
                                "Sink input does not close to one claimed direct request "
                                "property."
                            )
                        else:
                            status = ClaimVerificationStatus.STRUCTURALLY_VERIFIED
                            reason = (
                                "Structurally verified local JS/TS request-input-to-supported "
                                "sink syntax. Runtime reachability, deployed request "
                                "provenance, path feasibility, exploitability, and risk are "
                                "not validated."
                            )
    return ClaimVerification(
        claim_id=claim.id or 0,
        status=status,
        verifier_name=VERIFIER_NAME,
        verifier_version=VERIFIER_VERSION,
        checks=checks,
        reason=reason,
    )


def verify_structural_claim(
    claim: SecurityClaim,
    snapshot_path: Path | None,
    expected_commit: str | None,
) -> ClaimVerification:
    """Independently check a certificate against a pinned snapshot.

    `structurally_verified` means only that exact source, sink, and local def-use facts
    close under this checker. It never validates exploitability or real-world risk.
    """
    if claim.language in {"javascript", "typescript"}:
        return _verify_javascript_claim(claim, snapshot_path, expected_commit)
    if claim.language != "python":
        return ClaimVerification(
            claim_id=claim.id or 0,
            status=ClaimVerificationStatus.UNSUPPORTED,
            verifier_name=VERIFIER_NAME,
            verifier_version=VERIFIER_VERSION,
            checks={"supported_language": False},
            reason=f"Checker does not support language {claim.language!r}.",
        )
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
        "caller_evidence_present": bool(claim.caller_evidence),
        "direct_callers_verified": False,
        "authorization_candidate_present": bool(claim.authorization_evidence),
        "authorization_syntax_verified": False,
        "registration_evidence_present": bool(claim.registration_evidence),
        "blueprint_registration_verified": False,
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
                *claim.authorization_evidence,
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
                            *claim.authorization_evidence,
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
                            caller_checks: list[bool] = []
                            for caller in claim.caller_evidence:
                                caller_path = _safe_file(snapshot_path, caller.file)
                                if caller_path is None or caller_path.suffix != ".py":
                                    caller_checks.append(False)
                                    continue
                                caller_text = caller_path.read_text(errors="replace")
                                caller_lines = caller_text.splitlines()
                                try:
                                    caller_tree = ast.parse(caller_text)
                                except SyntaxError:
                                    caller_checks.append(False)
                                    continue
                                caller_checks.append(
                                    _matches_line(caller_lines, caller)
                                    and any(
                                        isinstance(node, ast.Call)
                                        and node.lineno == caller.line
                                        and _call_name(node) == function.name
                                        for node in ast.walk(caller_tree)
                                    )
                                )
                            checks["direct_callers_verified"] = bool(
                                caller_checks and all(caller_checks)
                            )
                            if caller_checks and not checks["direct_callers_verified"]:
                                status = ClaimVerificationStatus.STRUCTURALLY_REFUTED
                                reason = (
                                    "Claimed direct-caller evidence does not match an "
                                    "independently parsed Python call site."
                                )
                                return ClaimVerification(
                                    claim_id=claim.id or 0,
                                    status=status,
                                    verifier_name=VERIFIER_NAME,
                                    verifier_version=VERIFIER_VERSION,
                                    checks=checks,
                                    reason=reason,
                                )
                            entry_decorators = _http_entry_decorators(function)
                            registration_subjects = _route_registration_subjects(
                                entry_decorators
                            )
                            registration_checks: list[bool] = []
                            for evidence in claim.registration_evidence:
                                registration_path = _safe_file(
                                    snapshot_path, evidence.file
                                )
                                if (
                                    registration_path is None
                                    or registration_path.suffix != ".py"
                                ):
                                    registration_checks.append(False)
                                    continue
                                registration_text = registration_path.read_text(
                                    errors="replace"
                                )
                                registration_lines = registration_text.splitlines()
                                try:
                                    registration_tree = ast.parse(registration_text)
                                except SyntaxError:
                                    registration_checks.append(False)
                                    continue
                                registration_checks.append(
                                    _matches_line(registration_lines, evidence)
                                    and _registration_at_line(
                                        registration_tree,
                                        evidence.line,
                                        registration_subjects,
                                    )
                                )
                            checks["blueprint_registration_verified"] = bool(
                                registration_checks and all(registration_checks)
                            )
                            if (
                                registration_checks
                                and not checks["blueprint_registration_verified"]
                            ):
                                status = ClaimVerificationStatus.STRUCTURALLY_REFUTED
                                reason = (
                                    "Claimed blueprint registration does not match an "
                                    "independently parsed route subject and call site."
                                )
                                return ClaimVerification(
                                    claim_id=claim.id or 0,
                                    status=status,
                                    verifier_name=VERIFIER_NAME,
                                    verifier_version=VERIFIER_VERSION,
                                    checks=checks,
                                    reason=reason,
                                )
                            authorization_checks = [
                                _matches_line(lines, evidence)
                                and _recognized_authorization_at_line(
                                    tree, function, evidence.line
                                )
                                for evidence in claim.authorization_evidence
                            ]
                            checks["authorization_syntax_verified"] = bool(
                                authorization_checks and all(authorization_checks)
                            )
                            if (
                                authorization_checks
                                and not checks["authorization_syntax_verified"]
                            ):
                                status = ClaimVerificationStatus.STRUCTURALLY_REFUTED
                                reason = (
                                    "Claimed authorization evidence does not match "
                                    "independently recognized same-function syntax."
                                )
                                return ClaimVerification(
                                    claim_id=claim.id or 0,
                                    status=status,
                                    verifier_name=VERIFIER_NAME,
                                    verifier_version=VERIFIER_VERSION,
                                    checks=checks,
                                    reason=reason,
                                )
                            closure_lines, parameters = _local_closure(function, sink)
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
                                    "control checks identify local syntax only. Any direct "
                                    "caller evidence proves call syntax, not runtime reachability. "
                                    "Authorization evidence identifies candidate syntax only, "
                                    "not authentication, scope, or control effectiveness. "
                                    "Blueprint registration evidence proves syntax only, "
                                    "not application startup or external reachability."
                                )
    return ClaimVerification(
        claim_id=claim.id or 0,
        status=status,
        verifier_name=VERIFIER_NAME,
        verifier_version=VERIFIER_VERSION,
        checks=checks,
        reason=reason,
    )

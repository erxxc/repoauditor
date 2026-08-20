"""Disabled, bounded, in-memory evidence tools for a future falsification agent.

This facade is intentionally not integrated with the challenger or CLI. It receives only
an already-built retrieval index, one trusted finding, and one in-memory architecture map;
it has no filesystem, database, network, subprocess, provider, or mutation interface.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Any, Callable

from ..config import AgentReadOnlyToolsConfig
from ..detect.retrieval import RetrievalIndex
from ..detect.retrieval.index import FunctionInfo
from ..map import ArchitectureMap
from ..store.models import Finding
from .slicing import build_structural_slice


TOOL_SURFACE_VERSION = "agent_read_only_tools_v1"


class ToolBoundaryError(ValueError):
    """Fail-closed request, integrity, allowlist, or budget violation."""


@dataclass(frozen=True)
class ToolCallResult:
    evidence: dict[str, Any]
    provenance: dict[str, Any]

    def model_dump(self) -> dict[str, Any]:
        return asdict(self)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _function_record(item: FunctionInfo) -> dict[str, Any]:
    return {
        "symbol": item.symbol,
        "file": item.file,
        "line_start": item.line_start,
        "line_end": item.line_end,
        "source": item.source,
        "language": item.language,
    }


class AgentReadOnlyTools:
    """Exact-dispatch, bounded evidence facade over trusted in-memory inputs."""

    def __init__(
        self,
        *,
        index: RetrievalIndex,
        finding: Finding,
        architecture: ArchitectureMap,
        snapshot_commit: str,
        expected_index_digest: str,
        config: AgentReadOnlyToolsConfig,
    ) -> None:
        self._config = config.model_copy(deep=True)
        self._index = index
        self._finding = finding
        self._architecture = architecture
        self._snapshot_commit = self._binding(snapshot_commit, label="snapshot commit")
        self._expected_index_digest = self._binding(
            expected_index_digest, label="retrieval index digest"
        )
        self._attempts = 0
        self._dispatch: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "indexed_source_excerpt": self._indexed_source_excerpt,
            "structural_slice": self._structural_slice,
            "callers": self._callers,
            "references": self._references,
            "architecture_evidence": self._architecture_evidence,
        }

    @property
    def attempts(self) -> int:
        return self._attempts

    def request(self, tool: str, **arguments: Any) -> ToolCallResult:
        if not self._config.enabled:
            raise ToolBoundaryError("agent read-only tools are disabled")
        self._verify_binding()
        if self._attempts >= self._config.maximum_calls:
            raise ToolBoundaryError("agent read-only tool call budget exhausted")
        self._attempts += 1
        if tool not in self._config.allowlist or tool not in self._dispatch:
            raise ToolBoundaryError("tool is not in the exact read-only allowlist")

        request_record = {"tool": tool, "arguments": arguments}
        evidence = self._dispatch[tool](arguments)
        evidence_bytes = _canonical_json(evidence)
        if len(evidence_bytes) > self._config.maximum_response_bytes:
            raise ToolBoundaryError("tool response exceeds the configured byte ceiling")
        provenance = {
            "surface_version": TOOL_SURFACE_VERSION,
            "tool": tool,
            "ordinal": self._attempts,
            "snapshot_commit": self._snapshot_commit,
            "index_digest": self._expected_index_digest,
            "request_digest": _digest(request_record),
            "response_digest": _digest(evidence),
            "response_bytes": len(evidence_bytes),
            "maximum_response_bytes": self._config.maximum_response_bytes,
            "maximum_results_per_call": self._config.maximum_results_per_call,
            "maximum_context_lines": self._config.maximum_context_lines,
        }
        return ToolCallResult(evidence=evidence, provenance=provenance)

    def _verify_binding(self) -> None:
        if self._architecture.commit != self._snapshot_commit:
            raise ToolBoundaryError("architecture snapshot commit drift")
        if self._architecture.repo_id != self._finding.repo_id:
            raise ToolBoundaryError("trusted finding and architecture repository drift")
        if self._index.content_digest() != self._expected_index_digest:
            raise ToolBoundaryError("retrieval index digest drift")

    def _exact_arguments(
        self, arguments: dict[str, Any], required: set[str]
    ) -> None:
        if set(arguments) != required:
            raise ToolBoundaryError(
                "tool arguments must exactly match: " + ", ".join(sorted(required))
            )

    def _query(self, value: Any, *, label: str) -> str:
        if not isinstance(value, str):
            raise ToolBoundaryError(f"{label} must be a string")
        if not value or not value.strip() or "\x00" in value:
            raise ToolBoundaryError(f"{label} is empty or contains a NUL byte")
        if len(value) > self._config.maximum_query_characters:
            raise ToolBoundaryError(f"{label} exceeds the configured character ceiling")
        if any(ord(character) < 32 for character in value):
            raise ToolBoundaryError(f"{label} contains a control character")
        return value

    def _binding(self, value: Any, *, label: str) -> str:
        if (
            not isinstance(value, str)
            or not value
            or not value.strip()
            or "\x00" in value
            or len(value) > 256
            or any(ord(character) < 32 for character in value)
        ):
            raise ToolBoundaryError(f"{label} is not a valid immutable binding")
        return value

    def _path(self, value: Any) -> str:
        path = self._query(value, label="path").replace("\\", "/")
        pure = PurePosixPath(path)
        windows_drive = bool(pure.parts and len(pure.parts[0]) >= 2 and pure.parts[0][1] == ":")
        if pure.is_absolute() or windows_drive or path.startswith("/") or any(
            part in {"", ".", ".."} for part in pure.parts
        ):
            raise ToolBoundaryError("path must be an exact canonical index-relative path")
        resolved = self._index.source_text(path)
        if resolved is None or resolved[0] != path:
            raise ToolBoundaryError("path is not an exact canonical indexed source path")
        return path

    def _bounded_records(self, records: list[FunctionInfo]) -> dict[str, Any]:
        selected = records[: self._config.maximum_results_per_call]
        return {
            "items": [_function_record(item) for item in selected],
            "returned": len(selected),
            "truncated_at_result_boundary": len(records) > len(selected),
        }

    def _indexed_source_excerpt(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._exact_arguments(arguments, {"file", "line_start", "line_end"})
        path = self._path(arguments["file"])
        start = arguments["line_start"]
        end = arguments["line_end"]
        if (
            not isinstance(start, int) or isinstance(start, bool) or start < 1
            or not isinstance(end, int) or isinstance(end, bool) or end < start
        ):
            raise ToolBoundaryError("line range must be positive, ordered integers")
        source_record = self._index.source_text(path)
        total_lines = len(source_record[1].splitlines()) if source_record else 0
        if start > total_lines or end > total_lines:
            raise ToolBoundaryError("line range exceeds the exact indexed source")
        item = self._index.file_excerpt(
            path, start, end, context_lines=self._config.maximum_context_lines
        )
        if item is None:
            raise ToolBoundaryError("indexed source excerpt is unavailable")
        return {"item": _function_record(item), "returned": 1}

    def _structural_slice(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._exact_arguments(arguments, set())
        evidence = build_structural_slice(self._index, self._finding)
        if evidence is None:
            return {"status": "unsupported", "slice": None}
        return {"status": evidence.status, "slice": asdict(evidence)}

    def _callers(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._exact_arguments(arguments, {"symbol"})
        symbol = self._query(arguments["symbol"], label="symbol")
        records = [
            excerpt
            for item in self._index.find_callers(symbol)
            if (
                excerpt := self._index.file_excerpt(
                    item.file,
                    item.line_start,
                    item.line_end,
                    context_lines=self._config.maximum_context_lines,
                )
            ) is not None
        ]
        return self._bounded_records(records)

    def _references(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._exact_arguments(arguments, {"token"})
        token = self._query(arguments["token"], label="reference token")
        records = self._index.find_text_references(
            token,
            limit=self._config.maximum_results_per_call + 1,
            context_lines=self._config.maximum_context_lines,
        )
        return self._bounded_records(records)

    def _architecture_evidence(self, arguments: dict[str, Any]) -> dict[str, Any]:
        self._exact_arguments(arguments, set())
        categories = {
            "trust_boundaries": [
                item.model_dump(mode="json")
                for item in self._architecture.trust_boundaries
            ],
            "entry_points": [
                item.model_dump(mode="json") for item in self._architecture.entry_points
            ],
            "data_stores": [
                item.model_dump(mode="json") for item in self._architecture.data_stores
            ],
            "integrations": [
                item.model_dump(mode="json") for item in self._architecture.integrations
            ],
        }
        result: dict[str, Any] = {"categories": {}, "truncated_at_result_boundary": False}
        for name, items in categories.items():
            selected = items[: self._config.maximum_results_per_call]
            result["categories"][name] = selected
            result["truncated_at_result_boundary"] = (
                result["truncated_at_result_boundary"] or len(items) > len(selected)
            )
        return result

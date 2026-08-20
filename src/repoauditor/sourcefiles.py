"""Shared helpers for walking an ingested snapshot's source files.

Used by the map stage (to build the architecture-recovery context) and the
retrieval index (to build the caller/callee graph). Kept deliberately small and
deterministic — no LLM, no config.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from pathlib import Path

# Source extensions worth feeding to the model / indexing. Intentionally narrow;
# lockfiles and manifests are handled separately by the supply-chain lens.
SOURCE_EXTENSIONS: set[str] = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php", ".java",
    ".kt", ".kts", ".rs", ".c", ".h", ".cpp", ".cs", ".sh",
}

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
_TEST_DIRS = {"test", "tests", "spec", "specs", "__tests__"}


def iter_source_files(root: Path) -> list[Path]:
    """Return source files under `root`, sorted, skipping vendored/build dirs."""
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in SOURCE_EXTENSIONS:
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        files.append(path)
    return files


def is_test_source(path: Path, root: Path) -> bool:
    """Return whether a source path is conventionally test-only.

    This is deliberately a narrow path/name classification, not a security or
    ground-truth heuristic. False negatives stay eligible as production source;
    false positives merely share the bounded test allocation.
    """
    rel = path.relative_to(root)
    lowered_parts = {part.lower() for part in rel.parts[:-1]}
    stem = rel.stem.lower()
    return (
        bool(lowered_parts & _TEST_DIRS)
        or stem.startswith(("test_", "spec_"))
        or stem.endswith(("_test", "_spec"))
    )


def _directory_bucket(path: Path, root: Path) -> str:
    """Group nearby files while retaining diversity across nested source trees."""
    parent_parts = path.relative_to(root).parts[:-1]
    return "/".join(parent_parts[:2]) if parent_parts else "."


def _path_digest(path: Path, root: Path) -> str:
    rel = path.relative_to(root).as_posix()
    return hashlib.sha256(f"source-coverage-v1\0{rel}".encode()).hexdigest()


def _directory_diverse_order(paths: list[Path], root: Path) -> list[Path]:
    buckets: dict[str, list[Path]] = defaultdict(list)
    for path in paths:
        buckets[_directory_bucket(path, root)].append(path)
    for bucket_paths in buckets.values():
        bucket_paths.sort(key=lambda path: _path_digest(path, root))

    bucket_names = sorted(
        buckets,
        key=lambda name: hashlib.sha256(
            f"source-directory-v1\0{name}".encode()
        ).hexdigest(),
    )
    ordered: list[Path] = []
    depth = 0
    while len(ordered) < len(paths):
        for name in bucket_names:
            if depth < len(buckets[name]):
                ordered.append(buckets[name][depth])
        depth += 1
    return ordered


def select_diverse_source_files(
    root: Path,
    limit: int,
    *,
    max_test_fraction: float = 0.25,
) -> list[Path]:
    """Select deterministic, directory-diverse source coverage within a file cap.

    Production paths receive at least 75% of a bounded selection when enough are
    available. Test paths may fill otherwise unused capacity. Ordering depends only
    on relative paths, so a pre-fix/post-fix pair with the same tree receives a
    comparable instrument rather than a commit-dependent sample.
    """
    if limit <= 0:
        return []
    files = iter_source_files(root)
    limit = min(limit, len(files))

    production = [path for path in files if not is_test_source(path, root)]
    tests = [path for path in files if is_test_source(path, root)]
    production = _directory_diverse_order(production, root)
    tests = _directory_diverse_order(tests, root)

    test_slots = min(len(tests), int(limit * max_test_fraction))
    production_slots = min(len(production), limit - test_slots)
    selected = production[:production_slots] + tests[:test_slots]

    if len(selected) < limit:
        selected_set = set(selected)
        remainder = [
            path
            for path in (*production[production_slots:], *tests[test_slots:])
            if path not in selected_set
        ]
        selected.extend(remainder[: limit - len(selected)])
    return selected


def read_numbered(path: Path) -> str:
    """Return a file's contents with 1-based line-number prefixes.

    Line numbers travel into the prompt so the model can cite exact `line_range`s.
    """
    lines = path.read_text(errors="replace").splitlines()
    width = len(str(len(lines))) if lines else 1
    return "\n".join(f"{i:>{width}}\t{line}" for i, line in enumerate(lines, start=1))


def truncate_utf8(value: str, maximum_bytes: int) -> tuple[str, bool]:
    """Return a valid UTF-8 prefix no larger than ``maximum_bytes``.

    Byte bounds are deterministic and conservative for provider context safety. A
    character-count bound is insufficient for repositories containing multibyte text.
    """
    if maximum_bytes < 0:
        raise ValueError("maximum_bytes must be non-negative")
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return value, False
    return encoded[:maximum_bytes].decode("utf-8", errors="ignore"), True


def read_numbered_bounded(path: Path, maximum_bytes: int) -> tuple[str, dict[str, int | bool]]:
    """Render a stable numbered prefix under an exact UTF-8 byte ceiling.

    Original 1-based line numbers are retained, including when the final included
    source line itself must be clipped. The omission notice is clearly outside the
    repository evidence block and cannot pass citation canonicalization.
    """
    if maximum_bytes <= 0:
        raise ValueError("maximum_bytes must be positive")
    text = path.read_text(errors="replace")
    lines = text.splitlines()
    width = len(str(len(lines))) if lines else 1
    rendered = "\n".join(
        f"{i:>{width}}\t{line}" for i, line in enumerate(lines, start=1)
    )
    original_bytes = len(rendered.encode("utf-8"))
    if original_bytes <= maximum_bytes:
        return rendered, {
            "original_bytes": original_bytes,
            "sent_bytes": original_bytes,
            "truncated": False,
        }

    notice = "\n# [REPOAUDITOR: remaining source evidence omitted by byte bound]"
    notice_bytes = len(notice.encode("utf-8"))
    prefix, _ = truncate_utf8(rendered, max(0, maximum_bytes - notice_bytes))
    bounded = prefix + notice
    return bounded, {
        "original_bytes": original_bytes,
        "sent_bytes": len(bounded.encode("utf-8")),
        "truncated": True,
    }

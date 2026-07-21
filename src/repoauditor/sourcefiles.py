"""Shared helpers for walking an ingested snapshot's source files.

Used by the map stage (to build the architecture-recovery context) and the
retrieval index (to build the caller/callee graph). Kept deliberately small and
deterministic — no LLM, no config.
"""

from __future__ import annotations

from pathlib import Path

# Source extensions worth feeding to the model / indexing. Intentionally narrow;
# lockfiles and manifests are handled separately by the supply-chain lens.
SOURCE_EXTENSIONS: set[str] = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php", ".java",
    ".rs", ".c", ".h", ".cpp", ".cs", ".sh",
}

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


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


def read_numbered(path: Path) -> str:
    """Return a file's contents with 1-based line-number prefixes.

    Line numbers travel into the prompt so the model can cite exact `line_range`s.
    """
    lines = path.read_text(errors="replace").splitlines()
    width = len(str(len(lines))) if lines else 1
    return "\n".join(f"{i:>{width}}\t{line}" for i, line in enumerate(lines, start=1))

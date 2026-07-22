"""Shared helpers for the deterministic tool adapters."""

from __future__ import annotations

from pathlib import Path


def relativize(file: str, snapshot_path: Path | None) -> str:
    """Express a tool-reported path relative to the snapshot root (posix), best effort.

    Deterministic tools report paths either absolute or relative to the working
    directory; the LLM lenses store findings as snapshot-relative posix. Normalizing to
    the same shape here is what lets a later corroboration pass line tool and lens
    findings up by file. Falls back to the path as-given when it can't be relativized.
    """
    if not file:
        return file
    p = Path(file)
    if snapshot_path is not None:
        try:
            return p.resolve().relative_to(Path(snapshot_path).resolve()).as_posix()
        except (ValueError, OSError):
            pass
    return p.as_posix()

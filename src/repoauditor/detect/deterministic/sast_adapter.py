"""SAST adapter (interface stub).

Wraps a static application security testing tool's output into canonical
`CandidateFinding`s. No real tool integration yet — interface only.
"""

from __future__ import annotations

from pathlib import Path

from ..ensemble import CandidateFinding

TOOL_NAME = "sast"


class SastAdapter:
    """Runs / parses a SAST tool and normalizes its output to candidate findings."""

    tool_name = TOOL_NAME

    def run(self, snapshot_path: Path) -> list[CandidateFinding]:
        # No real SAST tool wired yet — returns the canonical (empty) shape so the
        # normalize stage can consume deterministic output uniformly.
        return []

    def parse(self, raw_output: str) -> list[CandidateFinding]:
        """Parse pre-captured tool output into candidate findings (none wired yet)."""
        return []

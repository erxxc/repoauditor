"""SCA adapter (interface stub).

Wraps a software-composition-analysis tool (dependency vulnerability scanner) output
into canonical `CandidateFinding`s, reading the manifests inventoried at ingest time.
No real tool integration yet — interface only.
"""

from __future__ import annotations

from pathlib import Path

from ..ensemble import CandidateFinding

TOOL_NAME = "sca"


class ScaAdapter:
    """Runs / parses an SCA tool and normalizes its output to candidate findings."""

    tool_name = TOOL_NAME

    def run(self, snapshot_path: Path) -> list[CandidateFinding]:
        # No real SCA tool wired yet — returns the canonical (empty) shape.
        return []

    def parse(self, raw_output: str) -> list[CandidateFinding]:
        """Parse pre-captured tool output into candidate findings (none wired yet)."""
        return []

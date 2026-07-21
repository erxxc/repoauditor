"""Secrets adapter (interface stub).

Wraps a secret-scanner's output into canonical `CandidateFinding`s. No real tool
integration yet — interface only.
"""

from __future__ import annotations

from pathlib import Path

from ..ensemble import CandidateFinding

TOOL_NAME = "secrets"


class SecretsAdapter:
    """Runs / parses a secret scanner and normalizes its output to candidate findings."""

    tool_name = TOOL_NAME

    def run(self, snapshot_path: Path) -> list[CandidateFinding]:
        # No real secret scanner wired yet — returns the canonical (empty) shape.
        return []

    def parse(self, raw_output: str) -> list[CandidateFinding]:
        """Parse pre-captured tool output into candidate findings (none wired yet)."""
        return []

"""Engineering backlog projection (interface stub).

Projects the findings store into an engineering remediation backlog: one actionable
ticket per finding, ordered by technical severity and confidence, each carrying its
citation (file/line/snippet) and falsification status so an engineer can jump
straight to the code.

Reads via `store.db.list_findings` ONLY — never touches the database directly.
Not implemented in this scaffold.
"""

from __future__ import annotations

from ..config import Config, get_config


def build_backlog(repo_id: str, config: Config | None = None) -> str:
    """Render the engineering remediation backlog for a repo (reads from store only)."""
    config = config or get_config()
    raise NotImplementedError(
        "engineering backlog projection is stubbed in this scaffold"
    )

"""Leadership risk-memo projection (interface stub).

Projects the SAME findings store into a leadership-facing risk memo: findings ordered
by deal-relevant weighting (production exposure, remediation cost, rep & warranty
relevance) rather than raw technical severity, summarized with defensible benchmark
context (e.g. "detection precision on the benchmark corpus is X%") rather than raw
AI output. Uses the versioned template `templates/memo_v1.md`.

Reads via `store.db.list_findings` ONLY — never touches the database directly.
Not implemented in this scaffold.
"""

from __future__ import annotations

from ..config import Config, get_config


def build_memo(repo_id: str, config: Config | None = None) -> str:
    """Render the leadership risk memo for a repo (reads from store only)."""
    config = config or get_config()
    raise NotImplementedError("leadership memo projection is stubbed in this scaffold")

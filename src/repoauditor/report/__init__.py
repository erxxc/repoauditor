"""Report stage — two projections off the same findings store.

`engineering.build_backlog` (remediation ticket backlog) and `memo.build_memo`
(leadership risk summary). Both read from `store/` only; reports never touch the DB
directly.
"""

from .engineering import build_backlog
from .memo import build_memo

__all__ = ["build_backlog", "build_memo"]

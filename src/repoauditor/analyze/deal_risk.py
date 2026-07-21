"""Deal-relevant severity weighting (future work).

Planned behavior
----------------
Re-weight raw technical severity into deal-relevant risk for the leadership memo:
production exposure (is the vulnerable path actually deployed/reachable in prod),
remediation cost and timeline, and representation-&-warranty relevance (does this
finding bear on deal reps or warranties). Technical severity is an input, never
overwritten — this produces a separate deal-risk weighting layered on top, so the
engineering backlog and the leadership memo can order the same findings differently.

Reads from `store/` only. No implementation in this scaffold.
"""

from __future__ import annotations

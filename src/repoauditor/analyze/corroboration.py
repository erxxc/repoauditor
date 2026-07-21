"""Cross-lens / cross-tool corroboration scoring (future work).

Planned behavior
----------------
Score agreement and divergence across the detection sources for each finding.
When multiple independent lenses/tools flag the same location, that agreement is a
confidence signal and is one of the two things that can license a severity upgrade
(the other being a falsification pass confirming reachability). Divergence — one
source flags, others are silent, or they disagree on severity — is surfaced rather
than hidden, and feeds the normalize stage's adjudication.

Reads corroboration records from `store/`; writes nothing the store doesn't own.
No implementation in this scaffold.
"""

from __future__ import annotations

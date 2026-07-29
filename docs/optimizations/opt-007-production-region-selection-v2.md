# OPT-007 Production-region selection v2

Status: frozen implementation protocol as of 2026-07-29.

## Problem

The six-region production planner prioritizes deterministic scanner candidates and exact
architecture-map locations, then fills two reserved slots with stable path-only coverage.
Retained evidence shows that security-relevant code may instead be a syntactic caller or
callee of an architecture-mapped file. OPT-020 made that cross-file context observable, but
context expansions still do not receive primary-region lens coverage.

## Frozen change

Keep the configured region cap and stable-sample reservation unchanged. Within the remaining
evidence capacity, reserve at most
`detect.reserved_architecture_neighbor_regions` slots (default: one) for files connected to
an exact architecture-map location by the existing retrieval index:

1. an external function calls a symbol defined in the architecture-mapped file; then
2. a symbol defined in the architecture-mapped file calls a definition in another file.

Ordering is deterministic by relation type, architecture seed path, neighbor path, and
source line. Direct deterministic and architecture-map evidence retains priority in the
unreserved evidence slots. Unused neighbor capacity returns to direct evidence and then to
stable coverage; the planner always fills up to the existing cap when enough source files
exist.

The durable selection bases are `architecture-neighbor:call-name-match` and
`architecture-neighbor:callee-definition`. They describe syntactic name evidence, not a
type-resolved runtime or data-flow edge.

## Prohibited inputs and non-goals

- No advisory, CVE, patch, expected finding, target path, severity, or prior target verdict.
- No increase to provider calls, region cap, or live budget.
- No claim that a selected neighbor is vulnerable or runtime-reachable.
- No removal of deterministic evidence, architecture evidence, or stable blind sampling.
- No tuning against the revealed Plotly.js, aiohttp, PyJWT, Reposilite, ruby-saml, or
  simple-git target paths.

## Offline acceptance

1. Generic fixtures prove caller and callee neighbors can receive the reserved slot.
2. Selection remains deterministic across repeated runs and source-content changes that do
   not alter the indexed call relationship.
3. The configured cap and stable-sample reservation remain intact.
4. Missing/unsupported syntax degrades to the existing direct-evidence and stable-sample
   behavior.
5. Existing production-planner and selection-capture tests remain green.

Retained receipts that do not include snapshots or the architecture/retrieval inputs needed
for a faithful replay must not be reconstructed from target metadata. Any future live or
paid validation requires a separately frozen protocol and approved budget.

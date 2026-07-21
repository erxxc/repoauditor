"""Ingest stage — clone/snapshot a target repo and its dependency manifests.

Hash-keyed and idempotent: raw snapshots live under `data/raw/<repo_id>/<commit>/`
and re-ingesting an unchanged commit is a no-op.
"""

from .repo import IngestResult, ingest_repo, latest_snapshot
from .manifest import ManifestSnapshot, snapshot_manifests

__all__ = [
    "IngestResult",
    "ingest_repo",
    "latest_snapshot",
    "ManifestSnapshot",
    "snapshot_manifests",
]

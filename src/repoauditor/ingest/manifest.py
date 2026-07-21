"""Dependency manifest snapshot.

Scans an ingested snapshot for known dependency manifests and lockfiles and records
each one's relative path plus a content hash — an SBOM-ish inventory of what the
target declares it depends on. This is deterministic bookkeeping; the SCA analysis
that interprets these files lives in `detect/deterministic/sca_adapter.py`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Known ecosystem manifests / lockfiles, by exact filename.
MANIFEST_FILENAMES: set[str] = {
    # Python
    "requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile", "Pipfile.lock",
    "setup.py", "setup.cfg", "uv.lock",
    # JavaScript / Node
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    # Ruby
    "Gemfile", "Gemfile.lock",
    # Rust
    "Cargo.toml", "Cargo.lock",
    # Go
    "go.mod", "go.sum",
    # Java / JVM
    "pom.xml", "build.gradle", "build.gradle.kts",
    # PHP
    "composer.json", "composer.lock",
    # Containers
    "Dockerfile",
}


@dataclass(frozen=True)
class ManifestFile:
    path: str          # relative to the snapshot root
    sha256: str
    size_bytes: int


@dataclass
class ManifestSnapshot:
    repo_id: str
    commit: str
    manifests: list[ManifestFile] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(
            {
                "repo_id": self.repo_id,
                "commit": self.commit,
                "manifests": [asdict(m) for m in self.manifests],
            },
            indent=2,
            sort_keys=True,
        )


def snapshot_manifests(snapshot_root: Path, repo_id: str, commit: str) -> ManifestSnapshot:
    """Inventory dependency manifests within an ingested snapshot directory."""
    manifests: list[ManifestFile] = []
    for path in sorted(p for p in snapshot_root.rglob("*") if p.is_file()):
        if path.name in MANIFEST_FILENAMES:
            data = path.read_bytes()
            manifests.append(
                ManifestFile(
                    path=path.relative_to(snapshot_root).as_posix(),
                    sha256=hashlib.sha256(data).hexdigest(),
                    size_bytes=len(data),
                )
            )
    return ManifestSnapshot(repo_id=repo_id, commit=commit, manifests=manifests)

"""Repository ingest — git clone/pull, idempotent by commit hash.

A target is identified by a slugged `repo_id` (derived from its URL/path) and a
`commit` hash. The raw snapshot is stored at `data/raw/<repo_id>/<commit>/`. If that
directory already exists the ingest is a no-op — re-ingesting an unchanged commit
does no work.

Sources supported:
  * a git URL or a local git repository — cloned via GitPython, keyed by HEAD commit;
  * a plain local directory ("snapshot") — copied and keyed by a deterministic
    content hash of its files (used by the golden-fixture harness).
"""

from __future__ import annotations

import hashlib
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from ..config import Config, get_config
from ..store import db
from ..store.models import IngestedRepo


@dataclass(frozen=True)
class IngestResult:
    repo_id: str
    commit: str
    source: str
    snapshot_path: Path
    reused: bool  # True if the snapshot already existed (no-op ingest)


def _slugify(source: str) -> str:
    """Derive a stable repo_id from a URL or path (last path component, slugged)."""
    name = source.rstrip("/").split("/")[-1]
    name = re.sub(r"\.git$", "", name)
    name = re.sub(r"[^0-9A-Za-z._-]+", "-", name).strip("-._")
    return name.lower() or "repo"


def _looks_like_git(source: str) -> bool:
    if re.match(r"^(https?|git|ssh)://", source) or source.endswith(".git"):
        return True
    if "@" in source and ":" in source and not Path(source).exists():
        return True  # scp-style git remote, e.g. git@github.com:org/repo.git
    p = Path(source)
    return p.is_dir() and (p / ".git").exists()


def _hash_directory(root: Path) -> str:
    """Deterministic content hash of a directory tree (path + bytes), git ignored."""
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        if ".git" in path.relative_to(root).parts:
            continue
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()[:12]


def _copy_snapshot(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns(".git"))


def ingest_repo(
    source: str, config: Config | None = None, repo_id: str | None = None
) -> IngestResult:
    """Ingest `source` into the hash-keyed raw store, idempotently.

    Returns an `IngestResult`; `reused=True` means the commit was already ingested
    and nothing was written. `repo_id` overrides the id derived from the source name
    (useful when several sources share a basename, e.g. `.../snapshot`).
    """
    config = config or get_config()
    db.init_db(config)
    repo_id = repo_id or _slugify(source)

    if _looks_like_git(source):
        commit, snapshot_source, cleanup = _prepare_git(source, config, repo_id)
    else:
        src = Path(source)
        if not src.is_dir():
            raise FileNotFoundError(f"ingest source is not a directory or git repo: {source}")
        commit = _hash_directory(src)
        snapshot_source, cleanup = src, None

    dest = config.raw_dir / repo_id / commit
    if dest.exists():
        if cleanup is not None:
            cleanup()
        result = IngestResult(repo_id, commit, source, dest, reused=True)
        db.record_ingested_repo(IngestedRepo(
            repo_id=repo_id, source=source, commit_hash=commit
        ), config)
        return result

    _copy_snapshot(snapshot_source, dest)
    if cleanup is not None:
        cleanup()
    result = IngestResult(repo_id, commit, source, dest, reused=False)
    db.record_ingested_repo(IngestedRepo(
        repo_id=repo_id, source=source, commit_hash=commit
    ), config)
    return result


def latest_snapshot(config: Config, repo_id: str) -> tuple[Path, str]:
    """Return (snapshot_path, commit) for a repo's most recently ingested commit.

    Lets the repo-level detect/falsify stages find the code for `repo_id` without
    being handed the path. Raises if the repo has never been ingested.
    """
    repo_dir = config.raw_dir / repo_id
    if not repo_dir.is_dir():
        raise FileNotFoundError(f"repo not ingested: {repo_id} (looked in {repo_dir})")
    commits = [p for p in repo_dir.iterdir() if p.is_dir() and not p.name.startswith(".")]
    if not commits:
        raise FileNotFoundError(f"no snapshots found for repo: {repo_id}")
    latest = max(commits, key=lambda p: p.stat().st_mtime)
    return latest, latest.name


def _prepare_git(source: str, config: Config, repo_id: str):
    """Clone (or open) a git source into a temp checkout; return (commit, path, cleanup)."""
    from git import Repo  # imported lazily so non-git ingest doesn't need GitPython

    src_path = Path(source)
    if src_path.is_dir() and (src_path / ".git").exists():
        repo = Repo(src_path)
        commit = repo.head.commit.hexsha[:12]
        return commit, src_path, None

    # Remote URL: clone into a scratch dir under the raw store, then relocate.
    tmp = config.raw_dir / repo_id / ".clone-tmp"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.parent.mkdir(parents=True, exist_ok=True)
    repo = Repo.clone_from(source, tmp)
    commit = repo.head.commit.hexsha[:12]

    def cleanup() -> None:
        shutil.rmtree(tmp, ignore_errors=True)

    return commit, tmp, cleanup

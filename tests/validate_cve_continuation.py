"""Zero-model validator for the one frozen aiohttp continuation artifact."""

from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

from repoauditor.config import get_config
from test_cve_positive_live import (
    _snapshot_content_digest,
    _validate_continuation,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    args = parser.parse_args()

    config = get_config()
    config = config.model_copy(update={
        "paths": config.paths.model_copy(update={
            "data_dir": args.database.parent,
            "raw_dir": args.database.parent / "raw",
            "db_path": args.database,
        })
    })
    fixture = SimpleNamespace(expected={"findings": [{
        "file": "aiohttp/web_urldispatcher.py"
    }]})
    _repo_id, commit, _design = _validate_continuation(
        fixture, config, args.results
    )
    if _snapshot_content_digest(args.snapshot) != commit:
        raise SystemExit(
            "materialized continuation snapshot differs from retained commit"
        )
    print(
        "continuation artifact qualified offline: "
        f"run=30383181253 commit={commit}"
    )


if __name__ == "__main__":
    main()

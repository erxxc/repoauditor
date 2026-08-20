"""Prepare a bounded local Semgrep runtime without version-check network access."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path


def seed_version_cache(output: Path, *, timestamp: int | None = None) -> None:
    """Create a fresh empty version response so Semgrep skips its remote check."""
    if not output.parent.is_dir():
        raise RuntimeError(f"version-cache parent does not exist: {output.parent}")
    if output.exists():
        raise RuntimeError(f"refusing to overwrite Semgrep version cache: {output}")
    observed = int(time.time()) if timestamp is None else timestamp
    output.write_text(f"{observed}\n{json.dumps({})}\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    seed_version_cache(args.output)


if __name__ == "__main__":
    main()

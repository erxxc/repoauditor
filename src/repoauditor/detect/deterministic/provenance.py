"""Provenance helpers shared by deterministic scanner adapters."""

from __future__ import annotations

import gzip
import hashlib
import re
import subprocess
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator


SEMGREP_RULESET_SHA256 = (
    "e1fb774d43b23f8265ae07566a5e325763244df9ba6eb8cbefe51e3ce05540c4"
)
SEMGREP_CONFIGURATION = f"p/default@sha256:{SEMGREP_RULESET_SHA256}"
SEMGREP_RULESET_ARCHIVE = Path(__file__).with_name("semgrep-default.yml.gz")


def utc_now() -> datetime:
    return datetime.now(UTC)


def tool_version(binary: str, *arguments: str, timeout_seconds: int = 10) -> str | None:
    """Return a bounded, single-line version without making scanner success depend on it."""
    try:
        proc = subprocess.Popen(
            [binary, *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        output, _ = proc.communicate(timeout=min(timeout_seconds, 10))
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return None
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    value = output.strip().splitlines()
    return value[0][:200] if value else None


@contextmanager
def pinned_semgrep_configuration(_timeout_seconds: int) -> Iterator[tuple[Path, int]]:
    """Materialize the vendored registry payload and reject package corruption."""
    try:
        with gzip.open(SEMGREP_RULESET_ARCHIVE, "rb") as source:
            payload = source.read()
    except OSError as exc:
        raise RuntimeError(f"could not read pinned Semgrep ruleset: {exc}") from exc
    digest = hashlib.sha256(payload).hexdigest()
    if digest != SEMGREP_RULESET_SHA256:
        raise RuntimeError(
            "Semgrep ruleset digest changed: "
            f"expected {SEMGREP_RULESET_SHA256}, received {digest}"
        )
    text = payload.decode("utf-8")
    rule_count = len(re.findall(r"(?m)^\s*- id:", text))
    if rule_count < 1:
        raise RuntimeError("pinned Semgrep ruleset contains no rules")
    with tempfile.NamedTemporaryFile(suffix=".yml") as handle:
        handle.write(payload)
        handle.flush()
        yield Path(handle.name), rule_count

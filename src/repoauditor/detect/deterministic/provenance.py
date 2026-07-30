"""Provenance helpers shared by deterministic scanner adapters."""

from __future__ import annotations

import gzip
import hashlib
import re
import subprocess
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Iterator


SEMGREP_RULESET_SHA256 = (
    "e1fb774d43b23f8265ae07566a5e325763244df9ba6eb8cbefe51e3ce05540c4"
)
SEMGREP_CONFIGURATION = f"p/default@sha256:{SEMGREP_RULESET_SHA256}"
SEMGREP_RULESET_ARCHIVE = Path(__file__).with_name("semgrep-default.yml.gz")
SEMGREP_SUPPLEMENTAL_RULESET = Path(__file__).with_name("semgrep-supplemental.yml")


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


@lru_cache(maxsize=1)
def pinned_semgrep_rule_ids() -> tuple[str, ...]:
    """Return longest-first canonical ids from the vendored ruleset."""
    with gzip.open(SEMGREP_RULESET_ARCHIVE, "rt", encoding="utf-8") as source:
        ids = re.findall(r"(?m)^\s*- id:\s*(\S+)\s*$", source.read())
    return tuple(sorted(set(ids), key=lambda value: (-len(value), value)))


def supplemental_semgrep_provenance() -> tuple[Path, str, int]:
    """Return the versioned owned ruleset with its content identity."""
    payload = SEMGREP_SUPPLEMENTAL_RULESET.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    rule_count = len(re.findall(rb"(?m)^\s*- id:", payload))
    if rule_count < 1:
        raise RuntimeError("supplemental Semgrep ruleset contains no rules")
    return SEMGREP_SUPPLEMENTAL_RULESET, digest, rule_count


def canonical_semgrep_rule_id(rule_id: str) -> str:
    """Remove Semgrep's host/config-path prefix from a vendored registry rule id."""
    for canonical in pinned_semgrep_rule_ids():
        if rule_id == canonical or rule_id.endswith(f".{canonical}"):
            return canonical
    return rule_id


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
    rule_count = len(re.findall(rb"(?m)^\s*- id:", payload))
    if rule_count < 1:
        raise RuntimeError("pinned Semgrep ruleset contains no rules")
    with tempfile.NamedTemporaryFile(suffix=".yml") as handle:
        handle.write(payload)
        handle.flush()
        yield Path(handle.name), rule_count

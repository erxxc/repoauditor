"""Pure CLI presentation helpers with no persistence or pipeline behavior."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable

from .store.models import IngestedRepo, ReviewRequest


def repos_json(repos: Iterable[IngestedRepo]) -> str:
    """Return a stable JSON array for automation."""
    return json.dumps(
        [repo.model_dump(mode="json") for repo in repos],
        ensure_ascii=False,
        separators=(",", ":"),
    )


def repos_table(repos: Iterable[IngestedRepo]) -> str:
    """Render repository snapshots as an aligned, terminal-friendly table."""
    rows = [
        (repo.repo_id, repo.source, repo.commit_hash, repo.ingested_at or "-")
        for repo in repos
    ]
    if not rows:
        return "No ingested repositories."
    headers = ("REPO ID", "SOURCE", "COMMIT", "INGESTED AT")
    widths = [max(len(headers[i]), *(len(row[i]) for row in rows)) for i in range(4)]

    def line(row: tuple[str, str, str, str]) -> str:
        return "  ".join(value.ljust(widths[i]) for i, value in enumerate(row)).rstrip()

    separator = tuple("-" * width for width in widths)
    return "\n".join([line(headers), line(separator), *(line(row) for row in rows)])


def review_requests_json(requests: Iterable[ReviewRequest]) -> str:
    """Return open requests without flattening their evidence payloads."""
    return json.dumps(
        [request.model_dump(mode="json") for request in requests],
        ensure_ascii=False,
        separators=(",", ":"),
    )


def ndjson_event(stage: str, status: str, **details: object) -> str:
    """Serialize one streaming run event with a UTC timestamp."""
    event = {
        "stage": stage,
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        **details,
    }
    return json.dumps(event, ensure_ascii=False, separators=(",", ":"), default=str)

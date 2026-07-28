"""Pure CLI presentation helpers with no persistence or pipeline behavior."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .map import ArchitectureMap
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


def architecture_artifact_path(data_dir: Path, repo_id: str, commit: str) -> Path:
    """Return the deterministic location for a map-stage ASCII projection."""
    short_commit = commit[:12] if commit else "unknown"
    return data_dir / "artifacts" / repo_id / f"architecture-{short_commit}.txt"


def architecture_ascii(architecture: ArchitectureMap) -> str:
    """Render only relationships present in the recovered architecture map.

    Entry-point to trust-boundary association and integration direction are explicit map
    fields. Data stores have no recovered flow edge in the current schema, so they remain
    an inventory rather than being connected with a speculative arrow.
    """
    boundaries = sorted(
        architecture.trust_boundaries, key=lambda item: item.name.casefold()
    )
    entries = sorted(
        architecture.entry_points,
        key=lambda item: (
            (item.trust_boundary or "").casefold(),
            item.name.casefold(),
            item.location or "",
        ),
    )
    stores = sorted(
        architecture.data_stores,
        key=lambda item: (item.name.casefold(), item.location or ""),
    )
    integrations = sorted(
        architecture.integrations,
        key=lambda item: (item.name.casefold(), item.location or ""),
    )
    lines = [
        "REPOAUDITOR ARCHITECTURE MAP",
        f"repo-id: {architecture.repo_id}",
        f"commit: {architecture.commit}",
        "",
        "SCHEMATIC",
        "  Arrows show only recovered entry-boundary associations or integration direction.",
    ]
    if entries:
        for entry in entries:
            source = _node(entry.name, entry.location)
            if entry.trust_boundary:
                lines.append(
                    f"  {source} --crosses--> "
                    f"{{trust boundary: {entry.trust_boundary}}} --> "
                    f"[repository: {architecture.repo_id}]"
                )
            else:
                lines.append(
                    f"  {source} --boundary not recovered--> "
                    f"[repository: {architecture.repo_id}]"
                )
    else:
        lines.append("  (no entry points recovered)")

    lines.extend(["", "TRUST BOUNDARIES"])
    if boundaries:
        linked = {entry.trust_boundary for entry in entries if entry.trust_boundary}
        for boundary in boundaries:
            suffix = "" if boundary.name in linked else " [no linked entry point recovered]"
            lines.append(f"  - {boundary.name}{suffix}")
            if boundary.description:
                lines.append(f"    {boundary.description}")
    else:
        lines.append("  (none recovered)")

    lines.extend([
        "",
        "DATA STORES",
        "  Inventory only: the current map schema does not assert component-to-store flows.",
    ])
    if stores:
        for store in stores:
            details = []
            if store.kind:
                details.append(f"kind={store.kind}")
            if store.location:
                details.append(f"location={store.location}")
            suffix = f" ({'; '.join(details)})" if details else ""
            lines.append(f"  - [data store: {store.name}]{suffix}")
    else:
        lines.append("  (none recovered)")

    lines.extend(["", "EXTERNAL INTEGRATIONS"])
    if integrations:
        repo = f"[repository: {architecture.repo_id}]"
        for integration in integrations:
            target = _node(integration.name, integration.location)
            direction = (integration.direction or "").strip().lower()
            if direction == "inbound":
                lines.append(f"  {target} --inbound--> {repo}")
            elif direction == "outbound":
                lines.append(f"  {repo} --outbound--> {target}")
            elif direction == "bidirectional":
                lines.append(f"  {repo} <--bidirectional--> {target}")
            elif direction:
                lines.append(f"  {repo} --direction: {integration.direction}--> {target}")
            else:
                lines.append(f"  {repo} --direction not recovered-- {target}")
    else:
        lines.append("  (none recovered)")

    lines.extend([
        "",
        "LIMITATIONS",
        "  This is a projection of recovered map records, not a complete runtime trace.",
        "  Missing nodes or edges mean 'not recovered', not 'does not exist'.",
        "",
    ])
    return "\n".join(lines)


def _node(name: str, location: str | None) -> str:
    suffix = f" @ {location}" if location else ""
    return f"[{name}{suffix}]"

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
    """Render a terminal-safe layout of the recovered architecture map.

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
        "BOX-DRAWING LAYOUT",
        "  Recovered associations only; data stores remain unconnected inventory.",
        *_architecture_layout(architecture, boundaries, entries, stores, integrations),
        "",
        "RELATIONSHIP INVENTORY",
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


def _architecture_layout(
    architecture: ArchitectureMap,
    boundaries: list,
    entries: list,
    stores: list,
    integrations: list,
) -> list[str]:
    """Build a compact visual projection without manufacturing map relationships."""
    repo = f"[repository: {architecture.repo_id}]"
    lines = ["  ENTRY POINTS AND TRUST BOUNDARIES"]
    entries_by_boundary = {
        boundary.name: [
            entry for entry in entries if entry.trust_boundary == boundary.name
        ]
        for boundary in boundaries
    }
    linked_names = {
        entry.trust_boundary for entry in entries if entry.trust_boundary
    }
    groups: list[tuple[str, list]] = [
        (name, grouped) for name, grouped in entries_by_boundary.items() if grouped
    ]
    # Preserve associations whose named boundary was not recovered as a boundary record.
    groups.extend(
        (
            name,
            [entry for entry in entries if entry.trust_boundary == name],
        )
        for name in sorted(linked_names - set(entries_by_boundary), key=str.casefold)
    )
    for group_index, (boundary_name, grouped) in enumerate(groups):
        branch = "└─" if group_index == len(groups) - 1 and not _unlinked(entries) else "├─"
        lines.append(f"  {branch} {{trust boundary: {boundary_name}}}")
        continuation = "     " if branch == "└─" else "  │  "
        for entry_index, entry in enumerate(grouped):
            entry_branch = "└─" if entry_index == len(grouped) - 1 else "├─"
            lines.append(f"{continuation}{entry_branch} {_node(entry.name, entry.location)}")
        lines.append(f"{continuation}   crosses ─▶ {repo}")
    unlinked = _unlinked(entries)
    for index, entry in enumerate(unlinked):
        branch = "└─" if index == len(unlinked) - 1 else "├─"
        lines.append(
            f"  {branch} {_node(entry.name, entry.location)} "
            f"── boundary not recovered ─▶ {repo}"
        )
    if not entries:
        lines.append("  └─ (no entry points recovered)")

    lines.append("  EXTERNAL INTEGRATIONS")
    if integrations:
        for index, integration in enumerate(integrations):
            branch = "└─" if index == len(integrations) - 1 else "├─"
            target = _node(integration.name, integration.location)
            direction = (integration.direction or "").strip().lower()
            if direction == "inbound":
                relation = f"{target} ── inbound ─▶ {repo}"
            elif direction == "outbound":
                relation = f"{repo} ── outbound ─▶ {target}"
            elif direction == "bidirectional":
                relation = f"{repo} ◀─ bidirectional ─▶ {target}"
            elif direction:
                relation = f"{repo} ── direction: {integration.direction} ─▶ {target}"
            else:
                relation = f"{repo} ── direction not recovered ── {target}"
            lines.append(f"  {branch} {relation}")
    else:
        lines.append("  └─ (none recovered)")

    lines.append("  DATA STORES (INVENTORY; NO RECOVERED FLOW EDGE)")
    if stores:
        for index, store in enumerate(stores):
            branch = "└─" if index == len(stores) - 1 else "├─"
            lines.append(f"  {branch} [data store: {store.name}]")
    else:
        lines.append("  └─ (none recovered)")
    return lines


def _unlinked(entries: list) -> list:
    return [entry for entry in entries if not entry.trust_boundary]


def _node(name: str, location: str | None) -> str:
    suffix = f" @ {location}" if location else ""
    return f"[{name}{suffix}]"

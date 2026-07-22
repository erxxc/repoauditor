"""Engineering backlog projection — a ticket-style remediation backlog.

Reads `store.db.list_countable_findings` (NOT raw `list_findings` — the explicit forward
note from the dedup session): findings are collapsed to one entry per distinct issue, so a
finding corroborated by several sources is one ticket, not N. Entries are grouped by
technical severity (highest first) and, within a severity, ordered by trust boundary then
file — so an engineer triaging the list starts at the most dangerous, architecturally-anchored
issues.

Every ticket carries its full citation (file, line range, snippet): CLAUDE.md's "no finding
without a citation" rule is preserved end to end — citations are never summarized away. Reads
from `store/` only; never touches the DB directly.
"""

from __future__ import annotations

from pathlib import Path

from ..config import Config, get_config
from ..store import db
from ..store.models import Finding, Severity, severity_rank

# Highest-severity first — the order an engineer should work the backlog in.
_SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO,
]


def _source(finding: Finding) -> str:
    if finding.source_tool is not None:
        return f"{finding.source_tool} (tool)"
    return f"{finding.source_lens or 'unknown'} (lens)"


def _line_range(finding: Finding) -> str:
    if finding.line_start == finding.line_end:
        return str(finding.line_start)
    return f"{finding.line_start}-{finding.line_end}"


def _ticket(finding: Finding, boundaries: dict[int, str]) -> list[str]:
    """Render one finding as a self-contained remediation ticket (with its citation)."""
    boundary = boundaries.get(finding.trust_boundary_id, "(unmapped)")
    block = [
        f"### [finding #{finding.id}] {finding.title}",
        f"- **Severity:** {finding.severity}",
        f"- **Source:** {_source(finding)}",
        f"- **Falsification:** {finding.falsification_status}",
        f"- **Trust boundary:** {boundary}",
        f"- **Location:** `{finding.file}:{_line_range(finding)}`",
    ]
    if finding.corroborated_by:
        corr = ", ".join(
            f"{c.source_name} ({c.source_type})" for c in finding.corroborated_by
        )
        block.append(f"- **Corroborated by:** {corr}")
    block += ["", "```", finding.citation_snippet, "```"]
    if finding.description and finding.description.strip():
        block += ["", finding.description.strip()]
    block += ["", "---", ""]
    return block


def build_backlog(repo_id: str, config: Config | None = None) -> str:
    """Render the engineering remediation backlog for a repo (reads from store only)."""
    config = config or get_config()
    findings = db.list_countable_findings(repo_id, config)
    boundaries = {
        tb.id: tb.name
        for tb in db.list_trust_boundaries(repo_id, config)
        if tb.id is not None
    }

    if not findings:
        return (f"# Engineering Remediation Backlog — {repo_id}\n\n"
                "_No findings to triage._\n")

    findings.sort(key=lambda f: (
        -severity_rank(f.severity),
        boundaries.get(f.trust_boundary_id, "~"),  # "~" sorts unmapped last
        f.file,
        f.line_start,
    ))

    lines = [
        f"# Engineering Remediation Backlog — {repo_id}",
        "",
        f"_{len(findings)} distinct issue(s) — deduplicated across sources "
        "(`list_countable_findings`). Ordered by severity, then trust boundary._",
        "",
    ]
    for severity in _SEVERITY_ORDER:
        tier = [f for f in findings if f.severity is severity]
        if not tier:
            continue
        lines.append(f"## {severity.value.upper()} ({len(tier)})")
        lines.append("")
        for finding in tier:
            lines += _ticket(finding, boundaries)
    return "\n".join(lines)


def write_backlog(repo_id: str, config: Config | None = None) -> Path:
    """Render and write the engineering backlog, returning its artifact path."""
    config = config or get_config()
    out_dir = config.resolve(config.paths.data_dir) / "reports" / f"{repo_id}_engineering"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "backlog.md"
    path.write_text(build_backlog(repo_id, config))
    return path

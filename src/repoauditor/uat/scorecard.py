"""Score the purpose-built UAT fixture against persisted pipeline evidence.

This module never participates in detection and is invoked only after the pipeline has
finished. The expectation file remains outside the scanned snapshot, so it cannot leak the
answer key into model context.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..config import Config
from ..store import db
from ..store.models import EntityKind, FalsificationStatus


@dataclass(frozen=True)
class CaseResult:
    case: int
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class DemoScorecard:
    repo_id: str
    cases: tuple[CaseResult, ...]
    markdown_path: Path
    json_path: Path

    @property
    def passed(self) -> int:
        return sum(case.passed for case in self.cases)

    @property
    def total(self) -> int:
        return len(self.cases)


def _file_matches(candidate: str, expected: str) -> bool:
    return candidate.replace("\\", "/").endswith(expected.replace("\\", "/"))


def score_demo(
    repo_id: str, expectation_path: Path, config: Config, *, out_dir: Path | None = None
) -> DemoScorecard:
    """Evaluate all ten fixture behaviors and write Markdown plus structured JSON."""
    expected = json.loads(expectation_path.read_text(encoding="utf-8"))
    findings = db.list_findings(repo_id, config)
    countable = db.list_countable_findings(repo_id, config)
    requests = db.list_review_requests(repo_id, config)
    request_finding_ids = {request.finding_id for request in requests}
    entities = db.list_entities(repo_id, config)

    results: list[CaseResult] = []
    for item in expected["findings"]:
        matches = [f for f in findings if _file_matches(f.file, item["file"])]
        passed = any(f.falsification_status is FalsificationStatus.CONFIRMED for f in matches)
        results.append(CaseResult(
            item["case"], item["title"], passed,
            f"{len(matches)} matching stored finding(s); confirmed={passed}",
        ))

    store_ok = any(
        entity.kind is EntityKind.DATA_STORE
        and "customer" in f"{entity.name} {entity.location or ''} {entity.metadata or {}}".lower()
        for entity in entities
    )
    results.append(CaseResult(
        6, "Production-like customer datastore", store_ok,
        "customer datastore recovered by map" if store_ok else "customer datastore not recovered",
    ))

    for item in expected["expected_killed"]:
        matches = [f for f in findings if _file_matches(f.file, item["file"])]
        passed = any(f.falsification_status is FalsificationStatus.KILLED for f in matches)
        results.append(CaseResult(
            item["case"], f"Killed: {item['kill_basis']}", passed,
            f"{len(matches)} matching candidate(s); killed={passed}",
        ))

    unresolved = expected["expected_unresolved"][0]
    matches = [f for f in findings if _file_matches(f.file, unresolved["file"])]
    reviewed = any(f.id in request_finding_ids for f in matches)
    results.append(CaseResult(
        9, "Ambiguous finding routed to review", reviewed,
        f"{len(matches)} matching candidate(s); review request created={reviewed}",
    ))

    raw_secret = [f for f in findings if _file_matches(f.file, "storefront/config.py")]
    countable_secret = [f for f in countable if _file_matches(f.file, "storefront/config.py")]
    collapsed = len(raw_secret) >= 2 and len(countable_secret) == 1
    results.append(CaseResult(
        10, "Duplicate secret collapses to one countable issue", collapsed,
        f"raw={len(raw_secret)}; countable={len(countable_secret)}",
    ))
    results.sort(key=lambda result: result.case)

    out_dir = out_dir or config.resolve(config.paths.data_dir) / "reports" / f"{repo_id}_demo"
    out_dir.mkdir(parents=True, exist_ok=True)
    markdown_path = out_dir / "uat_scorecard.md"
    json_path = out_dir / "uat_scorecard.json"
    payload = {
        "repo_id": repo_id,
        "passed": sum(result.passed for result in results),
        "total": len(results),
        "cases": [result.__dict__ for result in results],
    }
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    lines = [
        f"# UAT Demo Scorecard — {repo_id}", "",
        f"**{payload['passed']}/{payload['total']} expected behaviors passed.**", "",
        "| Case | Result | Behavior | Evidence |", "|---:|---|---|---|",
    ]
    for result in results:
        lines.append(
            f"| {result.case} | {'PASS' if result.passed else 'MISS'} | "
            f"{result.name} | {result.detail} |"
        )
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return DemoScorecard(repo_id, tuple(results), markdown_path, json_path)

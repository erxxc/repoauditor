"""Disposition-aware scoring for the purpose-built live UAT fixture.

This is evaluation logic, not pipeline logic. It deliberately mirrors the production
counting view by using ``matching.find_matches`` while tightening the evaluation population
to findings that falsification actually confirmed. Unresolved/deferred/killed findings are
reported separately and never relabeled as false positives.
"""

from __future__ import annotations

from collections import Counter

from repoauditor.matching import MatchGroup, find_matches, source_of
from repoauditor.store.models import FalsificationStatus, Finding


def _evidence(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "title": finding.title,
        "file": finding.file,
        "line_start": finding.line_start,
        "line_end": finding.line_end,
        "citation_snippet": finding.citation_snippet[:240],
        "source": str(source_of(finding)),
        "confidence": finding.confidence,
        "severity": finding.severity.value,
        "falsification_status": finding.falsification_status.value,
        "falsification_reason": finding.falsification_reason,
    }


def _case_targets(expected: dict) -> tuple[list[dict], list[dict]]:
    """Return model-applicable confirmed cases and explicitly excluded cases."""
    finding_by_case = {item["case"]: item for item in expected.get("findings", [])}
    applicable: list[dict] = []
    excluded: list[dict] = []
    for case in expected.get("planted_cases", []):
        if not case.get("in_findings_ground_truth"):
            continue
        finding = finding_by_case[case["case"]]
        target = {
            "case": case["case"],
            "id": case["id"],
            "title": finding["title"],
            "file": finding["file"],
            "line_start": finding["line_start"],
            "line_end": finding["line_end"],
            "citation_contains": finding["citation_contains"],
            "severity_range": case["severity_range"],
            "expected_sources": case["expected_sources"],
        }
        if any(source["type"] == "lens" for source in case["expected_sources"]):
            applicable.append(target)
        else:
            target["exclusion_reason"] = "no model lens in expected_sources"
            excluded.append(target)
    return applicable, excluded


def _match_basis(finding: Finding, target: dict) -> list[str]:
    if finding.file != target["file"]:
        return []
    basis: list[str] = []
    if target["citation_contains"] in finding.citation_snippet:
        basis.append("citation")
    if (
        finding.line_start <= target["line_end"]
        and target["line_start"] <= finding.line_end
    ):
        basis.append("line_overlap")
    return basis


def _group_evidence(group: MatchGroup) -> dict:
    representative = group.representative
    return {
        "representative": _evidence(representative),
        "member_count": len(group.findings),
        "sources": sorted(str(source) for source in group.distinct_sources),
        "members": [_evidence(finding) for finding in group.findings],
    }


def _group_match_basis(group: MatchGroup, target: dict) -> list[str]:
    """Match ground truth against any member; the representative is display-only."""
    basis = {
        signal
        for finding in group.findings
        for signal in _match_basis(finding, target)
    }
    return sorted(basis)


def _ratio(tp: int, denominator: int) -> float:
    return tp / denominator if denominator else 0.0


def _score_confirmed_groups(groups: list[MatchGroup], targets: list[dict]) -> dict:
    unmatched = list(enumerate(groups))
    cases: list[dict] = []
    severity_matches = 0
    for target in targets:
        match_index = None
        match_basis: list[str] = []
        for position, (_, group) in enumerate(unmatched):
            basis = _group_match_basis(group, target)
            if basis:
                match_index = position
                match_basis = basis
                break
        if match_index is None:
            cases.append({
                **target,
                "detected": False,
                "match_basis": [],
                "severity_within_expected_range": None,
                "matched_group": None,
            })
            continue
        _, group = unmatched.pop(match_index)
        severity_ok = group.representative.severity.value in target["severity_range"]
        severity_matches += int(severity_ok)
        cases.append({
            **target,
            "detected": True,
            "match_basis": match_basis,
            "severity_within_expected_range": severity_ok,
            "matched_group": _group_evidence(group),
        })

    tp = sum(case["detected"] for case in cases)
    fp = len(unmatched)
    fn = len(cases) - tp
    return {
        "expected_case_count": len(cases),
        "countable_confirmed_finding_count": len(groups),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": _ratio(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
        "severity_matches": severity_matches,
        "severity_evaluated_count": tp,
        "severity_accuracy_on_matched": _ratio(severity_matches, tp),
        "cases": cases,
        "unmatched_confirmed_groups": [
            _group_evidence(group) for _, group in unmatched
        ],
    }


def _disposition_target(expected: dict, case: dict, disposition: str) -> dict:
    if disposition == "killed":
        detail = next(item for item in expected["expected_killed"] if item["case"] == case["case"])
    else:
        detail = next(
            item for item in expected["expected_unresolved"] if item["case"] == case["case"]
        )
    return {
        "case": case["case"],
        "id": case["id"],
        "title": case["category"],
        "file": detail["file"],
        "line_start": case["location"]["line_approx"],
        "line_end": case["location"]["line_approx"],
        "citation_contains": detail["citation_contains"],
        "severity_range": case["severity_range"],
        "expected_disposition": disposition,
    }


def _score_disposition(findings: list[Finding], target: dict) -> dict:
    same_issue = [
        finding for finding in findings if _match_basis(finding, target)
    ]
    expected_status = (
        FalsificationStatus.KILLED
        if target["expected_disposition"] == "killed"
        else FalsificationStatus.UNRESOLVED
    )
    correct = [finding for finding in same_issue if finding.falsification_status is expected_status]
    return {
        **target,
        "candidate_raised": bool(same_issue),
        "correct_disposition": bool(correct),
        "observed_statuses": sorted({
            finding.falsification_status.value for finding in same_issue
        }),
        "matches": [_evidence(finding) for finding in same_issue],
    }


def score_live_uat(findings: list[Finding], expected: dict) -> dict:
    """Score final confirmed issues and disposition controls as separate populations."""
    confirmed = [
        finding for finding in findings
        if finding.falsification_status is FalsificationStatus.CONFIRMED
    ]
    groups = find_matches(confirmed).groups
    targets, excluded = _case_targets(expected)
    final_score = _score_confirmed_groups(groups, targets)

    planted = expected.get("planted_cases", [])
    killed_targets = [
        _disposition_target(expected, case, "killed")
        for case in planted if case["expected_disposition"] == "killed"
    ]
    unresolved_targets = [
        _disposition_target(expected, case, "unresolved")
        for case in planted if case["expected_disposition"] == "requires-review"
    ]
    killed_checks = [_score_disposition(findings, target) for target in killed_targets]
    unresolved_checks = [
        _score_disposition(findings, target) for target in unresolved_targets
    ]

    disposition_counts = Counter(
        finding.falsification_status.value for finding in findings
    )
    unresolved = [
        _evidence(finding) for finding in findings
        if finding.falsification_status is FalsificationStatus.UNRESOLVED
    ]
    deferred = [
        _evidence(finding) for finding in findings
        if finding.falsification_status is FalsificationStatus.DEFERRED
    ]
    killed = [
        _evidence(finding) for finding in findings
        if finding.falsification_status is FalsificationStatus.KILLED
    ]
    return {
        "methodology": (
            "Confirmed findings only are grouped with production matching semantics for "
            "precision/recall. Identity is file+citation or file+line overlap; severity is "
            "evaluated separately. Tool-only expected cases are excluded from model recall."
        ),
        "raw_finding_count": len(findings),
        "raw_disposition_counts": dict(sorted(disposition_counts.items())),
        "raw_confirmed_finding_count": len(confirmed),
        "collapsed_confirmed_duplicate_count": len(confirmed) - len(groups),
        "final_countable_confirmed": final_score,
        "excluded_expected_cases": excluded,
        "killed_case_checks": killed_checks,
        "unresolved_case_checks": unresolved_checks,
        "killed_findings": killed,
        "unresolved_findings": unresolved,
        "deferred_findings": deferred,
    }

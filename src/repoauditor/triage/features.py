"""SARIF ingestion + feature engineering for the triage classifier.

Implements the EPSS-style feature-engineering approach adapted to SAST triage (the
actionable-warning / alert-quality literature): turn each static-analysis alert into a
fixed-width numeric vector of signals that correlate with whether an analyst will call
it actionable. The SARIF reader is tool-agnostic (SARIF 2.1.0); Semgrep is the minimum
supported producer, but any tool emitting SARIF works because we read only standard
fields (`ruleId`, `level`, `locations`, `codeFlows`, and the `security-severity`
property Semgrep/CodeQL set).

The feature set is deliberately *low-cardinality and numeric*: the high-cardinality
`ruleId` is folded into two learned signals — the rule's Beta-Binomial prior mean and
its historical false-positive rate from `TriageLabel` — rather than one-hot encoded, so
the vector width is stable and `synthetic.py` can generate matching rows.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..store.models import Severity

# --------------------------------------------------------------------------- #
# Canonical feature order. `synthetic.py` MUST emit these same names so training
# rows and scored rows share one schema. Keep additions append-only.
# --------------------------------------------------------------------------- #
FEATURE_NAMES: list[str] = [
    "severity_ordinal",       # SARIF level: none/note/warning/error -> 0..3
    "security_severity",      # Semgrep/CodeQL security-severity property, 0..10
    "cwe_is_injection",       # CWE in the injection family (77/78/79/89/90/94/...)
    "cwe_is_crypto",          # CWE in the weak-crypto family (326/327/328/330)
    "cwe_is_authz",           # CWE in the access-control family (284/285/862/863)
    "cwe_known",              # a CWE could be parsed at all
    "rule_prior_mean",        # Beta-Binomial posterior mean actionable rate for the rule
    "historical_fp_rate",     # observed FP fraction from TriageLabel (0 if unlabelled)
    "rule_label_count_log",   # log1p(#labels backing the rule) — confidence in the prior
    "path_depth",             # number of path segments
    "is_test_path",           # under a tests/ / spec / __tests__ path
    "is_vendor_dependency",   # dependency code (node_modules/vendor/site-packages/...)
    "is_generated",           # generated/build/dist/minified artifact
    "is_config_file",         # yaml/json/toml/ini/xml/env config file
    "file_commit_count_log",  # log1p(total commits touching the file) — git churn
    "file_recent_churn_log",  # log1p(commits in the last 90 days)
    "file_age_days_log",      # log1p(days since the file's first commit)
    "dataflow_length",        # #locations in the SARIF codeFlow (source->sink distance)
    "has_dataflow",           # a taint/dataflow trace is present
    "finding_density_log",    # log1p(#findings in the same file)
    "message_length_log",     # log1p(len(message)) — terse rules vs verbose ones
]

# CWE families that co-occur with high actionable rates in the SAST literature.
_INJECTION_CWES = {20, 74, 77, 78, 79, 88, 89, 90, 91, 94, 95, 116, 502, 611, 943}
_CRYPTO_CWES = {295, 326, 327, 328, 330, 916}
_AUTHZ_CWES = {200, 284, 285, 287, 306, 862, 863}

_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)
_SARIF_LEVEL_ORDINAL = {"none": 0, "note": 1, "warning": 2, "error": 3}

_VENDOR_MARKERS = ("node_modules/", "vendor/", "site-packages/", "third_party/",
                    "third-party/", "bower_components/", ".venv/", "dist-packages/")
_GENERATED_MARKERS = ("generated/", "/build/", "/dist/", ".min.", "_pb2.", ".g.dart",
                      ".designer.", "/gen/")
_TEST_MARKERS = ("test/", "tests/", "__tests__/", "spec/", "_test.", ".test.",
                 ".spec.", "test_")
_CONFIG_SUFFIXES = (".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".xml",
                    ".env", ".properties")


@dataclass
class SarifFinding:
    """One tool-agnostic static-analysis finding parsed from SARIF.

    Only standard SARIF 2.1.0 fields are read, so any conformant producer (Semgrep is
    the baseline) is supported. `fingerprint` is a stable dedupe/label key derived from
    the rule + location + snippet.
    """

    rule_id: str
    tool_name: str
    level: str                       # SARIF result.level (none/note/warning/error)
    message: str
    file: str
    line_start: int
    line_end: int
    snippet: str
    rule_name: str = ""              # human rule name from driver.rules (for display/category)
    cwe: int | None = None
    security_severity: float | None = None
    dataflow_length: int = 0         # #locations across the result's codeFlows
    raw: dict = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Stable hash key over (rule, file, line, snippet) for labels/dedupe."""
        import hashlib

        h = hashlib.sha1(
            f"{self.rule_id}|{self.file}|{self.line_start}|{self.snippet}".encode()
        )
        return h.hexdigest()[:16]


def _extract_cwe(*texts: str) -> int | None:
    """Pull the first CWE id out of any of the given strings (tags, messages, help)."""
    for text in texts:
        if not text:
            continue
        m = _CWE_RE.search(text)
        if m:
            return int(m.group(1))
    return None


def load_sarif(source: str | Path) -> list[SarifFinding]:
    """Parse a SARIF 2.1.0 document (path or raw JSON string) into `SarifFinding`s.

    Tool-agnostic: reads only standard SARIF fields plus the widely-used
    `security-severity` rule property. Rules metadata (CWE tags, security-severity) is
    indexed once per run and joined onto each result by `ruleId`.
    """
    if isinstance(source, Path) or (isinstance(source, str) and "\n" not in source
                                    and source.strip().endswith(".sarif")):
        doc = json.loads(Path(source).read_text())
    else:
        doc = json.loads(source)

    findings: list[SarifFinding] = []
    for run in doc.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        tool_name = driver.get("name", "sast")
        # Index rule metadata (CWE tags + security-severity) by rule id.
        rule_meta: dict[str, dict] = {}
        for rule in driver.get("rules", []):
            rid = rule.get("id", "")
            props = rule.get("properties", {})
            tags = props.get("tags", []) or []
            rule_meta[rid] = {
                "name": rule.get("name", "") or (rule.get("shortDescription", {}) or {}).get("text", ""),
                "cwe": _extract_cwe(*tags, rule.get("name", ""),
                                    (rule.get("help", {}) or {}).get("text", "")),
                "security_severity": _to_float(props.get("security-severity")),
            }

        for result in run.get("results", []):
            rule_id = result.get("ruleId") or result.get("rule", {}).get("id", "unknown")
            meta = rule_meta.get(rule_id, {})
            loc = _primary_location(result)
            props = result.get("properties", {}) or {}
            cwe = meta.get("cwe") or _extract_cwe(
                *(result.get("taxa", []) and [str(result["taxa"])] or []),
                _message_text(result),
            )
            findings.append(
                SarifFinding(
                    rule_id=rule_id,
                    tool_name=tool_name,
                    level=result.get("level", "warning"),
                    message=_message_text(result),
                    file=loc["file"],
                    line_start=loc["line_start"],
                    line_end=loc["line_end"],
                    snippet=loc["snippet"],
                    rule_name=meta.get("name", ""),
                    cwe=cwe,
                    security_severity=(meta.get("security_severity")
                                       or _to_float(props.get("security-severity"))),
                    dataflow_length=_dataflow_length(result),
                    raw=result,
                )
            )
    return findings


def sarif_severity(finding: SarifFinding) -> Severity:
    """Map a SARIF finding to a canonical `Severity`.

    Shared by the triage classifier and the detect-stage SAST adapter so a deterministic
    tool's severity is derived one way everywhere. Prefers the `security-severity` score
    (SARIF's 0..10 convention), falling back to the SARIF result level.
    """
    ss = finding.security_severity
    if ss is not None:
        if ss >= 9.0:
            return Severity.CRITICAL
        if ss >= 7.0:
            return Severity.HIGH
        if ss >= 4.0:
            return Severity.MEDIUM
        if ss >= 0.1:
            return Severity.LOW
        return Severity.INFO
    return {"error": Severity.HIGH, "warning": Severity.MEDIUM,
            "note": Severity.LOW, "none": Severity.INFO}.get(finding.level, Severity.MEDIUM)


def sarif_tool_confidence(finding: SarifFinding) -> float:
    """Nominal *tool* confidence for a SARIF finding (distinct from triage P(actionable)).

    Shared by triage and the SAST adapter. Derived from `security-severity` when present,
    else from the SARIF level.
    """
    if finding.security_severity is not None:
        return min(max(finding.security_severity / 10.0, 0.0), 1.0)
    return {"error": 0.7, "warning": 0.5, "note": 0.3, "none": 0.2}.get(finding.level, 0.5)


def _to_float(value) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _message_text(result: dict) -> str:
    msg = result.get("message", {})
    return msg.get("text", "") if isinstance(msg, dict) else str(msg)


def _primary_location(result: dict) -> dict:
    """First physical location of a result, with a safe empty default."""
    locs = result.get("locations", []) or []
    if not locs:
        return {"file": "unknown", "line_start": 1, "line_end": 1, "snippet": ""}
    phys = locs[0].get("physicalLocation", {})
    region = phys.get("region", {}) or {}
    start = region.get("startLine", 1)
    return {
        "file": phys.get("artifactLocation", {}).get("uri", "unknown"),
        "line_start": start,
        "line_end": region.get("endLine", start),
        "snippet": (region.get("snippet", {}) or {}).get("text", ""),
    }


def _dataflow_length(result: dict) -> int:
    """Total threadFlow location count across a result's codeFlows (0 if none).

    This is the SARIF encoding of source->sink distance; longer taint traces are a
    signal an analyst weighs when judging exploitability.
    """
    total = 0
    for flow in result.get("codeFlows", []) or []:
        for thread in flow.get("threadFlows", []) or []:
            total += len(thread.get("locations", []) or [])
    return total


# --------------------------------------------------------------------------- #
# Repo-context feature extraction
# --------------------------------------------------------------------------- #
@dataclass
class RepoFeatureContext:
    """Repo-scoped signals a single finding's features are computed against.

    Bundles the per-file finding density, the per-rule prior mean + historical FP rate
    (from the store), and a git-churn lookup — computed once per triage run and reused
    across every finding, so feature extraction stays O(findings).
    """

    findings_per_file: dict[str, int] = field(default_factory=dict)
    rule_prior_mean: dict[str, float] = field(default_factory=dict)
    rule_fp_rate: dict[str, float] = field(default_factory=dict)
    rule_label_count: dict[str, int] = field(default_factory=dict)
    churn: dict[str, tuple[int, int, int]] = field(default_factory=dict)  # file -> (commits, recent, age_days)
    default_prior_mean: float = 0.3

    def prior_mean_for(self, rule_id: str) -> float:
        return self.rule_prior_mean.get(rule_id, self.default_prior_mean)


def extract_feature_vector(finding: SarifFinding, ctx: RepoFeatureContext) -> list[float]:
    """Compute the ordered `FEATURE_NAMES` vector for one finding.

    Pure and deterministic given `finding` + `ctx`; this is the exact function whose
    output `synthetic.py` mimics and the classifier consumes.
    """
    path = finding.file.lower()
    cwe = finding.cwe
    commits, recent, age = ctx.churn.get(finding.file, (0, 0, 0))
    feats = {
        "severity_ordinal": float(_SARIF_LEVEL_ORDINAL.get(finding.level, 2)),
        "security_severity": float(finding.security_severity or 0.0),
        "cwe_is_injection": float(cwe in _INJECTION_CWES) if cwe else 0.0,
        "cwe_is_crypto": float(cwe in _CRYPTO_CWES) if cwe else 0.0,
        "cwe_is_authz": float(cwe in _AUTHZ_CWES) if cwe else 0.0,
        "cwe_known": float(cwe is not None),
        "rule_prior_mean": ctx.prior_mean_for(finding.rule_id),
        "historical_fp_rate": ctx.rule_fp_rate.get(finding.rule_id, 0.0),
        "rule_label_count_log": math.log1p(ctx.rule_label_count.get(finding.rule_id, 0)),
        "path_depth": float(path.count("/")),
        "is_test_path": float(any(m in path for m in _TEST_MARKERS)),
        "is_vendor_dependency": float(any(m in path for m in _VENDOR_MARKERS)),
        "is_generated": float(any(m in path for m in _GENERATED_MARKERS)),
        "is_config_file": float(path.endswith(_CONFIG_SUFFIXES)),
        "file_commit_count_log": math.log1p(commits),
        "file_recent_churn_log": math.log1p(recent),
        "file_age_days_log": math.log1p(age),
        "dataflow_length": float(finding.dataflow_length),
        "has_dataflow": float(finding.dataflow_length > 0),
        "finding_density_log": math.log1p(ctx.findings_per_file.get(finding.file, 1)),
        "message_length_log": math.log1p(len(finding.message)),
    }
    return [feats[name] for name in FEATURE_NAMES]


def build_repo_context(
    findings: list[SarifFinding],
    *,
    rule_prior_mean: dict[str, float],
    rule_fp_rate: dict[str, float],
    rule_label_count: dict[str, int],
    churn: dict[str, tuple[int, int, int]] | None = None,
    default_prior_mean: float = 0.3,
) -> RepoFeatureContext:
    """Assemble the per-run feature context (finding density + store/git signals)."""
    density: dict[str, int] = {}
    for f in findings:
        density[f.file] = density.get(f.file, 0) + 1
    return RepoFeatureContext(
        findings_per_file=density,
        rule_prior_mean=rule_prior_mean,
        rule_fp_rate=rule_fp_rate,
        rule_label_count=rule_label_count,
        churn=churn or {},
        default_prior_mean=default_prior_mean,
    )


def git_churn(repo_path: Path, files: list[str], recent_days: int = 90) -> dict[str, tuple[int, int, int]]:
    """Best-effort per-file git churn: (total_commits, recent_commits, age_days).

    Degrades to an empty map if `repo_path` is not a git working tree (ingested
    snapshots usually aren't) — the churn features then read as 0, which the classifier
    treats as "no churn signal" rather than erroring. Uses GitPython, already a dep.
    """
    try:
        from datetime import datetime, timedelta, timezone

        from git import InvalidGitRepositoryError, Repo
    except Exception:
        return {}
    try:
        repo = Repo(repo_path, search_parent_directories=True)
    except (InvalidGitRepositoryError, Exception):
        return {}

    cutoff = datetime.now(timezone.utc) - timedelta(days=recent_days)
    out: dict[str, tuple[int, int, int]] = {}
    for rel in set(files):
        try:
            commits = list(repo.iter_commits(paths=rel))
        except Exception:
            continue
        if not commits:
            continue
        recent = sum(1 for c in commits if c.committed_datetime >= cutoff)
        age_days = (datetime.now(timezone.utc) - commits[-1].committed_datetime).days
        out[rel] = (len(commits), recent, max(age_days, 0))
    return out

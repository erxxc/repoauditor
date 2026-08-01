"""Dated, cached CVE enrichment from FIRST EPSS and CISA KEV.

Refresh is explicit and networked. Reads are offline, stale-aware, and informational only:
this module never changes finding validity, severity, or quantitative frequency.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..config import Config, get_config
from ..store import db
from ..store.models import Finding

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_MAX_AGE = timedelta(hours=48)
EPSS_CVE_PARAMETER_LIMIT = 2_000
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


class CveThreatSignal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    cve: str
    epss: float | None = Field(default=None, ge=0.0, le=1.0)
    percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_date: str | None = None
    known_exploited: bool
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    known_ransomware_campaign_use: str | None = None

    @field_validator("cve")
    @classmethod
    def normalize_cve(cls, value: str) -> str:
        value = value.upper()
        if not _CVE_RE.fullmatch(value):
            raise ValueError("invalid CVE identifier")
        return value


class ThreatIntelCache(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = 1
    repo_id: str
    requested_cves: list[str]
    retrieved_at: datetime
    epss_source: str = EPSS_URL
    epss_response_version: str | None = None
    kev_source: str = KEV_URL
    kev_catalog_version: str
    kev_date_released: str
    records: list[CveThreatSignal]

    @model_validator(mode="after")
    def validate_record_coverage(self) -> ThreatIntelCache:
        requested = sorted(set(self.requested_cves))
        recorded = sorted(record.cve for record in self.records)
        if requested != self.requested_cves:
            raise ValueError("requested CVEs must be normalized, unique, and sorted")
        if recorded != requested:
            raise ValueError("cached records must cover every requested CVE exactly once")
        return self


class ThreatIntelResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: str
    cache_path: Path | None
    cache: ThreatIntelCache | None
    age_hours: float | None = None
    detail: str


def finding_cves(finding: Finding) -> list[str]:
    text = " ".join((finding.title, finding.citation_snippet, finding.description or ""))
    return sorted({match.upper() for match in _CVE_RE.findall(text)})


def repo_cves(repo_id: str, config: Config | None = None) -> list[str]:
    config = config or get_config()
    return sorted({
        cve
        for finding in db.list_findings(repo_id, config)
        for cve in finding_cves(finding)
    })


def cache_path(repo_id: str, config: Config | None = None) -> Path:
    config = config or get_config()
    digest = hashlib.sha256(repo_id.encode("utf-8")).hexdigest()[:16]
    return config.resolve(config.paths.data_dir) / "threat-intel" / f"{digest}.json"


def _write_cache(path: Path, cache: ThreatIntelCache) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = cache.model_dump_json(indent=2).encode("utf-8") + b"\n"
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        os.chmod(temporary, 0o600)
        handle.write(payload)
    temporary.replace(path)


def _epss_batches(cves: list[str]) -> list[list[str]]:
    """Partition CVEs without exceeding FIRST's 2,000-character parameter limit."""
    batches: list[list[str]] = []
    current: list[str] = []
    current_length = 0
    for cve in cves:
        added_length = len(cve) + (1 if current else 0)
        if current and current_length + added_length > EPSS_CVE_PARAMETER_LIMIT:
            batches.append(current)
            current = []
            current_length = 0
            added_length = len(cve)
        if added_length > EPSS_CVE_PARAMETER_LIMIT:
            raise ValueError(f"CVE identifier exceeds FIRST query limit: {cve}")
        current.append(cve)
        current_length += added_length
    if current:
        batches.append(current)
    return batches


def refresh_threat_intel(
    repo_id: str,
    config: Config | None = None,
    *,
    client: httpx.Client | None = None,
    now: datetime | None = None,
) -> ThreatIntelResult:
    """Fetch and atomically cache current EPSS/KEV records for a repo's CVEs."""
    config = config or get_config()
    cves = repo_cves(repo_id, config)
    if not cves:
        return ThreatIntelResult(
            status="not-applicable", cache_path=None, cache=None,
            detail="repository findings contain no CVE identifiers",
        )
    owned_client = client is None
    client = client or httpx.Client(
        timeout=30.0,
        headers={"User-Agent": "RepoAuditor/0.1 threat-intel enrichment"},
        follow_redirects=True,
    )
    try:
        epss_by_cve: dict[str, dict] = {}
        epss_versions: set[str] = set()
        for batch in _epss_batches(cves):
            epss_response = client.get(EPSS_URL, params={"cve": ",".join(batch)})
            epss_response.raise_for_status()
            epss_doc = epss_response.json()
            if not isinstance(epss_doc, dict) or not isinstance(epss_doc.get("data"), list):
                raise ValueError("FIRST EPSS response lacks a data list")
            if epss_doc.get("version") is not None:
                epss_versions.add(str(epss_doc["version"]))
            epss_by_cve.update({
                str(item["cve"]).upper(): item
                for item in epss_doc["data"]
                if isinstance(item, dict) and "cve" in item
            })
        if len(epss_versions) > 1:
            raise ValueError("FIRST EPSS response versions changed during refresh")

        kev_response = client.get(KEV_URL)
        kev_response.raise_for_status()
        kev_doc = kev_response.json()
        if (
            not isinstance(kev_doc, dict)
            or not isinstance(kev_doc.get("vulnerabilities"), list)
            or not kev_doc.get("catalogVersion")
            or not kev_doc.get("dateReleased")
        ):
            raise ValueError("CISA KEV response lacks catalog metadata or vulnerabilities")
        kev_by_cve = {
            str(item["cveID"]).upper(): item
            for item in kev_doc["vulnerabilities"]
            if isinstance(item, dict) and "cveID" in item
        }
        records = []
        for cve in cves:
            epss = epss_by_cve.get(cve)
            kev = kev_by_cve.get(cve)
            records.append(CveThreatSignal(
                cve=cve,
                epss=float(epss["epss"]) if epss is not None else None,
                percentile=float(epss["percentile"]) if epss is not None else None,
                epss_date=str(epss.get("date")) if epss is not None else None,
                known_exploited=kev is not None,
                kev_date_added=str(kev.get("dateAdded")) if kev is not None else None,
                kev_due_date=str(kev.get("dueDate")) if kev is not None else None,
                known_ransomware_campaign_use=(
                    str(kev.get("knownRansomwareCampaignUse")) if kev is not None else None
                ),
            ))
        cache = ThreatIntelCache(
            repo_id=repo_id,
            requested_cves=cves,
            retrieved_at=now or datetime.now(UTC),
            epss_response_version=next(iter(epss_versions), None),
            kev_catalog_version=str(kev_doc["catalogVersion"]),
            kev_date_released=str(kev_doc["dateReleased"]),
            records=records,
        )
        path = cache_path(repo_id, config)
        _write_cache(path, cache)
        return ThreatIntelResult(
            status="current", cache_path=path, cache=cache, age_hours=0.0,
            detail=f"cached {len(records)} CVE record(s) from FIRST EPSS and CISA KEV",
        )
    finally:
        if owned_client:
            client.close()


def load_threat_intel(
    repo_id: str,
    config: Config | None = None,
    *,
    now: datetime | None = None,
    max_age: timedelta = DEFAULT_MAX_AGE,
) -> ThreatIntelResult:
    """Read cached enrichment without network access and classify freshness."""
    config = config or get_config()
    path = cache_path(repo_id, config)
    if not path.is_file():
        return ThreatIntelResult(
            status="missing", cache_path=path, cache=None,
            detail="no cached EPSS/KEV enrichment; run threat-enrich --refresh",
        )
    try:
        cache = ThreatIntelCache.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return ThreatIntelResult(
            status="invalid", cache_path=path, cache=None,
            detail=f"cached enrichment is invalid: {type(exc).__name__}: {exc}"[:500],
        )
    if cache.repo_id != repo_id:
        return ThreatIntelResult(
            status="invalid", cache_path=path, cache=None,
            detail="cached enrichment repo identity does not match",
        )
    current = now or datetime.now(UTC)
    retrieved = cache.retrieved_at
    if retrieved.tzinfo is None:
        retrieved = retrieved.replace(tzinfo=UTC)
    age = max(0.0, (current - retrieved).total_seconds() / 3600)
    status = "current" if current - retrieved <= max_age else "stale"
    return ThreatIntelResult(
        status=status, cache_path=path, cache=cache, age_hours=age,
        detail=(
            f"cache age {age:.1f}h; 48h freshness window; stale data remains visible "
            "but is not refreshed implicitly"
        ),
    )


def threat_signal_label(finding: Finding, result: ThreatIntelResult) -> str:
    cves = finding_cves(finding)
    if not cves:
        return "industry-baseline:no-CVE-signal"
    if result.cache is None:
        return f"industry-baseline:no-cached-EPSS-or-KEV ({','.join(cves)})"
    by_cve = {record.cve: record for record in result.cache.records}
    parts = []
    for cve in cves:
        record = by_cve.get(cve)
        if record is None:
            parts.append(f"{cve}:not-in-cache")
            continue
        epss = (
            f"epss={record.epss:.6f}@{record.epss_date}"
            if record.epss is not None
            else "epss=unavailable"
        )
        kev = f"kev={'yes' if record.known_exploited else 'no'}"
        parts.append(f"{cve}:{epss},{kev}")
    return f"cached-threat-intel:{result.status}:" + ";".join(parts)


def render_threat_intel(result: ThreatIntelResult) -> str:
    lines = [f"status: {result.status}", f"detail: {result.detail}"]
    if result.cache_path is not None:
        lines.append(f"cache: {result.cache_path}")
    if result.cache is not None:
        lines += [
            f"retrieved-at: {result.cache.retrieved_at.isoformat()}",
            f"epss-source: {result.cache.epss_source}",
            f"kev-source: {result.cache.kev_source}",
            f"kev-catalog: {result.cache.kev_catalog_version} ({result.cache.kev_date_released})",
        ]
        lines.extend(
            f"{record.cve}: epss={record.epss if record.epss is not None else 'unavailable'}; "
            f"percentile={record.percentile if record.percentile is not None else 'unavailable'}; "
            f"epss-date={record.epss_date or 'unavailable'}; kev={'yes' if record.known_exploited else 'no'}"
            for record in result.cache.records
        )
    lines.append("quantitative-effect: none (informational threat evidence only)")
    return "\n".join(lines)

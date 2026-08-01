"""OPT-012 dated EPSS/KEV cache, validation, and offline/stale behavior."""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime, timedelta

import pytest

from repoauditor.analyze.threat_intel import (
    EPSS_CVE_PARAMETER_LIMIT,
    ThreatIntelCache,
    _epss_batches,
    cache_path,
    load_threat_intel,
    refresh_threat_intel,
    threat_signal_label,
)
from repoauditor.store import db
from repoauditor.store.models import Finding


class Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class Client:
    def __init__(self, epss, kev):
        self.responses = [Response(epss), Response(kev)]
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


def _finding(repo_id="repo", cve="CVE-2024-0001"):
    return Finding(
        repo_id=repo_id, title=f"Dependency advisory {cve}", file="requirements.txt",
        line_start=1, line_end=1, citation_snippet=f"package affected by {cve}",
        source_tool="osv-scanner", confidence=0.8, severity="high",
    )


def _sources():
    epss = {
        "version": "1.0", "data": [{
            "cve": "CVE-2024-0001", "epss": "0.125", "percentile": "0.875",
            "date": "2026-08-01",
        }],
    }
    kev = {
        "catalogVersion": "2026.08.01", "dateReleased": "2026-08-01T12:00:00Z",
        "vulnerabilities": [{
            "cveID": "CVE-2024-0001", "dateAdded": "2026-07-30",
            "dueDate": "2026-08-20", "knownRansomwareCampaignUse": "Known",
        }],
    }
    return epss, kev


def test_refresh_validates_and_atomically_caches_authoritative_signals(tmp_config):
    db.init_db(tmp_config)
    finding = _finding()
    db.insert_finding(finding, tmp_config)
    epss, kev = _sources()
    client = Client(epss, kev)
    now = datetime(2026, 8, 1, 12, tzinfo=UTC)

    result = refresh_threat_intel("repo", tmp_config, client=client, now=now)

    assert result.status == "current"
    assert [record.cve for record in result.cache.records] == ["CVE-2024-0001"]
    record = result.cache.records[0]
    assert record.epss == 0.125 and record.percentile == 0.875
    assert record.known_exploited is True
    assert record.kev_date_added == "2026-07-30"
    assert result.cache.kev_catalog_version == "2026.08.01"
    assert stat.S_IMODE(result.cache_path.stat().st_mode) == 0o600
    assert client.calls[0][1]["params"]["cve"] == "CVE-2024-0001"
    assert client.calls[1][1] == {}


def test_offline_cache_is_current_then_stale_without_network(tmp_config):
    db.init_db(tmp_config)
    finding = _finding()
    db.insert_finding(finding, tmp_config)
    epss, kev = _sources()
    retrieved = datetime(2026, 8, 1, 12, tzinfo=UTC)
    refresh_threat_intel(
        "repo", tmp_config, client=Client(epss, kev), now=retrieved
    )

    current = load_threat_intel(
        "repo", tmp_config, now=retrieved + timedelta(hours=47)
    )
    stale = load_threat_intel(
        "repo", tmp_config, now=retrieved + timedelta(hours=49)
    )

    assert current.status == "current"
    assert stale.status == "stale" and stale.age_hours == 49
    assert "48h freshness window" in stale.detail
    assert threat_signal_label(finding, stale) == (
        "cached-threat-intel:stale:CVE-2024-0001:"
        "epss=0.125000@2026-08-01,kev=yes"
    )


def test_invalid_cache_and_malformed_refresh_fail_closed(tmp_config):
    db.init_db(tmp_config)
    db.insert_finding(_finding(), tmp_config)
    path = cache_path("repo", tmp_config)
    path.parent.mkdir(parents=True)
    path.write_text("not-json")

    loaded = load_threat_intel("repo", tmp_config)
    assert loaded.status == "invalid" and loaded.cache is None

    _, kev = _sources()
    with pytest.raises(ValueError, match="EPSS response"):
        refresh_threat_intel(
            "repo", tmp_config, client=Client({"data": "wrong"}, kev)
        )
    assert path.read_text() == "not-json"


def test_refresh_is_not_applicable_without_cves(tmp_config):
    db.init_db(tmp_config)
    finding = _finding(cve="advisory-without-identifier")
    db.insert_finding(finding, tmp_config)

    result = refresh_threat_intel("repo", tmp_config, client=object())

    assert result.status == "not-applicable"
    assert result.cache is None


def test_epss_batches_respect_first_parameter_limit():
    cves = [f"CVE-2026-{number:04d}" for number in range(1, 301)]

    batches = _epss_batches(cves)

    assert [cve for batch in batches for cve in batch] == cves
    assert len(batches) > 1
    assert all(len(",".join(batch)) <= EPSS_CVE_PARAMETER_LIMIT for batch in batches)


def test_cache_rejects_incomplete_record_coverage():
    with pytest.raises(ValueError, match="cover every requested CVE"):
        ThreatIntelCache(
            repo_id="repo",
            requested_cves=["CVE-2024-0001"],
            retrieved_at=datetime(2026, 8, 1, tzinfo=UTC),
            kev_catalog_version="2026.08.01",
            kev_date_released="2026-08-01T12:00:00Z",
            records=[],
        )

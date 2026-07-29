"""Scanner configuration and advisory provenance controls."""

from __future__ import annotations

import hashlib
import gzip

import pytest

from repoauditor.detect.deterministic import provenance
from repoauditor.detect.deterministic.execution import ScannerExecution


def test_pinned_semgrep_configuration_verifies_digest_and_rule_count(
    monkeypatch, tmp_path
):
    payload = b"rules:\n  - id: first\n    pattern: dangerous(...)\n"
    archive = tmp_path / "rules.yml.gz"
    with gzip.open(archive, "wb") as target:
        target.write(payload)
    digest = hashlib.sha256(payload).hexdigest()
    monkeypatch.setattr(provenance, "SEMGREP_RULESET_SHA256", digest)
    monkeypatch.setattr(provenance, "SEMGREP_RULESET_ARCHIVE", archive)

    with provenance.pinned_semgrep_configuration(1) as (path, rule_count):
        assert path.read_bytes() == payload
        assert rule_count == 1
        retained_path = path

    assert not retained_path.exists()


def test_pinned_semgrep_configuration_rejects_registry_drift(monkeypatch, tmp_path):
    archive = tmp_path / "rules.yml.gz"
    with gzip.open(archive, "wb") as target:
        target.write(b"rules: []\n")
    monkeypatch.setattr(provenance, "SEMGREP_RULESET_SHA256", "0" * 64)
    monkeypatch.setattr(provenance, "SEMGREP_RULESET_ARCHIVE", archive)

    with pytest.raises(RuntimeError, match="digest changed"):
        with provenance.pinned_semgrep_configuration(1):
            pass


def test_execution_serializes_complete_provenance():
    record = ScannerExecution(
        scanner="pip-audit",
        status="empty",
        applicable=True,
        output_valid=True,
        finding_count=0,
        target_count=1,
        target_count_basis="submitted-manifests",
        version="pip-audit 2.10.1",
        configuration="PyPI vulnerability service",
        invocation=("pip-audit", "-r", "$MANIFEST", "-f", "json"),
        configuration_resolution="live-service",
        advisory_database="PyPI Advisory Database",
        advisory_database_checked_at="2026-07-29T12:00:00Z",
    )

    payload = record.model_dump(mode="json")
    assert payload["version"] == "pip-audit 2.10.1"
    assert payload["invocation"] == [
        "pip-audit", "-r", "$MANIFEST", "-f", "json",
    ]
    assert payload["configuration_resolution"] == "live-service"
    assert payload["advisory_database_checked_at"] == "2026-07-29T12:00:00Z"

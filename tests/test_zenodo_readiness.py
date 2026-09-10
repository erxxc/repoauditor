from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_citation_and_zenodo_metadata_agree() -> None:
    citation = yaml.safe_load((ROOT / "CITATION.cff").read_text(encoding="utf-8"))
    zenodo = json.loads((ROOT / ".zenodo.json").read_text(encoding="utf-8"))
    assert citation["cff-version"] == "1.2.0"
    assert citation["type"] == "software"
    assert zenodo["upload_type"] == "software"
    for field in ("title", "version", "license"):
        assert citation[field] == zenodo[field]
    assert citation["authors"] == zenodo["creators"] == [{"name": "erxxc"}]
    assert zenodo["access_right"] == "open"
    assert zenodo["version"] == "0.1.0"
    assert citation["date-released"] == "2026-09-10"


def test_metadata_preserves_evidence_and_cross_project_boundaries() -> None:
    citation = yaml.safe_load((ROOT / "CITATION.cff").read_text(encoding="utf-8"))
    zenodo = json.loads((ROOT / ".zenodo.json").read_text(encoding="utf-8"))
    description = zenodo["description"]
    assert "review candidates" in description
    assert "not proof of exploitability" in description
    assert "do not execute PRNG recovery" in description
    related = {(item["relation"], item["identifier"]) for item in zenodo["related_identifiers"]}
    assert ("isSourceOf", "https://github.com/erxxc/repoauditor") in related
    assert ("isSupplementedBy", "https://github.com/erxxc/prng-lattice-lab") in related
    assert ("isSupplementedBy", "10.5281/zenodo.22697185") in related
    assert citation["references"][0]["doi"] == "10.5281/zenodo.22697185"


def test_release_metadata_and_required_notices_are_present() -> None:
    assert (ROOT / "LICENSE").read_text(encoding="utf-8").startswith("MIT License")
    assert (ROOT / "SECURITY.md").is_file()
    assert (ROOT / "THIRD_PARTY_NOTICES.md").is_file()
    assert (ROOT / "uv.lock").is_file()
    notes = (ROOT / "docs/releases/v0.1.0.md").read_text(encoding="utf-8")
    assert "38 closed bounded scopes and zero open items" in notes
    assert "No credentials" in notes

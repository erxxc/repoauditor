from __future__ import annotations

import json
import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/github-publication-readiness-receipt-2026-09-10.json"
WORKFLOWS = tuple(sorted((ROOT / ".github/workflows").glob("*.yml")))


def test_publication_security_files_are_present_and_bounded() -> None:
    security = (ROOT / "SECURITY.md").read_text()
    assert "security/advisories/new" in security
    assert "Do not disclose" in security
    assert "must be enabled before" in security

    codeowners = (ROOT / ".github/CODEOWNERS").read_text()
    assert "* @erxxc" in codeowners

    dependabot = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    ecosystems = {entry["package-ecosystem"] for entry in dependabot["updates"]}
    assert ecosystems == {"pip", "github-actions"}
    assert {entry["schedule"]["interval"] for entry in dependabot["updates"]} == {"weekly"}

    assert ".envrc" in (ROOT / ".gitignore").read_text().splitlines()


def test_all_reusable_actions_are_full_sha_pinned() -> None:
    receipt = json.loads(RECEIPT.read_text())
    expected_shas = set(receipt["action_pins"].values())
    uses_pattern = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
    observed: set[str] = set()

    for workflow in WORKFLOWS:
        text = workflow.read_text()
        for action in uses_pattern.findall(text):
            assert "@" in action, (workflow, action)
            _, ref = action.rsplit("@", 1)
            assert re.fullmatch(r"[0-9a-f]{40}", ref), (workflow, action)
            observed.add(ref)

    assert observed == expected_shas


def test_workflow_triggers_permissions_and_secret_boundaries_remain_explicit() -> None:
    for workflow in WORKFLOWS:
        data = yaml.safe_load(workflow.read_text())
        permissions = data.get("permissions")
        assert permissions["contents"] == "read"
        assert set(permissions.values()) == {"read"}

    tests = (ROOT / ".github/workflows/tests.yml").read_text()
    assert "pull_request:" in tests
    assert "secrets." not in tests

    secret_workflows = {
        "bounded-uat.yml": "ANTHROPIC_API_KEY",
        "live-tests.yml": "ANTHROPIC_API_KEY",
    }
    for name, secret in secret_workflows.items():
        text = (ROOT / ".github/workflows" / name).read_text()
        assert f"secrets.{secret}" in text
        assert "pull_request:" not in text


def test_third_party_fixture_license_boundary_is_disclosed() -> None:
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text()
    assert "does not relicense third-party fixture excerpts" in notices
    assert "GNU General Public License, version 3" in notices
    assert "Gunicorn 21.2.0" in notices
    assert "generated source\nsnapshots are ignored" in notices

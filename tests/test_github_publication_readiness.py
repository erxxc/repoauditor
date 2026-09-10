from __future__ import annotations

import json
import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/github-publication-readiness-receipt-2026-09-10.json"
WORKFLOWS = tuple(sorted((ROOT / ".github/workflows").glob("*.yml")))
HISTORICAL_ACTION_PINS = {
    "actions/checkout@v4": "11d5960a326750d5838078e36cf38b85af677262",
    "actions/cache@v4": "0057852bfaa89a56745cba8c7296529d2fc39830",
    "astral-sh/setup-uv@v6": "d0cc045d04ccac9d8b7881df0226f9e82c39688e",
    "actions/setup-python@v5": "a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/setup-go@v5": "40f1582b2485089dde7abd97c1529aa768e1baff",
    "actions/upload-artifact@v4": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/download-artifact@v4": "d3f86a106a0bac45b974a628896c90dbdf5c8093",
}
APPROVED_ACTIONS = {
    "actions/checkout",
    "actions/cache",
    "actions/cache/restore",
    "astral-sh/setup-uv",
    "actions/setup-python",
    "actions/setup-go",
    "actions/upload-artifact",
    "actions/download-artifact",
}


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
    assert receipt["action_pins"] == HISTORICAL_ACTION_PINS
    uses_pattern = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
    observed_actions: set[str] = set()

    for workflow in WORKFLOWS:
        text = workflow.read_text()
        for action in uses_pattern.findall(text):
            assert "@" in action, (workflow, action)
            identity, ref = action.rsplit("@", 1)
            assert identity in APPROVED_ACTIONS, (workflow, identity)
            assert re.fullmatch(r"[0-9a-f]{40}", ref), (workflow, action)
            observed_actions.add(identity)

    assert observed_actions == APPROVED_ACTIONS


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

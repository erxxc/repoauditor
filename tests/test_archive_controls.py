"""Zero-token manufactured controls for archive-entry containment."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from repoauditor import cli
from repoauditor.detect.ensemble import LensCandidate, LensFindings
from repoauditor.eval.archive_controls import (
    ArchivePathWitness,
    verify_archive_path_witness,
)
from repoauditor.eval.detection_sentinels import (
    evaluate_archive_detection_sentinels,
    load_detection_sentinels,
)
from repoauditor.llm import LLMClient, ScriptedBackend


FIXTURE = Path(__file__).parent / "fixtures" / "manufactured_archive_controls"
OWASP_PROMPT = (
    Path(__file__).parents[1]
    / "src" / "repoauditor" / "detect" / "lenses" / "owasp_v3.md"
)


def test_archive_controls_close_against_external_answer_key():
    manifest = json.loads((FIXTURE / "manifest.json").read_text())
    snapshot = FIXTURE / "snapshot"

    assert manifest["kind"] == "manufactured_solution"
    assert not (snapshot / "manifest.json").exists()
    observed = {}
    for case in manifest["cases"]:
        source = (snapshot / case["file"]).read_text()
        assert case["citation_snippet"] in source
        verification = verify_archive_path_witness(
            ArchivePathWitness(
                destination=case["destination"],
                entry_name=case["entry_name"],
                containment_enforced=case["containment_enforced"],
            )
        )
        observed[case["id"]] = verification.status.value

    assert observed == {
        case["id"]: case["expected"] for case in manifest["cases"]
    }


def test_archive_checker_does_not_mislabel_an_in_destination_entry():
    verification = verify_archive_path_witness(
        ArchivePathWitness(
            destination="/srv/javadocs",
            entry_name="api/index.html",
            containment_enforced=False,
        )
    )

    assert verification.status.value == "not_an_escape"
    assert verification.escapes_destination is False


def test_owasp_v3_preserves_archive_traversal_detection():
    prompt = OWASP_PROMPT.read_text()

    assert "Path traversal and unsafe archive extraction" in prompt
    assert "normalized containment check" in prompt
    assert "external entry-name flow" in prompt


def test_detection_sentinel_manifest_keeps_answer_key_outside_snapshot():
    manifest, snapshot, digest = load_detection_sentinels(FIXTURE)

    assert manifest.kind == "manufactured_solution"
    assert not (snapshot / "manifest.json").exists()
    assert len(digest) == 64


def test_archive_detection_qualification_requires_semantic_location_match(tmp_config):
    def handler(system, user, schema, context):
        assert schema is LensFindings
        if context["sentinel_id"] == "positive-unchecked-archive-entry":
            return LensFindings(findings=[LensCandidate(
                title="Archive path traversal permits destination escape",
                file="VulnerableArchive.kt",
                line_start=6,
                line_end=7,
                citation_snippet="val output = destination.resolve(entry.name)",
                severity="high",
                confidence=0.95,
                rationale=(
                    "An archive entry is resolved and written without a containment check."
                ),
            )])
        return LensFindings()

    result = evaluate_archive_detection_sentinels(
        FIXTURE,
        config=tmp_config,
        llm=LLMClient(ScriptedBackend(handler), tmp_config),
    )

    assert result.qualified
    assert result.positive_recovery == 1.0
    assert result.negative_recovery == 1.0
    assert result.observations[0].semantic_match_count == 1


def test_same_file_different_mechanism_does_not_pass_positive_control(tmp_config):
    def handler(system, user, schema, context):
        if context["sentinel_id"] == "positive-unchecked-archive-entry":
            return LensFindings(findings=[LensCandidate(
                title="Potential denial of service",
                file="VulnerableArchive.kt",
                line_start=6,
                line_end=7,
                citation_snippet="val output = destination.resolve(entry.name)",
                severity="medium",
                confidence=0.8,
                rationale="Large archives may consume disk space.",
            )])
        return LensFindings()

    result = evaluate_archive_detection_sentinels(
        FIXTURE,
        config=tmp_config,
        llm=LLMClient(ScriptedBackend(handler), tmp_config),
    )

    assert not result.qualified
    assert result.observations[0].observed == "absent"
    assert result.observations[0].semantic_match_count == 0


def test_detection_qualification_cli_records_usage_and_json(tmp_config, monkeypatch):
    def handler(system, user, schema, context):
        if context["sentinel_id"] == "positive-unchecked-archive-entry":
            return LensFindings(findings=[LensCandidate(
                title="Archive path traversal",
                file="VulnerableArchive.kt",
                line_start=6,
                line_end=7,
                citation_snippet="val output = destination.resolve(entry.name)",
                severity="high",
                confidence=0.9,
                rationale="Archive entry escapes its destination before a filesystem write.",
            )])
        return LensFindings()

    qualification = evaluate_archive_detection_sentinels(
        FIXTURE,
        config=tmp_config,
        llm=LLMClient(ScriptedBackend(handler), tmp_config),
    )
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    monkeypatch.setattr(
        cli,
        "evaluate_archive_detection_sentinels",
        lambda fixture, config: qualification,
    )

    result = CliRunner().invoke(
        cli.app, ["qualify-detection", "--format", "json"]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["qualified"] is True
    assert payload["model_usage"]["calls"] == 0

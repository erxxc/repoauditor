"""Zero-token manufactured controls for XML security-decision consistency."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from repoauditor import cli
from repoauditor.detect.ensemble import LensCandidate, LensFindings
from repoauditor.eval.detection_sentinels import (
    evaluate_xml_detection_sentinels,
    load_detection_sentinels,
)
from repoauditor.eval.xml_controls import (
    XMLRepresentationWitness,
    verify_xml_representation_witness,
)
from repoauditor.llm import LLMClient, ScriptedBackend


FIXTURE = Path(__file__).parent / "fixtures" / "manufactured_xml_controls"
OWASP_PROMPT = (
    Path(__file__).parents[1]
    / "src" / "repoauditor" / "detect" / "lenses" / "owasp_v3.md"
)


def test_xml_controls_close_against_external_answer_key():
    manifest = json.loads((FIXTURE / "manifest.json").read_text())
    snapshot = FIXTURE / "snapshot"

    assert manifest["kind"] == "manufactured_solution"
    assert not (snapshot / "manifest.json").exists()
    observed = {}
    for case in manifest["cases"]:
        source = (snapshot / case["file"]).read_text()
        assert case["citation_snippet"] in source
        verification = verify_xml_representation_witness(
            XMLRepresentationWitness(
                validated_representation=case["validated_representation"],
                consumed_representation=case["consumed_representation"],
                consumed_from_verified_node=case["consumed_from_verified_node"],
            )
        )
        observed[case["id"]] = verification.status.value

    assert observed == {
        case["id"]: case["expected"] for case in manifest["cases"]
    }


def test_xml_checker_refuses_an_inconsistent_declaration():
    verification = verify_xml_representation_witness(
        XMLRepresentationWitness(
            validated_representation="document",
            consumed_representation="other_document",
            consumed_from_verified_node=True,
        )
    )

    assert verification.status.value == "verification_incomplete"


def test_owasp_v3_assigns_xml_representation_mismatch_to_detection():
    prompt = OWASP_PROMPT.read_text()

    assert "XML security-decision representation mismatch" in prompt
    assert "separately parsed" in prompt
    assert "exact node or representation returned by verification" in prompt
    assert "do not assume two parsers necessarily disagree" in prompt


def test_xml_manifest_keeps_answer_key_outside_snapshot():
    manifest, snapshot, digest = load_detection_sentinels(FIXTURE)

    assert manifest.kind == "manufactured_solution"
    assert not (snapshot / "manifest.json").exists()
    assert len(digest) == 64


def test_xml_detection_requires_semantic_location_match(tmp_config):
    def handler(system, user, schema, context):
        assert schema is LensFindings
        if context["sentinel_id"] == "positive-distinct-xml-representations":
            return LensFindings(findings=[LensCandidate(
                title="XML parser differential crosses signature validation",
                file="VulnerableSaml.rb",
                line_start=6,
                line_end=10,
                citation_snippet=(
                    "return unless verify_signature(nokogiri_document, certificate)"
                ),
                severity="high",
                confidence=0.9,
                rationale=(
                    "Signature validation uses one parse tree while identity is consumed "
                    "from a separate representation."
                ),
            )])
        return LensFindings()

    result = evaluate_xml_detection_sentinels(
        FIXTURE,
        config=tmp_config,
        llm=LLMClient(ScriptedBackend(handler), tmp_config),
    )

    assert result.qualified
    assert result.positive_recovery == 1.0
    assert result.negative_recovery == 1.0
    assert result.observations[0].semantic_match_count == 1


def test_live_hyphenated_candidate_satisfies_frozen_semantic_rule(tmp_config):
    """Regression for Actions run 30372285245's retained positive candidate."""
    def handler(system, user, schema, context):
        if context["sentinel_id"] == "positive-distinct-xml-representations":
            return LensFindings(findings=[LensCandidate(
                title=(
                    "XML signature verified on Nokogiri tree, identity read from "
                    "separate REXML tree"
                ),
                file="VulnerableSaml.rb",
                line_start=5,
                line_end=9,
                citation_snippet=(
                    "  nokogiri_document = Nokogiri::XML(raw_xml)\n"
                    "  rexml_document = REXML::Document.new(raw_xml)\n"
                    "  return unless verify_signature(nokogiri_document, certificate)\n"
                    "\n"
                    "  REXML::XPath.first(rexml_document, "
                    "\"//Assertion/Subject/NameID\").text"
                ),
                severity="high",
                confidence=0.88,
                rationale=(
                    "Signature is validated against nokogiri_document while the "
                    "authenticated NameID is selected from a separately parsed "
                    "rexml_document of the same untrusted XML, enabling a "
                    "parser-differential/signature-wrapping representation mismatch."
                ),
            )])
        return LensFindings()

    result = evaluate_xml_detection_sentinels(
        FIXTURE,
        config=tmp_config,
        llm=LLMClient(ScriptedBackend(handler), tmp_config),
    )

    assert result.qualified
    assert result.observations[0].observed == "raised"
    assert result.observations[0].semantic_match_count == 1
    assert result.observations[1].observed == "absent"


def test_same_location_different_xml_mechanism_does_not_pass(tmp_config):
    def handler(system, user, schema, context):
        if context["sentinel_id"] == "positive-distinct-xml-representations":
            return LensFindings(findings=[LensCandidate(
                title="XML entity expansion",
                file="VulnerableSaml.rb",
                line_start=6,
                line_end=10,
                citation_snippet=(
                    "return unless verify_signature(nokogiri_document, certificate)"
                ),
                severity="high",
                confidence=0.8,
                rationale="The XML input might contain an external entity.",
            )])
        return LensFindings()

    result = evaluate_xml_detection_sentinels(
        FIXTURE,
        config=tmp_config,
        llm=LLMClient(ScriptedBackend(handler), tmp_config),
    )

    assert not result.qualified
    assert result.observations[0].observed == "absent"
    assert result.observations[0].semantic_match_count == 0


def test_xml_qualification_cli_emits_json_without_paid_test_calls(
    tmp_config, monkeypatch,
):
    qualification = evaluate_xml_detection_sentinels(
        FIXTURE,
        config=tmp_config,
        llm=LLMClient(ScriptedBackend(lambda *_args: LensFindings()), tmp_config),
    )
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    monkeypatch.setattr(
        cli, "evaluate_xml_detection_sentinels",
        lambda fixture, config: qualification,
    )

    result = CliRunner().invoke(
        cli.app, ["qualify-xml-detection", "--format", "json"]
    )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["qualified"] is False
    assert payload["model_usage"]["calls"] == 0

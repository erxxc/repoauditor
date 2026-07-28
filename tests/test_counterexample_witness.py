"""Zero-token manufactured controls for concrete regex-guard witnesses."""

import json
from pathlib import Path

from repoauditor.falsify.counterexample import (
    RegexGuardWitness,
    WitnessVerificationStatus,
    verify_javascript_regex_guard_witness,
)


FIXTURE = Path(__file__).parent / "fixtures" / "manufactured_regex_controls"


def test_manufactured_regex_witnesses_close_against_external_answer_key():
    manifest = json.loads((FIXTURE / "manifest.json").read_text())
    snapshot = FIXTURE / "snapshot"
    source = (snapshot / "guards.js").read_text().splitlines()

    assert manifest["kind"] == "manufactured_solution"
    assert not (snapshot / "manifest.json").exists()
    for case in manifest["cases"]:
        expression = source[case["line"] - 1].strip().removeprefix("return ").rstrip(";")
        result = verify_javascript_regex_guard_witness(
            RegexGuardWitness(
                input=case["witness"],
                control_expression=expression,
                expected_security_effect="manufactured effect; not checked",
            )
        )
        assert result.status is WitnessVerificationStatus(case["expected"]), case["id"]


def test_regex_witness_checker_refuses_unsupported_dialect_features():
    result = verify_javascript_regex_guard_witness(
        RegexGuardWitness(
            input="anything",
            control_expression="/danger/g.test(value)",
            expected_security_effect="not checked",
        )
    )

    assert result.status is WitnessVerificationStatus.VERIFICATION_INCOMPLETE
    assert "Unsupported JavaScript regex flags" in result.reason

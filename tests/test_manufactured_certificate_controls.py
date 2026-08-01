"""Zero-token manufactured controls for deterministic certificate contracts."""

import json
from pathlib import Path

from repoauditor.detect.retrieval import RetrievalIndex
from repoauditor.falsify.claims import claim_from_slice, verify_structural_claim
from repoauditor.falsify.slicing import build_structural_slice
from repoauditor.store.models import ClaimVerificationStatus, Finding


FIXTURE = Path(__file__).parent / "fixtures" / "manufactured_certificate_controls"


def test_manufactured_certificate_controls_close_against_external_answer_key():
    manifest = json.loads((FIXTURE / "manifest.json").read_text())
    snapshot = FIXTURE / "snapshot"
    assert manifest["kind"] == "manufactured_solution"
    assert not (snapshot / "manifest.json").exists()
    index = RetrievalIndex().build(snapshot)

    for ordinal, case in enumerate(manifest["cases"], 1):
        source = (snapshot / case["file"]).read_text().splitlines()
        assert case["citation"] in source[case["line"] - 1]
        finding = Finding(
            id=ordinal,
            repo_id="manufactured_certificate_controls",
            title=case["title"],
            file=case["file"],
            line_start=case["line"],
            line_end=case["line"],
            citation_snippet=case["citation"],
            source_tool="manufactured-certificate-control",
            confidence=1.0,
            severity="high",
        )
        evidence = build_structural_slice(index, finding)
        assert evidence is not None, case["id"]
        assert evidence.status == case["expected_slice"], case["id"]
        claim = claim_from_slice(ordinal, evidence, "manufactured-commit").model_copy(
            update={"id": ordinal}
        )
        verification = verify_structural_claim(
            claim, snapshot, "manufactured-commit"
        )
        assert verification.status is ClaimVerificationStatus(
            case["expected_verification"]
        ), case["id"]
        if check := case.get("expected_check"):
            assert verification.checks[check] is case["expected_check_value"], case["id"]


def test_manufactured_certificate_ground_truth_has_specific_basis():
    manifest = json.loads((FIXTURE / "manifest.json").read_text())
    assert len(manifest["cases"]) == 13
    assert len({case["id"] for case in manifest["cases"]}) == 13
    assert all(len(case["basis"]) >= 30 for case in manifest["cases"])

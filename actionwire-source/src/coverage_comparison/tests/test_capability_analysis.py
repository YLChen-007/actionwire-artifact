from __future__ import annotations

import unittest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from src.coverage_comparison.capability_analysis import (
    _records_for_chain,
    stable_capability_requirement_id,
    validate_capability_response,
    CAPABILITY_COMPARE_SYSTEM,
)
from src.coverage_comparison.contracts import CoverageComparisonError
from src.coverage_comparison.pipeline import run_coverage_comparison
from src.coverage_comparison.prompts import COMPARE_SYSTEM
from src.coverage_comparison.source_validation import SourceValidationConfig
from src.coverage_comparison.source_validation_prompts import (
    build_source_validation_user,
)

from src.coverage_comparison.tests.test_coverage_comparison import (
    FakeRunner,
    FakeSourceRunner,
    GATE,
    RID,
    coverage_chain,
    inputs,
    project_spec,
)


def response(*, decision: str = "missing-check", overlaps: list[str] | None = None) -> dict:
    gate_ids = [GATE] if decision in {"covered", "wrong-check"} else []
    return {
        "group_id": "HSG-" + "c" * 16,
        "chain_id": "C-" + "1" * 12,
        "proposals": [
            {
                "capability_facet": "internal network destination",
                "guard_rule": "Reject private and link-local destinations.",
                "applicability": "When the model controls the request URL.",
                "applicability_verdict": "applicable",
                "decision": decision,
                "capability_line_refs": [{"start_line": 2, "end_line": 3}],
                "controlled_argument": "url",
                "call_shape_facts": ["request receives a model-controlled URL"],
                "boundary_hypothesis": "The tool exposes external retrieval, not internal services.",
                "protected_asset_hypothesis": "Loopback and private network services.",
                "risk_if_unguarded": "The model can issue an SSRF request to an internal service.",
                "gate_ids": gate_ids,
                "covered_semantics": (
                    "The gate rejects only one literal host."
                    if decision in {"covered", "wrong-check"}
                    else None
                ),
                "gap": (
                    "No gate rejects private or link-local destinations."
                    if decision in {"wrong-check", "missing-check"}
                    else None
                ),
                "uncertainty": None,
                "overlap_requirement_ids": overlaps or [],
            }
        ],
    }


class CapabilityAnalysisContractTests(unittest.TestCase):
    def test_stable_capability_requirement_identity(self) -> None:
        first = stable_capability_requirement_id(
            sink_type_id="ST-" + "b" * 16,
            card_sha256="7" * 64,
            capability_facet="internal network destination",
            guard_rule="Reject private destinations.",
            applicability="When the model controls the URL.",
        )
        second = stable_capability_requirement_id(
            sink_type_id="ST-" + "b" * 16,
            card_sha256="7" * 64,
            capability_facet=" internal   network destination ",
            guard_rule="Reject private destinations.",
            applicability="When the model controls the URL.",
        )
        self.assertEqual(first, second)
        self.assertRegex(first, r"^CAPR-[0-9a-f]{16}$")

    def test_novel_missing_check_creates_capability_candidate(self) -> None:
        chain = coverage_chain()
        rows = validate_capability_response(response(), chain=chain)
        proposals, assessments, candidates, requirements = _records_for_chain(
            chain, rows
        )
        self.assertEqual(1, len(proposals))
        self.assertEqual("novel", proposals[0]["disposition"])
        self.assertEqual("missing-check", assessments[0]["decision"])
        self.assertEqual(1, len(candidates))
        self.assertEqual("coverage-candidate/v7", candidates[0]["schema_version"])
        self.assertEqual("capability-card", candidates[0]["requirement_source"])
        self.assertIn(
            (chain.project, chain.chain_id, candidates[0]["requirement_id"]),
            requirements,
        )

    def test_group_overlap_is_audited_without_duplicate_candidate(self) -> None:
        chain = coverage_chain()
        rows = validate_capability_response(response(overlaps=[RID]), chain=chain)
        proposals, _assessments, candidates, _requirements = _records_for_chain(
            chain, rows
        )
        self.assertEqual("covered-by-group", proposals[0]["disposition"])
        self.assertEqual([], candidates)

    def test_uncovered_card_overlap_reopens_safe_group_decision(self) -> None:
        chain = coverage_chain()
        rows = validate_capability_response(
            response(decision="wrong-check", overlaps=[RID]), chain=chain
        )
        proposals, assessments, candidates, requirements = _records_for_chain(
            chain,
            rows,
            group_decisions={RID: "not-applicable"},
        )
        self.assertEqual("group-overlap-conflict", proposals[0]["disposition"])
        self.assertEqual(1, len(candidates))
        self.assertEqual([RID], candidates[0]["overlap_requirement_ids"])
        self.assertEqual(
            "coverage-overlap-conflict-validation/v7",
            candidates[0]["overlap_conflict_policy_version"],
        )
        overlap = candidates[0]["overlap_group_requirements"]
        self.assertEqual("not-applicable", overlap[0]["primary_decision"])
        source_requirement = requirements[
            (chain.project, chain.chain_id, candidates[0]["requirement_id"])
        ]
        self.assertEqual(overlap, source_requirement["overlap_group_requirements"])
        user = build_source_validation_user(
            chain,
            candidates,
            {candidates[0]["requirement_id"]: assessments[0]},
            {candidates[0]["requirement_id"]: source_requirement},
        )
        self.assertIn("Overlap-conflict policy", user)
        self.assertIn(chain.oracle["requirements"][0]["rule"], user)

    def test_uncovered_card_overlap_deduplicates_existing_group_gap(self) -> None:
        chain = coverage_chain()
        rows = validate_capability_response(
            response(decision="wrong-check", overlaps=[RID]), chain=chain
        )
        proposals, _assessments, candidates, _requirements = _records_for_chain(
            chain,
            rows,
            group_decisions={RID: "missing-check"},
        )
        self.assertEqual("covered-by-group", proposals[0]["disposition"])
        self.assertEqual([], candidates)

    def test_invalid_card_citation_fails(self) -> None:
        chain = coverage_chain()
        invalid = response()
        invalid["proposals"][0]["capability_line_refs"] = [
            {"start_line": 99, "end_line": 99}
        ]
        with self.assertRaisesRegex(CoverageComparisonError, "out of range"):
            validate_capability_response(invalid, chain=chain)

    def test_wrong_check_requires_relevant_gate(self) -> None:
        chain = coverage_chain(gate=False)
        with self.assertRaisesRegex(CoverageComparisonError, "unknown identifiers"):
            validate_capability_response(response(decision="wrong-check"), chain=chain)

    def test_pipeline_promotes_only_source_confirmed_capability_candidate(self) -> None:
        class CombinedRunner:
            def __init__(self) -> None:
                self.group = FakeRunner("covered")

            def __call__(self, system: str, user: str) -> str:
                if system == COMPARE_SYSTEM:
                    return self.group(system, user)
                if system == CAPABILITY_COMPARE_SYSTEM:
                    return json.dumps(response())
                raise AssertionError(system)

            def audit_payload(self) -> dict:
                return {"transport": "fake", "available_tools": [], "calls": []}

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source_root = root / "source"
            source_root.mkdir()
            (source_root / "source.py").write_text("evidence\n", encoding="utf-8")
            chain = coverage_chain()
            with patch(
                "src.coverage_comparison.pipeline.load_coverage_inputs",
                return_value=inputs(chain),
            ):
                result = run_coverage_comparison(
                    specs=[project_spec(source_root)],
                    handler_root=root,
                    sink_root=root,
                    group_root=root,
                    evidence_registry=root / "registry.json",
                    out_dir=root / "out",
                    generation_command="fixture",
                    runner=CombinedRunner(),
                    source_validation_config=SourceValidationConfig(
                        enable_lsp=False, strategy="agent-only"
                    ),
                    source_validation_runner_factory=lambda _spec, _config: FakeSourceRunner(),
                )
            candidates = [
                json.loads(line)
                for line in (root / "out/candidates.jsonl").read_text().splitlines()
            ]
            self.assertEqual(1, len(candidates))
            self.assertEqual("capability-card", candidates[0]["requirement_source"])
            self.assertEqual(
                1, result["manifest"]["counts"]["capability_canonical_candidates"]
            )


if __name__ == "__main__":
    unittest.main()

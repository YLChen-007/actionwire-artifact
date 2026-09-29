from __future__ import annotations

import json
import unittest
from dataclasses import replace

from src.coverage_comparison.contracts import CoverageComparisonError
from src.coverage_comparison.learned_invariants import (
    LEARNED_COMPARE_SYSTEM,
    analyze_learned_invariants,
    load_learned_catalog,
    route_learned_requirements,
    stable_learned_candidate_id,
    validate_learned_response,
)
from src.coverage_comparison.same_origin import SameOriginRun
from src.coverage_comparison.source_validation import SourceValidationConfig
from src.coverage_comparison.source_validation_prompts import build_source_validation_user
from src.coverage_comparison.tests.test_coverage_comparison import GATE, coverage_chain


def origin_run(chain):
    sink = {
        "schema_version": "coverage-same-origin-witness/v7",
        "origin_witness_id": "ORIGIN-" + "1" * 16,
        "project": chain.project,
        "chain_id": chain.chain_id,
        "gate_uid": None,
        "controlled_value_id": "CV-1",
    }
    gate = {
        "schema_version": "coverage-same-origin-witness/v7",
        "origin_witness_id": "ORIGIN-" + "2" * 16,
        "project": chain.project,
        "chain_id": chain.chain_id,
        "gate_uid": GATE,
        "controlled_value_id": "CV-1",
    }
    return SameOriginRun(
        witnesses=(sink, gate),
        exclusions=(),
        qualified_chains={chain.key: chain},
        witness_by_gate={(chain.project, chain.chain_id, GATE): gate},
        sink_witness_by_chain={chain.key: sink},
    )


def learned_rule() -> dict:
    catalog = load_learned_catalog()
    return next(
        row
        for row in catalog["patterns"]
        if row["pattern_key"] == "powershell-encoded-command-ec"
    )


def response(chain, rule, *, decision="wrong-check") -> dict:
    gates = [GATE] if decision in {"covered", "wrong-check"} else []
    witnesses = ["ORIGIN-" + "1" * 16]
    if gates:
        witnesses.append("ORIGIN-" + "2" * 16)
    return {
        "project": chain.project,
        "revision": chain.revision,
        "chain_id": chain.chain_id,
        "assessments": [
            {
                "requirement_id": rule["requirement_id"],
                "applicability": "applicable",
                "controlled_value_id": "CV-1",
                "origin_witness_ids": witnesses,
                "controlled_facet": "url from the model-facing handler",
                "effective_sink_facet": "url passed to request",
                "decision": decision,
                "gate_ids": gates,
                "covered_semantics": (
                    "The gate checks only one variant."
                    if decision in {"covered", "wrong-check"}
                    else None
                ),
                "transform_or_policy_delta": (
                    "The learned variant remains uncovered."
                    if decision in {"wrong-check", "missing-check"}
                    else None
                ),
                "security_effect": (
                    "The effective capability reaches the sink without the learned policy."
                    if decision in {"wrong-check", "missing-check"}
                    else None
                ),
                "uncertainty": None,
            }
        ],
    }


class LearnedInvariantTests(unittest.TestCase):
    def test_catalog_contains_stable_fifteen_rules(self) -> None:
        catalog = load_learned_catalog()
        self.assertEqual(15, len(catalog["patterns"]))
        self.assertEqual(
            15, len({row["requirement_id"] for row in catalog["patterns"]})
        )
        self.assertTrue(
            all(row["requirement_id"].startswith("LIR-") for row in catalog["patterns"])
        )

    def test_exact_routes_do_not_form_hc_st_cartesian_products(self) -> None:
        catalog = load_learned_catalog()
        chain = coverage_chain()
        semantic = dict(chain.semantic_ir)
        semantic["sink_constraint"] = {
            **semantic["sink_constraint"],
            "capability_class": "process-spawn",
            "controlled_argument": "_popen_cwd;args",
        }
        command_chain = replace(
            chain,
            project="hermes-agent",
            handler_criterion_id="HC-af72e7eeddd90792",
            sink_type_id="ST-e02ed71b8c27e312",
            semantic_ir=semantic,
        )
        self.assertIn(
            "dangerous-command-pattern-completeness",
            {
                row["pattern_key"]
                for row in route_learned_requirements(command_chain, catalog)
            },
        )

        unrelated_semantic = dict(semantic)
        unrelated_semantic["sink_constraint"] = {
            **semantic["sink_constraint"],
            "controlled_argument": "written-file-content",
        }
        unrelated = replace(command_chain, semantic_ir=unrelated_semantic)
        self.assertNotIn(
            "dangerous-command-pattern-completeness",
            {
                row["pattern_key"]
                for row in route_learned_requirements(unrelated, catalog)
            },
        )

    def test_wrong_check_requires_gate_and_sink_origin_witnesses(self) -> None:
        chain = coverage_chain()
        rule = learned_rule()
        rows = validate_learned_response(
            response(chain, rule),
            chain=chain,
            requirements=[rule],
            origin=origin_run(chain),
        )
        self.assertEqual("wrong-check", rows[0]["decision"])
        invalid = response(chain, rule)
        invalid["assessments"][0]["origin_witness_ids"] = [
            "ORIGIN-" + "1" * 16
        ]
        with self.assertRaisesRegex(CoverageComparisonError, "gate coverage"):
            validate_learned_response(
                invalid,
                chain=chain,
                requirements=[rule],
                origin=origin_run(chain),
            )

    def test_missing_check_uses_only_sink_origin(self) -> None:
        chain = coverage_chain()
        rule = learned_rule()
        rows = validate_learned_response(
            response(chain, rule, decision="missing-check"),
            chain=chain,
            requirements=[rule],
            origin=origin_run(chain),
        )
        self.assertEqual([], rows[0]["gate_ids"])

    def test_learned_candidate_identity_and_schema(self) -> None:
        chain = coverage_chain()
        chain = chain.__class__(
            **{
                **chain.__dict__,
                "project": "openclaw",
                "handler_criterion_id": "HC-af72e7eeddd90792",
                "sink_type_id": "ST-e02ed71b8c27e312",
            }
        )
        semantic = dict(chain.semantic_ir)
        semantic["sink_constraint"] = {
            **semantic["sink_constraint"],
            "capability_class": "process-spawn",
        }
        chain = chain.__class__(**{**chain.__dict__, "semantic_ir": semantic})
        origin = origin_run(chain)

        class Runner:
            def __call__(self, system: str, user: str) -> str:
                self.assert_system(system)
                payload = json.loads(user.split("\n", 1)[1])
                result = response(
                    chain,
                    payload["learned_requirements"][0],
                    decision="missing-check",
                )
                result["assessments"] = [
                    response(chain, rule, decision="missing-check")["assessments"][0]
                    for rule in payload["learned_requirements"]
                ]
                return json.dumps(result)

            @staticmethod
            def assert_system(system: str) -> None:
                if system != LEARNED_COMPARE_SYSTEM:
                    raise AssertionError(system)

        result = analyze_learned_invariants(
            chains=[chain], origin=origin, runner=Runner(), jobs=1
        )
        candidate = result.provisional_candidates[0]
        self.assertEqual(
            stable_learned_candidate_id(
                chain=chain,
                requirement_id=candidate["requirement_id"],
                failure_mode="missing-check",
                gate_ids=[],
            ),
            candidate["candidate_id"],
        )
        assessment = next(
            row
            for row in result.assessments
            if row["requirement_id"] == candidate["requirement_id"]
        )
        requirement = result.requirements[
            (chain.project, chain.chain_id, candidate["requirement_id"])
        ]
        source_user = build_source_validation_user(
            chain,
            [candidate],
            {candidate["requirement_id"]: assessment},
            {candidate["requirement_id"]: requirement},
            prompt_version=SourceValidationConfig(
                learned_invariant_policy=True
            ).prompt_version(),
        )
        self.assertNotIn(candidate["training_report_ids"][0], source_user)
        self.assertIn("coverage-source-validation/v7", source_user)


if __name__ == "__main__":
    unittest.main()

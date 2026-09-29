from __future__ import annotations

import unittest

from src.coverage_comparison.applicability_contract import (
    APPLICABILITY_CONTRACT_VERSION,
)
from src.coverage_comparison.contracts import CoverageComparisonError
from src.coverage_comparison.member_applicability import (
    evaluate_member_applicability,
)
from src.coverage_comparison.member_applicability_facts import MEMBER_FACTS_VERSION
from src.coverage_comparison.normative_evidence import resolve_normative_evidence


def contract() -> dict[str, object]:
    return {
        "schema_version": APPLICABILITY_CONTRACT_VERSION,
        "required_sink_roles": ["url"],
        "allowed_value_authorities": ["model-arbitrary", "model-component"],
        "required_capability_facets": ["network-egress"],
        "required_boundary": "private-network",
        "required_effect": "outbound-request",
        "call_shape_predicates": ["remote-url"],
    }


def resolution(
    status: str = "normative", contract_value: dict[str, object] | None = None
) -> dict[str, object]:
    kind = "explicit-source-policy" if status == "normative" else "capability-card"
    return resolve_normative_evidence(
        group_id="HSG-test",
        requirement_id="R-test",
        evidence_ids=["EV-test"],
        evidence_rows=[
            {
                "evidence_id": "EV-test",
                "kind": kind,
                "source_path": "policy.md",
                "sha256": "a" * 64,
                "exact_quote": "The network boundary is mandatory.",
                "supported_claim": "Validate model-selected destinations.",
            }
        ],
        applicability_contract=contract_value or contract(),
    )


def facts(chain_id: str = "C-test", **updates: object) -> dict[str, object]:
    row: dict[str, object] = {
        "schema_version": MEMBER_FACTS_VERSION,
        "group_id": "HSG-test",
        "requirement_id": "R-test",
        "project": "project",
        "revision": "revision",
        "chain_id": chain_id,
        "upstream_status": "complete",
        "field_witnesses": [
            {
                "sink_role": "url",
                "field": "args.url",
                "value_authority": "model-arbitrary",
                "witness_ids": ["ORIGIN-a"],
            }
        ],
        "capability_facets": ["network-egress"],
        "boundaries": ["private-network"],
        "effects": ["outbound-request"],
        "call_shape_predicates": ["remote-url"],
        "completeness": {
            "sink_roles": "complete",
            "value_authorities": "complete",
            "capability_facets": "complete",
            "boundary": "complete",
            "effect": "complete",
            "call_shape_predicates": "complete",
        },
    }
    row.update(updates)
    return row


class MemberApplicabilityTests(unittest.TestCase):
    def test_all_dimensions_and_exact_field_witness_are_required(self) -> None:
        result = evaluate_member_applicability(
            resolution=resolution(), member_facts=facts()
        )
        self.assertEqual("applicable", result["decision"])
        self.assertEqual("args.url", result["field_witnesses"][0]["field"])
        self.assertTrue(
            all(row["status"] == "match" for row in result["checks"].values())
        )

    def test_each_authoritative_negative_is_not_applicable(self) -> None:
        negatives = {
            "sink_role": {"field_witnesses": []},
            "authority": {
                "field_witnesses": [
                    {
                        "sink_role": "url",
                        "field": "config.base_url",
                        "value_authority": "operator-config",
                        "witness_ids": ["ORIGIN-config"],
                    }
                ]
            },
            "facet": {"capability_facets": []},
            "boundary": {"boundaries": []},
            "effect": {"effects": []},
            "call_shape": {"call_shape_predicates": []},
        }
        for label, updates in negatives.items():
            with self.subTest(label=label):
                result = evaluate_member_applicability(
                    resolution=resolution(), member_facts=facts(**updates)
                )
                self.assertEqual("not-applicable", result["decision"])
                self.assertIn(
                    "mismatch", {row["status"] for row in result["checks"].values()}
                )

    def test_incomplete_exact_field_witness_is_unknown(self) -> None:
        completeness = dict(facts()["completeness"])
        completeness["sink_roles"] = "partial"
        completeness["value_authorities"] = "partial"
        result = evaluate_member_applicability(
            resolution=resolution(),
            member_facts=facts(field_witnesses=[], completeness=completeness),
        )
        self.assertEqual("unknown", result["decision"])

    def test_every_required_sink_role_needs_an_allowed_authority_witness(self) -> None:
        resolved_contract = contract()
        resolved_contract["required_sink_roles"] = ["body", "url"]
        resolved = resolution(contract_value=resolved_contract)
        member = facts()
        member["field_witnesses"] = [
            *member["field_witnesses"],
            {
                "sink_role": "body",
                "field": "args.body",
                "value_authority": "model-component",
                "witness_ids": ["ORIGIN-body"],
            },
        ]
        self.assertEqual(
            "applicable",
            evaluate_member_applicability(resolution=resolved, member_facts=member)[
                "decision"
            ],
        )
        member["field_witnesses"] = member["field_witnesses"][:1]
        self.assertEqual(
            "not-applicable",
            evaluate_member_applicability(resolution=resolved, member_facts=member)[
                "decision"
            ],
        )

    def test_upstream_or_normative_incompleteness_fails_closed(self) -> None:
        for resolved, member in (
            (resolution("non-normative"), facts()),
            (resolution(), facts(upstream_status="partial")),
        ):
            with self.subTest(resolution=resolved["status"]):
                result = evaluate_member_applicability(
                    resolution=resolved, member_facts=member
                )
                self.assertEqual("upstream-incomplete", result["decision"])

    def test_invalid_field_witness_and_completeness_are_rejected(self) -> None:
        invalid_witness = facts()
        invalid_witness["field_witnesses"] = [
            {
                "sink_role": "url",
                "field": "args.url",
                "value_authority": "model-arbitrary",
                "witness_ids": [],
            }
        ]
        invalid_completeness = facts()
        invalid_completeness["completeness"] = {"sink_roles": "complete"}
        forbidden_report_binding = {**facts(), "report_id": "GT-forbidden"}
        for row in (invalid_witness, invalid_completeness, forbidden_report_binding):
            with self.subTest(row=row), self.assertRaises(CoverageComparisonError):
                evaluate_member_applicability(resolution=resolution(), member_facts=row)


if __name__ == "__main__":
    unittest.main()

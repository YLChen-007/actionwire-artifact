from __future__ import annotations

import json
import unittest

from src.coverage_comparison.applicability_contract import (
    APPLICABILITY_CONTRACT_VERSION,
)
from src.coverage_comparison.contracts import CoverageComparisonError
from src.coverage_comparison.member_applicability_facts import MEMBER_FACTS_VERSION
from src.coverage_comparison.member_applicability_partition import (
    derive_member_applicability_partition,
    serialize_member_applicability_jsonl,
    validate_member_applicability_partition,
)
from src.coverage_comparison.normative_evidence import resolve_normative_evidence


def resolution() -> dict[str, object]:
    return resolve_normative_evidence(
        group_id="HSG-test",
        requirement_id="R-test",
        evidence_ids=["EV-test"],
        evidence_rows=[
            {
                "evidence_id": "EV-test",
                "kind": "explicit-source-policy",
                "source_path": "policy.md",
                "sha256": "a" * 64,
                "exact_quote": "The network boundary is mandatory.",
                "supported_claim": "Validate model-selected destinations.",
            }
        ],
        applicability_contract={
            "schema_version": APPLICABILITY_CONTRACT_VERSION,
            "required_sink_roles": ["url"],
            "allowed_value_authorities": ["model-arbitrary"],
            "required_capability_facets": ["network-egress"],
            "required_boundary": "private-network",
            "required_effect": "outbound-request",
            "call_shape_predicates": ["remote-url"],
        },
    )


def facts(
    project: str,
    chain_id: str,
    *,
    authority: str = "model-arbitrary",
) -> dict[str, object]:
    return {
        "schema_version": MEMBER_FACTS_VERSION,
        "group_id": "HSG-test",
        "requirement_id": "R-test",
        "project": project,
        "revision": "revision",
        "chain_id": chain_id,
        "upstream_status": "complete",
        "field_witnesses": [
            {
                "sink_role": "url",
                "field": "args.url"
                if authority == "model-arbitrary"
                else "config.base_url",
                "value_authority": authority,
                "witness_ids": ["ORIGIN-" + chain_id],
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


def binding(row: dict[str, object]) -> dict[str, object]:
    return {
        key: row[key]
        for key in ("group_id", "requirement_id", "project", "revision", "chain_id")
    }


class MemberApplicabilityPartitionTests(unittest.TestCase):
    def test_same_hsg_requirement_does_not_propagate_across_members(self) -> None:
        controlled = facts("alpha", "C-alpha")
        configured = facts("beta", "C-beta", authority="operator-config")
        run = derive_member_applicability_partition(
            resolutions=[resolution()],
            member_facts=[configured, controlled],
            expected_bindings=[binding(controlled), binding(configured)],
        )
        decisions = {row["project"]: row["decision"] for row in run.assessments}
        self.assertEqual({"alpha": "applicable", "beta": "not-applicable"}, decisions)

    def test_expected_facts_and_resolutions_are_exhaustive(self) -> None:
        row = facts("alpha", "C-alpha")
        with self.assertRaisesRegex(CoverageComparisonError, "exactly cover"):
            derive_member_applicability_partition(
                resolutions=[resolution()],
                member_facts=[],
                expected_bindings=[binding(row)],
            )
        with self.assertRaisesRegex(CoverageComparisonError, "duplicate expected"):
            derive_member_applicability_partition(
                resolutions=[resolution()],
                member_facts=[row],
                expected_bindings=[binding(row), binding(row)],
            )
        with self.assertRaisesRegex(CoverageComparisonError, "resolutions"):
            derive_member_applicability_partition(
                resolutions=[],
                member_facts=[row],
                expected_bindings=[binding(row)],
            )

    def test_partition_validator_rejects_missing_duplicate_and_tampered_rows(
        self,
    ) -> None:
        row = facts("alpha", "C-alpha")
        run = derive_member_applicability_partition(
            resolutions=[resolution()],
            member_facts=[row],
            expected_bindings=[binding(row)],
        )
        assessment = dict(run.assessments[0])
        with self.assertRaisesRegex(CoverageComparisonError, "partition"):
            validate_member_applicability_partition([], [binding(row)])
        with self.assertRaisesRegex(CoverageComparisonError, "duplicate"):
            validate_member_applicability_partition(
                [assessment, assessment], [binding(row)]
            )
        assessment["decision"] = "unknown"
        with self.assertRaisesRegex(CoverageComparisonError, "hash"):
            validate_member_applicability_partition([assessment], [binding(row)])

    def test_jsonl_serialization_is_deterministic(self) -> None:
        alpha = facts("alpha", "C-alpha")
        beta = facts("beta", "C-beta", authority="operator-config")
        rows = derive_member_applicability_partition(
            resolutions=[resolution()],
            member_facts=[alpha, beta],
            expected_bindings=[binding(alpha), binding(beta)],
        ).assessments
        first = serialize_member_applicability_jsonl(rows)
        second = serialize_member_applicability_jsonl(list(reversed(rows)))
        self.assertEqual(first, second)
        self.assertEqual(2, len([json.loads(line) for line in first.splitlines()]))
        self.assertEqual("", serialize_member_applicability_jsonl([]))


if __name__ == "__main__":
    unittest.main()

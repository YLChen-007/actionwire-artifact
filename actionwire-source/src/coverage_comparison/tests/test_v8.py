from __future__ import annotations

import unittest

from src.coverage_comparison.canonical_requirements import canonicalize_requirement
from src.coverage_comparison.v8 import (
    APPROVAL_GROUP_ID,
    POLICY_DIMENSIONS,
    _canonical_comparison,
    _merge_requirements,
)


def requirement(requirement_id: str, dimension: str, rule: str) -> dict[str, object]:
    return {
        "requirement_id": requirement_id,
        "dimension": dimension,
        "rule": rule,
        "applicability": f"when {dimension} applies",
        "evidence_ids": ["EV-" + "1" * 16],
        "source_proposal_ids": ["RP-" + "2" * 16],
        "origin_chain_refs": [
            {
                "project": "mercury-agent",
                "revision": "revision",
                "chain_id": "C-" + "3" * 12,
            }
        ],
        "origin_gate_ids": ["GU" + "4" * 20],
    }


class CanonicalV8Tests(unittest.TestCase):
    def test_existing_cr_identity_is_stable_and_policy_cr_is_added(self) -> None:
        old = requirement(
            "R-" + "a" * 16,
            "type",
            "Reject non-string commands before approval.",
        )
        prior = canonicalize_requirement(old, group_id=APPROVAL_GROUP_ID)
        prior.pop("legacy_refines_requirement_ids")
        policy = requirement(
            "R-" + "b" * 16,
            "redirection-effect",
            "A read-like command must not bypass approval when redirection writes.",
        )
        rows, by_id, legacy, recomputed_group = _merge_requirements(
            [prior],
            {"requirements": [old, policy]},
        )
        self.assertEqual(prior["requirement_id"], legacy[old["requirement_id"]])
        self.assertEqual(legacy, recomputed_group)
        self.assertEqual(2, len(rows))
        self.assertIn(legacy[policy["requirement_id"]], by_id)

    def test_recomputed_group_rows_preserve_non_group_assessments(self) -> None:
        current = {
            "schema_version": "coverage-comparison/v7",
            "project": "mercury-agent",
            "chain_id": "C-" + "1" * 12,
            "requirements": [
                {"requirement_id": "R-" + "a" * 16, "decision": "wrong-check"}
            ],
        }
        prior = {
            **current,
            "requirements": [
                {"requirement_id": "CR-" + "c" * 16, "decision": "covered"}
            ],
        }
        result = _canonical_comparison(
            current,
            legacy_to_cr={"R-" + "a" * 16: "CR-" + "b" * 16},
            prior=prior,
        )
        self.assertEqual(
            {"CR-" + "b" * 16, "CR-" + "c" * 16},
            {row["requirement_id"] for row in result["requirements"]},
        )

    def test_policy_catalog_has_exactly_four_independent_dimensions(self) -> None:
        self.assertEqual(
            {
                "indirect-file-operands",
                "shell-expansion-semantics",
                "redirection-effect",
                "command-action-semantics",
            },
            POLICY_DIMENSIONS,
        )


if __name__ == "__main__":
    unittest.main()

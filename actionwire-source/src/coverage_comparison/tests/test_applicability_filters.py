from __future__ import annotations

import unittest

from src.coverage_comparison.applicability_filters import apply_applicability_filters


def requirement(
    requirement_id: str, rule: str, facet: str = "model-controlled path"
) -> dict[str, object]:
    return {
        "requirement_id": requirement_id,
        "rule": rule,
        "applicability": "Required when applicable",
        "controlled_facet": facet,
        "policy_basis": "group-oracle",
        "protected_asset": "project asset governed by test",
        "evidence": [],
    }


def candidate(candidate_id: str, requirement_id: str) -> dict[str, object]:
    return {
        "candidate_id": candidate_id,
        "requirement_id": requirement_id,
        "project": "project",
        "chain_id": "C-test",
    }


def disposition(candidate_id: str) -> dict[str, object]:
    return {
        "schema_version": "coverage-precision-filter/v10",
        "candidate_id": candidate_id,
        "disposition": "needs-source-validation",
        "reason": "unvalidated",
        "replacement_candidate_id": None,
    }


class ApplicabilityFilterTests(unittest.TestCase):
    def test_direct_content_role_must_be_controlled(self) -> None:
        result = apply_applicability_filters(
            candidates=[candidate("CAND-content", "CR-content")],
            requirements=[
                requirement(
                    "CR-content",
                    "Validate executable content before writing.",
                    "model-controlled content-validation",
                )
            ],
            comparisons=[
                {
                    "project": "project",
                    "chain_id": "C-test",
                    "controlled_argument": "path",
                    "values": [{"source_parameter": "task_id"}],
                }
            ],
            prior_dispositions=[disposition("CAND-content")],
        )
        self.assertEqual("role-not-controlled", result.dispositions[0]["disposition"])

    def test_generic_hardening_requires_source_boundary(self) -> None:
        result = apply_applicability_filters(
            candidates=[candidate("CAND-error", "CR-error")],
            requirements=[
                requirement(
                    "CR-error",
                    "File-read failures must not reveal distinguishable error messages.",
                )
            ],
            comparisons=[
                {
                    "project": "project",
                    "chain_id": "C-test",
                    "controlled_argument": "path",
                    "values": [{"source_parameter": "path"}],
                }
            ],
            prior_dispositions=[disposition("CAND-error")],
        )
        self.assertEqual(
            "policy-evidence-missing", result.dispositions[0]["disposition"]
        )

    def test_stronger_resolved_path_rule_subsumes_symlink_only_rule(self) -> None:
        candidates = [
            candidate("CAND-strong", "CR-strong"),
            candidate("CAND-weak", "CR-weak"),
        ]
        requirements = [
            requirement(
                "CR-strong",
                "Before writing, validate the resolved absolute path against an allowed "
                "directory and reject traversal or symlink escape.",
            ),
            requirement(
                "CR-weak",
                "Resolve symlinks before writing and reject targets outside the allowed directory.",
            ),
        ]
        result = apply_applicability_filters(
            candidates=candidates,
            requirements=requirements,
            comparisons=[
                {
                    "project": "project",
                    "chain_id": "C-test",
                    "controlled_argument": "path",
                    "values": [{"source_parameter": "path"}],
                }
            ],
            prior_dispositions=[
                disposition("CAND-strong"),
                disposition("CAND-weak"),
            ],
        )
        subsumed = next(
            row for row in result.dispositions if row["disposition"] == "subsumed"
        )
        self.assertEqual("CAND-strong", subsumed["replacement_candidate_id"])

    def test_existing_confirmed_disposition_is_unchanged(self) -> None:
        prior = disposition("CAND-confirmed")
        prior["disposition"] = "confirmed"
        result = apply_applicability_filters(
            candidates=[candidate("CAND-confirmed", "CR-confirmed")],
            requirements=[requirement("CR-confirmed", "A concrete path boundary.")],
            comparisons=[
                {
                    "project": "project",
                    "chain_id": "C-test",
                    "controlled_argument": "path",
                    "values": [{"source_parameter": "path"}],
                }
            ],
            prior_dispositions=[prior],
        )
        self.assertEqual("confirmed", result.dispositions[0]["disposition"])


if __name__ == "__main__":
    unittest.main()

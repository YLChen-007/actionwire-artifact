from __future__ import annotations

import unittest

from src.coverage_comparison.precision_filters import filter_precision_candidates
from src.coverage_comparison.v10 import _filter_ground_truth, _target_validation_ids


def requirement(
    requirement_id: str,
    *,
    applicability: str = "Required when applicable",
    facet: str = "model-controlled path",
    rule: str = "Constrain the controlled path.",
) -> dict[str, object]:
    return {
        "requirement_id": requirement_id,
        "rule": rule,
        "applicability": applicability,
        "controlled_facet": facet,
        "security_effect": rule,
        "enforcement_stage": "pre-effect",
        "state_lifetime": "single-call",
        "evidence": [],
    }


def candidate(candidate_id: str, requirement_id: str) -> dict[str, object]:
    return {
        "candidate_id": candidate_id,
        "requirement_id": requirement_id,
        "group_id": "HSG-test",
        "project": "project",
        "revision": "revision",
        "chain_id": "C-test",
        "failure_mode": "missing-check",
        "gate_ids": [],
        "provenance": {
            "sources": [
                {
                    "kind": "group-oracle",
                    "legacy_requirement_id": "R-test",
                    "payload_sha256": "0" * 64,
                }
            ]
        },
    }


def comparison() -> dict[str, object]:
    return {
        "project": "project",
        "chain_id": "C-test",
        "controlled_argument": "path",
        "values": [{"source_parameter": "args.path"}],
    }


def validation(
    candidate_id: str,
    verdict: str,
    *,
    reason: str = "source confirms a direct effect",
    security_effect: str = "direct effect",
) -> dict[str, object]:
    return {
        "provisional_candidate_id": candidate_id,
        "validation_id": "SVAL-" + candidate_id,
        "verdict": verdict,
        "reason": reason,
        "security_effect": security_effect,
    }


class PrecisionFilterTests(unittest.TestCase):
    def test_only_confirmed_candidate_is_promoted(self) -> None:
        row = candidate("CAND-confirmed", "CR-path")
        run = filter_precision_candidates(
            candidates=[row],
            requirements=[requirement("CR-path")],
            comparisons=[comparison()],
            validations=[validation("CAND-confirmed", "confirmed-uncovered")],
        )
        self.assertEqual((row,), run.canonical_candidates)
        self.assertEqual("confirmed", run.dispositions[0]["disposition"])

    def test_recommendation_and_uncontrolled_encoding_are_excluded(self) -> None:
        rows = [
            candidate("CAND-recommend", "CR-recommend"),
            candidate("CAND-encoding", "CR-encoding"),
        ]
        run = filter_precision_candidates(
            candidates=rows,
            requirements=[
                requirement(
                    "CR-recommend", applicability="Recommended for file writes"
                ),
                requirement(
                    "CR-encoding", facet="model-controlled encoding"
                ),
            ],
            comparisons=[comparison()],
            validations=[],
        )
        self.assertEqual((), run.canonical_candidates)
        self.assertEqual(
            ["facet-not-controlled", "recommendation-only"],
            sorted(row["disposition"] for row in run.dispositions),
        )

    def test_effective_duplicate_keeps_confirmed_identity(self) -> None:
        first = candidate("CAND-a", "CR-a")
        second = candidate("CAND-b", "CR-b")
        run = filter_precision_candidates(
            candidates=[first, second],
            requirements=[requirement("CR-a"), requirement("CR-b")],
            comparisons=[comparison()],
            validations=[validation("CAND-b", "confirmed-uncovered")],
        )
        self.assertEqual((second,), run.canonical_candidates)
        duplicate = next(
            row for row in run.dispositions if row["disposition"] == "duplicate"
        )
        self.assertEqual("CAND-b", duplicate["replacement_candidate_id"])

    def test_indirect_impact_and_unsupported_conjunct_are_rejected(self) -> None:
        rows = [
            candidate("CAND-compromise", "CR-compromise"),
            candidate("CAND-overbroad", "CR-overbroad"),
        ]
        run = filter_precision_candidates(
            candidates=rows,
            requirements=[
                requirement("CR-compromise", rule="Protect browser credentials."),
                requirement("CR-overbroad", rule="Cap size and reject special files."),
            ],
            comparisons=[comparison()],
            validations=[
                validation(
                    "CAND-compromise",
                    "confirmed-uncovered",
                    reason="Actual secret exfiltration additionally requires a browser compromise; page-context JS alone cannot read process.env.",
                    security_effect="Browser environment exposure.",
                ),
                validation(
                    "CAND-overbroad",
                    "confirmed-uncovered",
                    reason="The special-file clause of the requirement is not independently source-supported.",
                ),
            ],
        )
        self.assertEqual((), run.canonical_candidates)
        self.assertEqual(
            ["impact-not-model-reachable", "requirement-overbroad"],
            sorted(row["disposition"] for row in run.dispositions),
        )

    def test_training_targets_and_subset_reuse_preserve_matches(self) -> None:
        dispositions = [
            {"candidate_id": "CAND-a", "disposition": "needs-source-validation"},
            {"candidate_id": "CAND-b", "disposition": "confirmed"},
        ]
        ground_truth = [
            {
                "report_id": "GT-a",
                "evaluation_partition": "training",
                "matched_candidate_ids": ["CAND-a"],
                "candidate_assessments": [
                    {"candidate_id": "CAND-a", "verdict": "match"}
                ],
                "status": "covered",
            },
            {
                "report_id": "GT-b",
                "evaluation_partition": "training",
                "matched_candidate_ids": ["CAND-b"],
                "candidate_assessments": [
                    {"candidate_id": "CAND-b", "verdict": "match"}
                ],
                "status": "covered",
            },
        ]
        self.assertEqual(
            {"CAND-a"},
            _target_validation_ids(
                ground_truth=ground_truth, dispositions=dispositions
            ),
        )
        filtered = _filter_ground_truth(ground_truth, candidate_ids={"CAND-b"})
        self.assertEqual(["missed", "covered"], [row["status"] for row in filtered])


if __name__ == "__main__":
    unittest.main()

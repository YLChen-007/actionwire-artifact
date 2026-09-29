from __future__ import annotations

import unittest

from src.runtime_validation.candidate_l2_projection import (
    CANDIDATE_MISSING,
    LINKED_UNSUPPORTED,
    NON_APPLICABLE,
    identify_ground_truth,
    project_ground_truth,
)


def _report(*, boundary: str = "eligible", candidates: list[str] | None = None) -> dict:
    return {
        "report_id": "GT-test",
        "project": "example",
        "boundary_status": boundary,
        "matched_candidate_ids": candidates or [],
    }


def _result(candidate_id: str, disposition: str) -> dict:
    return {"candidate_id": candidate_id, "disposition": disposition}


class CandidateL2ProjectionTest(unittest.TestCase):
    def test_boundary_and_missing_rows_do_not_become_runtime_negatives(self) -> None:
        boundary = identify_ground_truth(_report(boundary="out-of-model"), set())
        self.assertEqual(NON_APPLICABLE, project_ground_truth(boundary, {})["disposition"])
        missing = identify_ground_truth(_report(candidates=["CAND-missing"]), set())
        self.assertEqual(CANDIDATE_MISSING, project_ground_truth(missing, {})["disposition"])

    def test_confirmed_wins_over_inconclusive_link(self) -> None:
        identification = identify_ground_truth(
            _report(candidates=["CAND-confirmed", "CAND-inconclusive"]),
            {"CAND-confirmed", "CAND-inconclusive"},
        )
        projection = project_ground_truth(
            identification,
            {
                "CAND-confirmed": _result("CAND-confirmed", "runtime-confirmed"),
                "CAND-inconclusive": _result("CAND-inconclusive", "inconclusive"),
            },
        )
        self.assertEqual("runtime-confirmed", projection["disposition"])

    def test_not_reproduced_requires_every_link_to_be_healthy_negative(self) -> None:
        identification = identify_ground_truth(
            _report(candidates=["CAND-negative", "CAND-unsupported"]),
            {"CAND-negative", "CAND-unsupported"},
        )
        projection = project_ground_truth(
            identification,
            {
                "CAND-negative": _result("CAND-negative", "not-reproduced"),
                "CAND-unsupported": _result("CAND-unsupported", "unsupported"),
            },
        )
        self.assertEqual(LINKED_UNSUPPORTED, projection["disposition"])

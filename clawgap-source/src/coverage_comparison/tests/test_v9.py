from __future__ import annotations

import unittest
from types import SimpleNamespace

from src.coverage_comparison.v9 import (
    _gt_pair_partition_complete,
    _gt_reuse_digest,
)


class CanonicalV9Tests(unittest.TestCase):
    def test_gt_reuse_digest_binds_candidate_payload(self) -> None:
        report = SimpleNamespace(
            report_id="GT-" + "1" * 16,
            project="fixture",
            revision="revision",
            boundary_status="eligible",
            chain_ids=("C-" + "2" * 12,),
            source_sha256=("3" * 64,),
        )
        key = (report.project, report.chain_ids[0])
        comparison = {"project": report.project, "chain_id": report.chain_ids[0]}
        candidate = {
            "candidate_id": "CAND-" + "4" * 16,
            "reason": "first payload",
        }
        config = {
            "transport": "openai-compatible/v1",
            "model": "fixture-model",
            "available_tools": [],
        }
        first = _gt_reuse_digest(
            report=report,
            comparisons={key: comparison},
            candidates={key: [candidate]},
            model_tool_config=config,
        )
        second = _gt_reuse_digest(
            report=report,
            comparisons={key: comparison},
            candidates={key: [{**candidate, "reason": "changed payload"}]},
            model_tool_config=config,
        )
        self.assertNotEqual(first, second)

    def test_gt_pair_partition_rejects_missing_extra_and_duplicate_pairs(self) -> None:
        chain_id = "C-" + "2" * 12
        candidate_id = "CAND-" + "4" * 16
        candidates = {
            ("fixture", chain_id): [{"candidate_id": candidate_id}]
        }
        base = {
            "project": "fixture",
            "chain_ids": [chain_id],
            "candidate_assessments": [{"candidate_id": candidate_id}],
        }
        self.assertTrue(
            _gt_pair_partition_complete(row=base, candidates=candidates)
        )
        for assessments in (
            [],
            [{"candidate_id": candidate_id}, {"candidate_id": candidate_id}],
            [{"candidate_id": "CAND-" + "5" * 16}],
        ):
            with self.subTest(assessments=assessments):
                self.assertFalse(
                    _gt_pair_partition_complete(
                        row={**base, "candidate_assessments": assessments},
                        candidates=candidates,
                    )
                )


if __name__ == "__main__":
    unittest.main()

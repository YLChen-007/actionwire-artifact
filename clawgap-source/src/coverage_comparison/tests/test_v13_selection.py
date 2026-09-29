from __future__ import annotations

import unittest

from src.coverage_comparison.v13_selection import (
    partition_upstream_incomplete,
    select_dense_chain_batches,
)


class V13SelectionTests(unittest.TestCase):
    def test_partial_group_is_fail_closed_before_source_validation(self) -> None:
        rows = partition_upstream_incomplete(
            candidates=[
                {
                    "candidate_id": "CAND-a",
                    "group_oracle_status": "partial",
                }
            ],
            dispositions=[
                {
                    "candidate_id": "CAND-a",
                    "disposition": "needs-source-validation",
                }
            ],
        )
        self.assertEqual("upstream-incomplete", rows[0]["disposition"])

    def test_dense_chains_are_selected_until_target_is_met(self) -> None:
        candidates = [
            {
                "candidate_id": f"CAND-{chain}-{index}",
                "project": "project",
                "chain_id": chain,
            }
            for chain, size in (("C-large", 5), ("C-medium", 3), ("C-small", 1))
            for index in range(size)
        ]
        dispositions = [
            {
                "candidate_id": row["candidate_id"],
                "disposition": "needs-source-validation",
            }
            for row in candidates
        ]
        batches = select_dense_chain_batches(
            candidates=candidates,
            dispositions=dispositions,
            target_remaining=3,
            max_batch_size=4,
        )
        selected = [row for batch in batches for row in batch.candidates]
        self.assertEqual(8, len(selected))
        self.assertEqual({"C-large", "C-medium"}, {row["chain_id"] for row in selected})
        self.assertEqual(3, len(batches))

    def test_no_batch_when_target_already_satisfied(self) -> None:
        self.assertEqual(
            (),
            select_dense_chain_batches(
                candidates=[], dispositions=[], target_remaining=149
            ),
        )


if __name__ == "__main__":
    unittest.main()

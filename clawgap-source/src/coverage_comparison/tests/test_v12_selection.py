from __future__ import annotations

import unittest

from src.coverage_comparison.v12_selection import select_wrong_check_batches


class V12SelectionTests(unittest.TestCase):
    def test_batches_only_deferred_wrong_checks_by_chain(self) -> None:
        candidates = [
            {
                "candidate_id": f"CAND-{index}",
                "project": "project",
                "chain_id": "C-chain",
                "failure_mode": "wrong-check" if index < 5 else "missing-check",
            }
            for index in range(6)
        ]
        dispositions = [
            {
                "candidate_id": row["candidate_id"],
                "disposition": (
                    "confirmed" if row["candidate_id"] == "CAND-0" else "needs-source-validation"
                ),
            }
            for row in candidates
        ]
        batches = select_wrong_check_batches(
            candidates=candidates,
            dispositions=dispositions,
            max_batch_size=2,
        )
        self.assertEqual(2, len(batches))
        self.assertEqual(
            ["CAND-1", "CAND-2", "CAND-3", "CAND-4"],
            [row["candidate_id"] for batch in batches for row in batch.candidates],
        )
        self.assertTrue(all(batch.chain_id == "C-chain" for batch in batches))

    def test_rejects_nonpositive_batch_size(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive"):
            select_wrong_check_batches(
                candidates=[], dispositions=[], max_batch_size=0
            )


if __name__ == "__main__":
    unittest.main()

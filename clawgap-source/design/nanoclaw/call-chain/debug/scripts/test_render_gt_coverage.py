from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("render_gt_coverage.py")
SPEC = importlib.util.spec_from_file_location("nanoclaw_coverage", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NanoClawCoverageTest(unittest.TestCase):
    def test_gate_identity_is_exact_chain_anchor(self) -> None:
        row = {
            "gate_name": "isPathInside",
            "gate_file": "src/route.ts",
            "gate_line": "130",
        }
        self.assertEqual(
            ("isPathInside", "src/route.ts", 130), MODULE._gate_identity(row)
        )

    def test_lock_snapshot_preserves_all_item_counts(self) -> None:
        reports = MODULE._lock_snapshot(MODULE.DEFAULT_GT)
        self.assertEqual(4, len(reports))
        self.assertEqual(6, sum(row["sinks"] for row in reports))
        self.assertEqual(22, sum(row["gates"] for row in reports))
        self.assertEqual(9, sum(row["cross_component_edges"] for row in reports))
        self.assertEqual(11, sum(row["extraction_records"] for row in reports))


if __name__ == "__main__":
    unittest.main()

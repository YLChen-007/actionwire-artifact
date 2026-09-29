from __future__ import annotations

import csv
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("render_gt_coverage.py")
SPEC = importlib.util.spec_from_file_location("droidclaw_coverage", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


class DroidClawCoverageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.output = root / "output"
        self.out = root / "coverage"
        write_csv(
            self.output / "static/call-chains/handler-sink-chains.csv",
            [
                {
                    "chain_id": "C-shell",
                    "sink_id": "S-shell",
                    "project_id": "droidclaw",
                    "tool_name": "shell",
                    "handler_file": "src/actions.ts",
                    "handler_line": 699,
                    "sink_file": "src/actions.ts",
                    "sink_line": 703,
                    "sink_argument": "action.action;command",
                    "call_chain": "1#executeShell@actions.ts->executeShell@actions.ts",
                }
            ],
        )
        write_csv(
            self.output / "static/call-chains/sink-constraints.csv",
            [
                {
                    "constraint_id": "SC-shell",
                    "sink_id": "S-shell",
                    "capability_class": "adb-shell-execution",
                    "controlled_argument": "action.action;command",
                }
            ],
        )
        write_csv(
            self.output / "static/call-chains/chain-gates.csv",
            [
                {
                    "chain_id": "C-shell",
                    "gate_uid": "GU-existing",
                    "gate_name": "inlineCondition",
                    "gate_file": "src/actions.ts",
                    "gate_line": 701,
                }
            ],
        )
        write_csv(
            self.output / "gate-semantics/gate-index.csv",
            [{"gate_uid": "GU-existing"}],
        )
        manifest = self.output / "static/gates/manifest.json"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(
            json.dumps({"counts": MODULE.EXPECTED_GATE_COUNTS}), encoding="utf-8"
        )
        chain_manifest = self.output / "static/call-chains/manifest.json"
        chain_manifest.write_text(
            json.dumps({"counts": MODULE.EXPECTED_CHAIN_COUNTS}), encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def render(self) -> dict[str, object]:
        return MODULE.render(
            oracle_path=MODULE.DEFAULT_ORACLE,
            lock_path=MODULE.DEFAULT_LOCK,
            inventory_path=MODULE.DEFAULT_INVENTORY,
            gt_root=MODULE.DEFAULT_GT,
            pipeline_output=self.output,
            out_dir=self.out,
            command="python renderer",
        )

    def test_exact_chain_existing_gate_and_expected_missing_pass(self) -> None:
        summary = self.render()
        self.assertEqual(1, summary["covered_sink_references"])
        self.assertEqual(1, summary["covered_existing_gates"])
        self.assertEqual(1, summary["correctly_missing_controls"])
        self.assertEqual([], summary["global_failures"])

    def test_fake_approval_gate_cannot_cover_expected_missing(self) -> None:
        path = self.output / "static/call-chains/chain-gates.csv"
        rows = MODULE._csv(path)
        rows.append(
            {
                "chain_id": "C-shell",
                "gate_uid": "GU-fake",
                "gate_name": "shellActionApproval",
                "gate_file": "src/actions.ts",
                "gate_line": "703",
            }
        )
        write_csv(path, rows)
        summary = self.render()
        self.assertEqual(0, summary["correctly_missing_controls"])
        self.assertTrue(summary["global_failures"])

    def test_detector_count_drift_fails(self) -> None:
        manifest = self.output / "static/gates/manifest.json"
        manifest.write_text(
            json.dumps({"counts": {**MODULE.EXPECTED_GATE_COUNTS, "filter_rows": 2}}),
            encoding="utf-8",
        )
        summary = self.render()
        self.assertIn(
            "gate count filter_rows expected 3, got 2", summary["global_failures"]
        )


if __name__ == "__main__":
    unittest.main()

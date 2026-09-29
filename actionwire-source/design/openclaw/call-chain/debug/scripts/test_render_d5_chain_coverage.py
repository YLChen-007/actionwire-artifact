#!/usr/bin/env python3
"""Tests for the OpenClaw new-vuls D5 coverage renderer."""

from __future__ import annotations

import csv
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from render_d5_chain_coverage import (
    DEFAULT_GT,
    DEFAULT_HANDLERS,
    DEFAULT_INVENTORY,
    DEFAULT_PIPELINE,
    DEFAULT_SOURCE,
    locate_gate_anchor,
    render,
)


class RenderOpenClawD5CoverageTests(unittest.TestCase):
    def render_to(self, out_dir: Path, *, inventory: Path = DEFAULT_INVENTORY):
        return render(
            ground_truth_dir=DEFAULT_GT,
            inventory_path=inventory,
            pipeline_output=DEFAULT_PIPELINE,
            source_root=DEFAULT_SOURCE,
            handler_inventory_path=DEFAULT_HANDLERS,
            out_dir=out_dir,
            command=(
                "python design/openclaw/call-chain/debug/scripts/"
                "render_d5_chain_coverage.py"
            ),
        )

    def test_all_new_vuls_items_are_accounted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out_dir = Path(directory)
            stats = self.render_to(out_dir)
            self.assertEqual(stats["reports"], 6)
            self.assertEqual(stats["total_items"], 72)
            self.assertEqual(stats["items"], {"gate": 59, "handler": 6, "sink": 7})
            with (out_dir / "d5-chain-coverage-items.csv").open(
                newline="", encoding="utf-8"
            ) as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 72)
            self.assertEqual(
                Counter(row["item_kind"] for row in rows),
                {"gate": 59, "handler": 6, "sink": 7},
            )

    def test_revision_eligible_items_are_covered(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out_dir = Path(directory)
            stats = self.render_to(out_dir)
            self.assertEqual(stats["eligible_sink_items"], 5)
            self.assertEqual(stats["covered_eligible_sink_items"], 5)
            self.assertEqual(stats["eligible_existing_gate_items"], 7)
            self.assertEqual(stats["covered_eligible_existing_gate_items"], 7)
            self.assertEqual(stats["eligible_gap_count"], 0)
            self.assertEqual(stats["chain_rows"], 5)
            self.assertEqual(
                stats["sink_status"],
                {"covered": 5, "out-of-model": 2},
            )
            self.assertEqual(
                stats["scope_status"],
                {"eligible": 4, "out-of-model": 2},
            )

    def test_current_gate_anchor_uses_exact_source_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory)
            target = source_root / "src/example.ts"
            target.parent.mkdir(parents=True)
            target.write_text(
                "const allowed = false;\nif (!allowed) throw new Error('blocked');\n",
                encoding="utf-8",
            )
            item = {
                "name": "example gate",
                "kind": "statement",
                "location": "src/example.ts:2",
                "evidence": "if (!allowed) throw new Error('blocked');",
            }
            anchor = locate_gate_anchor(source_root, item)
            self.assertEqual(anchor.status, "current")
            self.assertEqual(anchor.rendered, "src/example.ts:2")
            self.assertEqual(anchor.reason, "evidence matched fixed source")

    def test_report_has_root_command_and_inventory_hash_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out_dir = Path(directory) / "coverage"
            self.render_to(out_dir)
            lines = (out_dir / "d5-chain-coverage.md").read_text(
                encoding="utf-8"
            ).splitlines()
            self.assertEqual(lines[0], "# OpenClaw new-vuls D5 coverage")
            self.assertTrue(lines[2].startswith("生成命令（仓库根目录）：`python "))

            inventory = json.loads(DEFAULT_INVENTORY.read_text(encoding="utf-8"))
            target = next(
                row
                for row in inventory["records"]
                if row["report_path"].startswith("new-vuls/")
            )
            target["report_sha256"] = "0" * 64
            drifted = Path(directory) / "inventory.json"
            drifted.write_text(json.dumps(inventory), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "ground-truth hash drift"):
                self.render_to(Path(directory) / "drift", inventory=drifted)


if __name__ == "__main__":
    unittest.main()

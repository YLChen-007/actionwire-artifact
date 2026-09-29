#!/usr/bin/env python3
"""Unit tests for the locked OpenClaw-CN source/GT inventory."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
MODULE_PATH = Path(__file__).with_name("generate_inventory.py")
SPEC = importlib.util.spec_from_file_location("openclaw_cn_inventory", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class OpenClawCNInventoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.gt = ROOT / "design/openclaw-cn/groundtruth/new-vuls"
        self.source = ROOT / "benchmark/typescript/openclaw-cn"
        self.lock_path = (
            ROOT / "design/openclaw-cn/inventory/openclaw-cn-source-gt-lock.json"
        )
        self.lock = json.loads(self.lock_path.read_text(encoding="utf-8"))

    def test_lock_has_exact_hashes_scope_and_raw_counts(self) -> None:
        current = MODULE.build_lock(self.gt, self.source)
        self.assertEqual(self.lock, current)
        self.assertEqual(MODULE.EXPECTED, current["counts"])
        self.assertEqual(8, len(current["reports"]))
        self.assertRegex(current["analysis_scope"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertGreater(current["analysis_scope"]["file_count"], 1000)
        self.assertTrue(
            all(len(report["sha256"]) == 64 for report in current["reports"])
        )

    def test_inventory_accounts_for_all_records_and_15_to_13_sinks(self) -> None:
        inventory = MODULE.build_inventory(self.gt, self.lock)
        self.assertEqual(MODULE.EXPECTED, inventory["counts"])
        self.assertEqual(156, len(inventory["records"]))
        self.assertEqual(13, inventory["derived_counts"]["concrete_sinks"])
        sinks = [row for row in inventory["records"] if row["kind"] == "sink"]
        self.assertEqual(15, len(sinks))
        self.assertEqual(
            13, len({(row["current_file"], row["current_line"]) for row in sinks})
        )
        self.assertEqual(2, sum(row["mapping_status"] == "duplicate" for row in sinks))

    def test_gate_classification_and_oracle_are_exact(self) -> None:
        inventory = MODULE.build_inventory(self.gt, self.lock)
        gates = [row for row in inventory["records"] if row["kind"] == "gate"]
        self.assertEqual(69, len(gates))
        self.assertEqual(
            5, sum(row["anchor_status"] == "expected-missing" for row in gates)
        )
        self.assertEqual(
            13, sum(row["mapping_status"] == "protected-sibling" for row in gates)
        )
        oracle = MODULE.build_oracle(inventory)
        self.assertEqual(13, len(oracle["eligible_sink_records"]))
        self.assertEqual(13, len(oracle["protected_sibling_evidence"]))
        self.assertEqual(28, oracle["expected"]["handler_rows"])
        self.assertEqual(25, oracle["expected"]["unique_tool_names"])

    def test_every_function_gate_keeps_definition_anchor_and_call_witness(self) -> None:
        inventory = MODULE.build_inventory(self.gt, self.lock)
        function_gates = [
            row
            for row in inventory["records"]
            if row["kind"] == "gate"
            and isinstance(row["original"], dict)
            and row["original"].get("kind") == "function"
            and row["anchor_status"] != "expected-missing"
        ]
        self.assertTrue(function_gates)
        for gate in function_gates:
            with self.subTest(gate=gate["name"]):
                self.assertRegex(gate["original_location"], r":\d+")
                self.assertTrue(gate["current_file"])
                self.assertGreater(gate["current_line"], 0)
                self.assertTrue(gate["gate_name"])


if __name__ == "__main__":
    unittest.main()

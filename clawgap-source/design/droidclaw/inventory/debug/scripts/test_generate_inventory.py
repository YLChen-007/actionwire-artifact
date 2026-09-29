from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("generate_inventory.py")
SPEC = importlib.util.spec_from_file_location("droidclaw_inventory", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DroidClawInventoryTest(unittest.TestCase):
    def test_lock_and_all_seven_records_are_accounted(self) -> None:
        lock = MODULE.build_lock(MODULE.DEFAULT_GT)
        self.assertEqual(MODULE.EXPECTED, lock["counts"])
        self.assertEqual(
            "46e9e36ebd010fb181ed61ef53b805a5ba42d4d4aa146c6d56e1ccce0366b60b",
            lock["reports"][0]["sha256"],
        )
        inventory = MODULE.build_inventory(
            MODULE.DEFAULT_GT, MODULE.DEFAULT_SOURCE, lock
        )
        self.assertEqual(7, len(inventory["records"]))
        sink = next(row for row in inventory["records"] if row["kind"] == "sink")
        self.assertEqual("DC-ACTION-SHELL", sink["canonical_sink_id"])
        self.assertEqual("src/actions.ts", sink["current_file"])
        self.assertEqual(703, sink["current_line"])

    def test_existing_and_missing_gates_remain_distinct(self) -> None:
        lock = MODULE.build_lock(MODULE.DEFAULT_GT)
        inventory = MODULE.build_inventory(
            MODULE.DEFAULT_GT, MODULE.DEFAULT_SOURCE, lock
        )
        oracle = MODULE.build_oracle(inventory)
        self.assertEqual("inlineCondition", oracle["existing_gate_records"][0]["gate_name"])
        self.assertEqual(701, oracle["existing_gate_records"][0]["gate_line"])
        self.assertEqual(
            "shellActionApproval", oracle["expected_missing_records"][0]["gate_name"]
        )
        self.assertEqual(703, oracle["expected_missing_records"][0]["gate_line"])
        self.assertEqual(
            ["executeShell@actions.ts"],
            oracle["eligible_sink_records"][0]["required_chain_markers"],
        )

    def test_hash_drift_changes_lock(self) -> None:
        original = MODULE.build_lock(MODULE.DEFAULT_GT)
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            source = next(MODULE.DEFAULT_GT.glob("*.json"))
            changed = target / source.name
            payload = json.loads(source.read_text(encoding="utf-8"))
            payload["verdict_reason"] += " drift"
            changed.write_text(json.dumps(payload), encoding="utf-8")
            self.assertNotEqual(
                original["corpus_sha256"], MODULE.build_lock(target)["corpus_sha256"]
            )


if __name__ == "__main__":
    unittest.main()

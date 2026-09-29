from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("generate_inventory.py")
SPEC = importlib.util.spec_from_file_location("mercury_agent_inventory", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class MercuryAgentInventoryTest(unittest.TestCase):
    def test_lock_and_every_raw_record_are_accounted(self) -> None:
        lock = MODULE.build_lock(MODULE.DEFAULT_GT)
        self.assertEqual(MODULE.EXPECTED, lock["counts"])
        self.assertEqual(
            "419b83f2c5c9ea03ee3b6867c8f9328691079878a40476f685962b11fde59411",
            lock["corpus_sha256"],
        )
        inventory = MODULE.build_inventory(
            MODULE.DEFAULT_GT, MODULE.DEFAULT_SOURCE, lock
        )
        self.assertEqual(52, len(inventory["records"]))

    def test_sink_deduplication_and_cross_tool_state_are_explicit(self) -> None:
        lock = MODULE.build_lock(MODULE.DEFAULT_GT)
        inventory = MODULE.build_inventory(
            MODULE.DEFAULT_GT, MODULE.DEFAULT_SOURCE, lock
        )
        sinks = [row for row in inventory["records"] if row["kind"] == "sink"]
        self.assertEqual(5, len(sinks))
        self.assertEqual(
            {
                "MA-PROCESS-SPAWN",
                "MA-COMMAND-APPROVAL",
            },
            {row["canonical_sink_id"] for row in sinks},
        )
        self.assertEqual(
            0,
            sum(
                row["canonical_sink_id"] == "MA-PROCESS-SPAWN"
                and row["mapping_status"] == "duplicate"
                for row in sinks
            ),
        )
        self.assertEqual(
            3,
            sum(
                row["canonical_sink_id"] == "MA-COMMAND-APPROVAL"
                and row["mapping_status"] == "duplicate"
                for row in sinks
            ),
        )
        oracle = MODULE.build_oracle(inventory)
        self.assertEqual(5, len(oracle["eligible_sink_records"]))
        self.assertEqual(27, len(oracle["eligible_gate_records"]))
        self.assertEqual(0, len(oracle["cross_tool_state_record_ids"]))

    def test_hash_drift_changes_the_locked_corpus(self) -> None:
        original = MODULE.build_lock(MODULE.DEFAULT_GT)
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "groundtruth"
            shutil.copytree(MODULE.DEFAULT_GT, target)
            changed = next(target.rglob("*.json"))
            payload = json.loads(changed.read_text(encoding="utf-8"))
            payload["verdict_reason"] = str(payload.get("verdict_reason", "")) + " drift"
            changed.write_text(json.dumps(payload), encoding="utf-8")
            self.assertNotEqual(
                original["corpus_sha256"], MODULE.build_lock(target)["corpus_sha256"]
            )


if __name__ == "__main__":
    unittest.main()

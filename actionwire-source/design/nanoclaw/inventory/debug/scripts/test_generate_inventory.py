from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("generate_inventory.py")
SPEC = importlib.util.spec_from_file_location("nanoclaw_inventory", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NanoClawInventoryTest(unittest.TestCase):
    def test_locked_corpus_and_all_raw_records_are_accounted(self) -> None:
        lock = MODULE.build_lock(MODULE.DEFAULT_GT)
        self.assertEqual(MODULE.EXPECTED, lock["counts"])
        self.assertEqual(
            {
                "Advisory-GHSA-6rcp-vxwf-3mfp-add-mcp-server-approval-smuggling.json": "fe66ff804c9b6818360c71ca268db7b2ef7e5a24a987797c7f90e46385baa86b",
                "Advisory-GHSA-qcc4-p59m-p54m-a2a-inbox-symlink.json": "fe2cf72a51a0addec7ddf29bf261b7426dcc86247dae37abe5a82de0f19c5b10",
                "CVE-2026-29611-nanoclaw-send-file.json": "ca9b1dc3d6b9c7a564302060464897ab00c2d4c28d4cb94e9172e7d9b5b89873",
                "CVE-2026-31993-add-mcp-server-approval-smuggling.json": "c90f4802424eeb44350069f37ee7cc1c7c8fe3ce7fe4e9c0beca70352c4d02b8",
            },
            {row["path"]: row["sha256"] for row in lock["reports"]},
        )
        inventory = MODULE.build_inventory(
            MODULE.DEFAULT_GT, MODULE.DEFAULT_SOURCE, lock
        )
        self.assertEqual(MODULE.EXPECTED, inventory["counts"])
        self.assertEqual(52, len(inventory["records"]))

    def test_rebases_later_only_missing_and_duplicate_sink(self) -> None:
        lock = MODULE.build_lock(MODULE.DEFAULT_GT)
        inventory = MODULE.build_inventory(
            MODULE.DEFAULT_GT, MODULE.DEFAULT_SOURCE, lock
        )
        by_name = {}
        for row in inventory["records"]:
            by_name.setdefault(row["name"], []).append(row)
        copy = by_name["fs.copyFileSync(realSrc, dst)"][0]
        self.assertEqual(
            ("rebased", 138), (copy["anchor_status"], copy["current_line"])
        )
        self.assertEqual(
            "not-present",
            by_name["optional A2A message approval hold"][0]["anchor_status"],
        )
        self.assertEqual(
            "expected-missing",
            by_name["workspace/root containment gate"][0]["anchor_status"],
        )
        pending = by_name["better-sqlite3 Statement.run pending_approvals insert"]
        self.assertEqual(2, len(pending))
        self.assertEqual(
            {"canonical", "duplicate"}, {row["mapping_status"] for row in pending}
        )

    def test_hash_drift_changes_corpus_lock(self) -> None:
        original = MODULE.build_lock(MODULE.DEFAULT_GT)
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            for source in MODULE.DEFAULT_GT.glob("*.json"):
                (target / source.name).write_bytes(source.read_bytes())
            changed = target / "CVE-2026-29611-nanoclaw-send-file.json"
            payload = json.loads(changed.read_text(encoding="utf-8"))
            payload["verdict_reason"] += " drift"
            changed.write_text(json.dumps(payload), encoding="utf-8")
            self.assertNotEqual(
                original["corpus_sha256"], MODULE.build_lock(target)["corpus_sha256"]
            )


if __name__ == "__main__":
    unittest.main()

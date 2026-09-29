from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("generate_inventory.py")
SPEC = importlib.util.spec_from_file_location("openclaw_inventory", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class InventoryTest(unittest.TestCase):
    def test_real_corpus_is_fully_accounted(self) -> None:
        root = Path(__file__).resolve().parents[5]
        inventory = MODULE.build_inventory(
            root / "design/openclaw/groundtruth",
            root / "benchmark/typescript/openclaw",
            MODULE.DEFAULT_REVISION,
        )
        self.assertEqual(86, inventory["counts"]["reports"])
        self.assertEqual(159, inventory["counts"]["sink_references"])
        self.assertEqual(159, len({row["record_id"] for row in inventory["records"]}))
        for row in inventory["records"]:
            self.assertIn(row["anchor_status"], {"current", "rebased", "not-present", "out-of-model"})
            self.assertIn(row["mapping_status"], {"canonical", "duplicate", "core-boundary", "excluded-boundary"})
            self.assertRegex(row["report_sha256"], r"^[0-9a-f]{64}$")

    def test_annotated_and_multi_anchor_locations(self) -> None:
        self.assertEqual(
            [("src/a.ts", 10), ("src/b.ts", 20)],
            MODULE.parse_locations("src/a.ts:10 (old) / src/b.ts:20 (current)"),
        )

    def test_rebased_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "src/tool.ts"
            target.parent.mkdir()
            target.write_text("// moved\n// moved\nspawn(argv[0])\n", encoding="utf-8")
            status, path, line, witness, _ = MODULE.anchor_result(
                root, "src/tool.ts:30", "spawn(argv[0])"
            )
            self.assertEqual("rebased", status)
            self.assertEqual(("src/tool.ts", 3, "spawn(argv[0])"), (path, line, witness))

    def test_multi_anchor_uses_current_core_witness(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "src/current.ts"
            target.parent.mkdir()
            target.write_text("spawn(argv[0])\n", encoding="utf-8")
            status, path, line, witness, _ = MODULE.anchor_result(
                root,
                "extensions/old.ts:40 (excluded) / src/current.ts:1 (current)",
                "spawn(argv[0])",
            )
            self.assertEqual(("current", "src/current.ts", 1, "spawn(argv[0])"), (status, path, line, witness))

    def test_capability_rebase_crosses_known_implementation_move(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "src/node-host/runner.ts"
            target.parent.mkdir(parents=True)
            target.write_text(
                "const child = spawn(argv[0], argv.slice(1), {\n  cwd,\n});\n",
                encoding="utf-8",
            )
            result = MODULE.sink_anchor_result(
                root,
                "child_process.spawn",
                "src/node-host/invoke.ts:278",
                "const child = spawn(argv[0], argv.slice(1), options);",
                "process-spawn",
            )
            self.assertEqual(
                ("rebased", "src/node-host/runner.ts", 1), result[:3]
            )

    def test_new_vuls_rebased_capabilities_and_moved_policy_helpers(self) -> None:
        root = Path(__file__).resolve().parents[5]
        inventory = MODULE.build_inventory(
            root / "design/openclaw/groundtruth",
            root / "benchmark/typescript/openclaw",
            MODULE.DEFAULT_REVISION,
        )
        records = {
            (row["report_path"], row["report_sink_index"]): row
            for row in inventory["records"]
        }
        node_spawn = records[("new-vuls/Advirsory-GHSA-3h2q-j2v4-6w5r.json", 0)]
        self.assertEqual("rebased", node_spawn["anchor_status"])
        self.assertEqual("src/node-host/runner.ts", node_spawn["current_witness"]["file"])
        self.assertEqual("node:child_process.spawn", node_spawn["canonical_api"])

        jq = records[("new-vuls/jq-env-safebins-bypass.json", 0)]
        self.assertEqual("src/process/spawn-utils.ts", jq["current_witness"]["file"])
        self.assertIn("evaluateExecAllowlist", jq["existing_gate_names"])
        self.assertIn("isSafeBinUsage", jq["existing_gate_names"])


if __name__ == "__main__":
    unittest.main()

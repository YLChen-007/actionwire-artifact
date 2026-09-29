#!/usr/bin/env python3
"""Fixture tests for OpenClaw-CN's exact-chain coverage renderer."""

from __future__ import annotations

import csv
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
MODULE_PATH = Path(__file__).with_name("render_gt_coverage.py")
SPEC = importlib.util.spec_from_file_location("openclaw_cn_coverage", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else ["empty"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


class OpenClawCNCoverageRendererTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.pipeline = self.root / "output"
        self.out = self.root / "coverage"
        self.oracle_path = (
            ROOT / "design/openclaw-cn/inventory/openclaw-cn-static-oracle.json"
        )
        self.inventory_path = (
            ROOT / "design/openclaw-cn/inventory/debug/groundtruth-inventory.json"
        )
        self.lock_path = (
            ROOT / "design/openclaw-cn/inventory/openclaw-cn-source-gt-lock.json"
        )
        self.oracle = json.loads(self.oracle_path.read_text(encoding="utf-8"))
        self._write_fixture()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_fixture(self) -> None:
        chains = []
        constraints = []
        chain_gates = []
        chain_by_sink: dict[tuple[str, int], str] = {}
        for index, expected in enumerate(self.oracle["eligible_sink_records"], 1):
            chain_id = f"C-{index:012d}"
            sink_id = f"S-{index:016d}"
            chain_by_sink[(expected["sink_file"], expected["sink_line"])] = chain_id
            chains.append(
                {
                    "chain_id": chain_id,
                    "sink_id": sink_id,
                    "project_id": "openclaw-cn",
                    "tool_name": expected["tool_names"][0],
                    "handler_func": "execute",
                    "handler_qualified_name": "execute",
                    "handler_file": "fixture.ts",
                    "handler_line": 1,
                    "source_parameter": "args",
                    "depth": 1,
                    "sink_label": expected["sink_label"],
                    "sink_file": expected["sink_file"],
                    "sink_line": expected["sink_line"],
                    "sink_column": 1,
                    "sink_argument": expected["controlled_facet"],
                    "call_chain": "1#execute@fixture.ts->sink@sink.ts",
                }
            )
            constraints.append(
                {
                    "constraint_id": f"SC-{index:016d}",
                    "sink_id": sink_id,
                    "sink_api": expected["sink_label"],
                    "sink_label": expected["sink_label"],
                    "sink_file": expected["sink_file"],
                    "sink_line": expected["sink_line"],
                    "sink_column": 1,
                    "controlled_argument": expected["controlled_facet"],
                    "capability_class": expected["capability_class"],
                    "call_shape": "sink(value)",
                    "capability_card": "card.md",
                    "capability_card_sha256": "0" * 64,
                }
            )
            for seq, gate in enumerate(expected["existing_gates"], 1):
                chain_gates.append(
                    {
                        "chain_id": chain_id,
                        "call_chain": "1#execute@fixture.ts->sink@sink.ts",
                        "sink_id": sink_id,
                        "gate_seq": seq,
                        "detector": "dominance",
                        "gate_uid": f"GU-{gate['inventory_record_id']}",
                        "gate_id": f"G-{gate['inventory_record_id']}",
                        "gate_name": gate["gate_name"],
                        "gate_file": gate["gate_file"],
                        "gate_line": gate["gate_line"],
                        "enclosing_function": "helper",
                        "static_verdict": "confirmed",
                    }
                )

        # The real DB has a second agent-specific chain to the shared node-host sink.
        node_expected = next(
            row
            for row in self.oracle["eligible_sink_records"]
            if row["sink_file"] == "src/node-host/runner.ts"
        )
        node_chain = next(
            row
            for row in chains
            if row["sink_file"] == node_expected["sink_file"]
            and row["sink_line"] == node_expected["sink_line"]
        )
        chains.append({**node_chain, "chain_id": "C-nodes-extra", "tool_name": "nodes"})

        # A project-neutral sink catalog may discover additional handler-reachable
        # production sinks. They stay visible in the audit but are not GT denominator rows.
        chains.append(
            {
                **node_chain,
                "chain_id": "C-shared-audit-extra",
                "sink_id": "S-shared-audit-extra",
                "tool_name": "exec",
                "sink_label": "fetch",
                "sink_file": "src/unrelated-network.ts",
                "sink_line": 20,
                "sink_argument": "url",
            }
        )
        constraints.append(
            {
                **constraints[0],
                "constraint_id": "SC-shared-audit-extra",
                "sink_id": "S-shared-audit-extra",
                "sink_api": "fetch",
                "sink_label": "fetch",
                "sink_file": "src/unrelated-network.ts",
                "sink_line": 20,
                "controlled_argument": "url",
                "capability_class": "network-egress",
            }
        )

        sibling_chain = chain_by_sink[("src/browser/pw-tools-core.snapshot.ts", 175)]
        sibling_sink = next(row["sink_id"] for row in chains if row["chain_id"] == sibling_chain)
        for seq, gate in enumerate(self.oracle["protected_sibling_evidence"], 100):
            chain_gates.append(
                {
                    "chain_id": sibling_chain,
                    "call_chain": "1#execute@fixture.ts->sink@sink.ts",
                    "sink_id": sibling_sink,
                    "gate_seq": seq,
                    "detector": "dominance",
                    "gate_uid": f"GU-{gate['inventory_record_id']}",
                    "gate_id": f"G-{gate['inventory_record_id']}",
                    "gate_name": gate["gate_name"],
                    "gate_file": gate["gate_file"],
                    "gate_line": gate["gate_line"],
                    "enclosing_function": "protectedSibling",
                    "static_verdict": "confirmed",
                }
            )

        root = self.pipeline / "static/call-chains"
        write_csv(root / "handler-sink-chains.csv", chains)
        write_csv(root / "sink-constraints.csv", constraints)
        write_csv(root / "chain-gates.csv", chain_gates)
        (root / "manifest.json").write_text(
            json.dumps({"counts": {"eligible_chain_gate_rows": len(chain_gates)}}),
            encoding="utf-8",
        )
        gates = self.pipeline / "static/gates"
        gates.mkdir(parents=True, exist_ok=True)
        (gates / "manifest.json").write_text(
            json.dumps({"counts": {"slice_failures": 0}}), encoding="utf-8"
        )

    def render(self) -> dict[str, object]:
        return MODULE.render(
            oracle_path=self.oracle_path,
            lock_path=self.lock_path,
            inventory_path=self.inventory_path,
            gt_root=ROOT / "design/openclaw-cn/groundtruth/new-vuls",
            pipeline_output=self.pipeline,
            out_dir=self.out,
            command="python fixture",
        )

    def test_complete_fixture_passes_all_15_13_64_5_contracts(self) -> None:
        summary = self.render()
        self.assertEqual(13, summary["concrete_sink_records"])
        self.assertEqual(15, summary["covered_sink_references"])
        self.assertEqual(64, summary["covered_present_gate_references"])
        self.assertEqual(5, summary["checked_expected_missing_references"])
        self.assertEqual(13, summary["gt_matched_chains"])
        self.assertEqual(13, summary["gt_matched_constraints"])
        self.assertEqual(2, summary["additional_shared_chains"])
        self.assertEqual(1, summary["additional_shared_constraints"])
        self.assertEqual([], summary["global_failures"])
        first_lines = (self.out / "gt-coverage.md").read_text(encoding="utf-8").splitlines()[:4]
        self.assertTrue(any("生成命令" in line for line in first_lines))

    def test_protected_sibling_cannot_be_removed(self) -> None:
        path = self.pipeline / "static/call-chains/chain-gates.csv"
        with path.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        protected = self.oracle["protected_sibling_evidence"][0]
        rows = [
            row
            for row in rows
            if not (
                row["gate_name"] == protected["gate_name"]
                and row["gate_file"] == protected["gate_file"]
                and int(row["gate_line"]) == protected["gate_line"]
            )
        ]
        write_csv(path, rows)
        with self.assertRaisesRegex(ValueError, "coverage failed"):
            self.render()

    def test_navigation_sibling_cannot_masquerade_as_evaluate_gate(self) -> None:
        path = self.pipeline / "static/call-chains/chain-gates.csv"
        with path.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        chain_path = self.pipeline / "static/call-chains/handler-sink-chains.csv"
        with chain_path.open(encoding="utf-8") as handle:
            evaluate_chain = next(
                row["chain_id"]
                for row in csv.DictReader(handle)
                if row["sink_label"] == "page.evaluate"
            )
        template = rows[0]
        rows.append(
            {
                **template,
                "chain_id": evaluate_chain,
                "gate_name": "assertBrowserNavigationAllowed",
                "gate_file": "src/browser/navigation-guard.ts",
                "gate_line": "25",
                "gate_uid": "GU-false-sibling",
            }
        )
        write_csv(path, rows)
        with self.assertRaisesRegex(ValueError, "coverage failed"):
            self.render()


if __name__ == "__main__":
    unittest.main()

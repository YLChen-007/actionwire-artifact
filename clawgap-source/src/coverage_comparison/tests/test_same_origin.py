from __future__ import annotations

import csv
import unittest
from pathlib import Path

from src.coverage_comparison.inputs import load_coverage_inputs
from src.coverage_comparison.same_origin import _effect_order, _read_csv, analyze_same_origin
from src.projects import get_project, list_projects


ROOT = Path(__file__).resolve().parents[3]


class CurrentSameOriginRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.specs = [get_project(project_id) for project_id in list_projects()]
        inputs = load_coverage_inputs(
            cls.specs,
            handler_root=ROOT / "output/cross-project/handler-types",
            sink_root=ROOT / "output/cross-project/sink-types",
            group_root=ROOT / "output/cross-project/group-oracles",
            evidence_registry=ROOT / "src/group_oracle/oracle-evidence-registry.json",
        )
        all_chains = {chain.key: chain for chain in inputs.chains}
        with (
            ROOT / "design/common/groundtruth-oracle/groundtruth-oracles.csv"
        ).open(newline="", encoding="utf-8") as handle:
            keys = {
                (row["project"], chain_id)
                for row in csv.DictReader(handle)
                for chain_id in row["chain_ids"].split(";")
            }
        cls.origin_run = analyze_same_origin(
            chains=[all_chains[key] for key in sorted(keys)],
            specs=cls.specs,
        )

    def assert_confirmed(self, project: str, chain_id: str, gate_uid: str) -> None:
        row = self.origin_run.witness_by_gate.get((project, chain_id, gate_uid))
        self.assertIsNotNone(row)
        self.assertEqual("same-origin-confirmed", row["verdict"])
        self.assertTrue(row["t_to_gate"])
        self.assertTrue(row["t_to_sink"])

    def assert_excluded(self, project: str, chain_id: str, gate_uid: str) -> None:
        rows = [
            row
            for row in self.origin_run.exclusions
            if row["project"] == project
            and row["chain_id"] == chain_id
            and row["gate_uid"] == gate_uid
        ]
        self.assertEqual(1, len(rows))
        self.assertNotEqual("same-origin-confirmed", rows[0]["verdict"])

    def test_direct_python_typescript_and_dispatch_witnesses(self) -> None:
        self.assert_confirmed(
            "droidclaw", "C-cbf151b190b6", "GU901654dbfa5024753b6d"
        )
        self.assert_confirmed(
            "chatgpt-on-wechat", "C-5dc10e8ecc95", "GU451d7429157743ab24ce"
        )
        self.assert_confirmed(
            "openclaw", "C-69d9c5038eab", "GU67230106e609c7af944a"
        )
        self.assert_confirmed(
            "openclaw-cn", "C-80f385bc4731", "GU7113538cc54fac41fc53"
        )
        self.assert_confirmed(
            "QwenPaw", "C-25692672827b", "GU1d91a93496f10a86f10f"
        )

    def test_helper_root_and_post_sink_examples_are_excluded(self) -> None:
        spec = get_project("hermes-agent").resolved()
        rows = {
            row["chain_id"]: row
            for row in _read_csv(
                spec.output_root
                / "static/call-chains/handler-sink-chains.csv"
            )
        }
        order, error = _effect_order(
            spec=spec,
            chain_row=rows["C-03b24e1d6b8f"],
            gate_file="tools/browser_tool.py",
            gate_line=1945,
            owner="_run_browser_command",
            static_verdict="confirmed",
        )
        self.assertIsNone(order)
        self.assertEqual("post-sink", error)
        order, error = _effect_order(
            spec=spec,
            chain_row=rows["C-0162b599da15"],
            gate_file="tools/send_message_tool.py",
            gate_line=547,
            owner="_send_to_platform",
            static_verdict="branch-confirmed",
        )
        self.assertIsNone(order)
        self.assertEqual("post-sink", error)


if __name__ == "__main__":
    unittest.main()

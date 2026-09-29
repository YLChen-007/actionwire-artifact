from __future__ import annotations

import csv
import importlib.util
import json
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("render_gt_coverage.py")
SPEC = importlib.util.spec_from_file_location("mercury_agent_coverage", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


class MercuryAgentCoverageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.output = root / "output"
        self.out = root / "coverage"
        oracle = MODULE._json(MODULE.DEFAULT_ORACLE)

        sink_groups: dict[tuple[object, ...], list[dict[str, object]]] = defaultdict(list)
        for row in oracle["eligible_sink_records"]:
            key = (
                row["tool_name"],
                row["handler_file"],
                row["handler_line"],
                row["sink_file"],
                row["sink_line"],
            )
            sink_groups[key].append(row)

        chains: list[dict[str, object]] = []
        constraints: list[dict[str, object]] = []
        chain_by_key: dict[tuple[object, ...], dict[str, object]] = {}
        for index, (key, records) in enumerate(sorted(sink_groups.items()), 1):
            tool, handler_file, handler_line, sink_file, sink_line = key
            chain_id = f"C-{index:04d}"
            sink_id = f"S-{index:04d}"
            facets = ";".join(sorted({str(row["controlled_facet"]) for row in records}))
            chain = {
                "chain_id": chain_id,
                "sink_id": sink_id,
                "project_id": "mercury-agent",
                "tool_name": tool,
                "handler_file": handler_file,
                "handler_line": handler_line,
                "sink_file": sink_file,
                "sink_line": sink_line,
                "sink_argument": facets,
            }
            chains.append(chain)
            chain_by_key[(tool, sink_file, sink_line)] = chain
            constraints.append(
                {
                    "constraint_id": f"SC-{index:04d}",
                    "sink_id": sink_id,
                    "capability_class": records[0]["capability_class"],
                    "controlled_argument": facets,
                }
            )

        # A gate report can describe a current tool/sink dimension that has no
        # independent d5_sink_points record (for example write_file). Keep that
        # structural chain in the hermetic fixture without inventing a GT sink.
        for row in oracle["eligible_gate_records"]:
            key = (row["tool_name"], row["sink_file"], row["sink_line"])
            if key in chain_by_key:
                continue
            index = len(chains) + 1
            chain = {
                "chain_id": f"C-{index:04d}",
                "sink_id": f"S-{index:04d}",
                "project_id": "mercury-agent",
                "tool_name": row["tool_name"],
                "handler_file": "",
                "handler_line": 0,
                "sink_file": row["sink_file"],
                "sink_line": row["sink_line"],
                "sink_argument": "",
            }
            chains.append(chain)
            chain_by_key[key] = chain

        gate_groups: dict[tuple[object, ...], dict[str, object]] = {}
        for row in oracle["eligible_gate_records"]:
            chain = chain_by_key[(row["tool_name"], row["sink_file"], row["sink_line"])]
            key = (
                chain["chain_id"],
                row["gate_name"],
                row["gate_file"],
                row["gate_line"],
            )
            previous = gate_groups.get(key)
            if previous is None or (
                previous["definition_file"] == previous["gate_file"]
                and previous["definition_line"] == previous["gate_line"]
                and (
                    row["definition_file"] != row["gate_file"]
                    or row["definition_line"] != row["gate_line"]
                )
            ):
                gate_groups[key] = row

        chain_gates: list[dict[str, object]] = []
        gate_index: list[dict[str, object]] = []
        for index, (key, row) in enumerate(sorted(gate_groups.items()), 1):
            chain_id, gate_name, gate_file, gate_line = key
            definition_file = row["definition_file"]
            definition_line = row["definition_line"]
            gate_uid = f"GU{index:020d}"
            chain_gates.append(
                {
                    "chain_id": chain_id,
                    "gate_uid": gate_uid,
                    "gate_name": gate_name,
                    "gate_file": gate_file,
                    "gate_line": gate_line,
                }
            )
            gate_index.append({"gate_uid": gate_uid})
            definition = None
            if definition_file != gate_file or definition_line != gate_line:
                definition = {"file": definition_file, "start_line": definition_line}
            slice_path = self.output / "gate-semantics/repository" / gate_uid / "slice.json"
            slice_path.parent.mkdir(parents=True, exist_ok=True)
            slice_path.write_text(
                json.dumps({"gate": {"definition_span": definition}}), encoding="utf-8"
            )

        write_csv(self.output / "static/call-chains/handler-sink-chains.csv", chains)
        write_csv(self.output / "static/call-chains/sink-constraints.csv", constraints)
        write_csv(self.output / "static/call-chains/chain-gates.csv", chain_gates)
        write_csv(self.output / "gate-semantics/gate-index.csv", gate_index)
        manifest = self.output / "static/gates/manifest.json"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps({"counts": {"slice_failures": 0}}), encoding="utf-8")

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

    def test_all_locked_sink_and_gate_records_are_covered(self) -> None:
        summary = self.render()
        self.assertEqual(5, summary["covered_sink_references"])
        self.assertEqual(27, summary["covered_gate_records"])
        self.assertEqual(0, summary["cross_tool_state_records"])
        self.assertEqual([], summary["global_failures"])

    def test_missing_exact_gate_is_not_hidden_by_duplicate_gt_records(self) -> None:
        path = self.output / "static/call-chains/chain-gates.csv"
        rows = MODULE._csv(path)
        write_csv(path, rows[1:])
        summary = self.render()
        self.assertTrue(summary["global_failures"])
        self.assertLess(summary["covered_gate_records"], summary["eligible_gate_records"])


if __name__ == "__main__":
    unittest.main()

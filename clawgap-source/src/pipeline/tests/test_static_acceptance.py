from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from src.pipeline.static_acceptance import render_acceptance


CHAIN_FIELDS = (
    "chain_id",
    "tool_name",
    "sink_file",
    "sink_line",
    "call_chain",
)
GATE_FIELDS = (
    "chain_id",
    "gate_seq",
    "gate_uid",
    "gate_name",
    "gate_file",
    "gate_line",
    "static_verdict",
)
CONSTRAINT_FIELDS = (
    "constraint_id",
    "sink_id",
    "sink_api",
    "sink_file",
    "sink_line",
    "controlled_argument",
    "capability_class",
    "call_shape",
    "capability_card",
    "capability_card_sha256",
)


def write_csv(
    path: Path,
    fields: tuple[str, ...],
    rows: list[dict[str, str]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


class StaticAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.ground_truth = self.root / "ground-truth"
        self.pipeline_output = self.root / "pipeline-output"
        self.output = self.root / "coverage"
        self.oracle = self.root / "oracle.json"
        self.source.mkdir()
        self.ground_truth.mkdir()
        (self.source / "tool.py").write_text(
            "def fixed_policy():\n    return True\n",
            encoding="utf-8",
        )
        (self.ground_truth / "summary-reported.md").write_text(
            "- `fixture-report-ISSUE-REPORT.md`\n",
            encoding="utf-8",
        )
        self.oracle_payload = {
            "schema_version": "python-static-acceptance/v1",
            "project_id": "fixture",
            "analysis_revision": "revision",
            "report_inventory": "summary-reported.md",
            "expected_sink_capabilities": {"tool.py:20": "file-write"},
            "dimensions": [
                {
                    "id": "fixture-dimension",
                    "current_status": "affected",
                    "model_scope": "handler-to-sink",
                    "reason": "A model-controlled path reaches the file-write sink.",
                    "source_reports": ["fixture-report"],
                    "flows": [
                        {
                            "handler": "fixture_tool",
                            "sink_points": ["tool.py:20"],
                        }
                    ],
                    "expected_existing_gates": ["tool.py:10"],
                    "expected_missing": ["inode-validation"],
                    "forbidden_fabricated_gate_terms": ["inode"],
                    "current_policy_anchors": [
                        {
                            "location": "tool.py:1",
                            "contains": "def fixed_policy",
                        }
                    ],
                    "stale_report_anchors": ["tool.py:99@historical"],
                }
            ],
            "structural_expectations": [
                {"handler": "fixture_tool", "sink_points": ["tool.py:20"]}
            ],
        }
        self.chains = [
            {
                "chain_id": "C-fixture",
                "tool_name": "fixture_tool",
                "sink_file": "tool.py",
                "sink_line": "20",
                "call_chain": "1#fixture_tool@tool.py->open@tool.py",
            }
        ]
        self.gates = [
            {
                "chain_id": "C-fixture",
                "gate_seq": "1",
                "gate_uid": "GU-fixture",
                "gate_name": "path_boundary",
                "gate_file": "tool.py",
                "gate_line": "10",
                "static_verdict": "confirmed",
            }
        ]
        self.constraints = [
            {
                "constraint_id": "SC-fixture",
                "sink_id": "S-fixture",
                "sink_api": "builtins.open",
                "sink_file": "tool.py",
                "sink_line": "20",
                "controlled_argument": "path",
                "capability_class": "file-write",
                "call_shape": "open(path, 'w')",
                "capability_card": "cards/builtins.open.write.md",
                "capability_card_sha256": "a" * 64,
            }
        ]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def render(self) -> dict[str, object]:
        self.oracle.write_text(
            json.dumps(self.oracle_payload) + "\n",
            encoding="utf-8",
        )
        static = self.pipeline_output / "static/call-chains"
        write_csv(static / "handler-sink-chains.csv", CHAIN_FIELDS, self.chains)
        write_csv(static / "chain-gates.csv", GATE_FIELDS, self.gates)
        write_csv(
            static / "sink-constraints.csv",
            CONSTRAINT_FIELDS,
            self.constraints,
        )
        return render_acceptance(
            title="fixture",
            generation_script="design/fixture/render_gt_coverage.py",
            oracle_path=self.oracle,
            ground_truth_root=self.ground_truth,
            source_root=self.source,
            pipeline_output=self.pipeline_output,
            out_dir=self.output,
        )

    def failed_kinds(self) -> set[str]:
        with (self.output / "gt-coverage.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            return {
                row["row_kind"]
                for row in csv.DictReader(handle)
                if row["status"] == "fail"
            }

    def test_complete_envelope_passes_and_records_root_command(self) -> None:
        result = self.render()
        self.assertEqual(0, result["failures"])
        report = (self.output / "gt-coverage.md").read_text(encoding="utf-8")
        self.assertIn(
            "design/fixture/render_gt_coverage.py",
            report.splitlines()[2],
        )

    def test_wrong_structural_capability_fails_global_constraint(self) -> None:
        self.constraints[0]["capability_class"] = "file-read"
        self.assertGreater(self.render()["failures"], 0)
        self.assertIn("pipeline-sink-constraint", self.failed_kinds())

    def test_missing_or_duplicate_constraint_fails(self) -> None:
        self.constraints.clear()
        self.assertGreater(self.render()["failures"], 0)
        self.assertIn("pipeline-sink-constraint", self.failed_kinds())

        self.constraints = [
            {
                "constraint_id": "SC-first",
                "sink_id": "S-fixture",
                "sink_api": "builtins.open",
                "sink_file": "tool.py",
                "sink_line": "20",
                "controlled_argument": "path",
                "capability_class": "file-write",
                "call_shape": "open(path, 'w')",
                "capability_card": "cards/builtins.open.write.md",
                "capability_card_sha256": "a" * 64,
            },
            {
                "constraint_id": "SC-second",
                "sink_id": "S-fixture",
                "sink_api": "builtins.open",
                "sink_file": "tool.py",
                "sink_line": "20",
                "controlled_argument": "path",
                "capability_class": "file-write",
                "call_shape": "open(path, 'w')",
                "capability_card": "cards/builtins.open.write.md",
                "capability_card_sha256": "a" * 64,
            },
        ]
        self.assertGreater(self.render()["failures"], 0)
        self.assertIn("pipeline-sink-constraint", self.failed_kinds())

    def test_zero_gate_chain_requires_one_placeholder(self) -> None:
        self.oracle_payload["dimensions"][0]["expected_existing_gates"] = []
        self.gates = [
            {
                "chain_id": "C-fixture",
                "gate_seq": "",
                "gate_uid": "",
                "gate_name": "",
                "gate_file": "",
                "gate_line": "",
                "static_verdict": "",
            }
        ]
        self.assertEqual(0, self.render()["failures"])

        self.gates.clear()
        self.assertGreater(self.render()["failures"], 0)
        self.assertIn("pipeline-chain-gates", self.failed_kinds())

    def test_needs_review_or_nonconsecutive_gate_sequence_fails(self) -> None:
        self.gates[0]["static_verdict"] = "needs-review"
        self.assertGreater(self.render()["failures"], 0)
        self.assertIn("pipeline-chain-gates", self.failed_kinds())

        self.gates[0]["static_verdict"] = "confirmed"
        self.gates[0]["gate_seq"] = "2"
        self.assertGreater(self.render()["failures"], 0)
        self.assertIn("pipeline-chain-gates", self.failed_kinds())

    def test_orphan_chain_gate_fails(self) -> None:
        self.gates.append(dict(self.gates[0], chain_id="C-orphan"))
        self.assertGreater(self.render()["failures"], 0)
        self.assertIn("pipeline-chain-gates", self.failed_kinds())

    def test_unrepresented_inventory_report_fails(self) -> None:
        (self.ground_truth / "summary-reported.md").write_text(
            "- `fixture-report-ISSUE-REPORT.md`\n"
            "- `second-report-ISSUE-REPORT.md`\n",
            encoding="utf-8",
        )
        self.assertGreater(self.render()["failures"], 0)
        self.assertIn("source-report", self.failed_kinds())

    def test_expected_missing_control_cannot_be_fabricated(self) -> None:
        self.gates[0]["gate_name"] = "inode validation"
        self.assertGreater(self.render()["failures"], 0)
        self.assertIn("expected-missing", self.failed_kinds())


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Regression-contract tests for the AstrBot GT coverage renderer."""

from __future__ import annotations

import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import render_gt_coverage


REPO_ROOT = Path(__file__).resolve().parents[5]
REVISION = "0e973bd4d483d18e1672c4dfa2eb7aae31bc1f83"


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise AssertionError("test fixtures must declare their CSV fields")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


class AstrBotGTCoverageRendererTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.pipeline_output = self.root / "pipeline-output"
        self.out_dir = self.root / "report"
        self.source_root = self.root / "source"
        self.ground_truth = self.root / "ground-truth"
        self.oracle = self.root / "oracle.json"
        (self.source_root / "agent").mkdir(parents=True)
        (self.source_root / "agent/tool.py").write_text(
            "def fixed_policy():\n    return True\n",
            encoding="utf-8",
        )
        self.ground_truth.mkdir()
        (self.ground_truth / "fixture.json").write_text(
            json.dumps({"report_name": "fixture-report"}) + "\n",
            encoding="utf-8",
        )
        self.oracle.write_text(
            json.dumps(
                {
                    "schema_version": "astrbot-static-acceptance/v1",
                    "project_id": "AstrBot",
                    "analysis_revision": REVISION,
                    "expected_sink_capabilities": {
                        "agent/tool.py:20": "file-write"
                    },
                    "dimensions": [
                        {
                            "id": "fixture-dimension",
                            "current_status": "affected",
                            "flows": [
                                {
                                    "handler": "fixture_tool",
                                    "sink_points": ["agent/tool.py:20"],
                                }
                            ],
                            "expected_existing_gates": ["agent/tool.py:10"],
                            "expected_missing": ["inode-validation"],
                            "forbidden_fabricated_gate_terms": ["inode"],
                            "source_reports": ["fixture-report"],
                            "current_policy_anchors": [
                                {
                                    "location": "agent/tool.py:1",
                                    "contains": "def fixed_policy",
                                }
                            ],
                            "stale_report_anchors": [],
                        }
                    ],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.chains = [
            {
                "chain_id": "C-fixture",
                "tool_name": "fixture_tool",
                "sink_file": "agent/tool.py",
                "sink_line": "20",
                "call_chain": "1#Fixture.call@tool.py->open@tool.py",
            }
        ]
        self.gates = [
            {
                "chain_id": "C-fixture",
                "gate_uid": "GU-fixture",
                "gate_file": "agent/tool.py",
                "gate_line": "10",
                "gate_name": "path boundary",
            }
        ]
        self.constraints = [
            {
                "constraint_id": "SC-fixture",
                "sink_file": "agent/tool.py",
                "sink_line": "20",
                "capability_class": "file-write",
            }
        ]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_renderer(self) -> int:
        static = self.pipeline_output / "static/call-chains"
        write_csv(static / "handler-sink-chains.csv", self.chains)
        write_csv(static / "chain-gates.csv", self.gates)
        write_csv(static / "sink-constraints.csv", self.constraints)
        with redirect_stdout(io.StringIO()):
            return render_gt_coverage.main(
                [
                    "--oracle",
                    str(self.oracle),
                    "--ground-truth",
                    str(self.ground_truth),
                    "--source-root",
                    str(self.source_root),
                    "--pipeline-output",
                    str(self.pipeline_output),
                    "--out-dir",
                    str(self.out_dir),
                ]
            )

    def test_complete_fixture_passes_and_records_reproduction_command(self) -> None:
        self.assertEqual(0, self.run_renderer())
        report = (self.out_dir / "gt-coverage.md").read_text(encoding="utf-8")
        self.assertIn("Acceptance failures: **0**", report)
        self.assertIn(
            "design/AstrBot/call-chain/debug/script/render_gt_coverage.py",
            report.splitlines()[2],
        )

    def test_missing_handler_sink_chain_fails(self) -> None:
        self.chains[0]["tool_name"] = "different_tool"
        self.assertEqual(1, self.run_renderer())

    def test_wrong_or_duplicate_sink_constraint_fails(self) -> None:
        self.constraints[0]["capability_class"] = "file-read"
        self.assertEqual(1, self.run_renderer())
        self.constraints[0]["capability_class"] = "file-write"
        self.constraints.append(dict(self.constraints[0], constraint_id="SC-second"))
        self.assertEqual(1, self.run_renderer())

    def test_missing_existing_gate_fails(self) -> None:
        self.gates[0]["gate_line"] = "11"
        self.assertEqual(1, self.run_renderer())

    def test_fabricated_expected_missing_gate_fails(self) -> None:
        self.gates.append(
            {
                "chain_id": "C-fixture",
                "gate_uid": "GU-fabricated",
                "gate_file": "agent/tool.py",
                "gate_line": "12",
                "gate_name": "inode validation",
            }
        )
        self.assertEqual(1, self.run_renderer())

    def test_unrepresented_raw_report_fails(self) -> None:
        (self.ground_truth / "extra.json").write_text(
            json.dumps({"report_name": "unrepresented-report"}) + "\n",
            encoding="utf-8",
        )
        self.assertEqual(1, self.run_renderer())

    def test_checked_in_static_output_satisfies_acceptance_oracle(self) -> None:
        with redirect_stdout(io.StringIO()):
            result = render_gt_coverage.main(
                [
                    "--oracle",
                    str(REPO_ROOT / "design/AstrBot/astrbot-4.25.2-acceptance.json"),
                    "--ground-truth",
                    str(REPO_ROOT / "design/AstrBot/groundtruth/new-vuls"),
                    "--source-root",
                    str(REPO_ROOT / "benchmark/python/AstrBot"),
                    "--pipeline-output",
                    str(REPO_ROOT / "output/AstrBot"),
                    "--out-dir",
                    str(self.out_dir),
                ]
            )
        self.assertEqual(0, result)
        with (self.out_dir / "gt-coverage.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            rows = list(csv.DictReader(handle))
        self.assertFalse([row for row in rows if row["status"] == "fail"])
        report = (self.out_dir / "gt-coverage.md").read_text(encoding="utf-8")
        self.assertIn(
            "--oracle design/AstrBot/astrbot-4.25.2-acceptance.json",
            report.splitlines()[2],
        )


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Regression-contract tests for the CowAgent static GT coverage renderer."""

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
REVISION = "55aaf60a57ea6e9f4b8a54797572d98f65e88d2f"


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise AssertionError("test fixtures must declare their CSV fields")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


class CowAgentGTCoverageRendererTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.pipeline_output = self.root / "pipeline-output"
        self.out_dir = self.root / "report"
        self.oracle = self.root / "oracle.json"
        self.oracle.write_text(
            json.dumps(
                {
                    "schema_version": "cowagent-static-acceptance/v1",
                    "project_id": "chatgpt-on-wechat",
                    "analysis_revision": REVISION,
                    "dimensions": [
                        {
                            "id": "fixture-dimension",
                            "handler": "fixture_tool",
                            "sink_points": ["agent/tool.py:20"],
                            "expected_existing_gates": ["agent/tool.py:10"],
                            "expected_missing": ["mandatory-user-approval"],
                            "forbidden_fabricated_gate_terms": [
                                "approval",
                                "consent",
                            ],
                            "source_reports": ["fixture-report"],
                            "duplicate_reports": [],
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
                "call_chain": "1#Fixture.execute@tool.py->sink@tool.py",
            }
        ]
        self.gates = [
            {
                "chain_id": "C-fixture",
                "gate_uid": "GU-fixture",
                "gate_file": "agent/tool.py",
                "gate_line": "10",
                "gate_name": "existing safety check",
            }
        ]
        self.constraints = [
            {
                "constraint_id": "SC-fixture",
                "sink_file": "agent/tool.py",
                "sink_line": "20",
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
            "design/chatgpt-on-wechat/call-chain/debug/script/render_gt_coverage.py",
            report.splitlines()[2],
        )

    def test_missing_handler_sink_chain_fails(self) -> None:
        self.chains[0]["tool_name"] = "different_tool"
        self.assertEqual(1, self.run_renderer())

    def test_duplicate_sink_constraint_fails(self) -> None:
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
                "gate_name": "mandatory user approval",
            }
        )
        self.assertEqual(1, self.run_renderer())

    def test_checked_in_static_output_satisfies_acceptance_oracle(self) -> None:
        with redirect_stdout(io.StringIO()):
            result = render_gt_coverage.main(
                [
                    "--oracle",
                    str(
                        REPO_ROOT
                        / "design/chatgpt-on-wechat/groundtruth/"
                        "cowagent-2.0.8-acceptance.json"
                    ),
                    "--pipeline-output",
                    str(REPO_ROOT / "output/chatgpt-on-wechat"),
                    "--out-dir",
                    str(self.out_dir),
                ]
            )
        self.assertEqual(0, result)
        with (self.out_dir / "gt-coverage.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(25, len(rows))
        self.assertFalse([row for row in rows if row["status"] == "fail"])
        report = (self.out_dir / "gt-coverage.md").read_text(encoding="utf-8")
        self.assertIn(
            "--oracle design/chatgpt-on-wechat/groundtruth/"
            "cowagent-2.0.8-acceptance.json",
            report.splitlines()[2],
        )


if __name__ == "__main__":
    unittest.main()

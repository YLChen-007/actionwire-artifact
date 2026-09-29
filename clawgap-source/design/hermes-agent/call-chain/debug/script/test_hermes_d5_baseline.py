#!/usr/bin/env python3
"""Unit and repository-smoke tests for the Hermes D5 coverage baseline."""

from __future__ import annotations

import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from hermes_d5_baseline import (  # noqa: E402
    BaselineError,
    build_baseline,
    compare_coverage,
    load_baseline,
    read_items,
)
from ql_baseline_hook import (  # noqa: E402
    _run_baseline,
    mark_ql_edit,
    marker_path,
    ql_target,
    run_marked_baseline,
)


REVISION = "04439ac77f08915b4886bc3c79165a9538af6219"
BASELINE = (
    REPO_ROOT
    / "design/hermes-agent/call-chain/baseline/d5-covered-items-v1.json"
)
CURRENT_ITEMS = (
    REPO_ROOT
    / "design/hermes-agent/call-chain/debug/d5-chain-coverage-items.csv"
)


def row(
    index: int,
    *,
    status: str,
    name: str,
    verdict: str = "confirmed",
) -> dict[str, str]:
    return {
        "json_id": "report",
        "json_file": "report.json",
        "item_kind": "gate",
        "item_index": str(index),
        "gt_name": name,
        "gt_type": "dominance",
        "gt_location": f"tool.py:{index}",
        "coverage_status": status,
        "match_kind": "exact-location" if status == "covered" else "",
        "detector_verdict": verdict if status == "covered" else "",
        "chain_count": "1" if status == "covered" else "0",
        "chain_ids": "C-test" if status == "covered" else "",
        "matched_evidence": "gate@tool.py" if status == "covered" else "",
        "notes": "",
    }


class BaselineComparatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = [
            row(1, status="covered", name="existing gate"),
            row(2, status="uncovered", name="future gate"),
        ]
        self.baseline = build_baseline(self.rows, analysis_revision=REVISION)

    def compare(self, rows: list[dict[str, str]]) -> dict[str, object]:
        return compare_coverage(rows, self.baseline, analysis_revision=REVISION)

    def test_equal_and_reordered_rows_pass(self) -> None:
        result = self.compare(list(reversed(self.rows)))
        self.assertEqual(1, result["required_items"])
        self.assertEqual([], result["newly_covered"])

    def test_newly_covered_item_is_a_non_failing_superset(self) -> None:
        improved = copy.deepcopy(self.rows)
        improved[1].update(
            {
                "coverage_status": "covered",
                "match_kind": "gate-symbol",
                "detector_verdict": "branch-confirmed",
            }
        )
        result = self.compare(improved)
        self.assertEqual(2, result["covered_items"])
        self.assertEqual("future gate", result["newly_covered"][0]["gt_name"])

    def test_required_item_becoming_uncovered_fails(self) -> None:
        regressed = copy.deepcopy(self.rows)
        regressed[0].update(
            {
                "coverage_status": "uncovered",
                "match_kind": "",
                "detector_verdict": "",
            }
        )
        with self.assertRaisesRegex(BaselineError, "existing gate"):
            self.compare(regressed)

    def test_needs_review_does_not_satisfy_gate_baseline(self) -> None:
        regressed = copy.deepcopy(self.rows)
        regressed[0]["detector_verdict"] = "needs-review"
        with self.assertRaisesRegex(BaselineError, "needs-review"):
            self.compare(regressed)

    def test_new_gate_cannot_hide_lost_required_gate(self) -> None:
        replaced = copy.deepcopy(self.rows)
        replaced[0].update(
            {
                "coverage_status": "uncovered",
                "match_kind": "",
                "detector_verdict": "",
            }
        )
        replaced[1].update(
            {
                "coverage_status": "covered",
                "match_kind": "gate-symbol",
                "detector_verdict": "confirmed",
            }
        )
        with self.assertRaisesRegex(BaselineError, "existing gate"):
            self.compare(replaced)

    def test_ground_truth_identity_change_requires_new_baseline(self) -> None:
        changed = copy.deepcopy(self.rows)
        changed[1]["gt_name"] = "renamed future gate"
        with self.assertRaisesRegex(BaselineError, "identity changed"):
            self.compare(changed)

    def test_revision_change_requires_new_baseline(self) -> None:
        with self.assertRaisesRegex(BaselineError, "revision mismatch"):
            compare_coverage(
                self.rows,
                self.baseline,
                analysis_revision="different-revision",
            )


class RepositoryBaselineSmokeTest(unittest.TestCase):
    def test_checked_in_d5_items_satisfy_approved_baseline(self) -> None:
        result = compare_coverage(
            read_items(CURRENT_ITEMS),
            load_baseline(BASELINE),
            analysis_revision=REVISION,
        )
        self.assertEqual(95, result["required_items"])
        self.assertEqual(
            {"handler": 9, "gate": 74, "sink": 12},
            result["covered_counts"],
        )


class QLBaselineHookTargetTest(unittest.TestCase):
    def test_ql_qll_and_pack_metadata_trigger(self) -> None:
        self.assertEqual(
            "src/ql/get_gates.ql",
            ql_target(REPO_ROOT, "src/ql/get_gates.ql"),
        )
        self.assertEqual(
            "src/ql/call/call.qll",
            ql_target(REPO_ROOT, REPO_ROOT / "src/ql/call/call.qll"),
        )
        self.assertEqual(
            "src/ql/qlpack.yml",
            ql_target(REPO_ROOT, "src/ql/qlpack.yml"),
        )

    def test_non_ql_and_outside_paths_do_not_trigger(self) -> None:
        self.assertIsNone(ql_target(REPO_ROOT, "src/ql/tests/fixture.py"))
        self.assertIsNone(ql_target(REPO_ROOT, "design/query.ql"))
        self.assertIsNone(ql_target(REPO_ROOT, "../outside.ql"))


def hook_payload(path: str, *, session_id: str = "session-a") -> dict[str, object]:
    return {
        "session_id": session_id,
        "tool_input": {"file_path": path},
    }


class QLBaselineOncePerTurnTest(unittest.TestCase):
    def test_default_runner_executes_all_project_regressions(self) -> None:
        completed = subprocess.CompletedProcess(["regression"], 0, "passed", "")
        with patch("ql_baseline_hook.subprocess.run", return_value=completed) as run:
            result = _run_baseline(REPO_ROOT)
        self.assertEqual(0, result.returncode)
        self.assertEqual(6, run.call_count)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertTrue(str(commands[0][1]).endswith("test_hermes_d5_baseline.py"))
        self.assertTrue(
            str(commands[1][1]).endswith(
                "test_chatgpt_on_wechat_gt_coverage.py"
            )
        )
        self.assertTrue(
            str(commands[2][1]).endswith("test_astrbot_gt_coverage.py")
        )
        self.assertTrue(
            str(commands[3][1]).endswith("test_qwenpaw_gt_coverage.py")
        )
        self.assertTrue(
            str(commands[4][1]).endswith("test_nanobot_gt_coverage.py")
        )
        self.assertTrue(
            str(commands[5][1]).endswith("test_poco_agent_gt_coverage.py")
        )

    def test_repeated_edits_accumulate_in_one_session_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            payload = hook_payload("src/ql/get_gates.ql")
            self.assertEqual(
                "src/ql/get_gates.ql",
                mark_ql_edit(REPO_ROOT, payload, state_root=state_root),
            )
            mark_ql_edit(
                REPO_ROOT,
                hook_payload("src/ql/call/sinks_af.qll"),
                state_root=state_root,
            )
            marker = marker_path(REPO_ROOT, payload, state_root=state_root)
            self.assertIsNotNone(marker)
            state = json.loads(marker.read_text(encoding="utf-8"))
            self.assertEqual(
                ["src/ql/call/sinks_af.qll", "src/ql/get_gates.ql"],
                state["modified_paths"],
            )

    def test_markers_are_isolated_by_claude_session(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            first = hook_payload("src/ql/get_gates.ql", session_id="session-a")
            second = hook_payload("src/ql/get_gates.ql", session_id="session-b")
            mark_ql_edit(REPO_ROOT, first, state_root=state_root)
            self.assertTrue(
                marker_path(REPO_ROOT, first, state_root=state_root).is_file()
            )
            self.assertFalse(
                marker_path(REPO_ROOT, second, state_root=state_root).exists()
            )

    def test_successful_stop_runs_once_and_consumes_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            payload = hook_payload("src/ql/get_gates.ql")
            mark_ql_edit(REPO_ROOT, payload, state_root=state_root)
            calls: list[Path] = []

            def passing_runner(root: Path) -> subprocess.CompletedProcess[str]:
                calls.append(root)
                return subprocess.CompletedProcess(["baseline"], 0, "passed", "")

            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    0,
                    run_marked_baseline(
                        REPO_ROOT,
                        payload,
                        state_root=state_root,
                        runner=passing_runner,
                    ),
                )
                self.assertEqual(
                    0,
                    run_marked_baseline(
                        REPO_ROOT,
                        payload,
                        state_root=state_root,
                        runner=passing_runner,
                    ),
                )
            self.assertEqual([REPO_ROOT], calls)

    def test_failed_stop_keeps_marker_for_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory)
            payload = hook_payload("src/ql/get_gates.ql")
            mark_ql_edit(REPO_ROOT, payload, state_root=state_root)

            def failing_runner(_root: Path) -> subprocess.CompletedProcess[str]:
                return subprocess.CompletedProcess(
                    ["baseline"], 1, "", "missing approved item"
                )

            with redirect_stderr(io.StringIO()) as error:
                self.assertEqual(
                    2,
                    run_marked_baseline(
                        REPO_ROOT,
                        payload,
                        state_root=state_root,
                        runner=failing_runner,
                    ),
                )
            self.assertIn("missing approved item", error.getvalue())
            self.assertTrue(
                marker_path(REPO_ROOT, payload, state_root=state_root).is_file()
            )


if __name__ == "__main__":
    unittest.main()

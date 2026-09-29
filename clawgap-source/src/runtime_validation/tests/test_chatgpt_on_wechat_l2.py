from __future__ import annotations

import json
import py_compile
import tempfile
import unittest
from pathlib import Path

from src.runtime_validation.chatgpt_on_wechat_l2 import (
    HISTORICAL_TARGET_CANDIDATES,
    TARGET_CANDIDATES,
    _expected_stages,
    _historical_case,
    _instrument_project,
    _select_cases,
    _sink_matches,
    _source_bindings,
)
from src.runtime_validation.contracts import ValidationError


REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOT = REPO_ROOT / "benchmark/python/chatgpt-on-wechat"
SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)
HISTORICAL_SOURCE = (
    REPO_ROOT
    / "output/cross-project/coverage-comparison/training-regression-candidates.jsonl"
)


def _case(candidate_id: str) -> dict:
    return _select_cases(SOURCE_CAMPAIGN, candidate_id=candidate_id)[0]


class ChatGPTOnWeChatTargetedL2Test(unittest.TestCase):
    def test_exact_current_candidates_are_selected(self) -> None:
        cases = _select_cases(SOURCE_CAMPAIGN)
        self.assertEqual(
            tuple(TARGET_CANDIDATES),
            tuple(row["candidate_binding"]["candidate_id"] for row in cases),
        )
        with self.assertRaisesRegex(ValidationError, "not a current GT-linked"):
            _select_cases(
                SOURCE_CAMPAIGN, candidate_id="CAND-26ed97d9d3b5b549"
            )

    def test_historical_overlay_contains_only_web_fetch_and_vision(self) -> None:
        cases = _select_cases(
            HISTORICAL_SOURCE,
            historical=True,
        )
        self.assertEqual(
            tuple(HISTORICAL_TARGET_CANDIDATES),
            tuple(row["candidate_binding"]["candidate_id"] for row in cases),
        )
        self.assertEqual(
            {"web_fetch", "vision"},
            {row["tool_or_action_name"] for row in cases},
        )
        with self.assertRaisesRegex(ValidationError, "admitted historical"):
            _select_cases(
                HISTORICAL_SOURCE,
                candidate_id="CAND-b49cfc884f2168f1",
                historical=True,
            )

    def test_historical_cases_are_source_bound_and_missing_check(self) -> None:
        rows = [
            json.loads(line)
            for line in HISTORICAL_SOURCE.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        source = {
            row["candidate_id"]: row
            for row in rows
            if row["project"] == "chatgpt-on-wechat"
        }
        for candidate_id in HISTORICAL_TARGET_CANDIDATES:
            with self.subTest(candidate_id=candidate_id):
                case = _historical_case(source[candidate_id])
                self.assertTrue(case["execution_eligible"])
                self.assertEqual([], case["gates"])
                self.assertIn(
                    "missing_check_boundary_confirmed",
                    _expected_stages(case),
                )

    def test_source_bindings_and_browser_contradiction_are_pinned(self) -> None:
        bindings = _source_bindings(_select_cases(SOURCE_CAMPAIGN))
        for relative in (
            "app.py",
            "agent/protocol/agent_stream.py",
            "agent/tools/bash/bash.py",
            "agent/tools/read/read.py",
            "agent/tools/web_fetch/web_fetch.py",
            "agent/tools/vision/vision.py",
            "agent/tools/browser/browser_tool.py",
        ):
            self.assertIn(relative, bindings)
        browser = (
            SOURCE_ROOT / "agent/tools/browser/browser_tool.py"
        ).read_text(encoding="utf-8")
        self.assertIn('url = "https://" + url', browser)

    def test_instrumentation_markers_apply_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            for relative in (
                "agent/protocol",
                "bridge",
                "agent/tools/bash",
                "agent/tools/read",
                "agent/tools/web_fetch",
                "agent/tools/vision",
            ):
                (project / relative).mkdir(parents=True)
            for relative in (
                "app.py",
                "bridge/agent_initializer.py",
                "agent/protocol/agent_stream.py",
                "agent/tools/bash/bash.py",
                "agent/tools/read/read.py",
                "agent/tools/web_fetch/web_fetch.py",
                "agent/tools/vision/vision.py",
            ):
                source = SOURCE_ROOT / relative
                target = project / relative
                target.write_text(
                    source.read_text(encoding="utf-8"), encoding="utf-8"
                )
            transformed = _instrument_project(project)
            for relative in transformed:
                py_compile.compile(
                    str(project / relative), doraise=True, cfile=str(project / "_.pyc")
                )
        self.assertEqual(8, len(transformed))
        self.assertIn("clawgap_l2_runtime.py", transformed)
        self.assertIn("bridge/agent_initializer.py", transformed)
        self.assertIn("agent/protocol/agent_stream.py", transformed)

    def test_exploit_witnesses_cannot_be_satisfied_by_controls(self) -> None:
        for candidate_id in TARGET_CANDIDATES:
            with self.subTest(candidate_id=candidate_id):
                case = _case(candidate_id)
                self.assertTrue(_sink_matches(case, "exploit", _sink_event(case)))
                self.assertFalse(
                    _sink_matches(case, "control", _control_sink_event(case))
                )

    def test_expected_stage_uses_gate_only_when_cited(self) -> None:
        gated = _case("CAND-2b4f8af87ad95c56")
        missing = _case("CAND-7afa41ea2e82453d")
        self.assertIn("gate_observed", _expected_stages(gated))
        self.assertNotIn("gate_observed", _expected_stages(missing))
        self.assertIn(
            "missing_check_boundary_confirmed", _expected_stages(missing)
        )


def _sink_event(case: dict) -> dict:
    candidate_id = case["candidate_binding"]["candidate_id"]
    arguments = case["forced_tool_calls"][0]["arguments"]
    if candidate_id in {
        "CAND-2b4f8af87ad95c56",
        "CAND-7afa41ea2e82453d",
    }:
        detail = {"path": arguments["path"]}
    elif candidate_id in {
        "CAND-70cbbd81dff4ec04",
        "CAND-c93d316d66e49992",
        "CAND-f4a49abfcf4c992c",
        "CAND-ff3a7b0ab4b0a449",
    }:
        detail = {"command": arguments["command"]}
    else:
        detail = {"url": arguments["url"]}
    return {"detail": detail}


def _control_sink_event(case: dict) -> dict:
    candidate_id = case["candidate_binding"]["candidate_id"]
    arguments = case["forced_tool_calls"][1]["arguments"]
    if candidate_id in {
        "CAND-2b4f8af87ad95c56",
        "CAND-7afa41ea2e82453d",
    }:
        detail = {"path": arguments["path"]}
    elif candidate_id in {
        "CAND-70cbbd81dff4ec04",
        "CAND-c93d316d66e49992",
        "CAND-f4a49abfcf4c992c",
        "CAND-ff3a7b0ab4b0a449",
    }:
        detail = {"command": arguments["command"]}
    else:
        detail = {"url": arguments["url"]}
    return {"detail": detail}


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import os
import py_compile
import tempfile
import unittest
from pathlib import Path

from src.runtime_validation.astrbot_l2 import (
    CITED_SOURCE_HASHES,
    FAMILIES,
    TARGET_CANDIDATES,
    _expected_stages,
    _instrument_project,
    _normalized_umo,
    _prepare_fixture,
    _select_cases,
    _sink_matches,
    _source_bindings,
)
from src.runtime_validation.contracts import ValidationError, sha256_file


REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOT = REPO_ROOT / "benchmark/python/AstrBot"
SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)


class AstrBotTargetedL2Test(unittest.TestCase):
    def test_exact_gt_linked_candidates_are_selected(self) -> None:
        cases = _select_cases(SOURCE_CAMPAIGN)
        self.assertEqual(
            tuple(TARGET_CANDIDATES),
            tuple(row["candidate_binding"]["candidate_id"] for row in cases),
        )
        with self.assertRaisesRegex(ValidationError, "not a GT-linked"):
            _select_cases(
                SOURCE_CAMPAIGN,
                candidate_id="CAND-17ca47a2675d7feb",
            )

    def test_cited_source_hashes_are_pinned(self) -> None:
        bindings = _source_bindings(_select_cases(SOURCE_CAMPAIGN))
        for relative, expected in CITED_SOURCE_HASHES.items():
            self.assertEqual(expected, bindings[relative])
            self.assertEqual(expected, sha256_file(SOURCE_ROOT / relative))

    def test_instrumentation_markers_apply_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            relatives = (
                "astrbot/cli/__main__.py",
                "astrbot/core/agent/runners/tool_loop_agent_runner.py",
                "astrbot/core/tools/computer_tools/fs.py",
                "astrbot/dashboard/server.py",
            )
            for relative in relatives:
                target = project / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    (SOURCE_ROOT / relative).read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
            transformed = _instrument_project(project)
            for relative in transformed:
                py_compile.compile(
                    str(project / relative), doraise=True, cfile=str(project / "_.pyc")
                )
        self.assertEqual(5, len(transformed))
        self.assertIn("clawgap_l2_runtime.py", transformed)
        self.assertIn("astrbot/core/tools/computer_tools/fs.py", transformed)

    def test_workspace_derivation_follows_real_umo_normalization(self) -> None:
        self.assertEqual(
            "webchat_FriendMessage_webchat_clawgap-member_session-1",
            _normalized_umo("session-1"),
        )

    def test_hardlink_fixture_confines_the_outside_canary(self) -> None:
        case = _select_cases(
            SOURCE_CAMPAIGN, candidate_id="CAND-36a7affd32f9adf1"
        )[0]
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            fixture = _prepare_fixture(
                runtime=runtime,
                case=case,
                role="exploit",
                session_id="session-1",
            )
            alias = Path(str(fixture["expected_sink_path"]))
            outside = Path(str(fixture["outside_target"]))
            self.assertTrue(alias.exists())
            self.assertTrue(os.path.samefile(alias, outside))
            self.assertTrue(str(alias).endswith("hardlink_to_outside.txt"))

    def test_exploit_witnesses_cannot_be_satisfied_by_controls(self) -> None:
        for candidate_id in TARGET_CANDIDATES:
            with self.subTest(candidate_id=candidate_id):
                case = _select_cases(SOURCE_CAMPAIGN, candidate_id=candidate_id)[0]
                exploit = {
                    "detail": {
                        "path": (
                            "/runtime/data/plugins/demo/skills/SKILL.md"
                            if FAMILIES[candidate_id] != "workspace-hardlink-write"
                            else "/runtime/data/workspaces/x/hardlink_to_outside.txt"
                        ),
                        "expected_path": (
                            "/runtime/data/plugins/demo/skills/SKILL.md"
                            if FAMILIES[candidate_id] != "workspace-hardlink-write"
                            else "/runtime/data/workspaces/x/hardlink_to_outside.txt"
                        ),
                        "samefile_with_outside_target": (
                            FAMILIES[candidate_id] == "workspace-hardlink-write"
                        ),
                    }
                }
                control = {
                    "detail": {
                        "path": (
                            "/runtime/data/skills/SKILL.md"
                            if FAMILIES[candidate_id] != "workspace-hardlink-write"
                            else "/runtime/data/workspaces/x/safe_file.txt"
                        ),
                        "expected_path": (
                            "/runtime/data/skills/SKILL.md"
                            if FAMILIES[candidate_id] != "workspace-hardlink-write"
                            else "/runtime/data/workspaces/x/safe_file.txt"
                        ),
                        "samefile_with_outside_target": False,
                    }
                }
                self.assertTrue(_sink_matches(case, "exploit", exploit))
                self.assertFalse(_sink_matches(case, "control", control))

    def test_missing_check_boundary_is_required_in_order(self) -> None:
        case = _select_cases(SOURCE_CAMPAIGN)[0]
        stages = _expected_stages(case)
        self.assertIn("gate_observed", stages)
        self.assertIn("missing_check_boundary_confirmed", stages)
        self.assertLess(
            stages.index("gate_observed"),
            stages.index("missing_check_boundary_confirmed"),
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import py_compile
import tempfile
import unittest
from pathlib import Path

from src.runtime_validation.qwenpaw_l2 import (
    MODEL_NAME,
    TARGET_CANDIDATES,
    _expected_stages,
    _instrument_project,
    _render_provider_config,
    _select_cases,
    _sink_matches,
    _source_bindings,
    _validate_missing_jq_environment_rule,
)
from src.runtime_validation.contracts import ValidationError, sha256_file


REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOT = REPO_ROOT / "benchmark/python/QwenPaw"
SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)


class QwenPawTargetedL2Test(unittest.TestCase):
    def test_exact_gt_linked_candidate_is_selected(self) -> None:
        cases = _select_cases(SOURCE_CAMPAIGN)
        self.assertEqual(
            tuple(TARGET_CANDIDATES),
            tuple(row["candidate_binding"]["candidate_id"] for row in cases),
        )
        with self.assertRaisesRegex(ValidationError, "not the GT-linked"):
            _select_cases(
                SOURCE_CAMPAIGN,
                candidate_id="CAND-7658c898d4011c06",
            )

    def test_cited_source_and_missing_jq_rule_are_pinned(self) -> None:
        bindings = _source_bindings(_select_cases(SOURCE_CAMPAIGN))
        self.assertEqual(
            6,
            len(
                set(bindings).intersection(
                    {
                        "pyproject.toml",
                        "src/qwenpaw/cli/main.py",
                        "src/qwenpaw/app/routers/console.py",
                        "src/qwenpaw/agents/tool_guard_mixin.py",
                        "src/qwenpaw/security/tool_guard/rules/dangerous_shell_commands.yaml",
                        "src/qwenpaw/agents/tools/shell.py",
                    }
                )
            ),
        )
        rule_path = (
            SOURCE_ROOT
            / "src/qwenpaw/security/tool_guard/rules/dangerous_shell_commands.yaml"
        )
        _validate_missing_jq_environment_rule(rule_path)
        source = rule_path.read_text(encoding="utf-8")
        self.assertIn("- id: TOOL_CMD_JQ_SYSTEM", source)
        self.assertNotIn("- id: TOOL_CMD_JQ_ENV", source)

    def test_instrumentation_markers_apply_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            relatives = (
                "src/qwenpaw/cli/main.py",
                "src/qwenpaw/agents/tool_guard_mixin.py",
                "src/qwenpaw/security/tool_guard/engine.py",
                "src/qwenpaw/agents/tools/shell.py",
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
        self.assertIn("src/clawgap_l2_runtime.py", transformed)
        self.assertIn("src/qwenpaw/agents/tools/shell.py", transformed)

    def test_provider_config_is_loopback_and_model_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory)
            provider, active = _render_provider_config(
                secret,
                provider_base_url="http://127.0.0.1:CarefulPort/v1",
            )
            self.assertEqual(
                sha256_file(provider),
                sha256_file(provider),
            )
            self.assertEqual("clawgap.json", provider.name)
            self.assertEqual("active_model.json", active.name)
            self.assertIn('"clawgap-loopback-mock"', provider.read_text(encoding="utf-8"))
            self.assertIn(MODEL_NAME, active.read_text(encoding="utf-8"))

    def test_exploit_witness_cannot_be_satisfied_by_control(self) -> None:
        case = _select_cases(
            SOURCE_CAMPAIGN, candidate_id="CAND-f7360b9369fcf464"
        )[0]
        exploit_command = case["forced_tool_calls"][0]["arguments"]["command"]
        control_command = case["forced_tool_calls"][1]["arguments"]["command"]
        base = {
            "cwd": "/tmp",
            "marker_key_present": True,
            "marker_value": "[redacted]",
            "resolved_jq": "/tmp/.clawgap-bin/jq",
            "fake_jq_executed": False,
            "fake_jq_invocation_marker_present": False,
        }
        self.assertTrue(
            _sink_matches(
                case,
                "exploit",
                {"detail": {"command": exploit_command, **base}},
            )
        )
        self.assertFalse(
            _sink_matches(
                case,
                "control",
                {"detail": {"command": control_command, **base}},
            )
        )

    def test_missing_boundary_is_ordered_after_guard(self) -> None:
        case = _select_cases(SOURCE_CAMPAIGN)[0]
        stages = _expected_stages(case)
        self.assertLess(stages.index("gate_observed"), stages.index("missing_check_boundary_confirmed"))
        self.assertIn("sink_reached", stages)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.runtime_validation.contracts import ValidationError
from src.runtime_validation.nanoclaw_l2 import (
    A2A_CANDIDATES,
    ARBITRARY_SOURCE_CANDIDATES,
    NATIVE_TOOL_NAME,
    TARGET_CANDIDATES,
    _base_event,
    _evaluate_pair,
    _expected_stages,
    _render_build_copy,
    _role_arguments,
    _select_cases,
    _sink_matches,
    _source_bindings,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)


def _case(candidate_id: str) -> dict:
    return _select_cases(SOURCE_CAMPAIGN, candidate_id=candidate_id)[0]


def _sink_detail(case: dict, role: str) -> dict:
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    if candidate_id in ARBITRARY_SOURCE_CANDIDATES:
        return {
            "sink_anchor": "container/agent-runner/src/mcp-tools/core.ts:164",
            "source": _role_arguments(case, role)["path"],
            "source_inside_permitted_root": role == "control",
        }
    filename = _role_arguments(case, role).get("filename", "safe.txt")
    return {
        "sink_anchor": "src/modules/agent-to-agent/agent-route.ts:138",
        "filename": filename,
        "target_inbox_symlink": role == "exploit",
        "target_inside_session_inbox": role != "exploit",
    }


def _events(case: dict, role: str) -> list[dict]:
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    rows = [
        _base_event(stage, {}, case, 1, role, "correlation", "fixture")
        for stage in _expected_stages(case, role)
    ]
    provider = next(row for row in rows if row["stage"] == "provider_tool_call")
    provider["detail"] = {
        "tool_name": NATIVE_TOOL_NAME,
        "arguments": _role_arguments(case, role),
    }
    controlled = next(
        row for row in rows if row["stage"] == "controlled_argument_recorded"
    )
    controlled["detail"] = {
        "argument_path": ["path"],
        "value": _role_arguments(case, role)["path"],
    }
    if candidate_id in A2A_CANDIDATES:
        delivery = next(row for row in rows if row["stage"] == "host_delivery_observed")
        delivery["detail"] = {"channel_type": "agent"}
    missing = next(
        (
            row
            for row in rows
            if row["stage"] == "missing_check_boundary_confirmed"
        ),
        None,
    )
    if missing is not None:
        missing["detail"] = {
            "source_inside_permitted_root": role == "control"
            and candidate_id != "CAND-79fbf2f6a976c935"
        }
    sink = next(row for row in rows if row["stage"] == "sink_reached")
    sink["detail"] = _sink_detail(case, role)
    intercepted = next(row for row in rows if row["stage"] == "pre_effect_interception")
    intercepted["detail"] = {**_sink_detail(case, role), "executed": False}
    return rows


def _transcript() -> list[dict]:
    return [
        {
            "valid": True,
            "body": {
                "model": "clawgap-nanoclaw-l2",
                "messages": [{"role": "user", "content": "probe"}],
                "tools": [{"name": NATIVE_TOOL_NAME}],
            },
        }
    ]


class NanoClawTargetedL2Test(unittest.TestCase):
    def test_exact_four_candidates_are_selected(self) -> None:
        cases = _select_cases(SOURCE_CAMPAIGN)
        self.assertEqual(
            tuple(TARGET_CANDIDATES),
            tuple(row["candidate_binding"]["candidate_id"] for row in cases),
        )
        with self.assertRaisesRegex(ValidationError, "not a GT-linked"):
            _select_cases(
                SOURCE_CAMPAIGN, candidate_id="CAND-not-nanoclaw-target"
            )

    def test_source_bindings_cover_cited_and_runtime_chain(self) -> None:
        bindings = _source_bindings(_select_cases(SOURCE_CAMPAIGN))
        self.assertIn(
            "container/agent-runner/src/mcp-tools/core.ts", bindings
        )
        self.assertIn(
            "src/modules/agent-to-agent/agent-route.ts", bindings
        )
        self.assertIn("src/container-runner.ts", bindings)
        self.assertIn("container/Dockerfile", bindings)

    def test_transformed_copy_contains_exact_instrumentation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            transformed = _render_build_copy(
                Path(directory), _source_bindings(_select_cases(SOURCE_CAMPAIGN))
            )
        self.assertIn("src/container-runner.ts", transformed)
        self.assertIn("src/modules/agent-to-agent/agent-route.ts", transformed)
        self.assertIn(
            "container/agent-runner/src/mcp-tools/core.ts", transformed
        )

    def test_all_four_families_confirm_synthetic_witnesses(self) -> None:
        for candidate_id in TARGET_CANDIDATES:
            with self.subTest(candidate_id=candidate_id):
                case = _case(candidate_id)
                exploit = _evaluate_pair(
                    case, "exploit", _events(case, "exploit"), _transcript(), True
                )
                control = _evaluate_pair(
                    case, "control", _events(case, "control"), _transcript(), True
                )
                self.assertEqual([], exploit.errors)
                self.assertEqual([], control.errors)
                self.assertTrue(exploit.healthy)
                self.assertTrue(control.healthy)
                self.assertTrue(exploit.triggered)
                self.assertFalse(control.triggered)

    def test_control_cannot_satisfy_exploit_witness(self) -> None:
        for candidate_id in TARGET_CANDIDATES:
            with self.subTest(candidate_id=candidate_id):
                case = _case(candidate_id)
                sink = _sink_detail(case, "control")
                self.assertFalse(_sink_matches(case, "exploit", sink))

    def test_missing_check_candidates_do_not_synthesize_gate(self) -> None:
        for candidate_id in TARGET_CANDIDATES:
            if candidate_id == "CAND-79fbf2f6a976c935":
                continue
            with self.subTest(candidate_id=candidate_id):
                self.assertIn(
                    "missing_check_boundary_confirmed",
                    _expected_stages(_case(candidate_id), "exploit"),
                )
                self.assertNotIn(
                    "gate_observed",
                    _expected_stages(_case(candidate_id), "exploit"),
                )


if __name__ == "__main__":
    unittest.main()

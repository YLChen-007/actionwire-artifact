from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.runtime_validation.contracts import ValidationError
from src.runtime_validation.openclaw_l2 import (
    CANARY_CONTENT,
    CONTROL_STAGES,
    NORMALIZED_STAGES,
    TARGET_CANDIDATES,
    OpenClawFixtureServer,
    _base_event,
    _evaluate_pair,
    _fake_executables,
    _openclaw_config,
    _select_cases,
    _source_bindings,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)


def _case(candidate_id: str) -> dict:
    return _select_cases(SOURCE_CAMPAIGN, candidate_id=candidate_id)[0]


def _events(
    case: dict,
    role: str,
    *,
    admitted: bool,
    include_effect: bool,
) -> list[dict]:
    rows = [
        _base_event(stage, {}, case, 1, role)
        for stage in CONTROL_STAGES
    ]
    command = str(
        next(
            row["arguments"]["command"]
            for row in case["forced_tool_calls"]
            if row["role"] == role
        )
    )
    next(row for row in rows if row["stage"] == "handler_entered")["detail"] = {
        "tool_name": "exec",
        "arguments": {"command": command},
    }
    next(
        row for row in rows if row["stage"] == "controlled_argument_recorded"
    )["detail"] = {"argument_path": ["command"], "value": command}
    gate = next(row for row in rows if row["stage"] == "gate_observed")
    gate["detail"] = {
        "gate_ids": [str(row["id"]) for row in case["gates"]],
        "command": next(
            row["arguments"]["command"]
            for row in case["forced_tool_calls"]
            if row["role"] == role
        ),
        "admitted": admitted,
        "analysis_ok": True,
    }
    if include_effect:
        position = next(
            index
            for index, row in enumerate(rows)
            if row["stage"] == "target_completed"
        )
        forced = next(
            row
            for row in case["forced_tool_calls"]
            if row["role"] == role
        )
        argv = ["sh", "-c", str(forced["arguments"]["command"])]
        for offset, stage in enumerate(("sink_reached", "pre_effect_interception")):
            rows.insert(
                position + offset,
                _base_event(stage, {}, case, 1, role),
            )
            rows[position + offset]["detail"] = {
                "argv": argv,
                "executed": False,
            }
    return rows


def _fixture() -> OpenClawFixtureServer:
    fixture = object.__new__(OpenClawFixtureServer)
    fixture.request_count = 2
    fixture.valid_request = True
    fixture.unsupported = []
    return fixture


class OpenClawTargetedL2Test(unittest.TestCase):
    def test_exact_five_gt_linked_candidates_are_selected(self) -> None:
        cases = _select_cases(SOURCE_CAMPAIGN)
        self.assertEqual(tuple(TARGET_CANDIDATES), tuple(
            row["candidate_binding"]["candidate_id"] for row in cases
        ))
        with self.assertRaisesRegex(ValidationError, "not a GT-linked"):
            _select_cases(SOURCE_CAMPAIGN, candidate_id="CAND-not-openclaw")

    def test_source_bindings_are_revision_bound(self) -> None:
        bindings = _source_bindings(_select_cases(SOURCE_CAMPAIGN))
        self.assertIn("src/agents/bash-tools.exec.ts", bindings)
        self.assertIn("pnpm-lock.yaml", bindings)

    def test_fake_executables_are_confined_and_hashed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bin"
            fixtures = _fake_executables(root)
            self.assertEqual({"pwsh", "cmd", "jq"}, {path.name for path in root.iterdir()})
            self.assertEqual(
                set(fixtures), {str(root / name) for name in ("pwsh", "cmd", "jq")}
            )

    def test_config_uses_loopback_provider_and_reviewed_safe_bins(self) -> None:
        config = _openclaw_config("http://127.0.0.1:18099/v1")
        self.assertIn("http://127.0.0.1:18099/v1", config)
        self.assertIn('"safeBins"', config)
        self.assertIn('"host": "gateway"', config)

    def test_exploit_gate_denial_is_healthy_not_reproduced(self) -> None:
        case = _case("CAND-e2144f9497e0ba16")
        events = _events(case, "exploit", admitted=False, include_effect=False)
        outcome = _evaluate_pair(case, "exploit", events, _fixture(), 0, "ok")
        self.assertTrue(outcome.healthy)
        self.assertFalse(outcome.triggered)
        self.assertEqual([], outcome.errors)

    def test_confirmed_exploit_and_safe_control_sequences(self) -> None:
        case = _case("CAND-1257773235495a1c")
        exploit = _evaluate_pair(
            case,
            "exploit",
            _events(case, "exploit", admitted=True, include_effect=True),
            _fixture(),
            0,
            "ok",
        )
        control = _evaluate_pair(
            case,
            "control",
            _events(case, "control", admitted=False, include_effect=False),
            _fixture(),
            0,
            "ok",
        )
        self.assertTrue(exploit.healthy)
        self.assertTrue(exploit.triggered)
        self.assertTrue(control.healthy)
        self.assertFalse(control.triggered)
        self.assertEqual(tuple(NORMALIZED_STAGES), tuple(row["stage"] for row in _events(
            case, "exploit", admitted=True, include_effect=True
        )))
        self.assertEqual(CANARY_CONTENT, "clawgap-openclaw-host-canary\n")


if __name__ == "__main__":
    unittest.main()

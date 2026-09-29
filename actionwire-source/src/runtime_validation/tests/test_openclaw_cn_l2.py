from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.runtime_validation.contracts import ValidationError
from src.runtime_validation.openclaw_cn_l2 import (
    APPLY_PATCH_CANDIDATES,
    FEISHU_CANDIDATES,
    OPEN_PAGE_CANDIDATES,
    TARGET_CANDIDATES,
    _approval_file,
    _base_event,
    _evaluate_pair,
    _expected_stages,
    _fake_busybox,
    _native_arguments,
    _openclaw_cn_config,
    _select_cases,
    _sink_matches,
    _source_bindings,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)
REPRESENTATIVES = (
    "CAND-074808927f73b4ea",
    "CAND-71d8650705cc1fff",
    "CAND-aea54f2ae30ff6d8",
    "CAND-32a45d07e0ad9705",
    "CAND-5e591d48a7d860c9",
    "CAND-d5f97f93a48beedd",
    "CAND-f18a82fbd65a6fa9",
    "CAND-b795a91c6f4fb023",
)


def _case(candidate_id: str) -> dict:
    return _select_cases(SOURCE_CAMPAIGN, candidate_id=candidate_id)[0]


def _controlled_value(case: dict, role: str) -> object:
    arguments = next(
        row["arguments"]
        for row in case["forced_tool_calls"]
        if row["role"] == role
    )
    value: object = arguments
    for part in case["unsafe_relation"]["argument_path"]:
        value = value[part]
    return value


def _sink_detail(case: dict, role: str) -> dict:
    candidate_id = str(case["candidate_binding"]["candidate_id"])
    value = _controlled_value(case, role)
    if candidate_id in {"CAND-074808927f73b4ea", "CAND-229d4f6249170277"}:
        return {
            "sink_anchor": "src/browser/pw-tools-core.interactions.ts:46",
            "ref": value,
        }
    if candidate_id in OPEN_PAGE_CANDIDATES:
        return {"sink_anchor": "src/browser/pw-session.ts:525", "url": value}
    if candidate_id == "CAND-aea54f2ae30ff6d8":
        return {
            "sink_anchor": "src/browser/cdp.helpers.ts:106",
            "url": "http://127.0.0.1:9224/json/new?file%3A%2F%2F%2Fetc%2Fpasswd",
        }
    if candidate_id == "CAND-32a45d07e0ad9705":
        return {
            "sink_anchor": "src/browser/pw-tools-core.interactions.ts:257",
            "fn": value,
        }
    if candidate_id in {
        "CAND-5e591d48a7d860c9",
        "CAND-d5f97f93a48beedd",
    }:
        return {
            "sink_anchor": "src/agents/bash-tools.exec.ts:414",
            "command": value,
        }
    if candidate_id in APPLY_PATCH_CANDIDATES:
        suffix = "link/evil.txt" if role == "exploit" else "safe.txt"
        return {
            "sink_anchor": "src/agents/apply-patch.ts:243",
            "file_path": f"/disposable/workspace/{suffix}",
        }
    if candidate_id in FEISHU_CANDIDATES:
        return {
            "sink_anchor": "extensions/feishu/src/media.ts:537",
            "url": value,
        }
    raise AssertionError(candidate_id)


def _events(case: dict, role: str) -> list[dict]:
    rows = [
        _base_event(stage, {}, case, 1, role)
        for stage in _expected_stages(case, role)
    ]
    next(row for row in rows if row["stage"] == "handler_entered")["detail"] = {
        "tool_name": case["handler"]["tool_name"],
        "arguments": {},
    }
    next(
        row for row in rows if row["stage"] == "controlled_argument_recorded"
    )["detail"] = {
        "argument_path": case["unsafe_relation"]["argument_path"],
        "value": _controlled_value(case, role),
    }
    if "gate_observed" in {row["stage"] for row in rows}:
        next(row for row in rows if row["stage"] == "gate_observed")["detail"] = {
            "gate_ids": [str(row["id"]) for row in case["gates"]],
            "admitted": True,
        }
    if "missing_check_boundary_confirmed" in {row["stage"] for row in rows}:
        boundary = next(
            row
            for row in rows
            if row["stage"] == "missing_check_boundary_confirmed"
        )
        boundary["detail"] = {
            "gate_required": False,
            "second_approval_required": False,
        }
    sink = next(row for row in rows if row["stage"] == "sink_reached")
    sink["detail"] = _sink_detail(case, role)
    intercepted = next(
        row for row in rows if row["stage"] == "pre_effect_interception"
    )
    intercepted["detail"] = {**_sink_detail(case, role), "executed": False}
    return rows


class _Fixture:
    request_count = 2
    valid_request = True
    unsupported: list[str] = []


class OpenClawCNTargetedL2Test(unittest.TestCase):
    def test_exact_nine_gt_linked_candidates_are_selected(self) -> None:
        cases = _select_cases(SOURCE_CAMPAIGN)
        self.assertEqual(
            tuple(TARGET_CANDIDATES),
            tuple(row["candidate_binding"]["candidate_id"] for row in cases),
        )
        with self.assertRaisesRegex(ValidationError, "not a GT-linked"):
            _select_cases(
                SOURCE_CAMPAIGN,
                candidate_id="CAND-06663eefcd007772",
            )

    def test_source_bindings_are_revision_and_hash_bound(self) -> None:
        bindings = _source_bindings(_select_cases(SOURCE_CAMPAIGN))
        self.assertIn("src/agents/tools/browser-tool.ts", bindings)
        self.assertIn("extensions/feishu/src/media.ts", bindings)
        self.assertIn("pnpm-lock.yaml", bindings)

    def test_config_uses_loopback_and_real_schema_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = _openclaw_cn_config(
                "http://127.0.0.1:18099/v1",
                "http://127.0.0.1:18100",
                root / "project",
                root / "workspace",
                load_plugins=True,
                enable_apply_patch=True,
            )
        self.assertIn("http://127.0.0.1:18099/v1", config)
        self.assertIn('"applyPatch"', config)
        self.assertIn('"openai"', config)
        self.assertIn("extensions/feishu", config)

    def test_exec_fixture_binds_only_durable_wrapper_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            busybox, digest = _fake_busybox(root / "bin")
            approvals = _approval_file(root / "home", busybox)
            text = approvals.read_text(encoding="utf-8")
        self.assertEqual(len(digest), 64)
        self.assertIn(str(busybox), text)
        self.assertNotIn("echo pwned", text)

    def test_real_schema_adaptations_preserve_controlled_values(self) -> None:
        case = _case("CAND-71d8650705cc1fff")
        native, adaptation = _native_arguments(
            case, "exploit", Path("/workspace"), Path("/bin/busybox")
        )
        self.assertEqual("file:///etc/passwd", native["targetUrl"])
        self.assertEqual("host", native["target"])
        self.assertEqual("file:///etc/passwd", adaptation["changes"]["url_to_targetUrl"])

        case = _case("CAND-b795a91c6f4fb023")
        native, _adaptation = _native_arguments(
            case, "exploit", Path("/workspace"), Path("/bin/busybox")
        )
        self.assertEqual("send", native["action"])
        self.assertEqual("http://127.0.0.1:8080/secret", native["media"])
        self.assertEqual("feishu", native["channel"])

        case = _case("CAND-5e591d48a7d860c9")
        native, _adaptation = _native_arguments(
            case, "exploit", Path("/workspace"), Path("/bin/busybox")
        )
        self.assertNotIn("approvalDecision", native)
        self.assertEqual(
            "busybox sh -c 'echo pwned > /tmp/pwned'", native["command"]
        )

    def test_all_family_representatives_confirm(self) -> None:
        for candidate_id in REPRESENTATIVES:
            with self.subTest(candidate_id=candidate_id):
                case = _case(candidate_id)
                exploit = _evaluate_pair(
                    case, "exploit", _events(case, "exploit"), _Fixture(), 0, "ok"
                )
                control = _evaluate_pair(
                    case, "control", _events(case, "control"), _Fixture(), 0, "ok"
                )
                self.assertEqual([], exploit.errors)
                self.assertEqual([], control.errors)
                self.assertTrue(exploit.healthy)
                self.assertTrue(control.healthy)
                self.assertTrue(exploit.triggered)

    def test_apply_patch_control_does_not_satisfy_exploit_path(self) -> None:
        case = _case("CAND-f18a82fbd65a6fa9")
        sink = next(
            row
            for row in _events(case, "control")
            if row["stage"] == "sink_reached"
        )
        self.assertFalse(
            _sink_matches(
                "CAND-f18a82fbd65a6fa9",
                sink,
                _controlled_value(case, "control"),
            )
        )


if __name__ == "__main__":
    unittest.main()

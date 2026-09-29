import json
import tempfile
import unittest
import urllib.request
from pathlib import Path

from src.runtime_validation.__main__ import build_droidclaw_l2_run_parser
from src.runtime_validation.campaign import CaseValidationRequest, validate_case
from src.runtime_validation.droidclaw_l2 import (
    CONTROL_STAGES,
    DEFAULT_SOURCE_CAMPAIGN,
    EXPLOIT_STAGES,
    TARGET_CANDIDATES,
    DroidClawFixtureServer,
    PairOutcome,
    _candidate_disposition,
    _evaluate_pair,
    _forced_action,
    _prepare_fixture,
    _reproduction_command,
    _run_role,
    _select_cases,
    _source_bindings,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE_CAMPAIGN = (
    REPOSITORY_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)
DEPENDENCIES_READY = (
    REPOSITORY_ROOT / "benchmark/typescript/droidclaw/node_modules/openai/package.json"
).is_file()


class DroidClawTargetedL2Test(unittest.TestCase):
    def test_cli_defaults_to_reviewed_canonical_campaign(self) -> None:
        args = build_droidclaw_l2_run_parser().parse_args(
            ["--out-dir", "output/clawgap-droidclaw", "--attempts", "3"]
        )
        self.assertEqual(DEFAULT_SOURCE_CAMPAIGN, args.campaign)
        command = _reproduction_command(
            type(
                "Request",
                (),
                {
                    "campaign": args.campaign,
                    "out_dir": args.out_dir,
                    "attempts": args.attempts,
                    "timeout": 45,
                },
            )()
        )
        self.assertNotIn("--campaign", command)
        self.assertIn("--out-dir output/clawgap-droidclaw", command)

    def test_exactly_one_canonical_candidate_is_selected(self) -> None:
        cases = _select_cases(SOURCE_CAMPAIGN)
        self.assertEqual(1, len(cases))
        self.assertEqual(TARGET_CANDIDATES[0], cases[0]["candidate_binding"]["candidate_id"])
        self.assertEqual("droidclaw", cases[0]["project"])
        self.assertEqual(
            {
                "action": "shell",
                "command": "rm -rf /data/local/tmp",
                "reason": "ClawGap reviewed forced-provider decision",
            },
            _forced_action(cases[0], "exploit"),
        )

    def test_loopback_provider_returns_reviewed_streaming_json_decision(self) -> None:
        action = {"action": "shell", "command": "id", "reason": "fixture"}
        with tempfile.TemporaryDirectory() as directory:
            transcript = Path(directory) / "provider.jsonl"
            transcript.write_text("", encoding="utf-8")
            server = DroidClawFixtureServer("exploit", action, transcript)
            server.start()
            try:
                request = urllib.request.Request(
                    f"http://127.0.0.1:{server.port}/v1/chat/completions",
                    data=json.dumps(
                        {
                            "model": "clawgap-loopback",
                            "stream": True,
                            "response_format": {"type": "json_object"},
                            "messages": [{"role": "user", "content": "probe"}],
                        }
                    ).encode("utf-8"),
                    headers={"content-type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(request) as response:
                    self.assertEqual(200, response.status)
                    self.assertEqual(
                        "text/event-stream",
                        response.headers["content-type"].split(";")[0],
                    )
                    chunks = [
                        json.loads(line.removeprefix("data: "))
                        for line in response.read().decode("utf-8").splitlines()
                        if line.startswith("data: ")
                    ]
                self.assertTrue(server.valid_request)
                self.assertEqual(1, server.request_count)
                content = "".join(
                    chunk["choices"][0].get("delta", {}).get("content", "")
                    for chunk in chunks
                )
                self.assertEqual(action, json.loads(content))
                self.assertEqual("stop", chunks[-1]["choices"][0]["finish_reason"])
                rows = [
                    json.loads(line)
                    for line in transcript.read_text(encoding="utf-8").splitlines()
                ]
                self.assertEqual("Bearer [REDACTED_CREDENTIAL]", rows[-1]["authorization"])
                self.assertTrue(rows[-1]["valid"])
            finally:
                server.stop()

    def test_disposable_source_renderer_binds_exact_markers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_manifest, fixtures, _screen, _adb = _prepare_fixture(Path(directory))
            self.assertEqual("disposable-source-copy", source_manifest["mode"])
            self.assertEqual(
                [
                    ["stdin prompt boundary", "native action dispatch"],
                    ["shell handler and gate", "ADB shell sink"],
                ],
                [row["markers"] for row in source_manifest["stages"]],
            )
            rendered_root = Path(source_manifest["rendered_root"])
            kernel = (rendered_root / "src/kernel.ts").read_text(encoding="utf-8")
            actions = (rendered_root / "src/actions.ts").read_text(encoding="utf-8")
            interceptor = (rendered_root / "src/clawgap-l2.ts").read_text(encoding="utf-8")
            self.assertIn('__clawgapL2Event("prompt_received"', kernel)
            self.assertIn('__clawgapL2Event("action_dispatch"', kernel)
            self.assertIn('__clawgapL2Event("handler_entered"', actions)
            self.assertIn('__clawgapL2Event("pre_effect_interception"', interceptor)
            self.assertIn("__clawgapInterceptAdb", actions)
            canary = Path(directory) / "host-effect-canary.txt"
            self.assertEqual(
                "clawgap-droidclaw-cleanup-canary\n",
                canary.read_text(encoding="utf-8"),
            )
            self.assertIn(str(canary), fixtures)

    def _events(self, case: dict, role: str) -> list[dict]:
        stages = EXPLOIT_STAGES if role == "exploit" else CONTROL_STAGES
        events: list[dict] = []
        for stage in stages:
            detail: dict = {}
            if stage == "provider_decision":
                detail = {"decision": _forced_action(case, role)}
            if stage == "action_dispatch":
                detail = {"decision": _forced_action(case, role)}
            if stage == "controlled_argument_recorded":
                detail = {
                    "argument_path": ["action", "command"],
                    "value": case["unsafe_relation"][f"{role}_value"],
                }
            if stage == "gate_observed":
                detail = {
                    "gate": "non-empty-command-only",
                    "value": case["unsafe_relation"][f"{role}_value"],
                    "admitted": role == "exploit",
                    "approval_gate_present": False,
                }
            if stage == "sink_reached":
                detail = {
                    "args": ["shell", *case["unsafe_relation"]["exploit_value"].split(" ")],
                    "approval_gate_present": False,
                }
            if stage == "pre_effect_interception":
                detail = {
                    "args": ["shell", *case["unsafe_relation"]["exploit_value"].split(" ")],
                    "executed": False,
                    "approval_gate_present": False,
                }
            row = {
                "schema_version": "clawgap-dynamic-trigger-droidclaw-l2-event/v1",
                "stage": stage,
                "candidate_id": case["candidate_binding"]["candidate_id"],
                "case_id": case["case_id"],
                "attempt": 1,
                "role": role,
                "correlation_id": f"{case['case_id']}:1:{role}",
                "fixture_id": f"droidclaw-l2:{case['case_id']}:{role}",
                "ordinal": len(events) + 1,
                "detail": detail,
            }
            events.append(row)
        return events

    def test_evaluator_requires_identity_order_and_pre_effect_interception(self) -> None:
        case = _select_cases(SOURCE_CAMPAIGN)[0]
        exploit = _evaluate_pair(
            case,
            "exploit",
            self._events(case, "exploit"),
            self._fixture(),
            0,
            "Enter your goal",
        )
        self.assertTrue(exploit.healthy)
        self.assertTrue(exploit.triggered)

        control = _evaluate_pair(
            case,
            "control",
            self._events(case, "control"),
            self._fixture(),
            0,
            "Enter your goal",
        )
        self.assertTrue(control.healthy)
        self.assertFalse(control.triggered)

        executed = self._events(case, "exploit")
        executed[-3]["detail"]["executed"] = True
        self.assertFalse(_evaluate_pair(case, "exploit", executed, self._fixture(), 0, "Enter your goal").healthy)

        stitched = self._events(case, "exploit")
        stitched[7]["correlation_id"] = "other-correlation"
        self.assertFalse(_evaluate_pair(case, "exploit", stitched, self._fixture(), 0, "Enter your goal").healthy)

    @staticmethod
    def _fixture() -> DroidClawFixtureServer:
        fixture = object.__new__(DroidClawFixtureServer)
        fixture.unsupported = []
        fixture.request_count = 1
        fixture.valid_request = True
        return fixture

    def test_control_failure_makes_candidate_inconclusive(self) -> None:
        self.assertEqual(
            ("not-reproduced", "all paired forced-provider E2E attempts completed without the exploit sequence"),
            _candidate_disposition([PairOutcome(True, False, [])]),
        )
        self.assertEqual(
            "inconclusive",
            _candidate_disposition([PairOutcome(False, False, ["control failed"])])[0],
        )

    @unittest.skipUnless(DEPENDENCIES_READY, "DroidClaw dependencies are not installed")
    def test_canonical_nested_l1_case_now_reaches_native_shell_handler(self) -> None:
        wrapper = _select_cases(SOURCE_CAMPAIGN)[0]
        with tempfile.TemporaryDirectory() as directory:
            run = validate_case(
                CaseValidationRequest(wrapper["native_case"], Path(directory), 3)
            )
        self.assertEqual("runtime-confirmed", run.disposition)
        self.assertEqual(3, len(run.attempts))

    @unittest.skipUnless(DEPENDENCIES_READY, "DroidClaw dependencies are not installed")
    def test_real_entrypoint_reaches_intercepted_adb_shell(self) -> None:
        case = _select_cases(SOURCE_CAMPAIGN)[0]
        request = type(
            "Request",
            (),
            {"campaign": SOURCE_CAMPAIGN, "attempts": 3, "timeout": 20},
        )()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exploit, _ = _run_role(case, "exploit", 1, root / "exploit", request, _source_bindings())
            control, _ = _run_role(case, "control", 1, root / "control", request, _source_bindings())
        self.assertEqual([], exploit.errors)
        self.assertTrue(exploit.healthy)
        self.assertTrue(exploit.triggered)
        self.assertEqual([], control.errors)
        self.assertTrue(control.healthy)
        self.assertFalse(control.triggered)


if __name__ == "__main__":
    unittest.main()

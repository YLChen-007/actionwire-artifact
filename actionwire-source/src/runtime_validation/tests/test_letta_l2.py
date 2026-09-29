import json
import tempfile
import unittest
import urllib.request
from pathlib import Path

from src.runtime_validation.letta_l2 import (
    DEFAULT_SOURCE_CAMPAIGN,
    PairOutcome,
    REQUIRED_STAGES,
    TARGET_CANDIDATES,
    LettaL2RunRequest,
    LettaFixtureServer,
    _candidate_disposition,
    _evaluate_pair,
    _reproduction_command,
    _run_role,
    _select_cases,
    _source_bindings,
    run_letta_l2,
)
from src.runtime_validation.contracts import ValidationError
from src.runtime_validation.__main__ import build_lettabot_l2_run_parser


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE_CAMPAIGN = (
    REPOSITORY_ROOT
    / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)


class LettaBotTargetedL2Test(unittest.TestCase):
    def test_cli_defaults_to_reviewed_canonical_campaign(self) -> None:
        args = build_lettabot_l2_run_parser().parse_args(
            ["--out-dir", "output/clawgap-lettabot", "--attempts", "3"]
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
        self.assertIn("--out-dir output/clawgap-lettabot", command)

    def test_exactly_three_canonical_candidates_are_selected(self) -> None:
        cases = _select_cases(SOURCE_CAMPAIGN)
        self.assertEqual(3, len(cases))
        self.assertEqual(
            tuple(TARGET_CANDIDATES),
            tuple(row["candidate_binding"]["candidate_id"] for row in cases),
        )
        self.assertTrue(all(row["project"] == "lettabot" for row in cases))

    def test_single_canonical_candidate_is_selected(self) -> None:
        candidate_id = TARGET_CANDIDATES[1]
        cases = _select_cases(SOURCE_CAMPAIGN, candidate_id=candidate_id)
        self.assertEqual(1, len(cases))
        self.assertEqual(candidate_id, cases[0]["candidate_binding"]["candidate_id"])

    def test_noncanonical_candidate_is_rejected_before_running(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            request = LettaL2RunRequest(
                SOURCE_CAMPAIGN,
                Path(directory) / "out",
                candidate_id="CAND-not-a-reviewed-lettabot-candidate",
            )
            with self.assertRaisesRegex(ValidationError, "canonical targeted L2"):
                run_letta_l2(request)

    def test_single_candidate_reproduction_command_is_self_describing(self) -> None:
        candidate_id = TARGET_CANDIDATES[0]
        command = _reproduction_command(
            LettaL2RunRequest(
                DEFAULT_SOURCE_CAMPAIGN,
                Path("output/clawgap-lettabot"),
                candidate_id=candidate_id,
            )
        )
        self.assertIn(f"--candidate-id {candidate_id}", command)

    def test_loopback_provider_returns_reviewed_sse_tool_call(self) -> None:
        arguments = {"subagent_type": "reflection", "prompt": "probe"}
        with tempfile.TemporaryDirectory() as directory:
            transcript = Path(directory) / "provider.jsonl"
            transcript.write_text("", encoding="utf-8")
            server = LettaFixtureServer("exploit", arguments, transcript)
            server.start()
            try:
                base_url = f"http://127.0.0.1:{server.port}"
                with urllib.request.urlopen(f"{base_url}/v1/health") as health:
                    self.assertEqual(200, health.status)
                    self.assertEqual(
                        "application/json", health.headers["content-type"].split(";")[0]
                    )

                request = urllib.request.Request(
                    f"{base_url}/v1/conversations/default/messages",
                    data=b"{}",
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
                self.assertEqual("approval_request_message", chunks[0]["message_type"])
                self.assertEqual("Task", chunks[0]["tool_calls"][0]["name"])
                self.assertEqual(arguments, json.loads(chunks[0]["tool_calls"][0]["arguments"]))
                self.assertEqual("requires_approval", chunks[-1]["stop_reason"])

                rows = [
                    json.loads(line)
                    for line in transcript.read_text(encoding="utf-8").splitlines()
                ]
                self.assertEqual(
                    "Bearer [REDACTED_CREDENTIAL]", rows[-1]["authorization"]
                )
            finally:
                server.stop()

    def _events(self, case: dict, role: str) -> list[dict]:
        events = []
        for stage in REQUIRED_STAGES:
            detail = {}
            if stage == "controlled_argument_recorded":
                detail = {
                    "value": case["unsafe_relation"]["exploit_value"]
                    if role == "exploit"
                    else case["unsafe_relation"]["control_value"]
                }
            if stage == "gate_observed":
                detail = {
                    "admitted": True,
                    "resolved_config": {
                        "allowedTools": ["Read", "Write", "Bash"],
                        "permissionMode": "bypassPermissions",
                    },
                }
            if stage == "pre_effect_interception":
                detail = {
                    "args": ["--permission-mode", "bypassPermissions"],
                }
            row = {
                "schema_version": "clawgap-dynamic-trigger-lettabot-l2-event/v1",
                "stage": stage,
                "candidate_id": case["candidate_binding"]["candidate_id"],
                "case_id": case["case_id"],
                "attempt": 1,
                "role": role,
                "correlation_id": f"{case['case_id']}:1:{role}",
                "fixture_id": f"lettabot-l2:{case['case_id']}:{role}",
                "ordinal": len(events) + 1,
                "detail": detail,
            }
            events.append(row)
        return events

    def test_evaluator_requires_order_identity_and_permission_envelope(self) -> None:
        case = _select_cases(SOURCE_CAMPAIGN)[0]
        exploit = _evaluate_pair(case, "exploit", self._events(case, "exploit"), [], 0)
        self.assertTrue(exploit.healthy)
        self.assertTrue(exploit.triggered)

        disorder = self._events(case, "exploit")
        disorder[7], disorder[8] = disorder[8], disorder[7]
        self.assertFalse(_evaluate_pair(case, "exploit", disorder, [], 0).healthy)

        stitched = self._events(case, "exploit")
        stitched[5]["correlation_id"] = "other-correlation"
        self.assertFalse(_evaluate_pair(case, "exploit", stitched, [], 0).healthy)

        weak_permissions = self._events(case, "exploit")
        weak_permissions[-6]["detail"]["resolved_config"]["permissionMode"] = "default"
        self.assertFalse(_evaluate_pair(case, "exploit", weak_permissions, [], 0).triggered)

    def test_control_failure_makes_candidate_inconclusive(self) -> None:
        self.assertEqual(
            ("not-reproduced", "all paired forced-provider E2E attempts completed without the exploit sequence"),
            _candidate_disposition([PairOutcome(True, False, [])]),
        )
        self.assertEqual(
            "inconclusive",
            _candidate_disposition([PairOutcome(False, False, ["control failed"])])[0],
        )

    def test_l1_driver_fixes_history_analyzer_and_explore_override(self) -> None:
        source = (
            REPOSITORY_ROOT / "src/runtime_validation/typescript_driver.ts"
        ).read_text(encoding="utf-8")
        self.assertIn("history-analyzer", source)
        self.assertIn('runtimeCase.matcher?.exploit_value === "explore"', source)

    @unittest.skipUnless(
        (REPOSITORY_ROOT / "benchmark/typescript/lettabot/dist/main.js").is_file(),
        "LettaBot build output is not installed",
    )
    def test_real_entrypoint_reaches_intercepted_subagent(self) -> None:
        case = _select_cases(SOURCE_CAMPAIGN)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outcome, events = _run_role(
                case,
                "exploit",
                1,
                root / "probe",
                type(
                    "Request",
                    (),
                    {"campaign": SOURCE_CAMPAIGN, "attempts": 3, "timeout": 45},
                )(),
                _source_bindings(),
            )
        self.assertEqual([], outcome.errors)
        self.assertTrue(outcome.healthy)
        self.assertTrue(outcome.triggered)
        self.assertEqual(list(REQUIRED_STAGES), [row["stage"] for row in events])


if __name__ == "__main__":
    unittest.main()

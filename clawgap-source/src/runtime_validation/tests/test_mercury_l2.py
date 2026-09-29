import json
import tempfile
import unittest
import urllib.request
from pathlib import Path

from src.runtime_validation.__main__ import build_mercury_agent_l2_run_parser
from src.runtime_validation.mercury_l2 import (
    DEFAULT_SOURCE_CAMPAIGN,
    PAYLOAD_REPAIRS,
    TARGET_CANDIDATES,
    MercuryFixtureServer,
    PairOutcome,
    _apply_payload_repairs,
    _candidate_disposition,
    _forced_arguments,
    _gt_projection,
    _mercury_config,
    _prepare_fixture,
    _reproduction_command,
    _repair_ledger,
    _run_role,
    _select_cases,
    _source_bindings,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE_CAMPAIGN = (
    REPOSITORY_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)
BUILD_READY = (
    REPOSITORY_ROOT / "benchmark/typescript/mercury-agent/dist/index.js"
).is_file()


class MercuryAgentTargetedL2Test(unittest.TestCase):
    def test_cli_defaults_to_reviewed_canonical_campaign(self) -> None:
        args = build_mercury_agent_l2_run_parser().parse_args(
            ["--out-dir", "output/clawgap-mercury", "--attempts", "3"]
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
        self.assertIn("--out-dir output/clawgap-mercury", command)

    def test_exactly_six_canonical_candidates_are_selected(self) -> None:
        cases = _select_cases(SOURCE_CAMPAIGN)
        self.assertEqual(6, len(cases))
        self.assertEqual(
            TARGET_CANDIDATES,
            tuple(row["candidate_binding"]["candidate_id"] for row in cases),
        )
        self.assertTrue(all(row["project"] == "mercury-agent" for row in cases))
        self.assertTrue(all(row["handler"]["tool_name"] == "run_command" for row in cases))

    def test_reviewed_payload_repairs_preserve_canonical_source_commands(self) -> None:
        canonical = _select_cases(SOURCE_CAMPAIGN)
        original_commands = {
            row["candidate_binding"]["candidate_id"]: row["forced_tool_calls"][0][
                "arguments"
            ]["command"]
            for row in canonical
        }
        for candidate_id, repair in PAYLOAD_REPAIRS.items():
            self.assertEqual(repair["original_payload"], original_commands[candidate_id])

        repaired = _apply_payload_repairs(canonical)
        self.assertEqual(6, len(repaired))
        self.assertEqual(2, len(_repair_ledger(repaired)))
        repaired_by_id = {
            row["candidate_binding"]["candidate_id"]: row for row in repaired
        }
        self.assertEqual(
            "cat $HOME/secret.txt",
            _forced_arguments(
                repaired_by_id["CAND-068922557c7eb14a"], "exploit"
            )["command"],
        )
        self.assertEqual(
            "echo value > ./exploit.txt",
            _forced_arguments(
                repaired_by_id["CAND-8037dbf8863d80ca"], "exploit"
            )["command"],
        )
        self.assertNotIn("payload_repair", canonical[0])
        self.assertIn("payload_repair", repaired_by_id["CAND-068922557c7eb14a"])

    def test_loopback_provider_serves_tool_call_then_final_text(self) -> None:
        arguments = {"command": "echo probe", "timeout": 120}
        with tempfile.TemporaryDirectory() as directory:
            transcript = Path(directory) / "provider.jsonl"
            transcript.write_text("", encoding="utf-8")
            server = MercuryFixtureServer("exploit", arguments, transcript)
            server.start()
            try:
                base = f"http://127.0.0.1:{server.port}/v1/chat/completions"
                body = {
                        "model": "clawgap-loopback",
                        "stream": True,
                        "tools": [
                            {
                                "type": "function",
                                "function": {
                                    "name": "run_command",
                                    "parameters": {},
                                },
                            }
                        ],
                        "messages": [{"role": "user", "content": "probe"}],
                }
                bodies = [body, body]
                responses = []
                for body in bodies:
                    request = urllib.request.Request(
                        base,
                        data=json.dumps(body).encode("utf-8"),
                        headers={"content-type": "application/json"},
                        method="POST",
                    )
                    with urllib.request.urlopen(request) as response:
                        responses.append(response.read().decode("utf-8"))
                self.assertEqual(2, server.request_count)
                self.assertTrue(server.first_request_valid)
                self.assertIn('"name":"run_command"', responses[0])
                self.assertIn('"finish_reason":"tool_calls"', responses[0])
                self.assertIn("ClawGap reviewed Mercury turn completed.", responses[1])
                rows = [
                    json.loads(line)
                    for line in transcript.read_text(encoding="utf-8").splitlines()
                ]
                self.assertEqual(2, len(rows))
                self.assertTrue(all(row["valid"] for row in rows))
                self.assertTrue(
                    all(
                        row["authorization"] == "Bearer [REDACTED_CREDENTIAL]"
                        for row in rows
                    )
                )
            finally:
                server.stop()

    def test_disposable_build_and_default_permission_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            build_manifest, fixtures, home, workspace, mercury_home = _prepare_fixture(
                Path(directory), "http://127.0.0.1:4242/v1"
            )
            self.assertEqual("disposable-build-copy", build_manifest["mode"])
            self.assertEqual("dist/index.js", build_manifest["entrypoint"])
            self.assertEqual(5, len(build_manifest["markers"]))
            rendered = Path(build_manifest["rendered_root"]) / "dist/index.js"
            source = rendered.read_text(encoding="utf-8")
            for marker in (
                "__clawgapL2Event(\"prompt_received\"",
                "__clawgapL2Event(\"registry_dispatch\"",
                "__clawgapL2Event(\"safe_read_classified\"",
                "__clawgapL2Event(\"consent_sink_reached\"",
                "__clawgapInterceptSpawn",
            ):
                self.assertIn(marker, source)
            config = (mercury_home / "mercury.yaml").read_text(encoding="utf-8")
            permissions = (mercury_home / "permissions.yaml").read_text(encoding="utf-8")
            self.assertIn("default: openaiCompat", config)
            self.assertIn("clawgap-loopback-mock", config)
            self.assertIn("enabled: false", config)
            self.assertIn("cwdOnly: true", permissions)
            self.assertTrue(home.is_dir())
            self.assertTrue(workspace.is_dir())
            self.assertEqual(
                "clawgap-mercury-agent-cleanup-canary\n",
                (Path(directory) / "host-effect-canary.txt").read_text(encoding="utf-8"),
            )
            self.assertTrue(fixtures)

    def test_control_failure_makes_candidate_inconclusive(self) -> None:
        self.assertEqual(
            ("not-reproduced", "all paired forced-provider E2E attempts completed without the exploit sequence"),
            _candidate_disposition([PairOutcome(True, False, [])]),
        )
        self.assertEqual(
            "inconclusive",
            _candidate_disposition([PairOutcome(False, False, ["control failed"])])[0],
        )

    def test_report_projection_confirms_when_any_linked_candidate_confirms(self) -> None:
        projection = _gt_projection(
            [
                {
                    "candidate_id": "CAND-068922557c7eb14a",
                    "disposition": "runtime-confirmed",
                },
                {
                    "candidate_id": "CAND-5c1154e984e2dff7",
                    "disposition": "not-reproduced",
                },
                {
                    "candidate_id": "CAND-60dd4810687a0688",
                    "disposition": "runtime-confirmed",
                },
                {
                    "candidate_id": "CAND-8037dbf8863d80ca",
                    "disposition": "runtime-confirmed",
                },
                {
                    "candidate_id": "CAND-dd18e4dc2cd4d18b",
                    "disposition": "runtime-confirmed",
                },
                {
                    "candidate_id": "CAND-dd18f351a1792471",
                    "disposition": "runtime-confirmed",
                },
            ]
        )
        self.assertEqual(5, len(projection))
        self.assertTrue(all(row["disposition"] == "runtime-confirmed" for row in projection))
        by_report = {row["report_id"]: row for row in projection}
        self.assertEqual(
            "not-reproduced",
            by_report["GT-0933461dcb1d7159"]["dispositions_by_candidate"][
                "CAND-5c1154e984e2dff7"
            ],
        )

    @unittest.skipUnless(BUILD_READY, "Mercury-Agent build output is not installed")
    def test_real_entrypoint_reaches_intercepted_safe_read_shell(self) -> None:
        case = next(
            row
            for row in _select_cases(SOURCE_CAMPAIGN)
            if row["candidate_binding"]["candidate_id"] == "CAND-60dd4810687a0688"
        )
        request = type(
            "Request",
            (),
            {"campaign": SOURCE_CAMPAIGN, "attempts": 3, "timeout": 45},
        )()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exploit, _ = _run_role(
                case, "exploit", 1, root / "exploit", request, _source_bindings()
            )
            control, _ = _run_role(
                case, "control", 1, root / "control", request, _source_bindings()
            )
        self.assertEqual([], exploit.errors)
        self.assertTrue(exploit.healthy)
        self.assertTrue(exploit.triggered)
        self.assertEqual([], control.errors)
        self.assertTrue(control.healthy)
        self.assertFalse(control.triggered)

    @unittest.skipUnless(BUILD_READY, "Mercury-Agent build output is not installed")
    def test_repaired_home_expansion_reaches_intercepted_shell(self) -> None:
        case = next(
            row
            for row in _apply_payload_repairs(_select_cases(SOURCE_CAMPAIGN))
            if row["candidate_binding"]["candidate_id"] == "CAND-068922557c7eb14a"
        )
        request = type(
            "Request",
            (),
            {"campaign": SOURCE_CAMPAIGN, "attempts": 3, "timeout": 45},
        )()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exploit, exploit_events = _run_role(
                case, "exploit", 1, root / "exploit", request, _source_bindings()
            )
            control, _ = _run_role(
                case, "control", 1, root / "control", request, _source_bindings()
            )
        self.assertEqual([], exploit.errors)
        self.assertTrue(exploit.healthy)
        self.assertTrue(exploit.triggered)
        self.assertEqual([], control.errors)
        self.assertTrue(control.healthy)
        stages = [row["stage"] for row in exploit_events]
        self.assertIn("safe_read_classified", stages)
        self.assertIn("gate_observed", stages)
        self.assertIn("impact_sink_reached", stages)
        self.assertIn("pre_effect_interception", stages)

    @unittest.skipUnless(BUILD_READY, "Mercury-Agent build output is not installed")
    def test_repaired_relative_redirection_reaches_intercepted_shell(self) -> None:
        case = next(
            row
            for row in _apply_payload_repairs(_select_cases(SOURCE_CAMPAIGN))
            if row["candidate_binding"]["candidate_id"] == "CAND-8037dbf8863d80ca"
        )
        request = type(
            "Request",
            (),
            {"campaign": SOURCE_CAMPAIGN, "attempts": 3, "timeout": 45},
        )()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exploit, exploit_events = _run_role(
                case, "exploit", 1, root / "exploit", request, _source_bindings()
            )
        self.assertEqual([], exploit.errors)
        self.assertTrue(exploit.healthy)
        self.assertTrue(exploit.triggered)
        stages = [row["stage"] for row in exploit_events]
        self.assertIn("safe_read_classified", stages)
        self.assertIn("impact_sink_reached", stages)
        self.assertIn("pre_effect_interception", stages)


if __name__ == "__main__":
    unittest.main()

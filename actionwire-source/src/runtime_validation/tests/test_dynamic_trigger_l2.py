from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path

from src.runtime_validation.contracts import ValidationError
from src.runtime_validation.l2_runtime import (
    L2_PROJECTS,
    L2QualificationRequest,
    L2RunRequest,
    EntrypointSupervisor,
    LoopbackProvider,
    evaluate_l2_events,
    load_launch_profiles,
    qualify_l2,
    render_command,
    run_l2,
    validate_launch_profile,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
CAMPAIGN = (
    REPO_ROOT
    / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)


class LaunchProfileContractTest(unittest.TestCase):
    def test_all_ten_non_hermes_profiles_are_source_bound(self) -> None:
        profiles = load_launch_profiles()
        self.assertEqual(10, len(profiles))
        self.assertEqual(set(L2_PROJECTS), set(profiles))
        for profile in profiles.values():
            self.assertEqual("blocked", profile["qualification"]["status"])
            self.assertTrue(profile["qualification"]["blockers"])
            self.assertGreaterEqual(len(profile["instrumentation"]["anchors"]), 5)

    def test_profile_rejects_revision_and_path_drift(self) -> None:
        profiles = load_launch_profiles()
        invalid = copy.deepcopy(profiles["AstrBot"])
        invalid["revision"] = "0" * 40
        with self.assertRaisesRegex(ValidationError, "revision drift"):
            validate_launch_profile(invalid)
        invalid = copy.deepcopy(profiles["AstrBot"])
        invalid["state"]["disposable_roots"].append("../outside")
        with self.assertRaisesRegex(ValidationError, "escapes project root"):
            validate_launch_profile(invalid)


class LoopbackProviderTest(unittest.TestCase):
    def test_serves_exactly_one_reviewed_tool_call(self) -> None:
        with LoopbackProvider("exec", {"command": "clawgap-exploit"}, "exploit") as provider:
            request = urllib.request.Request(
                provider.base_url + "/chat/completions",
                data=json.dumps(
                    {"model": "clawgap-loopback", "messages": [{"role": "user", "content": "x"}]}
                ).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=2) as response:
                payload = json.loads(response.read())
        call = payload["choices"][0]["message"]["tool_calls"]
        self.assertEqual(1, len(call))
        self.assertEqual("exec", call[0]["function"]["name"])
        self.assertEqual(
            {"command": "clawgap-exploit"},
            json.loads(call[0]["function"]["arguments"]),
        )
        self.assertEqual(1, len(provider.transcripts))
        self.assertTrue(provider.transcripts[0]["valid"])

    def test_rejects_second_provider_request_for_same_role(self) -> None:
        import urllib.error

        with LoopbackProvider("exec", {"command": "safe"}, "control") as provider:
            request = urllib.request.Request(
                provider.base_url + "/chat/completions",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(request, timeout=2).read()
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request, timeout=2).read()
            self.assertEqual(409, raised.exception.code)


class EntrypointSupervisorTest(unittest.TestCase):
    def test_runs_command_in_process_group_and_terminates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            supervisor = EntrypointSupervisor(
                [sys.executable, "-c", "print('ready', flush=True)"],
                cwd=root,
                environment={"PATH": "/usr/bin:/bin", "HOME": str(root)},
                stdout_path=root / "stdout.log",
                stderr_path=root / "stderr.log",
            )
            supervisor.start()
            supervisor.wait_ready("process-exit", 5)
            supervisor.terminate()
            self.assertIn("ready", (root / "stdout.log").read_text())

    def test_render_command_rejects_unresolved_placeholder(self) -> None:
        self.assertEqual(
            ["echo", "ready"],
            render_command(["echo", "${CLAWGAP_L2_PROMPT}"], {"CLAWGAP_L2_PROMPT": "ready"}),
        )
        with self.assertRaisesRegex(ValidationError, "unresolved"):
            render_command(["echo", "${MISSING}"], {})


class PythonInstrumentationTest(unittest.TestCase):
    def test_sitecustomize_records_declared_source_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "fixture_target.py"
            target.write_text(
                "\n".join(
                    [
                        "def handler():",
                        "    return 'observed'",
                        "",
                        "",
                        "handler()",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            event_path = root / "events.jsonl"
            config_path = root / "instrumentation.json"
            config_path.write_text(
                json.dumps(
                    {
                        "case_id": "DTC-instrumentation",
                        "correlation_id": "DTC-instrumentation:1",
                        "attempt": 1,
                        "role": "exploit",
                        "event_path": str(event_path),
                        "provider_base_url": "http://127.0.0.1:1/v1",
                        "anchors": [
                            {"kind": "handler", "anchor": "fixture_target.py:1"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            environment = {
                "PATH": "/usr/bin:/bin",
                "HOME": str(root),
                "CLAWGAP_L2_INSTRUMENTATION": str(config_path),
                "PYTHONPATH": str(
                    REPO_ROOT
                    / "src/runtime_validation/l2_instrumentation/python"
                ),
            }
            supervisor = EntrypointSupervisor(
                [sys.executable, str(target)],
                cwd=root,
                environment=environment,
                stdout_path=root / "stdout.log",
                stderr_path=root / "stderr.log",
            )
            supervisor.start()
            supervisor.wait_ready("process-exit", 5)
            events = [
                json.loads(line)
                for line in event_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(1, len(events))
            self.assertEqual("handler", events[0]["kind"])


class L2TraceTest(unittest.TestCase):
    def test_trace_requires_provider_dispatch_and_pre_effect(self) -> None:
        case = {"case_id": "DTC-test", "gates": [{"id": "G1"}]}
        kinds = ["provider-request", "dispatch", "handler", "gate", "sink", "pre-effect"]
        correlation = f"{case['case_id']}:6"

        def events(attempt: int = 1, kind_override: str | None = "__unchanged__"):
            rows = []
            for index, kind in enumerate(kinds, 1):
                rows.append(
                    {
                        "event_id": f"E-{index}",
                        "case_id": case["case_id"],
                        "correlation_id": correlation,
                        "attempt": attempt,
                        "role": "exploit",
                        "kind": kind if index != 1 or kind_override == "__unchanged__" else kind_override,
                        "intercept_before_execution": kind == "pre-effect",
                    }
                )
            return rows

        self.assertTrue(evaluate_l2_events(case, events()))
        self.assertFalse(evaluate_l2_events(case, events(kind_override="handler")))
        self.assertFalse(evaluate_l2_events(case, list(reversed(events()))))
        self.assertFalse(evaluate_l2_events(case, events() + events(attempt=2)))


class L2QualificationCampaignTest(unittest.TestCase):
    def test_qualification_accounts_for_all_78_and_blocks_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out_dir = Path(directory) / "qualification"
            manifest = qualify_l2(L2QualificationRequest(CAMPAIGN, out_dir))
            self.assertEqual(78, manifest["candidate_count"])
            self.assertEqual(10, manifest["project_count"])
            self.assertEqual({"blocked": 78}, manifest["status_counts"])
            self.assertFalse(manifest["canonical_publication_ready"])
            ledger = [
                json.loads(line)
                for line in (out_dir / "qualification-ledger.jsonl").read_text().splitlines()
            ]
            self.assertEqual(78, len(ledger))
            self.assertEqual(78, len({row["candidate_id"] for row in ledger}))
            self.assertEqual(11, len({row["project"] for row in ledger}))
            self.assertEqual(
                10,
                len(
                    {
                        row["project"]
                        for row in ledger
                        if row["project"] != "hermes-agent"
                    }
                ),
            )
            with self.assertRaisesRegex(ValidationError, "canonical L2 publication is blocked"):
                run_l2(
                    L2RunRequest(
                        CAMPAIGN,
                        out_dir,
                        Path(directory) / "canonical",
                    )
                )


if __name__ == "__main__":
    unittest.main()

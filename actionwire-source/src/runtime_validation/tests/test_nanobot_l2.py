from __future__ import annotations

import json
import py_compile
import shutil
import tempfile
import unittest
import urllib.request
from pathlib import Path

from src.runtime_validation.contracts import ValidationError
from src.runtime_validation.candidate_l2 import (
    CandidateL2Request,
    validate_candidate_l2,
)
from src.runtime_validation.nanobot_l2 import (
    ALLOW_POLICIES,
    MODEL_NAME,
    PROVIDER_CREDENTIAL,
    TARGET_CANDIDATES,
    NanobotProviderServer,
    _expected_stages,
    _instrument_project,
    _render_config,
    _select_cases,
    _sink_matches,
    _source_bindings,
)
from src.projects import get_project


REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOT = get_project("nanobot").source_root
SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-expanded-v3"
)
V3_COVERAGE = REPO_ROOT / "output/cross-project/coverage-comparison-expanded-v3"


class NanobotTargetedL2Test(unittest.TestCase):
    def test_exact_five_gt_linked_candidates_are_selected(self) -> None:
        cases, repairs = _select_cases(SOURCE_CAMPAIGN)
        self.assertEqual(
            TARGET_CANDIDATES,
            tuple(row["candidate_binding"]["candidate_id"] for row in cases),
        )
        self.assertEqual(
            {
                "CAND-172340a317979d20",
                "CAND-41f28e9e17a06e89",
                "CAND-f68ce42e92cbb622",
            },
            {row["candidate_id"] for row in repairs},
        )
        with self.assertRaisesRegex(ValidationError, "five GT-linked"):
            _select_cases(SOURCE_CAMPAIGN, candidate_id="CAND-c5d8af7ff4820813")

    def test_payload_repairs_remove_blocked_loopback_url_carriers(self) -> None:
        cases, _ = _select_cases(SOURCE_CAMPAIGN)
        by_id = {
            row["candidate_binding"]["candidate_id"]: row for row in cases
        }
        commands = [
            row["arguments"]["command"]
            for row in by_id["CAND-172340a317979d20"]["forced_tool_calls"]
        ]
        self.assertNotIn("127.0.0.1", " ".join(commands))
        self.assertIn("echo allowlisted; touch nanobot-chain-canary", commands)
        comment = by_id["CAND-41f28e9e17a06e89"]["forced_tool_calls"][0][
            "arguments"
        ]["command"]
        self.assertTrue(comment.endswith("# echo allowlisted"))

    def test_cited_sources_are_bound(self) -> None:
        cases, _ = _select_cases(SOURCE_CAMPAIGN)
        bindings = _source_bindings(cases)
        self.assertEqual(11, len(bindings))
        self.assertIn("nanobot/agent/tools/shell.py", bindings)
        self.assertIn("nanobot/security/network.py", bindings)

    def test_instrumentation_and_allowpattern_backport_compile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            relatives = (
                "nanobot/config/schema.py",
                "nanobot/agent/loop.py",
                "nanobot/cli/commands.py",
                "nanobot/providers/custom_provider.py",
                "nanobot/agent/tools/registry.py",
                "nanobot/agent/tools/shell.py",
            )
            for relative in relatives:
                target = project / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(SOURCE_ROOT / relative, target)
            transformed = _instrument_project(project)
            self.assertEqual(7, len(transformed))
            for relative in transformed:
                py_compile.compile(
                    str(project / relative),
                    doraise=True,
                    cfile=str(project / "_.pyc"),
                )
            schema = (project / "nanobot/config/schema.py").read_text(
                encoding="utf-8"
            )
            loop = (project / "nanobot/agent/loop.py").read_text(
                encoding="utf-8"
            )
            self.assertIn("allow_patterns: list[str]", schema)
            self.assertIn("allow_patterns=self.exec_config.allow_patterns", loop)

    def test_config_is_loopback_and_policy_scoped(self) -> None:
        cases, _ = _select_cases(SOURCE_CAMPAIGN)
        case = next(
            row
            for row in cases
            if row["candidate_binding"]["candidate_id"]
            == "CAND-41f28e9e17a06e89"
        )
        config = _render_config(
            provider_port=18099,
            workspace=Path("/tmp/clawgap-nanobot-workspace"),
            case=case,
        )
        self.assertEqual(MODEL_NAME, config["agents"]["defaults"]["model"])
        self.assertEqual(
            "http://127.0.0.1:18099/v1",
            config["providers"]["custom"]["apiBase"],
        )
        self.assertEqual(
            ALLOW_POLICIES["CAND-41f28e9e17a06e89"],
            config["tools"]["exec"]["allowPatterns"],
        )
        self.assertTrue(config["tools"]["restrictToWorkspace"])

    def test_controls_cannot_satisfy_exploit_witnesses(self) -> None:
        cases, _ = _select_cases(SOURCE_CAMPAIGN)
        for case in cases:
            for role in ("exploit", "control"):
                command = case["forced_tool_calls"][
                    0 if role == "exploit" else 1
                ]["arguments"]["command"]
                detail = {"command": command, "cwd": "/tmp", "executed": False}
                if role == "exploit" and case["candidate_binding"][
                    "candidate_id"
                ] != "CAND-69c18202d18d7bcf":
                    self.assertTrue(_sink_matches(case, role, detail))
                else:
                    self.assertFalse(_sink_matches(case, role, detail))

    def test_missing_gate_and_healthy_negative_stage_contracts(self) -> None:
        cases, _ = _select_cases(SOURCE_CAMPAIGN)
        by_id = {
            row["candidate_binding"]["candidate_id"]: row for row in cases
        }
        missing = _expected_stages(
            by_id["CAND-49ccfec7491078f6"], "exploit"
        )
        self.assertNotIn("gate_observed", missing)
        self.assertIn("missing_check_boundary_confirmed", missing)
        blocked = _expected_stages(
            by_id["CAND-69c18202d18d7bcf"], "exploit"
        )
        self.assertIn("gate_observed", blocked)
        self.assertNotIn("sink_reached", blocked)
        self.assertNotIn("pre_effect_interception", blocked)

    def test_loopback_provider_emits_exact_openai_tool_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            transcript = Path(directory) / "provider.jsonl"
            arguments = {"command": "echo allowlisted", "working_dir": "/tmp"}
            server = NanobotProviderServer(
                role="control",
                arguments=arguments,
                transcript_path=transcript,
            )
            try:
                request = urllib.request.Request(
                    f"http://127.0.0.1:{server.port}/v1/chat/completions",
                    data=json.dumps(
                        {
                            "model": MODEL_NAME,
                            "messages": [{"role": "user", "content": "probe"}],
                            "tools": [
                                {
                                    "type": "function",
                                    "function": {"name": "exec"},
                                }
                            ],
                        }
                    ).encode(),
                    headers={
                        "Authorization": f"Bearer {PROVIDER_CREDENTIAL}",
                        "Content-Type": "application/json",
                    },
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    payload = json.loads(response.read())
                call = payload["choices"][0]["message"]["tool_calls"][0]
                self.assertEqual("exec", call["function"]["name"])
                self.assertEqual(arguments, json.loads(call["function"]["arguments"]))
                row = json.loads(transcript.read_text(encoding="utf-8"))
                self.assertEqual("forced-tool-call", row["request_kind"])
                self.assertEqual(
                    "Bearer [REDACTED_CREDENTIAL]",
                    row["authorization_redacted"],
                )
            finally:
                # The threaded loopback server is closed by the fixture.
                server.close()

    def test_canonical_validate_candidate_l2_uses_nanobot_executor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "out"
            manifest = validate_candidate_l2(
                CandidateL2Request(
                    out_dir=out,
                    candidates=V3_COVERAGE / "candidates.jsonl",
                    coverage_root=V3_COVERAGE,
                    source_campaign=SOURCE_CAMPAIGN,
                    project="nanobot",
                    candidate_id="CAND-41f28e9e17a06e89",
                )
            )
            self.assertEqual({"runtime-confirmed": 1}, manifest["status_counts"])
            result = json.loads(
                (
                    out
                    / "candidates"
                    / "CAND-41f28e9e17a06e89"
                    / "candidate-result.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual("nanobot-targeted-l2/v1", result["executor"])
            self.assertEqual(6, result["trace_accounting"]["valid"])


if __name__ == "__main__":
    unittest.main()

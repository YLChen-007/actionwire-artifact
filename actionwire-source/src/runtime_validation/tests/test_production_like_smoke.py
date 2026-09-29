from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.runtime_validation.contracts import sha256_file, sha256_text
from src.runtime_validation.lab_mcp_server import _validate as validate_lab_tool
from src.runtime_validation.production_like_smoke import (
    CONTROL,
    CONTROL_PROMPT,
    EXPLOIT,
    EXPLOIT_PROMPT,
    build_propagation_case,
    run_production_like_smoke,
)
from src.runtime_validation.propagation_contracts import (
    ProductionLikeSmokeRequest,
    digest,
    validate_propagation_case,
)


def _designer(case):
    return {
        "report_id": case["report_id"],
        "project": case["project"],
        "revision": case["revision"],
        "claim": "prompt-to-sink-propagation",
        "selection_mode": "mocked-provider-forced-tool-call",
        "effect_execution": "not-tested",
        "live_prompt_triggerability": "not-tested",
        "exploit_prompt": EXPLOIT_PROMPT,
        "control_prompt": CONTROL_PROMPT,
        "tool_name": "read_file",
        "exploit_path": EXPLOIT,
        "control_path": CONTROL,
        "instrumentation_stages": [row["stage"] for row in case["stages"]],
        "sink_policy": "intercept-before-effect",
        "target_launch": "hermes-one-shot-file-toolset",
        "mock_provider_protocol": "openai-chat-completions-sse",
    }


def _reviewer(_plan):
    return {
        "verdict": "approve",
        "reason": "fixture review approved",
        "checks": {
            "source_bound": True,
            "provider_forced": True,
            "ordered_value_flow": True,
            "control_blocked": True,
            "sink_intercepted": True,
            "authority_narrow": True,
            "no_effect_claim": True,
        },
    }


class ProductionLikeContractTest(unittest.TestCase):
    def test_case_identity_and_no_effect_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            request = ProductionLikeSmokeRequest(Path(directory))
            case = build_propagation_case(request)
            validate_propagation_case(case)
            self.assertEqual("mocked-provider-forced-tool-call", case["selection_mode"])
            self.assertEqual("prompt-to-sink-propagation", case["claim"])
            self.assertEqual("not-tested", case["effect_execution"])
            self.assertEqual("intercept-before-effect", case["sink_policy"])
            for role in ("exploit", "control"):
                self.assertEqual(
                    sha256_text(case["prompts"][role]),
                    case["prompt_bindings"][role]["sha256"],
                )
                self.assertEqual(
                    digest(case["tool_calls"][role]),
                    case["provider_transcript_policy"]["tool_call_sha256"][role],
                )
            authority = case["orchestrator"]["authority"]
            self.assertNotIn("Bash", authority)
            self.assertNotIn("Edit", authority)
            self.assertNotIn("Write", authority)
            changed = json.loads(json.dumps(case))
            changed["values"]["exploit"] = "/dev/zero"
            with self.assertRaises(Exception):
                validate_propagation_case(changed)

    def test_narrow_lab_authority_rejects_host_requests(self) -> None:
        with self.assertRaises(ValueError):
            validate_lab_tool(
                "finalize_plan", {"mount": "/root", "docker": "--privileged"}
            )
        self.assertIn(
            "accepted",
            validate_lab_tool(
                "configure_mock_provider",
                {
                    "tool_name": "read_file",
                    "exploit": "/dev/./zero",
                    "control": "/dev/zero",
                },
            ),
        )


class ProductionLikeIntegrationTest(unittest.TestCase):
    def test_real_hermes_prompt_to_sink_propagation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "smoke"
            run = run_production_like_smoke(
                ProductionLikeSmokeRequest(root),
                designer=_designer,
                reviewer=_reviewer,
            )
            self.assertEqual("prompt-to-sink-confirmed", run.disposition)
            self.assertEqual("confirmed", run.native_outcome)
            self.assertEqual("confirmed", run.e2e_outcome)
            result = json.loads((root / "result.json").read_text())
            self.assertEqual("not-tested", result["effect_execution"])
            case = json.loads((root / "case.json").read_text())
            instrumentation = json.loads(
                (root / "instrumentation-manifest.json").read_text()
            )
            self.assertEqual("read-only", instrumentation["benchmark_mount"])
            self.assertTrue(instrumentation["overlay_bindings"])
            self.assertTrue(instrumentation["source_maps"])
            for binding in instrumentation["overlay_bindings"]:
                self.assertEqual(
                    binding["sha256"], sha256_file(Path.cwd() / binding["path"])
                )
            canaries = json.loads((root / "safety-canaries.json").read_text())
            self.assertFalse(canaries["matching_sink_child_process_created"])
            self.assertFalse(canaries["denial_of_service_executed"])
            self.assertFalse(canaries["external_target_network"])
            self.assertFalse(canaries["bound_source_modified"])
            self.assertFalse(canaries["target_environment_inherited_credentials"])
            self.assertFalse(canaries["host_filesystem_escape_observed"])
            self.assertTrue(canaries["provider_loopback_only"])
            self.assertTrue(canaries["benchmark_mounted_read_only"])
            self.assertTrue(canaries["target_process_groups_terminated"])
            active_canaries = json.loads(
                (root / "sandbox-canaries.json").read_text()
            )
            self.assertTrue(active_canaries["external_network_blocked"])
            self.assertTrue(active_canaries["read_only_source_write_blocked"])
            self.assertEqual([], active_canaries["inherited_credential_variables"])
            for tier in ("native", "e2e"):
                for attempt in range(1, 4):
                    for role in ("exploit", "control"):
                        attempt_root = (
                            root
                            / "attempts"
                            / tier
                            / f"attempt-{attempt:03d}"
                            / role
                        )
                        rows = [
                            json.loads(line)
                            for line in (attempt_root / "events.jsonl")
                            .read_text()
                            .splitlines()
                        ]
                        correlation = (
                            f"{case['case_id']}:{'e2e' if tier == 'e2e' else 'native'}:"
                            f"{attempt}:{role}"
                        )
                        for row in rows:
                            self.assertEqual(result["campaign_id"], row["campaign_id"])
                            self.assertEqual(case["case_id"], row["case_id"])
                            self.assertEqual(attempt, row["attempt"])
                            self.assertEqual(correlation, row["correlation_id"])
                            self.assertEqual(case["value_ids"][role], row["value_id"])
                            self.assertEqual(case["values"][role], row["details"]["value"])
                        gate = next(row for row in rows if row["stage"] == "gate_return")
                        self.assertEqual(role == "control", gate["details"]["return_value"])
                        sink_rows = [
                            row
                            for row in rows
                            if row["stage"] in {"popen_sink_argument", "sink_intercepted"}
                        ]
                        if role == "exploit":
                            self.assertEqual(2, len(sink_rows))
                            self.assertFalse(sink_rows[-1]["details"]["process_created"])
                            popen = next(
                                row for row in rows if row["stage"] == "popen_sink_argument"
                            )
                            self.assertIn(EXPLOIT, popen["details"]["payload"])
                        else:
                            self.assertEqual([], sink_rows)
                        if tier == "e2e":
                            transcript = [
                                json.loads(line)
                                for line in (attempt_root / "provider-transcript.jsonl")
                                .read_text()
                                .splitlines()
                            ]
                            first = transcript[0]
                            self.assertEqual(
                                case["tool_calls"][role], first["response_tool_call"]
                            )
                            self.assertTrue(
                                any(
                                    message.get("role") == "user"
                                    and message.get("content") == case["prompts"][role]
                                    for message in first["request"]["messages"]
                                )
                            )
            bindings = json.loads(
                (root / "provider-transcript-bindings.json").read_text()
            )
            self.assertEqual(6, len(bindings["bindings"]))
            manifest = json.loads((root / "manifest.json").read_text())
            for relative, expected in manifest["artifact_sha256"].items():
                self.assertEqual(expected, sha256_file(root / relative))


if __name__ == "__main__":
    unittest.main()

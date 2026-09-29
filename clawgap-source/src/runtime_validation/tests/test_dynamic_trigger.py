from __future__ import annotations

import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from src.runtime_validation.adapters import get_adapter
from src.runtime_validation.campaign_contracts import PROJECT_ADAPTERS
from src.runtime_validation.contracts import ValidationError
from src.runtime_validation.dynamic_trigger import (
    DynamicTriggerGenerationRequest,
    DynamicTriggerReviewRequest,
    _projection_rows,
    digest,
    evaluate_trace_events,
    generate_dynamic_trigger,
    validate_dynamic_case,
    review_dynamic_trigger,
    select_dynamic_candidates,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
COVERAGE_ROOT = REPO_ROOT / "output/cross-project/coverage-comparison"


def _semantic_rows() -> dict[tuple[str, str], dict]:
    projects = {
        json.loads(row)["project"]
        for row in (COVERAGE_ROOT / "candidates.jsonl").read_text().splitlines()
    }
    rows: dict[tuple[str, str], dict] = {}
    for project in projects:
        output_name = {"hermes-agent": "hermes"}.get(project, project)
        path = (
            REPO_ROOT
            / "output"
            / output_name
            / "call-chain-semantics"
            / "call-chain-semantics.jsonl"
        )
        for line in path.read_text().splitlines():
            row = json.loads(line)
            rows[(row["project"]["id"], row["chain_id"])] = row
    return rows


def _registered_tool(candidate: dict, semantic: dict) -> str:
    handler_tool = semantic["handler"]["tool_name"]
    supported = get_adapter(PROJECT_ADAPTERS[candidate["project"]]).supported_tools
    for value in (
        handler_tool,
        handler_tool.removeprefix("_handle_"),
        handler_tool.removesuffix("_tool"),
    ):
        if value in supported:
            return value
    return supported[0]


def _fake_runner(system: str, user: str) -> str:
    candidate = json.loads(user)["candidate"]
    semantic = _SEMANTICS[(candidate["project"], candidate["chain_id"])]
    return json.dumps(
        {
            "tool_name": _registered_tool(candidate, semantic),
            "exploit_args": {"value": "clawgap-exploit-fixture"},
            "control_args": {"value": "clawgap-safe-control"},
            "reproduction_prompt": "Replay the reviewed native tool call.",
            "relation": "equals",
            "argument_path": ["value"],
            "exploit_value": "clawgap-exploit-fixture",
            "control_value": "clawgap-safe-control",
            "reason": "deterministic test fragment",
        }
    )


_SEMANTICS = _semantic_rows()


class DynamicTriggerSelectionTest(unittest.TestCase):
    def test_freezes_exact_all_candidate_and_gt_denominators(self) -> None:
        selection = select_dynamic_candidates(
            COVERAGE_ROOT, COVERAGE_ROOT / "candidates.jsonl"
        )
        self.assertEqual(78, len(selection.candidates))
        self.assertEqual(78, len({row["candidate_id"] for row in selection.candidates}))
        self.assertEqual(11, len({row["project"] for row in selection.candidates}))
        self.assertEqual(
            {"wrong-check": 41, "missing-check": 37},
            dict(Counter(row["failure_mode"] for row in selection.candidates)),
        )
        self.assertEqual(46, len(selection.generic_coverage))

    def test_rejects_noncanonical_candidate_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "other-candidates.jsonl"
            path.write_bytes((COVERAGE_ROOT / "candidates.jsonl").read_bytes())
            with self.assertRaisesRegex(ValidationError, "canonical candidates"):
                select_dynamic_candidates(COVERAGE_ROOT, path)

    def test_rejects_duplicate_or_wrong_row_count(self) -> None:
        required = (
            "candidates.jsonl",
            "comparisons.jsonl",
            "generic-ground-truth-coverage.jsonl",
            "ground-truth-coverage.jsonl",
            "candidate-origin-audit.jsonl",
            "manifest.json",
            "ground-truth-manifest.json",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in required:
                (root / name).write_bytes((COVERAGE_ROOT / name).read_bytes())
            lines = (root / "candidates.jsonl").read_text().splitlines()
            (root / "candidates.jsonl").write_text(
                "\n".join(lines + lines[:1]) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValidationError, "denominator drift"):
                select_dynamic_candidates(root, root / "candidates.jsonl")
            (root / "candidates.jsonl").write_text(
                "\n".join(lines[:-1]) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValidationError, "denominator drift"):
                select_dynamic_candidates(root, root / "candidates.jsonl")


class DynamicTriggerCompilerTest(unittest.TestCase):
    def test_generates_reviews_and_accounts_for_all_78_cases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out_dir = Path(directory) / "campaign"
            request = DynamicTriggerGenerationRequest(
                COVERAGE_ROOT, COVERAGE_ROOT / "candidates.jsonl", out_dir
            )
            manifest = generate_dynamic_trigger(request, runner=_fake_runner)
            self.assertEqual(78, manifest["candidate_count"])
            cases = [
                json.loads(line)
                for line in (out_dir / "cases.jsonl").read_text().splitlines()
            ]
            self.assertEqual(78, len(cases))
            self.assertTrue(
                all(
                    case["observations"][-1]["kind"] == "pre-effect-interception"
                    for case in cases
                )
            )
            self.assertTrue(
                all(case["control_policy"]["paired_attempts"] == 3 for case in cases)
            )
            sink_families = {case["sink"]["family"] for case in cases}
            self.assertGreater(len(sink_families), 1)
            invalid = json.loads(json.dumps(cases[0]))
            invalid["unsafe_relation"]["relation"] = "unknown-relation"
            with self.assertRaisesRegex(ValidationError, "schema validation failed"):
                validate_dynamic_case(invalid)
            invalid = json.loads(json.dumps(cases[0]))
            invalid["observations"][0]["kind"] = "arbitrary-instrumentation"
            with self.assertRaisesRegex(ValidationError, "schema validation failed"):
                validate_dynamic_case(invalid)
            invalid = json.loads(json.dumps(cases[0]))
            invalid["prompts"]["reproduction"] = "call __import__('os')"
            with self.assertRaisesRegex(ValidationError, "executable expression"):
                validate_dynamic_case(invalid)
            invalid = json.loads(json.dumps(cases[0]))
            invalid["observations"][0]["source_anchor"] = "../escape.ts:1"
            with self.assertRaisesRegex(ValidationError, "escapes project root"):
                validate_dynamic_case(invalid)
            review = review_dynamic_trigger(DynamicTriggerReviewRequest(out_dir))
            self.assertEqual("accepted", review["status"])
            projection = [
                json.loads(line)
                for line in (out_dir / "gt-projection.jsonl").read_text().splitlines()
            ]
            self.assertEqual(
                {"candidate-missing": 5, "inconclusive": 38, "not-applicable": 3},
                dict(Counter(row["disposition"] for row in projection)),
            )


class DynamicTriggerTruthGateTest(unittest.TestCase):
    def test_projection_never_promotes_unmatched_reports(self) -> None:
        generic = [
            json.loads(line)
            for line in (
                COVERAGE_ROOT / "generic-ground-truth-coverage.jsonl"
            ).read_text().splitlines()
        ]
        confirmed = {
            candidate_id: {"disposition": "runtime-confirmed", "attempts": 3}
            for row in generic
            for candidate_id in row.get("matched_candidate_ids", [])
        }
        rows = _projection_rows(generic, confirmed)
        self.assertEqual(46, len(rows))
        self.assertEqual(
            {"runtime-confirmed": 38, "candidate-missing": 5, "not-applicable": 3},
            dict(Counter(row["disposition"] for row in rows)),
        )
        self.assertTrue(
            all(
                row["disposition"] == "candidate-missing"
                for row in rows
                if row["boundary_status"] == "eligible"
                and not row["matched_candidate_ids"]
            )
        )


class DynamicTriggerTraceTest(unittest.TestCase):
    def test_trace_requires_order_correlation_and_unique_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out_dir = Path(directory) / "campaign"
            generate_dynamic_trigger(
                DynamicTriggerGenerationRequest(
                    COVERAGE_ROOT, COVERAGE_ROOT / "candidates.jsonl", out_dir
                ),
                runner=_fake_runner,
            )
            case = json.loads((out_dir / "cases.jsonl").read_text().splitlines()[0])
        kinds = [
            "handler",
            *(["gate"] * len(case["gates"])),
            "sink",
            "pre-effect-interception",
        ]
        correlation = "DTC-CORR-" + digest(case["case_id"])[:16]
        events = [
            {
                "event_id": f"E-{index}",
                "case_id": case["case_id"],
                "correlation_id": correlation,
                "attempt": 1,
                "role": "exploit",
                "kind": kind,
            }
            for index, kind in enumerate(kinds, 1)
        ]
        self.assertTrue(evaluate_trace_events(case, events))
        self.assertFalse(evaluate_trace_events(case, list(reversed(events))))
        self.assertFalse(evaluate_trace_events(case, events + [events[-1]]))
        cross_attempt = [dict(row, attempt=2) for row in events[1:]]
        self.assertFalse(evaluate_trace_events(case, events[:1] + cross_attempt))


if __name__ == "__main__":
    unittest.main()

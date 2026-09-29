from __future__ import annotations

import json
import os
import stat
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from src.handler_baseline.contracts import (
    MOST_CREDIBLE_VULNERABILITIES_POLICY,
    BaselineError,
    aggregate_calls,
    credible_vulnerability_response_json_schema,
    redact_credentials,
    response_json_schema,
    validate_response,
)
from src.handler_baseline.ground_truth import (
    MATCH_FACETS,
    _maximum_report_capacity,
    _maximum_unique_matches,
    _validate_match,
    _verify_freeze,
    discover_reports,
)
from src.handler_baseline.inventory import HandlerTrial, build_inventory
from src.handler_baseline.pipeline import _atomic_text, run_blind_experiment, trial_config_digest
from src.handler_baseline.prompts import (
    build_discovery_user,
    build_repair_user,
    discovery_system,
)
from src.handler_baseline.render import summarize_trials
from src.handler_baseline.scope import build_ground_truth_handler_scope
from src.handler_baseline.transport import SandboxedClaudeCode, assert_sandbox_available
from src.projects import get_project, list_projects


def evidence(file: str = "tool.py", quote: str = "def handler(value):") -> dict[str, object]:
    return {"file": file, "line_start": 1, "line_end": 1, "quote": quote}


def finding(mode: str) -> dict[str, object]:
    gates = []
    if mode == "wrong-check":
        gates = [
            {
                "location": "tool.py:2",
                "semantics": "blocks only the literal unsafe value",
                "evidence": [evidence(quote="if value == 'unsafe':") | {"line_start": 2, "line_end": 2}],
            }
        ]
    return {
        "failure_mode": mode,
        "controlled_input": "value",
        "sink_capability": "process execution",
        "sink_location": "tool.py:4",
        "sink_argument": "value",
        "call_path": ["handler", "run"],
        "relevant_gates": gates,
        "uncovered_requirement": "reject all shell chaining",
        "trigger_property": "a semicolon executes a second command",
        "reason": "the sink parses shell metacharacters",
        "confidence": "high",
        "evidence": [evidence(quote="def handler(value):")],
    }


def response(trial_id: str, mode: str = "wrong-check") -> dict[str, object]:
    return {
        "trial_id": trial_id,
        "verdict": "findings",
        "findings": [finding(mode)],
        "negative_evidence": [],
        "uncertainty": None,
    }


def credible_vulnerability(
    rank: int = 1,
    mode: str = "wrong-check",
    *,
    controlled_input: str = "value",
    trigger: str = "a semicolon executes a second command",
) -> dict[str, object]:
    row = finding(mode)
    return {
        "rank": rank,
        "failure_mode": row["failure_mode"],
        "controlled_input": controlled_input,
        "sink_capability": row["sink_capability"],
        "sink_location": row["sink_location"],
        "sink_argument": row["sink_argument"],
        "call_path": row["call_path"],
        "relevant_gates": row["relevant_gates"],
        "uncovered_requirement": row["uncovered_requirement"],
        "trigger_property": trigger,
        "realistic_preconditions": "the handler is enabled in the documented default mode",
        "security_boundary": {
            "protected_asset": "host process authority",
            "trust_boundary": "model input must not become an unapproved second command",
            "requirement_source": "the handler's explicit unsafe-value rejection establishes the boundary",
            "evidence": [evidence(quote="if value == 'unsafe':") | {"line_start": 2, "line_end": 2}],
        },
        "capability_delta": {
            "intended_capability": "run one approved value",
            "unauthorized_capability": "run a second unapproved shell command",
            "why_not_equivalent": "no equivalent unapproved path is exposed by this handler",
            "evidence": [evidence(quote="run(value)") | {"line_start": 4, "line_end": 4}],
        },
        "credibility_checks": {
            "model_control_proven": True,
            "handler_reachability_proven": True,
            "security_boundary_proven": True,
            "gate_defect_proven": True,
            "trigger_effect_proven": True,
            "not_intended_behavior": True,
            "no_equivalent_capability": True,
            "realistic_preconditions": True,
        },
        "selection_reason": "complete handler, gate, sink, and impact proof",
        "reason": row["reason"],
        "confidence": "high",
        "evidence": [
            evidence(quote="def handler(value):"),
            evidence(quote="run(value)") | {"line_start": 4, "line_end": 4},
        ],
    }


def credible_response(
    trial_id: str, vulnerabilities: list[dict[str, object]]
) -> dict[str, object]:
    return {
        "trial_id": trial_id,
        "verdict": "vulnerabilities",
        "vulnerabilities": vulnerabilities,
        "negative_evidence": [],
        "uncertainty": None,
    }


class InventoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.specs = [get_project(name) for name in list_projects()]
        cls.trials = build_inventory(cls.specs)

    def test_live_inventory_is_complete_and_stable(self) -> None:
        self.assertEqual(12, len(self.specs))
        self.assertEqual(316, len(self.trials))
        self.assertEqual(316, len({row.trial_id for row in self.trials}))
        self.assertEqual(309, len({(row.project, row.tool_name) for row in self.trials}))

    def test_ground_truth_includes_markdown_only_and_json_only_reports(self) -> None:
        reports = discover_reports(self.specs)
        self.assertEqual(46, len(reports))
        lettabot = [row for row in reports if row.project == "lettabot"]
        self.assertEqual(1, len(lettabot))
        self.assertEqual(("Task",), lettabot[0].handlers)
        self.assertEqual(5, len([row for row in reports if row.project == "mercury-agent"]))

    def test_ground_truth_handler_scope_is_complete_mapped_and_label_blind(self) -> None:
        selected, scope = build_ground_truth_handler_scope(
            specs=self.specs, trials=self.trials
        )
        self.assertEqual(26, len(selected))
        self.assertEqual(11, len({trial.project for trial in selected}))
        self.assertEqual(
            {
                "curated_reports": 46,
                "report_handler_bindings": 48,
                "unique_handler_trials": 26,
                "projects": 11,
                "mapping_status": {
                    "exact": 22,
                    "markdown-fallback": 1,
                    "source-confirmed-drift": 25,
                },
                "unresolved_bindings": 0,
            },
            scope["counts"],
        )
        self.assertEqual(46, len(scope["report_trial_bindings"]))
        prompt = build_discovery_user(selected[0])
        for forbidden in ("ground_truth", "report_id", "GT-", "CVE-", "Advisory-"):
            self.assertNotIn(forbidden, prompt)
        bindings = {
            report_id: set(trial_ids)
            for report_id, trial_ids in scope["report_trial_bindings"].items()
        }
        self.assertEqual(
            34,
            _maximum_report_capacity(bindings, per_trial_capacity=2),
        )


class ContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "tool.py").write_text(
            "def handler(value):\n"
            "    if value == 'unsafe':\n"
            "        return\n"
            "    run(value)\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_wrong_and_missing_check_shapes(self) -> None:
        for mode in ("wrong-check", "missing-check"):
            with self.subTest(mode=mode):
                result = validate_response(
                    response("HB-1234567890abcdef", mode),
                    trial_id="HB-1234567890abcdef",
                    source_root=self.root,
                )
                self.assertEqual(mode, result["findings"][0]["failure_mode"])

    def test_multiple_findings_and_unknown_contract(self) -> None:
        value = response("HB-1234567890abcdef")
        value["findings"] = [finding("wrong-check"), finding("missing-check")]
        result = validate_response(
            value, trial_id=value["trial_id"], source_root=self.root
        )
        self.assertEqual(2, len(result["findings"]))
        self.assertEqual(2, len({row["finding_id"] for row in result["findings"]}))
        unknown = {
            "trial_id": value["trial_id"],
            "verdict": "unknown",
            "findings": [],
            "negative_evidence": [],
            "uncertainty": "sink call shape cannot be resolved",
        }
        self.assertEqual(
            "unknown",
            validate_response(
                unknown, trial_id=value["trial_id"], source_root=self.root
            )["verdict"],
        )

    def test_response_schema_encodes_verdict_dependent_uncertainty(self) -> None:
        conditionals = response_json_schema()["allOf"]
        self.assertEqual(3, len(conditionals))
        self.assertEqual(
            {"type": "array", "minItems": 1},
            conditionals[0]["then"]["properties"]["findings"],
        )
        self.assertEqual(
            {"type": "array", "maxItems": 0},
            conditionals[1]["then"]["properties"]["findings"],
        )
        self.assertEqual(
            {"type": "array", "minItems": 1},
            conditionals[1]["then"]["properties"]["negative_evidence"],
        )
        self.assertEqual(
            {"type": "null"},
            conditionals[0]["then"]["properties"]["uncertainty"],
        )

    def test_no_finding_requires_negative_evidence(self) -> None:
        value = {
            "trial_id": "HB-1234567890abcdef",
            "verdict": "no-finding",
            "findings": [],
            "negative_evidence": [],
            "uncertainty": None,
        }
        with self.assertRaisesRegex(BaselineError, "negative_evidence"):
            validate_response(value, trial_id=value["trial_id"], source_root=self.root)

    def test_findings_discard_unused_invalid_negative_evidence(self) -> None:
        value = response("HB-1234567890abcdef")
        value["negative_evidence"] = [
            evidence(quote="this quote is deliberately absent")
        ]
        result = validate_response(
            value, trial_id=value["trial_id"], source_root=self.root
        )
        self.assertEqual([], result["negative_evidence"])
        self.assertEqual(1, len(result["findings"]))

    def test_credible_contract_accepts_one_or_two_high_confidence_vulnerabilities(self) -> None:
        trial_id = "HB-1234567890abcdef"
        for rows in (
            [credible_vulnerability()],
            [
                credible_vulnerability(),
                credible_vulnerability(
                    2,
                    "missing-check",
                    controlled_input="other_value",
                    trigger="an unchecked alternate value reaches the sink",
                ),
            ],
        ):
            with self.subTest(count=len(rows)):
                result = validate_response(
                    credible_response(trial_id, rows),
                    trial_id=trial_id,
                    source_root=self.root,
                    report_policy=MOST_CREDIBLE_VULNERABILITIES_POLICY,
                )
                self.assertEqual(len(rows), len(result["vulnerabilities"]))
                self.assertEqual(
                    list(range(1, len(rows) + 1)),
                    [row["rank"] for row in result["vulnerabilities"]],
                )
                self.assertTrue(
                    all(row["confidence"] == "high" for row in result["vulnerabilities"])
                )

    def test_credible_contract_rejects_third_medium_rank_gap_and_unproven_candidate(self) -> None:
        trial_id = "HB-1234567890abcdef"
        cases: list[tuple[str, dict[str, object], str]] = []
        three = [
            credible_vulnerability(),
            credible_vulnerability(2, controlled_input="second"),
            credible_vulnerability(3, controlled_input="third"),
        ]
        cases.append(("third", credible_response(trial_id, three), "at most two"))
        medium = credible_response(trial_id, [credible_vulnerability()])
        medium["vulnerabilities"][0]["confidence"] = "medium"  # type: ignore[index]
        cases.append(("medium", medium, "high confidence"))
        rank_gap = credible_response(
            trial_id,
            [credible_vulnerability(), credible_vulnerability(1, controlled_input="second")],
        )
        cases.append(("rank", rank_gap, "contiguous"))
        unproven = credible_response(trial_id, [credible_vulnerability()])
        unproven["vulnerabilities"][0]["credibility_checks"][  # type: ignore[index]
            "not_intended_behavior"
        ] = False
        cases.append(("unproven", unproven, "unproven credibility"))
        for name, value, error in cases:
            with self.subTest(name=name), self.assertRaisesRegex(BaselineError, error):
                validate_response(
                    value,
                    trial_id=trial_id,
                    source_root=self.root,
                    report_policy=MOST_CREDIBLE_VULNERABILITIES_POLICY,
                )

    def test_credible_contract_rejects_duplicate_invariant_trigger_variants(self) -> None:
        trial_id = "HB-1234567890abcdef"
        value = credible_response(
            trial_id,
            [
                credible_vulnerability(trigger="semicolon chaining"),
                credible_vulnerability(2, trigger="newline chaining"),
            ],
        )
        with self.assertRaisesRegex(BaselineError, "duplicate vulnerability invariants"):
            validate_response(
                value,
                trial_id=trial_id,
                source_root=self.root,
                report_policy=MOST_CREDIBLE_VULNERABILITIES_POLICY,
            )

    def test_credible_no_vulnerability_and_unknown_contract(self) -> None:
        trial_id = "HB-1234567890abcdef"
        no_vulnerability = {
            "trial_id": trial_id,
            "verdict": "no-vulnerability",
            "vulnerabilities": [],
            "negative_evidence": [evidence()],
            "uncertainty": None,
        }
        unknown = {
            "trial_id": trial_id,
            "verdict": "unknown",
            "vulnerabilities": [],
            "negative_evidence": [],
            "uncertainty": "the runtime dispatch target cannot be resolved from source",
        }
        for value in (no_vulnerability, unknown):
            result = validate_response(
                value,
                trial_id=trial_id,
                source_root=self.root,
                report_policy=MOST_CREDIBLE_VULNERABILITIES_POLICY,
            )
            self.assertEqual(value["verdict"], result["verdict"])

    def test_credible_schema_caps_output_at_two_and_requires_high_confidence(self) -> None:
        schema = credible_vulnerability_response_json_schema()
        self.assertEqual(2, schema["properties"]["vulnerabilities"]["maxItems"])
        vulnerability = schema["properties"]["vulnerabilities"]["items"]
        self.assertEqual("high", vulnerability["properties"]["confidence"]["const"])

    def test_credible_prompt_distinguishes_delegated_capability_equivalence(self) -> None:
        prompt = discovery_system(MOST_CREDIBLE_VULNERABILITIES_POLICY)
        self.assertIn("delegated execution", prompt)
        self.assertIn("principal, autonomy", prompt)
        self.assertIn("semantic authorization gate", prompt)

    def test_credible_contract_repairs_only_adjacent_source_backed_citation_ranges(self) -> None:
        trial_id = "HB-1234567890abcdef"
        value = credible_response(trial_id, [credible_vulnerability()])
        citation = value["vulnerabilities"][0]["capability_delta"]["evidence"][0]  # type: ignore[index]
        citation["line_start"] = 3
        citation["line_end"] = 3
        result = validate_response(
            value,
            trial_id=trial_id,
            source_root=self.root,
            report_policy=MOST_CREDIBLE_VULNERABILITIES_POLICY,
        )
        repaired = result["vulnerabilities"][0]["capability_delta"]["evidence"][0]
        self.assertEqual((2, 4), (repaired["line_start"], repaired["line_end"]))

    def test_repair_prompt_includes_source_context_for_non_verbatim_quotes(self) -> None:
        trial_id = "HB-1234567890abcdef"
        value = credible_response(trial_id, [credible_vulnerability()])
        citation = value["vulnerabilities"][0]["relevant_gates"][0]["evidence"][0]  # type: ignore[index]
        citation["quote"] = "if value == unsafe:"
        prompt = build_repair_user(
            trial=HandlerTrial(
                trial_id=trial_id, project="fixture", revision="abc",
                source_root=str(self.root), source_sha256="source",
                inventory_path="fixture.csv", inventory_sha256="inventory", ordinal=1,
                tool_name="tool", form="decorator", handler_func="handler",
                file="tool.py", line=1, forwarded_body="-",
            ),
            invalid_response=json.dumps(value),
            validation_error=(
                "unrepaired response: vulnerability[1].relevant_gates[1]."
                "evidence[0].quote is not present in cited lines"
            ),
            source_root=self.root,
        )
        self.assertIn("Citation repair context", prompt)
        self.assertIn("current_non_verbatim_quote", prompt)
        self.assertIn("if value == 'unsafe':", prompt)

    def test_token_accounting_preserves_cache_categories_and_missing_usage(self) -> None:
        calls = [
            {
                "provider_reported": True,
                "usage": {
                    "provider_reported": True,
                    "input_tokens": 10,
                    "cache_creation_input_tokens": 3,
                    "cache_read_input_tokens": 5,
                    "output_tokens": 2,
                    "total_input_tokens": 18,
                    "total_tokens": 20,
                },
            },
            {"provider_reported": False, "usage": {"provider_reported": False}},
        ]
        total = aggregate_calls(calls)
        self.assertTrue(total["provider_reported"])
        self.assertEqual(18, total["total_input_tokens"])
        self.assertEqual(20, total["total_tokens"])

    def test_partial_usage_is_reported_as_observed_and_missing(self) -> None:
        row = {
            "status": "completed",
            "project": "fixture",
            "result": {"verdict": "no-finding", "findings": []},
            "transport": {"calls": []},
            "attempt_history": [
                {
                    "attempt": 1,
                    "status": "failed",
                    "elapsed_seconds": 1,
                    "calls": [{"phase": "analysis", "provider_reported": False, "usage": {}}],
                },
                {
                    "attempt": 2,
                    "status": "completed",
                    "elapsed_seconds": 2,
                    "calls": [
                        {
                            "phase": "analysis",
                            "provider_reported": True,
                            "usage": {
                                "provider_reported": True,
                                "input_tokens": 10,
                                "cache_creation_input_tokens": 3,
                                "cache_read_input_tokens": 5,
                                "output_tokens": 2,
                            },
                        }
                    ],
                },
            ],
        }
        summary = summarize_trials([row])
        self.assertEqual(20, summary["observed_token_subtotal"]["total_tokens"])
        self.assertEqual(1, summary["token_statistics_per_handler"]["missing_usage_trials"])
        self.assertEqual(2, summary["attempts"])
        self.assertEqual(1, summary["tokens_by_attempt_status"]["failed"]["attempts"])

    def test_ground_truth_match_requires_all_structured_facets(self) -> None:
        value = {
            "report_id": "GT-report",
            "finding_id": "HBF-finding",
            "verdict": "match",
            "facets": {name: True for name in MATCH_FACETS},
            "reason": "all nine independently verified facets agree",
        }
        result = _validate_match(value, "GT-report", "HBF-finding")
        self.assertEqual("match", result["verdict"])
        value["facets"]["same_trigger_mechanism"] = False
        with self.assertRaisesRegex(BaselineError, "verdict invariant"):
            _validate_match(value, "GT-report", "HBF-finding")

    def test_unique_match_assignment_does_not_reuse_one_finding(self) -> None:
        assigned = _maximum_unique_matches(
            {
                "GT-a": ["HBF-shared"],
                "GT-b": ["HBF-shared", "HBF-distinct"],
            }
        )
        self.assertEqual(2, len(assigned))
        self.assertEqual(2, len(set(assigned.values())))


class FakeClaudeEndToEndTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "tool.py").write_text(
            "def handler(value):\n"
            "    if value == 'unsafe':\n"
            "        return\n"
            "    run(value)\n",
            encoding="utf-8",
        )
        self.fake = self.root / "claude"
        self._write_success_fake()

    def _write_success_fake(self) -> None:
        self.fake.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/python3
                import json, sys
                if '--version' in sys.argv:
                    print('fake-claude 1.0')
                    raise SystemExit(0)
                prompt = sys.argv[sys.argv.index('-p') + 1]
                trial = json.loads(prompt.split('\\n', 1)[1])['trial_id']
                finding = {
                    'failure_mode':'wrong-check','controlled_input':'value',
                    'sink_capability':'process execution','sink_location':'tool.py:4',
                    'sink_argument':'value','call_path':['handler','run'],
                    'relevant_gates':[{'location':'tool.py:2','semantics':'literal block only',
                      'evidence':[{'file':'tool.py','line_start':2,'line_end':2,
                        'quote':"if value == 'unsafe':"}]}],
                    'uncovered_requirement':'reject shell chaining',
                    'trigger_property':'semicolon chaining','reason':'incomplete literal block',
                    'confidence':'high','evidence':[{'file':'tool.py','line_start':1,
                      'line_end':1,'quote':'def handler(value):'}]
                }
                result={'trial_id':trial,'verdict':'findings','findings':[finding],
                        'negative_evidence':[],'uncertainty':None}
                print(json.dumps({'is_error':False,'structured_output':result,
                  'usage':{'input_tokens':10,'cache_creation_input_tokens':3,
                    'cache_read_input_tokens':5,'output_tokens':2}}))
                """
            ),
            encoding="utf-8",
        )
        self.fake.chmod(self.fake.stat().st_mode | stat.S_IXUSR)

    def _write_failure_fake(self, *, sleep_seconds: int = 0) -> None:
        self.fake.write_text(
            "#!/usr/bin/python3\n"
            "import sys, time\n"
            "if '--version' in sys.argv:\n"
            "    print('fake-claude 1.0')\n"
            "    raise SystemExit(0)\n"
            f"time.sleep({sleep_seconds})\n"
            "print('fixture failure', file=sys.stderr)\n"
            "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        self.fake.chmod(self.fake.stat().st_mode | stat.S_IXUSR)

    def _write_credible_fake(self) -> None:
        vulnerability_json = json.dumps(credible_vulnerability())
        self.fake.write_text(
            textwrap.dedent(
                f"""\
                #!/usr/bin/python3
                import json, sys
                if '--version' in sys.argv:
                    print('fake-claude 1.0')
                    raise SystemExit(0)
                prompt = sys.argv[sys.argv.index('-p') + 1]
                trial = json.loads(prompt.split('\\n', 1)[1])['trial_id']
                vulnerability = json.loads({vulnerability_json!r})
                result={{'trial_id':trial,'verdict':'vulnerabilities',
                        'vulnerabilities':[vulnerability],
                        'negative_evidence':[],'uncertainty':None}}
                print(json.dumps({{'is_error':False,'structured_output':result,
                  'usage':{{'input_tokens':10,'cache_creation_input_tokens':3,
                    'cache_read_input_tokens':5,'output_tokens':2}}}}))
                """
            ),
            encoding="utf-8",
        )
        self.fake.chmod(self.fake.stat().st_mode | stat.S_IXUSR)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def trial(self) -> HandlerTrial:
        return HandlerTrial(
            trial_id="HB-1234567890abcdef", project="fixture", revision="abc",
            source_root=str(self.source), source_sha256="source", inventory_path="fixture.csv",
            inventory_sha256="inventory", ordinal=1, tool_name="tool", form="decorator",
            handler_func="handler", file="tool.py", line=1, forwarded_body="-",
        )

    def test_fake_run_writes_resumable_artifacts_and_never_freezes_focused_run(self) -> None:
        out = self.root / "out"
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-token"}, clear=False):
            first = run_blind_experiment(
                trials=[self.trial()], out_dir=out, generation_command="fixture",
                workers=1, timeout=30, claude_bin=str(self.fake), allow_freeze=False,
            )
            second = run_blind_experiment(
                trials=[self.trial()], out_dir=out, generation_command="fixture",
                workers=1, timeout=30, claude_bin=str(self.fake), allow_freeze=False,
            )
        self.assertEqual(1, first["manifest"]["counts"]["findings"])
        self.assertEqual(20, first["manifest"]["counts"]["observed_token_subtotal"]["total_tokens"])
        self.assertEqual(1, second["resumed"])
        self.assertFalse((out / "blind-freeze.json").exists())
        self.assertIn("Generation command: `fixture`", (out / "baseline-results.md").read_text())

    def test_failed_trial_is_retried_and_attempt_usage_is_preserved(self) -> None:
        out = self.root / "retry"
        self._write_failure_fake()
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-token"}, clear=False):
            first = run_blind_experiment(
                trials=[self.trial()], out_dir=out, generation_command="fixture",
                workers=1, timeout=30, claude_bin=str(self.fake), allow_freeze=False,
            )
            self._write_success_fake()
            second = run_blind_experiment(
                trials=[self.trial()], out_dir=out, generation_command="fixture",
                workers=1, timeout=30, claude_bin=str(self.fake), allow_freeze=False,
            )
        self.assertEqual({"failed": 1}, first["manifest"]["counts"]["status"])
        self.assertEqual(0, second["resumed"])
        self.assertEqual({"completed": 1}, second["manifest"]["counts"]["status"])
        self.assertEqual(2, second["manifest"]["counts"]["attempts"])
        self.assertEqual(
            1,
            second["manifest"]["counts"]["tokens_by_attempt_status"]["failed"][
                "missing_usage_attempts"
            ],
        )

    def test_credible_policy_writes_separate_vulnerability_artifacts_and_freeze(self) -> None:
        out = self.root / "credible"
        self._write_credible_fake()
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-token"}, clear=False):
            result = run_blind_experiment(
                trials=[self.trial()],
                out_dir=out,
                generation_command="fixture --report-policy most-credible-vulnerabilities",
                workers=1,
                timeout=30,
                claude_bin=str(self.fake),
                allow_freeze=True,
                report_policy=MOST_CREDIBLE_VULNERABILITIES_POLICY,
            )
        self.assertEqual(1, result["manifest"]["counts"]["vulnerabilities"])
        self.assertEqual({"1": 1}, result["manifest"]["counts"]["vulnerabilities_by_rank"])
        self.assertTrue((out / "vulnerabilities.jsonl").is_file())
        self.assertFalse((out / "findings.jsonl").exists())
        freeze = json.loads((out / "blind-freeze.json").read_text(encoding="utf-8"))
        self.assertIn("vulnerabilities_sha256", freeze)
        self.assertNotIn("findings_sha256", freeze)
        self.assertEqual(
            "vulnerabilities.jsonl",
            _verify_freeze(out)["candidate_artifact"],
        )
        self.assertIn(
            "Raw canonical vulnerabilities: **1**",
            (out / "baseline-results.md").read_text(encoding="utf-8"),
        )

    def test_schema_invalid_artifact_can_be_revalidated_without_provider_call(self) -> None:
        out = self.root / "revalidate"
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-token"}, clear=False):
            first = run_blind_experiment(
                trials=[self.trial()], out_dir=out, generation_command="fixture",
                workers=1, timeout=30, claude_bin=str(self.fake), allow_freeze=False,
            )
        self.assertEqual({"completed": 1}, first["manifest"]["counts"]["status"])
        current_path = out / "repository/trials/HB-1234567890abcdef/trial.json"
        current = json.loads(current_path.read_text(encoding="utf-8"))
        current["status"] = "schema-invalid"
        current["result"] = None
        current["error"] = "legacy validator rejected optional evidence"
        current_path.write_text(json.dumps(current), encoding="utf-8")
        attempt_path = next(
            (out / "repository/trials/HB-1234567890abcdef/attempts").glob("*/*.json")
        )
        attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
        attempt["status"] = "schema-invalid"
        attempt["result"] = None
        attempt["error"] = current["error"]
        attempt_path.write_text(json.dumps(attempt), encoding="utf-8")
        self._write_failure_fake()
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-token"}, clear=False):
            second = run_blind_experiment(
                trials=[self.trial()], out_dir=out, generation_command="fixture",
                workers=1, timeout=30, claude_bin=str(self.fake), allow_freeze=False,
            )
        self.assertEqual(1, second["resumed"])
        self.assertEqual({"completed": 1}, second["manifest"]["counts"]["status"])
        recovered = json.loads(current_path.read_text(encoding="utf-8"))
        self.assertEqual(0, recovered["validation_recovery"]["additional_provider_calls"])

    def test_timeout_is_terminal_and_usage_remains_unavailable(self) -> None:
        out = self.root / "timeout"
        self._write_failure_fake(sleep_seconds=5)
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-token"}, clear=False):
            result = run_blind_experiment(
                trials=[self.trial()], out_dir=out, generation_command="fixture",
                workers=1, timeout=1, claude_bin=str(self.fake), allow_freeze=False,
            )
        self.assertEqual({"timed-out": 1}, result["manifest"]["counts"]["status"])
        self.assertEqual(
            1, result["manifest"]["counts"]["token_statistics_per_handler"]["missing_usage_trials"]
        )

    def test_config_digest_changes_with_timeout_and_prompt_contract(self) -> None:
        trial = self.trial()
        first = trial_config_digest(
            trial, model="m", timeout=30, version="v", base_url="https://example.invalid"
        )
        second = trial_config_digest(
            trial, model="m", timeout=31, version="v", base_url="https://example.invalid"
        )
        self.assertNotEqual(first, second)
        changed_source = HandlerTrial(**{**trial.__dict__, "source_sha256": "changed"})
        third = trial_config_digest(
            changed_source, model="m", timeout=30, version="v",
            base_url="https://example.invalid",
        )
        self.assertNotEqual(first, third)

    def test_four_worker_scheduler_runs_trials_concurrently(self) -> None:
        out = self.root / "workers"
        trials = [
            HandlerTrial(**{**self.trial().__dict__, "trial_id": f"HB-{number:016x}"})
            for number in range(1, 5)
        ]
        lock = threading.Lock()
        active = 0
        maximum = 0

        def fake_run(trial: HandlerTrial, **_: object) -> tuple[dict[str, object], bool]:
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.1)
            with lock:
                active -= 1
            return {
                "trial_id": trial.trial_id,
                "project": trial.project,
                "revision": trial.revision,
                "handler": {"tool_name": trial.tool_name},
                "status": "completed",
                "result": {"verdict": "no-finding", "findings": []},
                "transport": {"calls": []},
                "elapsed_seconds": 0.1,
            }, False

        with patch("src.handler_baseline.pipeline.run_trial", side_effect=fake_run):
            run_blind_experiment(
                trials=trials, out_dir=out, generation_command="fixture",
                workers=4, timeout=30, claude_bin=str(self.fake), allow_freeze=False,
            )
        self.assertEqual(4, maximum)

    def test_atomic_replacement_preserves_mode_and_redacts_credentials(self) -> None:
        path = self.root / "report.md"
        path.write_text("old", encoding="utf-8")
        path.chmod(0o640)
        _atomic_text(path, "new")
        self.assertEqual(0o640, stat.S_IMODE(path.stat().st_mode))
        self.assertEqual("new", path.read_text(encoding="utf-8"))
        self.assertNotIn("sk-secretsecret", redact_credentials("sk-secretsecret"))


class SandboxTest(unittest.TestCase):
    def test_bubblewrap_hides_repository_and_mounts_only_workspace(self) -> None:
        assert_sandbox_available()
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "source"
            source.mkdir()
            (source / "ok.txt").write_text("ok", encoding="utf-8")
            runner = SandboxedClaudeCode.__new__(SandboxedClaudeCode)
            runner.source_root = source.resolve()
            runner.model = "deepseek-v4-flash"
            runner.base_url = "https://example.invalid"
            runner.credential_env = "DEEPSEEK_API_KEY"
            runner.claude_bin = "/usr/bin/true"
            runner.bwrap_bin = assert_sandbox_available()
            command = runner._command("system", "user")
            self.assertIn(str(source.resolve()), command)
            self.assertNotIn(str(Path.cwd()), command)
            self.assertIn("--safe-mode", command)
            self.assertIn("--no-session-persistence", command)
            self.assertNotIn("--fallback-model", command)
            self.assertEqual("dontAsk", command[command.index("--permission-mode") + 1])
            self.assertEqual("Read,Grep,Glob", command[command.index("--tools") + 1])


if __name__ == "__main__":
    unittest.main()

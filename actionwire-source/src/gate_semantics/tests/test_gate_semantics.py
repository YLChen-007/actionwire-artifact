from __future__ import annotations

import asyncio
import csv
import json
import runpy
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from jsonschema import validate

from src.gate_semantics.behavior_checker import (
    SCHEMA_PATH as BEHAVIOR_SCHEMA_PATH,
    build_behavior_profile,
    check_and_upgrade_semantic,
    validate_behavior_semantic_ir,
)
from src.gate_semantics.agent_sdk import (
    ALL_RESEARCH_TOOLS,
    BUILTIN_RESEARCH_TOOLS,
    LSP_RESEARCH_TOOLS,
    ClaudeAgentSDKRunner,
    ClaudeCLIRunner,
    _source_root_denial,
    aggregate_token_usage,
    normalize_token_usage,
)
from src.gate_semantics.candidates import CandidateSeed, load_candidates
from src.gate_semantics.checker import (
    build_parser as build_checker_parser,
    run as run_checker,
)
from src.gate_semantics.contracts import (
    ANALYSIS_SCHEMA_PATH,
    COMPOUND_ANALYSIS_SCHEMA_PATH,
    COMPOUND_SEMANTIC_SCHEMA_PATH,
    REGULAR_HARD_TOKEN_LIMIT,
    SEMANTIC_SCHEMA_PATH,
    ContractError,
    estimate_tokens,
    load_schema,
    parse_json_response,
    validate_analysis_response,
    validate_compound_semantic_ir,
    validate_semantic_ir,
)
from src.gate_semantics.main import (
    DEFAULT_OUTPUT,
    build_parser,
    explicit_generation_command,
    independent_example_command,
)
from src.gate_semantics.pipeline import (
    GateSelectionError,
    _source_research_audit,
    analyze_gate,
    analyze_gate_detailed,
    run_pipeline,
)
from src.gate_semantics.prompts import (
    REVIEW_SYSTEM,
    SYSTEM,
    build_repair_user,
    build_review_user,
    build_user,
)
from src.gate_semantics.render import render_chain_semantics
from src.gate_semantics.slicer import PythonGateSlicer
from src.sink_capacity.agent import run_agent


SOURCE = """\
import re

BLOCKED = {"internal"}
PREFIX_PATTERNS = [r"sk-[A-Za-z0-9_-]{10,}"]
PREFIX_RE = re.compile(r"(?<![A-Za-z0-9_-])(" + "|".join(PREFIX_PATTERNS) + r")(?![A-Za-z0-9_-])")

def is_safe(value: str, allow_internal: bool = False) -> bool:
    normalized = value.strip().lower()
    if not normalized:
        return False
    if normalized in BLOCKED and not allow_internal:
        return False
    return True

def sanitize(value: str) -> str:
    return value.replace("<", "")

def replace(value):
    return "unrelated project function"

def consume(value):
    return value

def predicate_handler(value):
    if not is_safe(value):
        return "blocked"
    return consume(value)

def b2_handler(value):
    error = is_safe(value)
    if not error:
        return "blocked"
    return consume(value)

def filter_handler(values):
    safe_values = []
    for value in values:
        if is_safe(value):
            safe_values.append(value)
    return consume(safe_values)

def transform_handler(value):
    clean = sanitize(value)
    return consume(clean)

def nested_transform_handler(value):
    result = consume(f"prefix {sanitize(value)}")
    if result:
        return "outer result"
    return result

def two_arg_check(pattern, value):
    return pattern == value

def second_arg_handler(value):
    if not two_arg_check("fixed", value):
        return "blocked"
    return consume(value)

def inline_delivery_handler(delivery):
    extra = delivery.get("deliver_extra", {})
    repo = extra.get("repo", "")
    pr_number = extra.get("pr_number", "")
    if not repo or not pr_number:
        return "blocked"
    return consume((repo, pr_number))

def receiver_derivation_handler(video_url):
    unrelated = consume(video_url)
    resolved_url = video_url
    if resolved_url.startswith("file://"):
        resolved_url = resolved_url[len("file://"):]
    local_path = Path(os.path.expanduser(resolved_url))
    if local_path.is_file():
        return local_path
    elif is_safe(video_url):
        return "remote"
    return unrelated

def regex_handler(value):
    if PREFIX_RE.search(value):
        return "blocked"
    return consume(value)
"""


def _line(source: str, fragment: str, occurrence: int = 1) -> int:
    seen = 0
    for number, line in enumerate(source.splitlines(), 1):
        if fragment in line:
            seen += 1
            if seen == occurrence:
                return number
    raise AssertionError(fragment)


def _write_csv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def valid_ir(gate_slice, *, mode: str | None = None) -> dict:
    selected_mode = mode or str(gate_slice.gate["mode"])
    rejecting_op = "drop-if" if selected_mode == "filter" else "block-if"
    examples = []
    if selected_mode != "transform":
        examples = [
            {
                "input": "internal",
                "rejected_by": "S1",
                "reason": "The value belongs to the blocked set.",
            }
        ]
    step_op = "transform" if selected_mode == "transform" else rejecting_op
    return {
        "gate_id": gate_slice.gate_id,
        "mode": selected_mode,
        "input": f"{gate_slice.input_value_id}: candidate value",
        "output": f"{gate_slice.output_value_id}: gate result",
        "summary": "Checks whether the candidate value satisfies the source-defined policy.",
        "steps": [
            {
                "id": "S1",
                "op": step_op,
                "rule": (
                    "Remove less-than characters from the value."
                    if selected_mode == "transform"
                    else "The normalized value belongs to the blocked set."
                ),
            }
        ],
        "default": "pass"
        if selected_mode != "transform"
        else "return transformed value",
        "on_error": "block" if selected_mode != "transform" else "propagate error",
        "reject_examples": examples,
        "bypass_examples": [],
        "status": "complete",
    }


class GateSemanticsFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        (self.root / "tool.py").write_text(SOURCE, encoding="utf-8")
        self.debug = self.root / "debug"
        self.debug.mkdir()

        dominance_fields = [
            "gate_fn",
            "gate_file",
            "gate_line",
            "gate_column",
            "gate_call_expr",
            "checked_expr",
            "checked_file",
            "checked_line",
            "checked_column",
            "source_param",
            "condition_expr",
            "guard_kind",
            "taint_verdict",
            "in_func",
            "sink_label",
            "sink_file",
            "sink_line",
        ]
        predicate_line = _line(SOURCE, "if not is_safe(value):")
        _write_csv(
            self.debug / "dominance.csv",
            dominance_fields,
            [
                {
                    "gate_fn": "is_safe",
                    "gate_file": "tool.py",
                    "gate_line": predicate_line,
                    "gate_column": 12,
                    "gate_call_expr": "is_safe(value)",
                    "checked_expr": "value",
                    "checked_file": "tool.py",
                    "checked_line": predicate_line,
                    "checked_column": 20,
                    "source_param": "value",
                    "condition_expr": "not is_safe(value)",
                    "guard_kind": "in-condition",
                    "taint_verdict": "confirmed",
                    "in_func": "predicate_handler",
                    "sink_label": "consume",
                    "sink_file": "tool.py",
                    "sink_line": predicate_line + 2,
                },
                {
                    "gate_fn": "is_safe",
                    "gate_file": "tool.py",
                    "gate_line": predicate_line,
                    "gate_column": 12,
                    "gate_call_expr": "is_safe(value)",
                    "checked_expr": "value",
                    "checked_file": "tool.py",
                    "checked_line": predicate_line,
                    "checked_column": 20,
                    "source_param": "value",
                    "condition_expr": "not is_safe(value)",
                    "guard_kind": "in-condition",
                    "taint_verdict": "confirmed",
                    "in_func": "predicate_handler",
                    "sink_label": "second_sink",
                    "sink_file": "tool.py",
                    "sink_line": predicate_line + 3,
                },
                {
                    "gate_fn": "is_safe",
                    "gate_file": "tool.py",
                    "gate_line": predicate_line,
                    "taint_verdict": "needs-review",
                    "in_func": "predicate_handler",
                    "sink_label": "consume",
                    "sink_file": "tool.py",
                    "sink_line": predicate_line + 2,
                },
            ],
        )

        filter_line = _line(SOURCE, "if is_safe(value):")
        _write_csv(
            self.debug / "filter.csv",
            [
                "gate_kind",
                "gate_fn",
                "gate_file",
                "gate_line",
                "gate_column",
                "gate_call_expr",
                "checked_var",
                "checked_expr",
                "condition_expr",
                "sink_label",
                "sink_file",
                "sink_line",
            ],
            [
                {
                    "gate_kind": "filter",
                    "gate_fn": "is_safe",
                    "gate_file": "tool.py",
                    "gate_line": filter_line,
                    "gate_column": 12,
                    "gate_call_expr": "is_safe(value)",
                    "checked_var": "value",
                    "checked_expr": "value",
                    "condition_expr": "is_safe(value)",
                    "sink_label": "consume",
                    "sink_file": "tool.py",
                    "sink_line": filter_line + 2,
                }
            ],
        )

        transform_line = _line(SOURCE, "clean = sanitize(value)")
        definition_line = _line(SOURCE, "def sanitize")
        _write_csv(
            self.debug / "transform.csv",
            [
                "handler_func",
                "transform_fn",
                "transform_file",
                "transform_line",
                "transform_call_file",
                "transform_call_line",
                "transform_call_column",
                "transform_call_expr",
                "transform_role",
                "transform_primitive",
                "taint_verdict",
                "sink_label",
                "sink_file",
                "sink_line",
            ],
            [
                {
                    "handler_func": "transform_handler",
                    "transform_fn": "sanitize",
                    "transform_file": "tool.py",
                    "transform_line": definition_line,
                    "transform_call_file": "tool.py",
                    "transform_call_line": transform_line,
                    "transform_call_column": 13,
                    "transform_call_expr": "sanitize(value)",
                    "transform_role": "sink-transform",
                    "transform_primitive": "tool.py::sanitize",
                    "taint_verdict": "confirmed",
                    "sink_label": "consume",
                    "sink_file": "tool.py",
                    "sink_line": transform_line + 1,
                }
            ],
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_cli_uses_canonical_gate_semantics_output_by_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args([])
        self.assertEqual(DEFAULT_OUTPUT, args.out_dir)
        self.assertEqual("sdk", args.agent_transport)
        self.assertFalse(args.no_lsp)
        self.assertFalse(args.debug_fidelity_review)
        self.assertNotIn("--debug-fidelity-review", explicit_generation_command(args))
        self.assertIn("--agent-transport sdk", explicit_generation_command(args))
        self.assertIn("--agent-transport sdk", independent_example_command(args))

        no_lsp = parser.parse_args(["--no-lsp"])
        self.assertIn("--no-lsp", explicit_generation_command(no_lsp))
        self.assertIn("--no-lsp", independent_example_command(no_lsp))

        review = parser.parse_args(["--debug-fidelity-review"])
        self.assertIn("--debug-fidelity-review", explicit_generation_command(review))
        self.assertIn("--debug-fidelity-review", independent_example_command(review))

    def candidates(self):
        return load_candidates(
            self.debug / "dominance.csv",
            self.debug / "filter.csv",
            self.debug / "transform.csv",
        )

    def test_slices_are_callsite_bound_deduplicated_and_sink_free(self) -> None:
        slicer = PythonGateSlicer(self.root, revision="fixture-revision")
        slices = slicer.build_slices(self.candidates())
        self.assertEqual(3, len(slices))

        predicate = next(item for item in slices if item.gate["mode"] == "predicate")
        self.assertEqual("value", predicate.checked_value["expression"])
        self.assertEqual(
            "value -> is_safe.value",
            predicate.checked_value["actual_to_formal_binding"],
        )
        self.assertEqual("not is_safe(value)", predicate.callsite["condition"])
        self.assertEqual(2, len(predicate.chain_refs))
        payload = json.dumps(predicate.prompt_payload(), ensure_ascii=False)
        self.assertNotIn("sink_label", payload)
        self.assertNotIn("second_sink", payload)
        self.assertTrue(
            any(
                chunk.source == 'BLOCKED = {"internal"}'
                for chunk in predicate.source_bundle
            )
        )
        filter_gate = next(item for item in slices if item.gate["mode"] == "filter")
        self.assertEqual("value", filter_gate.dataflow["source_symbol"])
        self.assertEqual(["value"], filter_gate.dataflow["t_to_g_path"])
        transform_gate = next(
            item for item in slices if item.gate["mode"] == "transform"
        )
        self.assertFalse(
            any(
                chunk.role == "helper" and chunk.symbol == "replace"
                for chunk in transform_gate.source_bundle
            )
        )
        self.assertNotIn("unresolved-helper:replace", transform_gate.unresolved_symbols)

        second_run = slicer.build_slices(self.candidates())
        self.assertEqual(
            [item.gate_id for item in slices],
            [item.gate_id for item in second_run],
        )

    def test_gate_uid_ignores_revision_and_line_but_distinguishes_callsites(self) -> None:
        predicate_seed = next(
            seed
            for seed in self.candidates()
            if seed.mode == "predicate" and seed.owner_function == "predicate_handler"
        )
        original = PythonGateSlicer(self.root, revision="revision-a").build_slice(
            predicate_seed
        )
        revised = PythonGateSlicer(self.root, revision="revision-b").build_slice(
            predicate_seed
        )
        self.assertNotEqual(original.gate_id, revised.gate_id)
        self.assertEqual(original.gate_uid, revised.gate_uid)
        self.assertEqual(original.content_digest, revised.content_digest)

        shifted_root = self.root / "shifted"
        shifted_root.mkdir()
        (shifted_root / "tool.py").write_text("\n" + SOURCE, encoding="utf-8")
        shifted_seed = replace(
            predicate_seed,
            call_line=predicate_seed.call_line + 1,
            checked_line=predicate_seed.checked_line + 1,
        )
        shifted = PythonGateSlicer(
            shifted_root, revision="revision-c"
        ).build_slice(shifted_seed)
        self.assertEqual(original.gate_uid, shifted.gate_uid)
        self.assertEqual(original.content_digest, shifted.content_digest)

        second_callsite = PythonGateSlicer(
            self.root, revision="revision-a"
        ).build_slice(
            CandidateSeed(
                mode="predicate",
                gate_name="is_safe",
                call_file="tool.py",
                call_line=_line(SOURCE, "error = is_safe(value)"),
                static_verdict="confirmed",
                owner_function="b2_handler",
                checked_hint="value",
                source_param="value",
            )
        )
        self.assertNotEqual(original.gate_uid, second_callsite.gate_uid)

        changed_source = SOURCE.replace(
            "    return True\n\ndef sanitize",
            '    return value != "changed"\n\ndef sanitize',
        )
        (self.root / "tool.py").write_text(changed_source, encoding="utf-8")
        changed = PythonGateSlicer(self.root, revision="revision-a").build_slice(
            predicate_seed
        )
        self.assertEqual(original.gate_uid, changed.gate_uid)
        self.assertNotEqual(original.content_digest, changed.content_digest)

    def test_prompt_allows_bounded_source_research_without_unresolved_hint(self) -> None:
        gate_slice = next(
            item
            for item in PythonGateSlicer(
                self.root, revision="fixture-revision"
            ).build_slices(self.candidates())
            if item.gate["mode"] == "predicate"
        )
        self.assertEqual([], gate_slice.unresolved_symbols)
        user = build_user(gate_slice)
        review = build_review_user(gate_slice, {"semantic_ir": {}, "evidence": {}})
        self.assertIn("even when unresolved_symbols is empty", SYSTEM)
        self.assertIn("unresolved_symbols is a hint, not an authorization boundary", user)
        self.assertIn(str(self.root.resolve()), user)
        self.assertIn("Use Read/Grep/Glob", review)
        self.assertIn(str(self.root.resolve()), review)
        self.assertIn("GATE-ENTRY COMPLETENESS", SYSTEM)
        self.assertIn("checked_value` is the primary tracked value", SYSTEM)
        self.assertIn("Assume execution has already reached the selected gate", SYSTEM)
        self.assertIn("`callsite.activation` remains debug context only", SYSTEM)
        self.assertNotIn("Preserve `callsite.activation`", SYSTEM)
        self.assertIn("Missing upstream activation is never a", REVIEW_SYSTEM)
        self.assertIn("included as if it were this gate's semantics", REVIEW_SYSTEM)
        self.assertIn("source_rules", SYSTEM)
        self.assertIn("not copied verbatim", REVIEW_SYSTEM)
        self.assertIn("zero to five `bypass_examples`", SYSTEM)
        self.assertIn("merely a normal permitted input", REVIEW_SYSTEM)
        self.assertIn("Never summarize an outcome-changing helper", SYSTEM)
        self.assertIn("Audit every supplied `unresolved_symbols`", SYSTEM)
        self.assertIn("Examine every fail-open", SYSTEM)
        self.assertIn("fail-open path omitted", REVIEW_SYSTEM)

    def test_repair_prompt_retains_authoritative_gate_slice_for_evidence(self) -> None:
        gate_slice = next(
            item
            for item in PythonGateSlicer(
                self.root, revision="fixture-revision"
            ).build_slices(self.candidates())
            if item.gate["mode"] == "predicate"
        )
        repair = build_repair_user(
            gate_slice,
            '{"semantic_ir": {}}',
            ["evidence is missing semantic atom 'S1'"],
        )
        self.assertIn("GATE SLICE (authoritative source spans", repair)
        self.assertIn('"file": "tool.py"', repair)
        self.assertIn(f'"start_line": {gate_slice.callsite["span"]["start_line"]}', repair)
        self.assertIn("evidence is missing semantic atom 'S1'", repair)

    def test_repair_prompt_explains_reject_op_and_source_rule_repairs(self) -> None:
        gate_slice = next(
            item
            for item in PythonGateSlicer(
                self.root, revision="fixture-revision"
            ).build_slices(self.candidates())
            if item.gate["mode"] == "predicate"
        )
        repair = build_repair_user(
            gate_slice,
            '{"semantic_ir": {}}',
            [
                "semantic_ir.reject_examples[0].rejected_by must reference "
                "block-if/drop-if, got 'normalize'",
                "semantic_ir.steps[0].source_rules[0] is not an exact contiguous "
                "substring of evidence.S1",
            ],
        )
        self.assertIn("TARGETED REPAIR RULES", repair)
        self.assertIn("itself rejects or throws must use block-if or drop-if", repair)
        self.assertIn("omit source_rules instead of paraphrasing code", repair)

    def test_source_research_audit_identifies_evidence_outside_slice(self) -> None:
        gate_slice = next(
            item
            for item in PythonGateSlicer(
                self.root, revision="fixture-revision"
            ).build_slices(self.candidates())
            if item.gate["mode"] == "predicate"
        )
        supplied = gate_slice.source_bundle[0]
        audit = _source_research_audit(
            gate_slice,
            {
                "S1": [
                    {
                        "file": supplied.file,
                        "line_start": supplied.line_start,
                        "line_end": supplied.line_end,
                    },
                    {"file": "tool.py", "line_start": 40, "line_end": 41},
                ]
            },
            max_turns=20,
        )
        self.assertEqual(list(ALL_RESEARCH_TOOLS), audit["allowed_tools"])
        self.assertEqual(
            ["Read", "Grep", "Glob"], audit["allowed_tools"][:3]
        )
        self.assertEqual(20, audit["max_turns"])
        self.assertEqual(
            [
                {
                    "step_id": "S1",
                    "file": "tool.py",
                    "line_start": 40,
                    "line_end": 41,
                }
            ],
            audit["additional_evidence"],
        )

    def test_b2_result_test_is_recovered(self) -> None:
        line = _line(SOURCE, "error = is_safe(value)")
        seed = CandidateSeed(
            mode="predicate",
            gate_name="is_safe",
            call_file="tool.py",
            call_line=line,
            static_verdict="confirmed",
            owner_function="b2_handler",
            checked_hint="value",
            source_param="value",
        )
        gate_slice = PythonGateSlicer(
            self.root, revision="fixture-revision"
        ).build_slice(seed)
        self.assertEqual("not error", gate_slice.callsite["condition"])
        self.assertIn('return "blocked"', gate_slice.callsite["source"])

    def test_enriched_witness_selects_nonfirst_checked_argument(self) -> None:
        line = _line(SOURCE, 'if not two_arg_check("fixed", value):')
        column = SOURCE.splitlines()[line - 1].index("value") + 1
        seed = CandidateSeed(
            mode="predicate",
            gate_name="two_arg_check",
            call_file="tool.py",
            call_line=line,
            call_column=12,
            static_verdict="confirmed",
            owner_function="second_arg_handler",
            checked_hint="value",
            checked_file="tool.py",
            checked_line=line,
            checked_column=column,
            source_param="value",
        )
        gate_slice = PythonGateSlicer(
            self.root, revision="fixture-revision"
        ).build_slice(seed)
        self.assertEqual("value", gate_slice.checked_value["expression"])
        self.assertEqual(
            "value -> two_arg_check.value",
            gate_slice.checked_value["actual_to_formal_binding"],
        )

    def test_inline_early_exit_recovers_composite_operands_and_derivations(self) -> None:
        line = _line(SOURCE, "if not repo or not pr_number:")
        seed = CandidateSeed(
            mode="predicate",
            gate_name="inline-condition",
            call_file="tool.py",
            call_line=line,
            call_column=8,
            static_verdict="confirmed",
            owner_function="inline_delivery_handler",
            source_param="delivery",
            detector_role="inline-condition",
        )
        gate_slice = PythonGateSlicer(
            self.root, revision="fixture-revision"
        ).build_slice(seed)

        self.assertEqual(
            "not repo or not pr_number", gate_slice.checked_value["expression"]
        )
        self.assertEqual(
            ["repo", "pr_number"],
            [
                component["expression"]
                for component in gate_slice.checked_value["components"]
            ],
        )
        self.assertEqual(
            "repo and pr_number -> inline condition operands",
            gate_slice.checked_value["actual_to_formal_binding"],
        )
        self.assertEqual("resolved", gate_slice.checked_value["binding_status"])
        self.assertEqual(
            "not repo or not pr_number", gate_slice.callsite["condition"]
        )
        self.assertEqual(
            'return "blocked"',
            gate_slice.callsite["branch_effects"]["condition_true"],
        )
        self.assertEqual(
            "continue", gate_slice.callsite["branch_effects"]["condition_false"]
        )
        derivations = {
            chunk.source
            for chunk in gate_slice.source_bundle
            if chunk.role == "local-derivation"
        }
        self.assertEqual(
            {
                'extra = delivery.get("deliver_extra", {})',
                'repo = extra.get("repo", "")',
                'pr_number = extra.get("pr_number", "")',
            },
            derivations,
        )
        self.assertEqual("delivery", gate_slice.dataflow["source_symbol"])
        self.assertEqual("inline-expression", gate_slice.gate["callee_kind"])

        semantic = {
            "gate_id": gate_slice.gate_id,
            "mode": "predicate",
            "input": f"{gate_slice.input_value_id}: repo and pr_number values",
            "output": f"{gate_slice.output_value_id}: pass/block decision; inputs remain unchanged",
            "summary": "Rejects GitHub delivery targets when either the repository or pull-request identifier is falsey.",
            "steps": [
                {
                    "id": "S1",
                    "op": "block-if",
                    "rule": "The repository value is falsey; short-circuit without evaluating the pull-request identifier.",
                },
                {
                    "id": "S2",
                    "op": "block-if",
                    "rule": "The repository is truthy and the pull-request identifier is falsey.",
                },
            ],
            "default": "Continue when both values are truthy; their formats are not validated.",
            "on_error": "Propagate truthiness-evaluation errors before the downstream operation.",
            "reject_examples": [
                {
                    "input": '{"repo":"","pr_number":"123"}',
                    "rejected_by": "S1",
                    "reason": "The repository value is empty and therefore falsey.",
                },
                {
                    "input": '{"repo":"owner/project","pr_number":""}',
                    "rejected_by": "S2",
                    "reason": "The pull-request identifier is empty and therefore falsey.",
                },
            ],
            "bypass_examples": [],
            "status": "complete",
        }
        self.assertEqual([], validate_semantic_ir(semantic))

    def test_call_receiver_recovers_branch_aware_local_derivation(self) -> None:
        line = _line(SOURCE, "if local_path.is_file():")
        seed = CandidateSeed(
            mode="predicate",
            gate_name="is_file",
            call_file="tool.py",
            call_line=line,
            static_verdict="confirmed",
            owner_function="receiver_derivation_handler",
            checked_hint="local_path",
            source_param="video_url",
            detector_role="in-condition",
        )
        gate_slice = PythonGateSlicer(
            self.root, revision="fixture-revision"
        ).build_slice(seed)

        self.assertEqual("local_path", gate_slice.checked_value["expression"])
        self.assertEqual(
            "boolean branch decision; input remains unchanged",
            gate_slice.gate["output_meaning"],
        )
        derivations = [
            chunk
            for chunk in gate_slice.source_bundle
            if chunk.role == "local-derivation"
        ]
        self.assertEqual(
            [
                "resolved_url = video_url",
                'if resolved_url.startswith("file://"):\n'
                '        resolved_url = resolved_url[len("file://"):]',
                "local_path = Path(os.path.expanduser(resolved_url))",
            ],
            [chunk.source for chunk in derivations],
        )
        self.assertEqual(
            sorted(chunk.line_start for chunk in derivations),
            [chunk.line_start for chunk in derivations],
        )
        self.assertFalse(
            any("unrelated = consume" in chunk.source for chunk in derivations)
        )
        self.assertEqual(
            "evaluate nested condition is_safe(video_url)",
            gate_slice.callsite["branch_effects"]["condition_false"],
        )
        self.assertEqual(
            [
                "library-contract:pathlib.Path.is_file"
                "@supported-python-version-unpinned"
            ],
            gate_slice.unresolved_symbols,
        )

    def test_local_derivation_gate_gets_boundary_fidelity_review(self) -> None:
        line = _line(SOURCE, "if local_path.is_file():")
        gate_slice = PythonGateSlicer(
            self.root, revision="fixture-revision"
        ).build_slice(
            CandidateSeed(
                mode="predicate",
                gate_name="is_file",
                call_file="tool.py",
                call_line=line,
                static_verdict="confirmed",
                owner_function="receiver_derivation_handler",
                checked_hint="local_path",
                source_param="video_url",
                detector_role="in-condition",
            )
        )
        draft = {
            "semantic_ir": valid_ir(gate_slice),
            "evidence": {
                "S1": [{"file": "tool.py", "line_start": line, "line_end": line}]
            },
        }
        reviewed_ir = {
            "gate_id": gate_slice.gate_id,
            "mode": "predicate",
            "input": f"{gate_slice.input_value_id}: locally derived path",
            "output": f"{gate_slice.output_value_id}: boolean branch decision",
            "summary": "Selects the local-file branch only when the derived path identifies an existing regular file.",
            "steps": [
                {
                    "id": "S1",
                    "op": "derive",
                    "rule": "Initialize resolved_url from video_url.",
                },
                {
                    "id": "S2",
                    "op": "normalize",
                    "rule": "Remove the leading file:// prefix when present.",
                },
                {
                    "id": "S3",
                    "op": "derive",
                    "rule": "Expand the user-home prefix and construct local_path.",
                },
                {
                    "id": "S4",
                    "op": "allow-if",
                    "rule": "is_file returns true for the derived path.",
                },
                {
                    "id": "S5",
                    "op": "unknown",
                    "rule": "Runtime-version-specific pathlib error behavior remains unresolved.",
                },
            ],
            "default": "False advances to the sibling URL predicate without rejection.",
            "on_error": "Runtime-version-specific pathlib error behavior is unresolved.",
            "reject_examples": [],
            "bypass_examples": [],
            "status": "partial",
        }
        reviewed = {
            "semantic_ir": reviewed_ir,
            "evidence": {
                "S1": [{"file": "tool.py", "line_start": line - 4, "line_end": line - 4}],
                "S2": [{"file": "tool.py", "line_start": line - 3, "line_end": line - 2}],
                "S3": [{"file": "tool.py", "line_start": line - 1, "line_end": line - 1}],
                "S4": [{"file": "tool.py", "line_start": line, "line_end": line}],
                "S5": [{"file": "tool.py", "line_start": line, "line_end": line}],
                "on_error": [
                    {"file": "tool.py", "line_start": line, "line_end": line}
                ],
            },
        }
        systems: list[str] = []

        def runner(system: str, _user: str) -> str:
            systems.append(system)
            return json.dumps(reviewed if system == REVIEW_SYSTEM else draft)

        ir, evidence, raw, errors = analyze_gate(
            gate_slice,
            runner=runner,
            repair_runner=runner,
            source_root=self.root,
            debug_fidelity_review=True,
        )
        self.assertEqual(2, len(raw))
        self.assertEqual([], errors)
        self.assertEqual("partial", ir["status"])
        self.assertEqual([], ir["reject_examples"])
        self.assertFalse(any(step["op"] == "block-if" for step in ir["steps"]))
        self.assertNotIn("on_error", evidence)
        self.assertEqual(REVIEW_SYSTEM, systems[-1])

    def test_local_derivation_gate_uses_one_call_in_product_mode(self) -> None:
        line = _line(SOURCE, "if local_path.is_file():")
        gate_slice = PythonGateSlicer(
            self.root, revision="fixture-revision"
        ).build_slice(
            CandidateSeed(
                mode="predicate",
                gate_name="is_file",
                call_file="tool.py",
                call_line=line,
                static_verdict="confirmed",
                owner_function="receiver_derivation_handler",
                checked_hint="local_path",
                source_param="video_url",
                detector_role="in-condition",
            )
        )
        response = {
            "semantic_ir": valid_ir(gate_slice),
            "evidence": {
                "S1": [{"file": "tool.py", "line_start": line, "line_end": line}]
            },
        }
        systems: list[str] = []

        def runner(system: str, _user: str) -> str:
            systems.append(system)
            return json.dumps(response)

        _ir, _evidence, raw, errors = analyze_gate(
            gate_slice,
            runner=runner,
            repair_runner=runner,
            source_root=self.root,
        )
        self.assertEqual([], errors)
        self.assertEqual(1, len(raw))
        self.assertEqual([SYSTEM], systems)

    def test_fidelity_review_allows_two_bounded_contract_repairs(self) -> None:
        line = _line(SOURCE, "if local_path.is_file():")
        gate_slice = PythonGateSlicer(
            self.root, revision="fixture-revision"
        ).build_slice(
            CandidateSeed(
                mode="predicate",
                gate_name="is_file",
                call_file="tool.py",
                call_line=line,
                static_verdict="confirmed",
                owner_function="receiver_derivation_handler",
                checked_hint="local_path",
                source_param="video_url",
                detector_role="in-condition",
            )
        )
        valid = {
            "semantic_ir": valid_ir(gate_slice),
            "evidence": {
                "S1": [{"file": "tool.py", "line_start": line, "line_end": line}]
            },
        }
        long_summary = json.loads(json.dumps(valid))
        long_summary["semantic_ir"]["summary"] = "word " * 36
        long_rule = json.loads(json.dumps(valid))
        long_rule["semantic_ir"]["steps"][0]["rule"] = "word " * 26
        responses = iter([valid, long_summary, long_rule, valid])

        def runner(_system: str, _user: str) -> str:
            return json.dumps(next(responses))

        ir, _, raw, errors = analyze_gate(
            gate_slice,
            runner=runner,
            repair_runner=runner,
            source_root=self.root,
            debug_fidelity_review=True,
        )
        self.assertEqual(valid["semantic_ir"], ir)
        self.assertEqual(4, len(raw))
        self.assertTrue(any("summary exceeds 35 words" in error for error in errors))
        self.assertTrue(any("rule exceeds 25 words" in error for error in errors))

    def test_nested_transform_does_not_inherit_outer_result_condition(self) -> None:
        line = _line(SOURCE, 'result = consume(f"prefix {sanitize(value)}")')
        seed = CandidateSeed(
            mode="transform",
            gate_name="sanitize",
            call_file="tool.py",
            call_line=line,
            static_verdict="confirmed",
            owner_function="nested_transform_handler",
            checked_hint="value",
            source_param="value",
            call_expr_hint="Attribute()",
        )
        gate_slice = PythonGateSlicer(
            self.root, revision="fixture-revision"
        ).build_slice(seed)
        self.assertEqual("sanitize(value)", gate_slice.gate["call_expression"])
        self.assertEqual("", gate_slice.callsite["condition"])
        self.assertIn("result = consume", gate_slice.callsite["source"])
        self.assertNotIn("if result", gate_slice.callsite["source"])

    def test_contract_and_reject_examples(self) -> None:
        gate_slice = next(
            item
            for item in PythonGateSlicer(
                self.root, revision="fixture-revision"
            ).build_slices(self.candidates())
            if item.gate["mode"] == "predicate"
        )
        ir = valid_ir(gate_slice)
        self.assertEqual([], validate_semantic_ir(ir))
        parsed_ir, evidence = validate_analysis_response(
            {
                "semantic_ir": ir,
                "evidence": {
                    "S1": [{"file": "tool.py", "line_start": 1, "line_end": 8}]
                },
            },
            expected_gate_id=gate_slice.gate_id,
            expected_mode="predicate",
            expected_input_id=gate_slice.input_value_id,
            expected_output_id=gate_slice.output_value_id,
        )
        self.assertEqual(ir, parsed_ir)
        self.assertIn("S1", evidence)

        invalid = json.loads(json.dumps(ir))
        invalid["reject_examples"][0]["rejected_by"] = "S9"
        errors = validate_semantic_ir(invalid)
        self.assertTrue(any("unknown atom" in error for error in errors))

        with_source_rules = json.loads(json.dumps(ir))
        with_source_rules["steps"][0]["source_rules"] = [
            'BLOCKED = {"internal"}'
        ]
        self.assertEqual([], validate_semantic_ir(with_source_rules))
        validate(instance=with_source_rules, schema=load_schema(SEMANTIC_SCHEMA_PATH))

        duplicate_rules = json.loads(json.dumps(with_source_rules))
        duplicate_rules["steps"][0]["source_rules"] *= 2
        self.assertTrue(
            any(
                "source_rules must not contain duplicates" in error
                for error in validate_semantic_ir(duplicate_rules)
            )
        )

        empty_rules = json.loads(json.dumps(with_source_rules))
        empty_rules["steps"][0]["source_rules"] = []
        self.assertTrue(
            any(
                "source_rules must be a non-empty list" in error
                for error in validate_semantic_ir(empty_rules)
            )
        )

        transform = json.loads(json.dumps(ir))
        transform["mode"] = "transform"
        self.assertTrue(
            any("transform gates" in error for error in validate_semantic_ir(transform))
        )

    def test_contract_and_bypass_examples(self) -> None:
        gate_slice = next(
            item
            for item in PythonGateSlicer(
                self.root, revision="fixture-revision"
            ).build_slices(self.candidates())
            if item.gate["mode"] == "predicate"
        )
        ir = valid_ir(gate_slice)
        ir["steps"].append(
            {
                "id": "S2",
                "op": "allow-if",
                "rule": "The normalized value does not belong to the blocked set.",
            }
        )
        example = {
            "input": "symbolic value matching an unmodeled alias",
            "passed_by": "S2",
            "reason": "The alias is absent from the source-defined blocked set.",
            "potential_security_impact": "The caller may process a security-equivalent value that the gate intended to block.",
            "precondition": "The downstream operation treats the alias as equivalent.",
        }
        ir["bypass_examples"] = [example]
        self.assertEqual([], validate_semantic_ir(ir))
        validate(instance=ir, schema=load_schema(SEMANTIC_SCHEMA_PATH))

        too_many = json.loads(json.dumps(ir))
        too_many["bypass_examples"] = [example] * 6
        self.assertTrue(
            any("at most five" in error for error in validate_semantic_ir(too_many))
        )

        unknown_atom = json.loads(json.dumps(ir))
        unknown_atom["bypass_examples"][0]["passed_by"] = "S8"
        self.assertTrue(
            any("unknown atom" in error for error in validate_semantic_ir(unknown_atom))
        )

        rejecting_atom = json.loads(json.dumps(ir))
        rejecting_atom["bypass_examples"][0]["passed_by"] = "S1"
        self.assertTrue(
            any(
                "allow-if/admit-if" in error
                for error in validate_semantic_ir(rejecting_atom)
            )
        )

        missing_impact = json.loads(json.dumps(ir))
        del missing_impact["bypass_examples"][0]["potential_security_impact"]
        self.assertTrue(
            any(
                "potential_security_impact must be" in error
                for error in validate_semantic_ir(missing_impact)
            )
        )

        transform = json.loads(json.dumps(ir))
        transform["mode"] = "transform"
        self.assertTrue(
            any(
                "transform gates must not fabricate bypass_examples" in error
                for error in validate_semantic_ir(transform)
            )
        )

    def test_hermes_gate_0002_root_operand_bypass_example(self) -> None:
        """A traversal name can select a root outside the configured search dir."""

        repo_root = Path(__file__).resolve().parents[3]
        helper = runpy.run_path(
            str(
                repo_root
                / "benchmark/python/hermes-agent/tools/path_security.py"
            )
        )["validate_within_dir"]

        sandbox = self.root / "gate-0002"
        search_dir = sandbox / "trusted" / "skills"
        attacker_dir = sandbox / "attacker"
        search_dir.mkdir(parents=True)
        attacker_dir.mkdir(parents=True)
        (attacker_dir / "SKILL.md").write_text(
            "outside trusted skills root", encoding="utf-8"
        )

        name = "../../attacker"
        file_path = "SKILL.md"
        skill_dir = search_dir / name
        self.assertTrue(skill_dir.is_dir())
        self.assertTrue((skill_dir / "SKILL.md").exists())

        target_file = skill_dir / file_path
        self.assertIsNone(helper(target_file, skill_dir))
        self.assertFalse(target_file.resolve().is_relative_to(search_dir.resolve()))
        self.assertEqual(
            "outside trusted skills root",
            target_file.read_text(encoding="utf-8"),
        )

    def test_regular_ir_hard_limit_is_2000_tokens(self) -> None:
        gate_slice = next(
            item
            for item in PythonGateSlicer(
                self.root, revision="fixture-revision"
            ).build_slices(self.candidates())
            if item.gate["mode"] == "predicate"
        )
        ir = valid_ir(gate_slice)
        ir["default"] = "Continue with the checked value. " * 200
        self.assertGreater(estimate_tokens(ir), 360)
        self.assertLessEqual(estimate_tokens(ir), REGULAR_HARD_TOKEN_LIMIT)
        self.assertEqual([], validate_semantic_ir(ir))

        too_large = json.loads(json.dumps(ir))
        too_large["default"] = "Continue with the checked value. " * 2000
        self.assertGreater(estimate_tokens(too_large), REGULAR_HARD_TOKEN_LIMIT)
        errors = validate_semantic_ir(too_large)
        self.assertTrue(
            any(
                f"hard limit is {REGULAR_HARD_TOKEN_LIMIT}" in error
                for error in errors
            )
        )

        invalid_summary = json.loads(json.dumps(ir))
        invalid_summary["summary"] = "word " * 36
        self.assertTrue(
            any(
                "summary exceeds 35 words" in error
                for error in validate_semantic_ir(invalid_summary)
            )
        )

    def test_schema_files_and_fenced_json_parser(self) -> None:
        self.assertEqual("GateSemanticIRV1", load_schema(SEMANTIC_SCHEMA_PATH)["title"])
        self.assertEqual(
            "GateAnalysisResponseV1", load_schema(ANALYSIS_SCHEMA_PATH)["title"]
        )
        self.assertEqual(
            "GateSemanticIRV2", load_schema(COMPOUND_SEMANTIC_SCHEMA_PATH)["title"]
        )
        self.assertEqual(
            "GateAnalysisResponseV2",
            load_schema(COMPOUND_ANALYSIS_SCHEMA_PATH)["title"],
        )
        self.assertEqual(
            {"ok": True}, parse_json_response('```json\n{"ok": true}\n```')
        )
        self.assertEqual(
            {"ok": True},
            parse_json_response(
                'Explanation mentioning {input, reason}.\n```json\n{"ok": true}\n```'
            ),
        )
        self.assertEqual(
            {"fragment_id": "F1", "rules": ["complete response"]},
            parse_json_response(
                'Evidence {"file":"tool.py","line_start":1,"line_end":1}. '
                'Result {"fragment_id":"F1","rules":["complete response"]}'
            ),
        )
        with self.assertRaises(ContractError):
            parse_json_response("not JSON")
        with self.assertRaisesRegex(ContractError, "semantic_ir must be a JSON object"):
            validate_analysis_response({"semantic_ir": [], "evidence": {}})

    def test_evidence_must_cover_steps_and_stay_inside_source(self) -> None:
        gate_slice = next(
            item
            for item in PythonGateSlicer(
                self.root, revision="fixture-revision"
            ).build_slices(self.candidates())
            if item.gate["mode"] == "predicate"
        )
        response = {"semantic_ir": valid_ir(gate_slice), "evidence": {}}
        with self.assertRaisesRegex(ContractError, "evidence is missing"):
            validate_analysis_response(response)

        response["evidence"] = {
            "S1": [{"file": "../tool.py", "line_start": 1, "line_end": 1}]
        }
        with self.assertRaisesRegex(ContractError, "source-relative"):
            analyze_gate(
                gate_slice,
                runner=lambda _system, _user: json.dumps(response),
                source_root=self.root,
            )

        response["evidence"] = {
            "S1": [{"file": "tool.py", "line_start": 1, "line_end": 999}]
        }
        with self.assertRaisesRegex(ContractError, "beyond"):
            analyze_gate(
                gate_slice,
                runner=lambda _system, _user: json.dumps(response),
                source_root=self.root,
            )

    def test_regex_matcher_gets_verbatim_source_rules_in_product_mode(self) -> None:
        line = _line(SOURCE, "if PREFIX_RE.search(value):")
        gate_slice = PythonGateSlicer(
            self.root, revision="fixture-revision"
        ).build_slice(
            CandidateSeed(
                mode="predicate",
                gate_name="search",
                call_file="tool.py",
                call_line=line,
                static_verdict="confirmed",
                owner_function="regex_handler",
                checked_hint="value",
                source_param="value",
                detector_role="in-condition",
            )
        )
        response = {
            "semantic_ir": valid_ir(gate_slice),
            "evidence": {
                "S1": [{"file": "tool.py", "line_start": line, "line_end": line}]
            },
        }

        ir, evidence, raw, errors = analyze_gate(
            gate_slice,
            runner=lambda _system, _user: json.dumps(response),
            source_root=self.root,
        )
        self.assertEqual([], errors)
        self.assertEqual(1, len(raw))
        self.assertEqual(2, len(ir["steps"][0]["source_rules"]))
        self.assertEqual(
            'PREFIX_PATTERNS = [r"sk-[A-Za-z0-9_-]{10,}"]',
            ir["steps"][0]["source_rules"][0],
        )
        self.assertEqual(3, len(evidence["S1"]))

    def test_regex_matcher_requires_verbatim_source_rules_in_debug_review(self) -> None:
        line = _line(SOURCE, "if PREFIX_RE.search(value):")
        gate_slice = PythonGateSlicer(
            self.root, revision="fixture-revision"
        ).build_slice(
            CandidateSeed(
                mode="predicate",
                gate_name="search",
                call_file="tool.py",
                call_line=line,
                static_verdict="confirmed",
                owner_function="regex_handler",
                checked_hint="value",
                source_param="value",
                detector_role="in-condition",
            )
        )
        draft_ir = valid_ir(gate_slice)
        draft = {
            "semantic_ir": draft_ir,
            "evidence": {
                "S1": [{"file": "tool.py", "line_start": line, "line_end": line}]
            },
        }
        reviewed_ir = json.loads(json.dumps(draft_ir))
        reviewed_ir["steps"][0]["source_rules"] = [
            'PREFIX_PATTERNS = [r"sk-[A-Za-z0-9_]{10,}"]',
            'PREFIX_RE = re.compile(r"(?<![A-Za-z0-9_-])(" + "|".join(PREFIX_PATTERNS) + r")(?![A-Za-z0-9_-])")',
        ]
        patterns_line = _line(SOURCE, "PREFIX_PATTERNS =")
        compile_line = _line(SOURCE, "PREFIX_RE = re.compile")
        reviewed = {
            "semantic_ir": reviewed_ir,
            "evidence": {
                "S1": [
                    {
                        "file": "tool.py",
                        "line_start": patterns_line,
                        "line_end": patterns_line,
                    },
                    {
                        "file": "tool.py",
                        "line_start": compile_line,
                        "line_end": compile_line,
                    },
                ]
            },
        }
        systems: list[str] = []

        def runner(system: str, _user: str) -> str:
            systems.append(system)
            return json.dumps(reviewed if system == REVIEW_SYSTEM else draft)

        ir, evidence, raw, errors = analyze_gate(
            gate_slice,
            runner=runner,
            repair_runner=runner,
            source_root=self.root,
            debug_fidelity_review=True,
        )
        self.assertEqual([], errors)
        self.assertEqual(2, len(raw))
        self.assertEqual(REVIEW_SYSTEM, systems[-1])
        self.assertEqual(2, len(ir["steps"][0]["source_rules"]))
        self.assertEqual(
            'PREFIX_PATTERNS = [r"sk-[A-Za-z0-9_-]{10,}"]',
            ir["steps"][0]["source_rules"][0],
        )
        self.assertEqual(2, len(evidence["S1"]))

    def test_source_rule_must_be_exact_substring_of_same_step_evidence(self) -> None:
        line = _line(SOURCE, "if PREFIX_RE.search(value):")
        gate_slice = PythonGateSlicer(
            self.root, revision="fixture-revision"
        ).build_slice(
            CandidateSeed(
                mode="predicate",
                gate_name="search",
                call_file="tool.py",
                call_line=line,
                static_verdict="confirmed",
                owner_function="regex_handler",
                checked_hint="value",
                source_param="value",
                detector_role="in-condition",
            )
        )
        ir = valid_ir(gate_slice)
        ir["steps"][0]["source_rules"] = ["PREFIX_PATTERNS = []"]
        response = {
            "semantic_ir": ir,
            "evidence": {
                "S1": [{"file": "tool.py", "line_start": 1, "line_end": line}]
            },
        }
        with self.assertRaisesRegex(ContractError, "not an exact contiguous substring"):
            analyze_gate(
                gate_slice,
                runner=lambda _system, _user: json.dumps(response),
                source_root=self.root,
            )

    def test_exact_source_rule_relocates_within_authoritative_slice_file(self) -> None:
        line = _line(SOURCE, "if not is_safe(value):")
        gate_slice = PythonGateSlicer(
            self.root, revision="fixture-revision"
        ).build_slice(
            CandidateSeed(
                mode="predicate",
                gate_name="is_safe",
                call_file="tool.py",
                call_line=line,
                static_verdict="confirmed",
                owner_function="predicate_handler",
                checked_hint="value",
                source_param="value",
                detector_role="in-condition",
            )
        )
        ir = valid_ir(gate_slice)
        exact_line = "normalized = value.strip().lower()"
        ir["steps"][0]["source_rules"] = [exact_line]
        response = {
            "semantic_ir": ir,
            "evidence": {
                "S1": [{"file": "tool.py", "line_start": line, "line_end": line}]
            },
        }
        semantic, evidence, _raw, errors = analyze_gate(
            gate_slice,
            runner=lambda _system, _user: json.dumps(response),
            source_root=self.root,
        )
        self.assertEqual([], errors)
        self.assertEqual([exact_line], semantic["steps"][0]["source_rules"])
        self.assertIn(
            {
                "file": "tool.py",
                "line_start": _line(SOURCE, exact_line),
                "line_end": _line(SOURCE, exact_line),
            },
            evidence["S1"],
        )

    def test_pipeline_uses_compact_artifact_and_separate_audit(self) -> None:
        calls = 0

        def runner(_system: str, user: str) -> str:
            nonlocal calls
            calls += 1
            marker = "EXPECTED IDENTIFIERS:\n"
            expected_text = user.split(marker, 1)[1].split("\n\n", 1)[0]
            expected = json.loads(expected_text)
            mode = expected["mode"]
            rejecting_op = "drop-if" if mode == "filter" else "block-if"
            response = {
                "semantic_ir": {
                    "gate_id": expected["gate_id"],
                    "mode": mode,
                    "input": f"{expected['input_value_id']}: candidate value",
                    "output": f"{expected['output_value_id']}: gate result",
                    "summary": "Checks the source-defined policy for the candidate value.",
                    "steps": [
                        {
                            "id": "S1",
                            "op": "transform" if mode == "transform" else rejecting_op,
                            "rule": (
                                "Remove less-than characters from the value."
                                if mode == "transform"
                                else "The value belongs to the blocked set."
                            ),
                        }
                    ],
                    "default": (
                        "return transformed value" if mode == "transform" else "pass"
                    ),
                    "on_error": ("propagate error" if mode == "transform" else "block"),
                    "reject_examples": (
                        []
                        if mode == "transform"
                        else [
                            {
                                "input": "internal",
                                "rejected_by": "S1",
                                "reason": "The value belongs to the blocked set.",
                            }
                        ]
                    ),
                    "bypass_examples": [],
                    "status": "complete",
                },
                "evidence": {
                    "S1": [{"file": "tool.py", "line_start": 1, "line_end": 8}]
                },
            }
            return json.dumps(response)

        out = self.root / "out"
        manifest = run_pipeline(
            source_root=self.root,
            dominance_candidates=self.debug / "dominance.csv",
            filter_candidates=self.debug / "filter.csv",
            transform_candidates=self.debug / "transform.csv",
            out_dir=out,
            generation_command="python -m src.gate_semantics.main ...",
            runner=runner,
        )
        self.assertEqual(3, calls)
        self.assertEqual(3, manifest["counts"]["catalog_gates"])
        self.assertEqual(3, manifest["counts"]["selected_gates"])
        self.assertEqual(3, manifest["counts"]["semantic_records"])
        self.assertEqual(3, manifest["counts"]["llm_chat_records"])
        self.assertEqual(0, manifest["counts"]["reused_semantics"])
        self.assertEqual(3, manifest["counts"]["generated_semantics"])
        self.assertFalse(manifest["agent"]["debug_fidelity_review"])
        catalog = list(
            csv.DictReader(
                (out / "gate-index.csv").read_text(encoding="utf-8").splitlines()
            )
        )
        self.assertEqual(["1", "2", "3"], [row["gate_number"] for row in catalog])
        self.assertTrue(all(row["gate_uid"].startswith("GU") for row in catalog))
        self.assertEqual(3, len({row["gate_uid"] for row in catalog}))
        self.assertEqual(
            sorted(row["gate_id"] for row in catalog),
            [row["gate_id"] for row in catalog],
        )
        catalog_markdown = (out / "gate-index.md").read_text(encoding="utf-8")
        self.assertTrue(
            catalog_markdown.startswith("# Check Gate Catalog\n\n> Generation command:")
        )
        self.assertIn("--gate-number 4", catalog_markdown)
        records = [
            json.loads(line)
            for line in (out / "gate-semantics.jsonl").read_text().splitlines()
        ]
        audits = [
            json.loads(line)
            for line in (out / "gate-semantics-audit.jsonl").read_text().splitlines()
        ]
        self.assertEqual(3, len(records))
        self.assertEqual(3, len(audits))
        slices = [
            json.loads(line)
            for line in (out / "gate-slices.jsonl").read_text().splitlines()
        ]
        self.assertEqual([1, 2, 3], [item["gate_number"] for item in slices])
        self.assertNotIn("evidence", records[0])
        self.assertIn("evidence", audits[0])
        self.assertFalse(audits[0]["debug_fidelity_review"])
        self.assertFalse(audits[0]["llm_usage"]["provider_reported"])
        self.assertEqual(0, manifest["counts"]["llm_total_tokens"])
        self.assertEqual(0, manifest["llm_usage"]["total_tokens"])
        self.assertEqual(
            ["Read", "Grep", "Glob"],
            audits[0]["source_research"]["allowed_tools"],
        )
        self.assertFalse(manifest["agent"]["lsp_enabled"])
        self.assertEqual("injected", manifest["agent"]["transport"])
        self.assertEqual("injected-runner", audits[0]["model"])
        self.assertTrue(audits[0]["source_chunks"])
        self.assertIn("sha256", audits[0]["source_chunks"][0])
        self.assertEqual(1, len(audits[0]["raw_responses"]))
        self.assertIn(
            "generation_command", json.loads((out / "manifest.json").read_text())
        )
        first_chat = json.loads(
            Path(manifest["outputs"]["llm_chat_files"]["1"]).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("gate-llm-chat/v1", first_chat["schema_version"])
        self.assertEqual(1, first_chat["gate_number"])
        self.assertFalse(first_chat["debug_fidelity_review"])
        self.assertEqual(1, len(first_chat["exchanges"]))
        self.assertIn("EXPECTED IDENTIFIERS", first_chat["exchanges"][0]["user"])
        self.assertIn("semantic_ir", first_chat["exchanges"][0]["assistant"])
        for row in catalog:
            gate_dir = out / "repository" / row["gate_uid"]
            self.assertTrue((gate_dir / "slice.json").is_file())
            self.assertTrue((gate_dir / "semantic.json").is_file())
            self.assertTrue((gate_dir / "audit.json").is_file())
            self.assertTrue((gate_dir / "chat.json").is_file())

        reused_manifest = run_pipeline(
            source_root=self.root,
            dominance_candidates=self.debug / "dominance.csv",
            filter_candidates=self.debug / "filter.csv",
            transform_candidates=self.debug / "transform.csv",
            out_dir=out,
            generation_command="python -m src.gate_semantics.main ...",
            runner=runner,
        )
        self.assertEqual(3, calls)
        self.assertEqual(3, reused_manifest["counts"]["reused_semantics"])
        self.assertEqual(0, reused_manifest["counts"]["generated_semantics"])

        debug_manifest = run_pipeline(
            source_root=self.root,
            dominance_candidates=self.debug / "dominance.csv",
            filter_candidates=self.debug / "filter.csv",
            transform_candidates=self.debug / "transform.csv",
            out_dir=out,
            generation_command=(
                "python -m src.gate_semantics.main --gate-number 1 "
                "--debug-fidelity-review"
            ),
            runner=runner,
            gate_numbers=[1],
            debug_fidelity_review=True,
        )
        self.assertEqual(5, calls)
        self.assertEqual(0, debug_manifest["counts"]["reused_semantics"])
        self.assertEqual(1, debug_manifest["counts"]["generated_semantics"])
        self.assertTrue(debug_manifest["agent"]["debug_fidelity_review"])
        debug_chat = json.loads(
            Path(debug_manifest["outputs"]["llm_chat_files"]["1"]).read_text(
                encoding="utf-8"
            )
        )
        self.assertTrue(debug_chat["debug_fidelity_review"])
        self.assertEqual(2, len(debug_chat["exchanges"]))

        legacy = self.root / "legacy"
        legacy.mkdir()
        shutil.copy2(out / "gate-index.csv", legacy / "gate-index.csv")
        for row in catalog:
            old_dir = (
                legacy
                / "selected"
                / f"{int(row['gate_number']):04d}-{row['gate_id']}"
            )
            old_dir.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(out / "repository" / row["gate_uid"], old_dir)
        migrated_manifest = run_pipeline(
            source_root=self.root,
            dominance_candidates=self.debug / "dominance.csv",
            filter_candidates=self.debug / "filter.csv",
            transform_candidates=self.debug / "transform.csv",
            out_dir=legacy,
            generation_command="python -m src.gate_semantics.main ...",
            runner=runner,
        )
        self.assertEqual(5, calls)
        self.assertEqual(3, migrated_manifest["counts"]["migrated_semantics"])
        self.assertEqual(3, migrated_manifest["counts"]["reused_semantics"])

        changed_source = SOURCE.replace(
            "    return True\n\ndef sanitize",
            '    return value != "changed"\n\ndef sanitize',
        )
        (self.root / "tool.py").write_text(changed_source, encoding="utf-8")
        changed_manifest = run_pipeline(
            source_root=self.root,
            dominance_candidates=self.debug / "dominance.csv",
            filter_candidates=self.debug / "filter.csv",
            transform_candidates=self.debug / "transform.csv",
            out_dir=out,
            generation_command="python -m src.gate_semantics.main ...",
            runner=runner,
        )
        self.assertEqual(7, calls)
        self.assertEqual(1, changed_manifest["counts"]["reused_semantics"])
        self.assertEqual(2, changed_manifest["counts"]["generated_semantics"])
        (self.root / "tool.py").write_text(SOURCE, encoding="utf-8")

        isolated = self.root / "isolated"
        isolated_manifest = run_pipeline(
            source_root=self.root,
            dominance_candidates=self.debug / "dominance.csv",
            filter_candidates=self.debug / "filter.csv",
            transform_candidates=self.debug / "transform.csv",
            out_dir=isolated,
            generation_command="python -m src.gate_semantics.main --gate-number 2",
            gate_numbers=[2],
            runner=runner,
        )
        self.assertEqual(8, calls)
        self.assertEqual(3, isolated_manifest["counts"]["catalog_gates"])
        self.assertEqual(1, isolated_manifest["counts"]["selected_gates"])
        self.assertEqual([2], isolated_manifest["selection"]["selected_gate_numbers"])
        self.assertEqual(
            [catalog[1]["gate_id"]],
            isolated_manifest["selection"]["selected_gate_ids"],
        )
        isolated_semantics = [
            json.loads(line)
            for line in (isolated / "gate-semantics.jsonl").read_text().splitlines()
        ]
        self.assertEqual(
            [catalog[1]["gate_id"]], [item["gate_id"] for item in isolated_semantics]
        )
        isolated_dir = isolated / "repository" / catalog[1]["gate_uid"]
        self.assertTrue((isolated_dir / "slice.json").is_file())
        self.assertTrue((isolated_dir / "semantic.json").is_file())
        self.assertTrue((isolated_dir / "audit.json").is_file())

        for invalid in ([0], [4], [2, 2]):
            with self.assertRaises(GateSelectionError):
                run_pipeline(
                    source_root=self.root,
                    dominance_candidates=self.debug / "dominance.csv",
                    filter_candidates=self.debug / "filter.csv",
                    transform_candidates=self.debug / "transform.csv",
                    out_dir=self.root / "invalid",
                    generation_command="test",
                    build_slices_only=True,
                    gate_numbers=invalid,
                )

    def test_owned_sdk_runner_is_audited_and_closed(self) -> None:
        class ClosableRunner:
            def __init__(self, *, fail: bool = False) -> None:
                self.fail = fail
                self.closed = False

            def __call__(self, _system: str, user: str) -> str:
                if self.fail:
                    raise RuntimeError("runner failed")
                marker = "EXPECTED IDENTIFIERS:\n"
                expected_text = user.split(marker, 1)[1].split("\n\n", 1)[0]
                expected = json.loads(expected_text)
                mode = expected["mode"]
                op = (
                    "transform"
                    if mode == "transform"
                    else "drop-if" if mode == "filter" else "block-if"
                )
                return json.dumps(
                    {
                        "semantic_ir": {
                            "gate_id": expected["gate_id"],
                            "mode": mode,
                            "input": f"{expected['input_value_id']}: value",
                            "output": f"{expected['output_value_id']}: result",
                            "summary": "Applies the selected source-defined gate behavior.",
                            "steps": [
                                {
                                    "id": "S1",
                                    "op": op,
                                    "rule": "Apply the source-defined operation.",
                                }
                            ],
                            "default": (
                                "return transformed value"
                                if mode == "transform"
                                else "pass"
                            ),
                            "on_error": "propagate error",
                            "reject_examples": [],
                            "bypass_examples": [],
                            "status": "complete",
                        },
                        "evidence": {
                            "S1": [
                                {
                                    "file": "tool.py",
                                    "line_start": 1,
                                    "line_end": 8,
                                }
                            ]
                        },
                    }
                )

            def audit_payload(self) -> dict[str, object]:
                return {
                    "transport": "test-sdk",
                    "available_tools": list(ALL_RESEARCH_TOOLS),
                    "token_usage": {
                        "provider_reported": True,
                        "input_tokens": 10,
                        "cache_creation_input_tokens": 0,
                        "cache_read_input_tokens": 0,
                        "output_tokens": 4,
                        "total_input_tokens": 10,
                        "total_tokens": 14,
                    },
                    "turns": [{"tool_calls": []}],
                }

            def close(self) -> None:
                self.closed = True

        success = ClosableRunner()
        with patch(
            "src.gate_semantics.pipeline.build_sdk_runner", return_value=success
        ):
            manifest = run_pipeline(
                source_root=self.root,
                dominance_candidates=self.debug / "dominance.csv",
                filter_candidates=self.debug / "filter.csv",
                transform_candidates=self.debug / "transform.csv",
                out_dir=self.root / "owned-success",
                generation_command="test",
                gate_numbers=[1],
            )
        self.assertTrue(success.closed)
        self.assertEqual(1, manifest["counts"]["semantic_records"])
        self.assertEqual(14, manifest["counts"]["llm_total_tokens"])
        audit = json.loads(
            next(
                (self.root / "owned-success" / "repository").glob("*/audit.json")
            ).read_text(encoding="utf-8")
        )
        self.assertEqual("test-sdk", audit["agent_session"]["transport"])
        self.assertEqual(14, audit["llm_usage"]["total_tokens"])

        failure = ClosableRunner(fail=True)
        with patch(
            "src.gate_semantics.pipeline.build_sdk_runner", return_value=failure
        ):
            failed_manifest = run_pipeline(
                source_root=self.root,
                dominance_candidates=self.debug / "dominance.csv",
                filter_candidates=self.debug / "filter.csv",
                transform_candidates=self.debug / "transform.csv",
                out_dir=self.root / "owned-failure",
                generation_command="test",
                gate_numbers=[1],
            )
        self.assertTrue(failure.closed)
        self.assertEqual(1, failed_manifest["counts"]["analysis_failures"])
        failed_chat = json.loads(
            Path(failed_manifest["outputs"]["llm_chat_files"]["1"]).read_text(
                encoding="utf-8"
            )
        )
        self.assertIn("runner failed", failed_chat["exchanges"][0]["error"])

    def test_repair_and_thirty_gate_render_budget(self) -> None:
        gate_slice = next(
            item
            for item in PythonGateSlicer(
                self.root, revision="fixture-revision"
            ).build_slices(self.candidates())
            if item.gate["mode"] == "predicate"
        )
        valid = {
            "semantic_ir": valid_ir(gate_slice),
            "evidence": {"S1": [{"file": "tool.py", "line_start": 1, "line_end": 8}]},
        }
        responses = iter(["not-json", json.dumps(valid)])

        def runner(_system: str, _user: str) -> str:
            return next(responses)

        ir, _, raw_responses, errors = analyze_gate(
            gate_slice,
            runner=runner,
            repair_runner=runner,
            source_root=self.root,
        )
        self.assertEqual(gate_slice.gate_id, ir["gate_id"])
        self.assertEqual(2, len(raw_responses))
        self.assertTrue(errors)

        records = []
        for number in range(30):
            current = json.loads(json.dumps(ir))
            current["gate_id"] = f"G{number:03d}"
            records.append(current)
        rendered = render_chain_semantics(records)
        self.assertLess(estimate_tokens(rendered), 9000)

    def test_regular_analysis_drops_unprovable_optional_claims(self) -> None:
        gate_slice = next(
            item
            for item in PythonGateSlicer(
                self.root, revision="fixture-revision"
            ).build_slices(self.candidates())
            if item.gate["mode"] == "predicate"
        )
        ir = valid_ir(gate_slice)
        ir["steps"][0]["op"] = "normalize"
        ir["steps"][0]["source_rules"] = ["paraphrased source, not a quote"]
        ir["bypass_examples"] = [
            {
                "input": "external",
                "passed_by": "S1",
                "reason": "The value passes this step.",
                "potential_security_impact": "The immediate consumer receives it.",
            }
        ]
        response = json.dumps(
            {
                "semantic_ir": ir,
                "evidence": {
                    "S1": [{"file": "tool.py", "line_start": 1, "line_end": 8}]
                },
            }
        )

        def no_repair(_system: str, _user: str) -> str:
            raise AssertionError("claim-preserving cleanup should avoid a repair call")

        analyzed, _, raw_responses, errors = analyze_gate(
            gate_slice,
            runner=lambda _system, _user: response,
            repair_runner=no_repair,
            source_root=self.root,
        )
        self.assertEqual([], analyzed["reject_examples"])
        self.assertEqual([], analyzed["bypass_examples"])
        self.assertNotIn("source_rules", analyzed["steps"][0])
        self.assertEqual([response], raw_responses)
        self.assertEqual([], errors)


class BehaviorCompleteSemanticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo = Path(__file__).resolve().parents[3]
        cls.source_root = cls.repo / "benchmark/python/hermes-agent"

    @staticmethod
    def payload(qualified: str, gate_id: str) -> dict:
        return {
            "gate_id": gate_id,
            "gate": {
                "mode": "predicate",
                "qualified_function": qualified,
                "call_expression": qualified.rsplit(".", 1)[-1] + "(command)",
            },
            "checked_value": {"value_id": "V" + gate_id[1:13]},
        }

    def test_hardline_profile_preserves_all_twelve_matchers(self) -> None:
        profile = build_behavior_profile(
            self.payload(
                "tools.approval.detect_hardline_command", "Ghardlineprofile"
            ),
            self.source_root,
        )
        self.assertIsNotNone(profile)
        ir = profile.semantic_ir
        self.assertEqual(12, len(ir["policies"][0]["rules"]))
        self.assertEqual("re.IGNORECASE", ir["policies"][0]["flags"][0])
        self.assertTrue(
            any("mkfs" in rule["matcher"] for rule in ir["policies"][0]["rules"])
        )
        self.assertEqual("A1", ir["entry"])
        self.assertEqual([], validate_behavior_semantic_ir(ir, expected=ir))
        validate(instance=ir, schema=json.loads(BEHAVIOR_SCHEMA_PATH.read_text()))

    def test_compact_command_type_profile_replaces_unchecked_prose(self) -> None:
        slice_payload = {
            "gate_id": "Gcommandtypeprofile",
            "gate": {
                "mode": "predicate",
                "qualified_function": "isinstance",
                "call_expression": "isinstance(command, str)",
                "output_value_id": "Dcommandtypeprofile",
            },
            "checked_value": {"value_id": "Vcommandtypeprofile"},
            "callsite": {
                "span": {
                    "file": "tools/terminal_tool.py",
                    "start_line": 1670,
                }
            },
        }
        unchecked = {
            "gate_id": slice_payload["gate_id"],
            "mode": "predicate",
            "input": f"{slice_payload['checked_value']['value_id']}: command",
            "output": f"{slice_payload['gate']['output_value_id']}: decision",
            "summary": "Incorrectly claims every command passes.",
            "steps": [{"id": "S1", "op": "allow-if", "rule": "Always pass."}],
            "default": "pass",
            "on_error": "pass",
            "reject_examples": [],
            "bypass_examples": [],
            "status": "complete",
        }
        recovered, evidence, report = check_and_upgrade_semantic(
            slice_payload=slice_payload,
            semantic_ir=unchecked,
            evidence={},
            source_root=self.source_root,
        )
        self.assertEqual("recovered", report["verdict"])
        self.assertEqual("hermes-command-type/v1", report["profile_id"])
        self.assertEqual("block-if", recovered["steps"][0]["op"])
        self.assertIn("S1", evidence)

    def test_foreground_profile_scopes_help_normalization_and_all_regexes(self) -> None:
        profile = build_behavior_profile(
            self.payload(
                "tools.terminal_tool._foreground_background_guidance",
                "Gforegroundprofile",
            ),
            self.source_root,
        )
        self.assertIsNotNone(profile)
        ir = profile.semantic_ir
        derived = ir["derived_values"][0]
        self.assertEqual(["C1"], derived["used_by"])
        self.assertEqual([derived["id"]], ir["checks"][0]["reads"])
        raw_id = ir["inputs"][0]["id"]
        self.assertTrue(all(raw_id in check["reads"] for check in ir["checks"][1:]))
        self.assertIn("' --help'", ir["checks"][0]["rule"])
        self.assertEqual(11, sum(len(policy["rules"]) for policy in ir["policies"]))
        self.assertTrue(
            any(
                "python(?:3)?" in rule["matcher"]
                for policy in ir["policies"]
                for rule in policy["rules"]
            )
        )
        self.assertEqual([], validate_behavior_semantic_ir(ir, expected=ir))

    def test_smart_profile_is_partial_and_preserves_context_policy_and_effects(self) -> None:
        payload = self.payload("tools.approval._smart_approve", "Gsmartprofile")
        profile = build_behavior_profile(payload, self.source_root)
        self.assertIsNotNone(profile)
        ir = profile.semantic_ir
        self.assertEqual("partial", ir["status"])
        self.assertEqual("partial", ir["completeness"]["dependencies"])
        self.assertEqual(5, len(ir["inputs"]))
        self.assertEqual(2, len(ir["activation"]))
        self.assertEqual(
            [ir["inputs"][0]["id"], ir["inputs"][1]["id"]],
            ir["derived_values"][0]["sources"],
        )
        self.assertIn("APPROVE if the command is clearly safe", ir["policies"][0]["template"])
        self.assertEqual("external-decision", ir["dependencies"][0]["kind"])
        self.assertEqual(1, len(ir["state_effects"]))
        self.assertEqual([], validate_behavior_semantic_ir(ir, expected=ir))

    def test_checker_upgrades_legacy_ir_and_rejects_broken_value_reference(self) -> None:
        payload = self.payload(
            "tools.terminal_tool._foreground_background_guidance",
            "Gforegroundprofile",
        )
        legacy = {
            "gate_id": "Gforegroundprofile",
            "mode": "predicate",
            "steps": [],
            "status": "complete",
        }
        upgraded, evidence, report = check_and_upgrade_semantic(
            slice_payload=payload,
            semantic_ir=legacy,
            evidence={},
            source_root=self.source_root,
        )
        self.assertEqual("recovered", report["verdict"])
        self.assertEqual("gate-semantic-ir/v3", upgraded["schema_version"])
        self.assertIn("P_LONG_LIVED", evidence)
        broken = json.loads(json.dumps(upgraded))
        broken["checks"][0]["reads"] = ["V_UNKNOWN"]
        self.assertTrue(
            any("unknown value" in error for error in validate_behavior_semantic_ir(broken))
        )

    def test_checker_cli_upgrades_a_stored_gate_and_preserves_original_in_audit(self) -> None:
        with tempfile.TemporaryDirectory() as raw_temp:
            store = Path(raw_temp) / "gate-semantics"
            gate_uid = "GU0123456789abcdefabcd"
            gate_dir = store / "repository" / gate_uid
            gate_dir.mkdir(parents=True)
            _write_csv(
                store / "gate-index.csv",
                ["gate_number", "gate_uid", "gate_id"],
                [
                    {
                        "gate_number": 245,
                        "gate_uid": gate_uid,
                        "gate_id": "Gforegroundprofile",
                    }
                ],
            )
            payload = self.payload(
                "tools.terminal_tool._foreground_background_guidance",
                "Gforegroundprofile",
            )
            legacy = {
                "gate_id": "Gforegroundprofile",
                "mode": "predicate",
                "steps": [],
                "status": "complete",
            }
            (gate_dir / "slice.json").write_text(
                json.dumps(payload), encoding="utf-8"
            )
            (gate_dir / "semantic.json").write_text(
                json.dumps(legacy), encoding="utf-8"
            )
            (gate_dir / "audit.json").write_text(
                json.dumps({"evidence": {}}), encoding="utf-8"
            )

            args = build_checker_parser().parse_args(
                [
                    "--source-root",
                    str(self.source_root),
                    "--gate-semantics-dir",
                    str(store),
                    "--gate-number",
                    "245",
                    "--write",
                ]
            )
            report = run_checker(args)

            self.assertEqual(1, report["counts"]["recovered"])
            stored = json.loads(
                (gate_dir / "semantic.json").read_text(encoding="utf-8")
            )
            audit = json.loads(
                (gate_dir / "audit.json").read_text(encoding="utf-8")
            )
            self.assertEqual("gate-semantic-ir/v3", stored["schema_version"])
            self.assertEqual(
                legacy,
                audit["semantic_check"]["original_semantic_ir"],
            )
            self.assertTrue((store / "semantic-check-report.json").is_file())

            second_report = run_checker(args)
            second_audit = json.loads(
                (gate_dir / "audit.json").read_text(encoding="utf-8")
            )
            self.assertEqual(1, second_report["counts"]["verified"])
            self.assertEqual(
                legacy,
                second_audit["semantic_check"]["original_semantic_ir"],
            )
            self.assertEqual(
                "verified",
                second_audit["semantic_check"]["latest_verification"]["verdict"],
            )


class ClaudeRunnerContractTest(unittest.TestCase):
    def test_runner_exposes_only_requested_read_tools(self) -> None:
        completed = type(
            "Completed",
            (),
            {"returncode": 0, "stdout": "{}", "stderr": ""},
        )()
        with patch(
            "src.sink_capacity.agent.subprocess.run", return_value=completed
        ) as mocked_run:
            self.assertEqual(
                "{}",
                run_agent(
                    "system",
                    "user",
                    allowed_tools=("Read", "Grep", "Glob"),
                ),
            )

        command = mocked_run.call_args.args[0]
        self.assertEqual("Read,Grep,Glob", command[command.index("--tools") + 1])
        self.assertEqual("project", command[command.index("--setting-sources") + 1])
        self.assertIn("--no-session-persistence", command)
        self.assertIn("--system-prompt", command)
        self.assertNotIn("--disallowedTools", command)
        self.assertNotIn("MultiEdit", command)
        environment = mocked_run.call_args.kwargs["env"]
        self.assertEqual(
            environment["ANTHROPIC_MODEL"],
            environment["ANTHROPIC_DEFAULT_HAIKU_MODEL"],
        )
        self.assertEqual(
            environment["ANTHROPIC_MODEL"],
            environment["ANTHROPIC_DEFAULT_SONNET_MODEL"],
        )
        self.assertEqual(
            environment["ANTHROPIC_MODEL"],
            environment["ANTHROPIC_DEFAULT_OPUS_MODEL"],
        )


class AgentSDKRunnerContractTest(unittest.TestCase):
    def test_token_usage_preserves_cache_categories_and_aggregates(self) -> None:
        first = normalize_token_usage(
            {
                "input_tokens": 100,
                "cache_creation_input_tokens": 20,
                "cache_read_input_tokens": 30,
                "output_tokens": 40,
            }
        )
        self.assertEqual(150, first["total_input_tokens"])
        self.assertEqual(190, first["total_tokens"])
        total = aggregate_token_usage(
            [first, {"input_tokens": 10, "output_tokens": 5}]
        )
        self.assertTrue(total["provider_reported"])
        self.assertEqual(160, total["total_input_tokens"])
        self.assertEqual(45, total["output_tokens"])
        self.assertEqual(205, total["total_tokens"])
        model_usage = normalize_token_usage(
            {
                "deepseek-v4-flash": {
                    "inputTokens": 8,
                    "cacheReadInputTokens": 2,
                    "outputTokens": 1,
                }
            }
        )
        self.assertEqual(11, model_usage["total_tokens"])

    def test_sdk_preserves_builtin_tools_and_exposes_only_readonly_lsp(self) -> None:
        runner = ClaudeAgentSDKRunner(
            source_root=Path.cwd() / "benchmark/python/hermes-agent",
            model="deepseek-v4-flash",
            timeout=30,
            max_turns=20,
            enable_lsp=True,
        )
        try:
            options = runner._options(SYSTEM)
            runner._turns.append(
                {
                    "turn": 1,
                    "role": "initial",
                    "system_prompt": "system content",
                    "user_prompt": "user content",
                    "effective_user_prompt": "user content",
                    "assistant_response": "assistant content",
                    "events": [],
                    "tool_calls": [],
                    "result": {
                        "usage": {
                            "input_tokens": 11,
                            "cache_read_input_tokens": 7,
                            "output_tokens": 5,
                        }
                    },
                }
            )
            audit = runner.audit_payload()
            chat = runner.chat_payload()
        finally:
            runner.close()

        self.assertEqual(list(ALL_RESEARCH_TOOLS), options.tools)
        self.assertEqual(list(BUILTIN_RESEARCH_TOOLS), options.tools[:3])
        self.assertTrue(set(LSP_RESEARCH_TOOLS).issubset(options.tools))
        self.assertNotIn("mcp__lsp__lsp_rename", options.tools)
        self.assertNotIn("mcp__lsp__lsp_code_action", options.tools)
        self.assertNotIn("mcp__lsp__lsp_formatting", options.tools)
        self.assertNotIn("mcp__lsp__lsp_range_formatting", options.tools)
        self.assertEqual("dontAsk", options.permission_mode)
        self.assertEqual([], options.setting_sources)
        self.assertEqual([], options.skills)
        self.assertTrue(options.strict_mcp_config)
        self.assertEqual(1, len(options.hooks["PreToolUse"]))
        self.assertEqual(
            "@theupsider/lsp-mcp@1.3.2",
            runner.audit_payload()["lsp"]["bridge"],
        )
        lsp = options.mcp_servers["lsp"]
        self.assertTrue(Path(lsp["command"]).is_file())
        self.assertEqual("error", lsp["env"]["LSP_MCP_LOG_LEVEL"])
        self.assertNotIn("system_prompt", audit["turns"][0])
        self.assertEqual("system content", chat["turns"][0]["system_prompt"])
        self.assertEqual("assistant content", chat["turns"][0]["assistant_response"])
        self.assertEqual(23, audit["token_usage"]["total_tokens"])
        self.assertEqual(audit["token_usage"], chat["token_usage"])

    def test_cli_fallback_records_json_usage(self) -> None:
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(
                    {
                        "result": "assistant content",
                        "is_error": False,
                        "usage": {
                            "input_tokens": 13,
                            "cache_creation_input_tokens": 2,
                            "output_tokens": 3,
                        },
                    }
                ),
                "stderr": "",
            },
        )()
        runner = ClaudeCLIRunner(
            source_root=Path.cwd() / "benchmark/python/hermes-agent",
            model="deepseek-v4-flash",
            timeout=30,
            max_turns=4,
        )
        with patch(
            "src.gate_semantics.agent_sdk.subprocess.run", return_value=completed
        ) as mocked_run:
            self.assertEqual("assistant content", runner("system", "user"))
        audit = runner.audit_payload()
        self.assertEqual(18, audit["token_usage"]["total_tokens"])
        command = mocked_run.call_args.args[0]
        self.assertEqual("json", command[command.index("--output-format") + 1])

    def test_sdk_without_lsp_keeps_all_builtin_research_tools(self) -> None:
        runner = ClaudeAgentSDKRunner(
            source_root=Path.cwd() / "benchmark/python/hermes-agent",
            model="deepseek-v4-flash",
            timeout=30,
            max_turns=20,
            enable_lsp=False,
        )
        try:
            options = runner._options(SYSTEM)
            audit = runner.audit_payload()
        finally:
            runner.close()

        self.assertEqual(["Read", "Grep", "Glob"], options.tools)
        self.assertEqual({}, options.mcp_servers)
        self.assertFalse(audit["lsp"]["enabled"])
        self.assertEqual(["Read", "Grep", "Glob"], audit["available_tools"])

    def test_source_root_policy_covers_builtin_and_lsp_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            source_root = base / "project"
            source_root.mkdir()
            inside = source_root / "inside.py"
            outside = base / "outside.py"
            inside.write_text("VALUE = 1\n", encoding="utf-8")
            outside.write_text("VALUE = 2\n", encoding="utf-8")
            (source_root / "outside-link.py").symlink_to(outside)

            self.assertIsNone(
                _source_root_denial(
                    source_root, "Read", {"file_path": str(inside)}
                )
            )
            self.assertIsNone(
                _source_root_denial(
                    source_root, "Read", {"file_path": inside.as_uri()}
                )
            )
            self.assertIsNone(
                _source_root_denial(
                    source_root, "Grep", {"path": "inside.py"}
                )
            )
            self.assertIsNone(
                _source_root_denial(
                    source_root, "mcp__lsp__lsp_workspace_symbols", {"query": "V"}
                )
            )
            for tool_name, tool_input in (
                ("Read", {"file_path": str(outside)}),
                ("Read", {"file_path": outside.as_uri()}),
                ("Grep", {"path": "../outside.py"}),
                ("Glob", {"path": str(base)}),
                (
                    "mcp__lsp__lsp_definition",
                    {"file": str(source_root / "outside-link.py")},
                ),
                ("mcp__lsp__lsp_init", {"root": "https://example.test/code"}),
            ):
                with self.subTest(tool=tool_name, tool_input=tool_input):
                    self.assertIsNotNone(
                        _source_root_denial(source_root, tool_name, tool_input)
                    )

    def test_source_root_hook_denies_external_path_and_audits_it(self) -> None:
        runner = ClaudeAgentSDKRunner(
            source_root=Path.cwd() / "benchmark/python/hermes-agent",
            model="deepseek-v4-flash",
            timeout=30,
            max_turns=20,
            enable_lsp=True,
        )
        try:
            result = asyncio.run(
                runner._guard_source_root(
                    {
                        "tool_name": "mcp__lsp__lsp_document_symbols",
                        "tool_input": {
                            "file": str(Path.cwd() / "src/gate_semantics/agent_sdk.py")
                        },
                    },
                    None,
                    object(),
                )
            )
            audit = runner.audit_payload()
        finally:
            runner.close()

        decision = result["hookSpecificOutput"]
        self.assertEqual("deny", decision["permissionDecision"])
        self.assertIn("outside", decision["permissionDecisionReason"])
        self.assertEqual(
            "mcp__lsp__lsp_document_symbols",
            audit["source_root_policy"]["denials"][0]["tool_name"],
        )
        self.assertEqual(1, audit["source_root_policy"]["checked_calls"])

    def test_packet_constraints_remove_broad_search_and_enforce_call_limit(self) -> None:
        source_root = Path.cwd() / "benchmark/python/hermes-agent"
        runner = ClaudeAgentSDKRunner(
            source_root=source_root,
            model="deepseek-v4-flash",
            timeout=30,
            max_turns=8,
            enable_lsp=True,
            allowed_source_files=("tools/approval.py",),
            max_tool_calls=1,
        )
        try:
            options = runner._options(SYSTEM)
            first = asyncio.run(
                runner._guard_source_root(
                    {
                        "tool_name": "Read",
                        "tool_input": {"file_path": "tools/approval.py"},
                    },
                    None,
                    object(),
                )
            )
            second = asyncio.run(
                runner._guard_source_root(
                    {
                        "tool_name": "Read",
                        "tool_input": {"file_path": "tools/approval.py"},
                    },
                    None,
                    object(),
                )
            )
            audit = runner.audit_payload()
        finally:
            runner.close()

        self.assertNotIn("Glob", options.tools)
        self.assertNotIn("mcp__lsp__lsp_workspace_symbols", options.tools)
        self.assertEqual({}, first)
        self.assertEqual(
            "deny", second["hookSpecificOutput"]["permissionDecision"]
        )
        self.assertIn(
            "tool-call limit",
            second["hookSpecificOutput"]["permissionDecisionReason"],
        )
        self.assertEqual(8, runner.max_turns)
        self.assertEqual(1, audit["packet_constraints"]["max_tool_calls"])


class CompoundGateProfileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        repo = Path(__file__).resolve().parents[3]
        cls.source_root = repo / "benchmark/python/hermes-agent"
        terminal_source = (cls.source_root / "tools/terminal_tool.py").read_text(
            encoding="utf-8"
        )
        call_line = _line(
            terminal_source,
            "approval = _check_all_guards(command, env_type)",
        )
        seed = CandidateSeed(
            mode="predicate",
            gate_name="_check_all_guards",
            call_file="tools/terminal_tool.py",
            call_line=call_line,
            static_verdict="confirmed",
            owner_function="terminal_tool",
            checked_hint="command",
            source_param="command",
        )
        cls.gate_slice = PythonGateSlicer(
            cls.source_root, revision="compound-fixture-revision"
        ).build_slice(seed)

    def test_profile_uses_curated_gate_only_source(self) -> None:
        gate_slice = self.gate_slice
        self.assertEqual(
            "hermes-check-all-guards/v2",
            gate_slice.compound_profile["profile_id"],
        )
        self.assertEqual("not force", gate_slice.callsite["condition"])
        self.assertEqual("project-compound-function", gate_slice.gate["callee_kind"])
        self.assertEqual(26, len(gate_slice.compound_profile["required_checks"]))
        self.assertEqual(
            [("P_HARDLINE", 12), ("P_DANGEROUS", 47)],
            [
                (policy["id"], len(policy["items"]))
                for policy in gate_slice.compound_profile["policies"]
            ],
        )
        self.assertEqual(
            ["external-policy:tirith-binary-matching-rules"],
            gate_slice.unresolved_symbols,
        )
        self.assertTrue(
            any(
                chunk.symbol == "check_all_command_guards"
                for chunk in gate_slice.source_bundle
            )
        )
        self.assertTrue(
            any(
                chunk.symbol == "_PATTERN_KEY_ALIASES-population"
                for chunk in gate_slice.source_bundle
            )
        )
        self.assertFalse(
            any(
                chunk.file == "agent/auxiliary_client.py"
                or chunk.symbol in {"call_llm", "_resolve_tirith_path"}
                for chunk in gate_slice.source_bundle
            )
        )

    def _runner(self, *, omit_force_check: bool = False):
        calls: list[str] = []

        def runner(_system: str, user: str) -> str:
            calls.append(user)
            if "EXPECTED FRAGMENT:\n" in user:
                expected_text = user.split("EXPECTED FRAGMENT:\n", 1)[1].split(
                    "\n\n", 1
                )[0]
                expected = json.loads(expected_text)
                fragment_id = expected["fragment_id"]
                unresolved = (
                    ["external-policy:tirith-binary-matching-rules"]
                    if fragment_id == "F4"
                    else []
                )
                return json.dumps(
                    {
                        "fragment_id": fragment_id,
                        "covered_checks": expected["check_ids"],
                        "covered_policies": expected["policy_ids"],
                        "summary": "Recovers this source-defined portion of the compound command policy.",
                        "rules": [
                            "Apply the supplied source rules in their recorded order."
                        ],
                        "on_error": "Use the supplied source-defined error behavior.",
                        "unresolved": unresolved,
                        "evidence": [expected["permitted_evidence"][0]],
                    }
                )

            expected_text = user.split("EXPECTED IDENTIFIERS:\n", 1)[1].split(
                "\n\n", 1
            )[0]
            expected = json.loads(expected_text)
            profile_text = user.split("REQUIRED COMPOUND PROFILE:\n", 1)[1].split(
                "\n\nSOURCE-GROUNDED FRAGMENTS:", 1
            )[0]
            profile = json.loads(profile_text)
            evidence: dict[str, list[dict[str, object]]] = {}
            for check in profile["required_checks"]:
                evidence[check["id"]] = [check["anchor"]]
            for policy in profile["policies"]:
                evidence[policy["id"]] = [policy["anchor"]]
            checks = []
            for check in profile["required_checks"]:
                if omit_force_check and check["id"] == "C01":
                    continue
                examples = ["model-formatted example normalized from the profile"]
                checks.append(
                    {
                        "id": check["id"],
                        "op": check["op"],
                        "summary": f"Applies {check['title'].lower()} to the current command decision.",
                        "input": "command and current approval state",
                        "output": "the profile-defined next decision state",
                        "rule": f"Evaluate {check['title'].lower()} exactly as defined by the supplied source fragment.",
                        "outcomes": check["outcomes"],
                        "on_error": "Use the source-defined error behavior for this check.",
                        "policy_refs": check["policy_refs"],
                        "reject_examples": examples,
                        "unresolved": check["required_unresolved"],
                    }
                )
            policies = []
            for policy in profile["policies"]:
                policies.append(
                    {
                        "id": policy["id"],
                        "summary": f"Preserves every rule in {policy['title'].lower()}.",
                        "matching": "Normalize the command and select the first source-order rule whose case-insensitive, dot-all condition matches.",
                        "rules": [
                            {
                                "id": item["id"],
                                "rule": f"Match commands described as {item['source_description']}.",
                            }
                            for item in policy["items"]
                        ],
                    }
                )
            semantic_ir = {
                "schema_version": "gate-semantic-ir/v2",
                "gate_id": expected["gate_id"],
                "mode": expected["mode"],
                "kind": "compound",
                "input": f"{expected['input_value_id']}: command",
                "output": f"{expected['output_value_id']}: decision",
                "summary": profile["summary"],
                "entry": profile["entry_check"],
                "checks": checks,
                "policies": policies,
                "terminals": profile["terminals"],
                "default": profile["default"],
                "on_error": profile["on_error"],
                "unresolved": profile["forced_unresolved"],
                "status": "partial",
            }
            return json.dumps(
                {
                    "semantic_ir": semantic_ir,
                    "evidence": {"anchors": list(evidence.values())},
                }
            )

        return runner, calls

    def test_compound_analysis_preserves_all_checks_in_semantic_ir(self) -> None:
        runner, calls = self._runner()
        ir, evidence, raw, errors, audit = analyze_gate_detailed(
            self.gate_slice,
            runner=runner,
            source_root=self.source_root,
        )
        self.assertEqual(7, len(calls))
        self.assertEqual(7, len(raw))
        self.assertEqual([], errors)
        self.assertEqual("partial", ir["status"])
        self.assertLessEqual(estimate_tokens(ir), 8000)
        self.assertEqual(26, len(ir["checks"]))
        self.assertEqual(59, sum(len(policy["rules"]) for policy in ir["policies"]))
        self.assertEqual(28, sum(len(spans) for spans in evidence.values()))
        self.assertEqual([], ir["checks"][0]["reject_examples"])
        self.assertEqual(2, len(ir["checks"][3]["reject_examples"]))
        self.assertEqual(
            ["external-policy:tirith-binary-matching-rules"], ir["unresolved"]
        )
        self.assertEqual(
            [],
            validate_compound_semantic_ir(ir, profile=self.gate_slice.compound_profile),
        )
        self.assertEqual("hermes-check-all-guards/v2", audit["profile_id"])
        self.assertEqual(6, len(audit["fragments"]))
        rendered = render_chain_semantics([ir])
        self.assertIn("C26", rendered)
        self.assertIn("H12", rendered)
        self.assertIn("D47", rendered)

        missing_policy_rule = json.loads(json.dumps(ir))
        missing_policy_rule["policies"][1]["rules"].pop()
        self.assertTrue(
            any(
                "every source policy entry" in error
                for error in validate_compound_semantic_ir(
                    missing_policy_rule,
                    profile=self.gate_slice.compound_profile,
                )
            )
        )

    def test_compound_analysis_rejects_missing_child_check(self) -> None:
        runner, _calls = self._runner(omit_force_check=True)
        with self.assertRaisesRegex(ContractError, "every required child check"):
            analyze_gate_detailed(
                self.gate_slice,
                runner=runner,
                source_root=self.source_root,
            )


if __name__ == "__main__":
    unittest.main()

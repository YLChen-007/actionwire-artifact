from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.gate_semantics.candidates import CandidateSeed
from src.gate_semantics.typescript_slicer import (
    TypeScriptGateSlicer,
    typescript_call_context,
)


class TypeScriptGateSlicerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "src/tool.ts"
        self.path.parent.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write(self, prefix: str = "") -> int:
        source = (
            prefix
            + "function assertAllowed(value: string) {\n"
            + "  if (value === 'blocked') throw new Error('blocked');\n"
            + "}\n\n"
            + "export async function execute(_id: string, args: { path: string }) {\n"
            + "  const selected = args.path.trim();\n"
            + "  assertAllowed(selected);\n"
            + "  return selected;\n"
            + "}\n"
        )
        self.path.write_text(source, encoding="utf-8")
        return source[: source.index("assertAllowed(selected)")].count("\n") + 1

    @staticmethod
    def _seed(line: int) -> CandidateSeed:
        return CandidateSeed(
            mode="predicate",
            gate_name="assertAllowed",
            call_file="src/tool.ts",
            call_line=line,
            call_column=3,
            owner_function="execute",
            checked_hint="selected",
            checked_file="src/tool.ts",
            checked_line=line,
            checked_column=17,
            source_param="args",
            detector_role="call-dominates",
        )

    def test_slice_records_call_shape_binding_branch_and_language(self) -> None:
        line = self._write()
        gate_slice = TypeScriptGateSlicer(
            self.root, project_name="fixture", revision="rev"
        ).build_slice(self._seed(line))
        self.assertEqual("typescript", gate_slice.project["language"])
        self.assertEqual("assertAllowed(selected)", gate_slice.gate["call_expression"])
        self.assertEqual("selected", gate_slice.checked_value["expression"])
        self.assertEqual(
            "selected -> value", gate_slice.checked_value["actual_to_formal_binding"]
        )
        self.assertEqual("resolved", gate_slice.checked_value["binding_status"])
        self.assertEqual("execute", gate_slice.callsite["enclosing_function"])
        self.assertTrue(
            any(chunk.role == "local-derivation" for chunk in gate_slice.source_bundle)
        )

    def test_gate_uid_ignores_lines_whitespace_and_comments(self) -> None:
        first_line = self._write()
        slicer = TypeScriptGateSlicer(self.root, project_name="fixture", revision="rev")
        first = slicer.build_slice(self._seed(first_line))
        second_line = self._write("// moved without semantic change\n\n")
        second = slicer.build_slice(self._seed(second_line))
        self.assertNotEqual(first.gate_id, second.gate_id)
        self.assertEqual(first.gate_uid, second.gate_uid)

    def test_call_context_selects_exact_multiline_call(self) -> None:
        line = self._write()
        shape, owners = typescript_call_context(self.root, "src/tool.ts", line, 3)
        self.assertEqual("assertAllowed(selected)", shape)
        self.assertEqual(("execute",), owners)

    def test_nested_execute_calls_in_different_factories_have_distinct_uids(
        self,
    ) -> None:
        source = """\
function normalize(value: unknown) { return value; }
function createRead() {
  return { execute: async (_id: string, params: unknown) => normalize(params) };
}
function createWrite() {
  return { execute: async (_id: string, params: unknown) => normalize(params) };
}
"""
        self.path.write_text(source, encoding="utf-8")
        lines = [
            index
            for index, line in enumerate(source.splitlines(), 1)
            if "execute:" in line
        ]
        slicer = TypeScriptGateSlicer(self.root, project_name="fixture", revision="rev")
        slices = [
            slicer.build_slice(
                CandidateSeed(
                    mode="transform",
                    gate_name="normalize",
                    call_file="src/tool.ts",
                    call_line=line,
                    call_column=63,
                    owner_function="execute",
                    checked_hint="params",
                    checked_file="src/tool.ts",
                    checked_line=line,
                    checked_column=73,
                    source_param="params",
                    detector_role="sink-transform",
                )
            )
            for line in lines
        ]
        self.assertEqual(
            ["createRead", "execute"], slices[0].callsite["lexical_owners"]
        )
        self.assertEqual(
            ["createWrite", "execute"], slices[1].callsite["lexical_owners"]
        )
        self.assertNotEqual(slices[0].gate_uid, slices[1].gate_uid)

    def test_relative_javascript_import_resolves_typescript_definition(self) -> None:
        helper = self.root / "src/normalize.ts"
        helper.write_text(
            "export function normalize(value: unknown) { return String(value).trim(); }\n",
            encoding="utf-8",
        )
        source = """\
import { normalize } from "./normalize.js";
export async function execute(_id: string, params: unknown) {
  return normalize(params);
}
"""
        self.path.write_text(source, encoding="utf-8")
        gate_slice = TypeScriptGateSlicer(
            self.root, project_name="fixture", revision="rev"
        ).build_slice(
            CandidateSeed(
                mode="transform",
                gate_name="normalize",
                call_file="src/tool.ts",
                call_line=3,
                call_column=10,
                owner_function="execute",
                checked_hint="params",
                checked_file="src/tool.ts",
                checked_line=3,
                checked_column=20,
                source_param="params",
                detector_role="sink-transform",
            )
        )
        self.assertEqual("src/normalize.ts", gate_slice.gate["definition_span"]["file"])
        self.assertTrue(
            any(
                chunk.role == "gate-function" and chunk.file == "src/normalize.ts"
                for chunk in gate_slice.source_bundle
            )
        )

    def test_uninitialized_local_dependency_does_not_break_slice(self) -> None:
        source = """\
function evaluateExecAllowlist(params: { analysis: { ok: boolean } }) {
  return params.analysis.ok;
}
export function execute(_id: string, args: { allowed: boolean }) {
  let analysis: { ok: boolean };
  if (args.allowed) analysis = { ok: true };
  return evaluateExecAllowlist({ analysis });
}
"""
        self.path.write_text(source, encoding="utf-8")
        gate_slice = TypeScriptGateSlicer(
            self.root, project_name="fixture", revision="rev"
        ).build_slice(
            CandidateSeed(
                mode="predicate",
                gate_name="evaluateExecAllowlist",
                call_file="src/tool.ts",
                call_line=7,
                call_column=10,
                owner_function="execute",
                checked_hint="{ analysis }",
                checked_file="src/tool.ts",
                checked_line=7,
                checked_column=32,
                source_param="args",
                detector_role="decision-return-branch",
            )
        )
        self.assertEqual("{ analysis }", gate_slice.checked_value["expression"])
        self.assertEqual("execute", gate_slice.callsite["enclosing_function"])

    def test_inline_condition_has_resolved_binding_and_stable_uid(self) -> None:
        source = """\
export function execute(args: { path?: string }) {
  const filePath = args.path;
  if (!filePath) return { error: 'path required' };
  return filePath;
}
"""
        self.path.write_text(source, encoding="utf-8")
        seed = CandidateSeed(
            mode="predicate",
            gate_name="inlineCondition",
            call_file="src/tool.ts",
            call_line=3,
            call_column=7,
            owner_function="execute",
            checked_hint="!filePath",
            checked_file="src/tool.ts",
            checked_line=3,
            checked_column=7,
            source_param="args",
            condition_hint="!filePath",
            detector_role="inline-early-return",
        )
        slicer = TypeScriptGateSlicer(
            self.root, project_name="nanoclaw", revision="rev"
        )
        first = slicer.build_slice(seed)
        self.assertEqual("resolved", first.checked_value["binding_status"])
        self.assertEqual(
            "filePath -> inline expression",
            first.checked_value["actual_to_formal_binding"],
        )
        self.assertEqual([], first.unresolved_symbols)
        self.path.write_text("// line move\n\n" + source, encoding="utf-8")
        moved = CandidateSeed(**{**seed.__dict__, "call_line": 5, "checked_line": 5})
        second = slicer.build_slice(moved)
        self.assertEqual(first.gate_uid, second.gate_uid)

    def test_string_literal_policy_has_resolved_binding_and_stable_uid(self) -> None:
        source = """\
const POLICY = [
  'use target="host"',
].join('\\n');
"""
        self.path.write_text(source, encoding="utf-8")
        seed = CandidateSeed(
            mode="predicate",
            gate_name="MANAGED_BROWSER_POLICY_PROMPT",
            call_file="src/tool.ts",
            call_line=2,
            call_column=3,
            owner_function="execute",
            checked_hint="'use target=\"host\"'",
            checked_file="src/tool.ts",
            checked_line=2,
            checked_column=3,
            source_param="args",
            condition_hint="'use target=\"host\"'",
            detector_role="prompt-policy",
        )
        slicer = TypeScriptGateSlicer(
            self.root, project_name="LobsterAI", revision="rev"
        )
        first = slicer.build_slice(seed)
        self.assertEqual("resolved", first.checked_value["binding_status"])
        self.assertEqual(
            "'use target=\"host\"' -> inline expression",
            first.checked_value["actual_to_formal_binding"],
        )
        self.assertEqual([], first.unresolved_symbols)
        self.path.write_text("// moved\n\n" + source, encoding="utf-8")
        moved = CandidateSeed(**{**seed.__dict__, "call_line": 4, "checked_line": 4})
        second = slicer.build_slice(moved)
        self.assertEqual(first.gate_uid, second.gate_uid)


if __name__ == "__main__":
    unittest.main()

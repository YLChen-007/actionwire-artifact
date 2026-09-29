from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import validate

from src.call_chain_semantics.assembler import (
    ChainAssemblyError,
    build_chain_slice,
    gate_semantic_path,
    load_gate_semantics,
    resolve_chain,
    select_chain_gates,
)
from src.call_chain_semantics.contracts import (
    SEMANTIC_SCHEMA_PATH,
    SLICE_SCHEMA_PATH,
    build_call_chain_semantic_ir,
    validate_call_chain_semantic_ir,
)
from src.call_chain_semantics.main import CALL_OUTPUT, GATE_OUTPUT, build_parser
from src.call_chain_semantics.pipeline import run_pipeline
from src.gate_semantics.behavior_checker import build_behavior_profile


REPO_ROOT = Path(__file__).resolve().parents[3]
CALL_DEBUG = REPO_ROOT / "design/hermes-agent/call-chain/debug"
GATE_INDEX = REPO_ROOT / GATE_OUTPUT / "gate-index.csv"
GROUND_TRUTH = (
    REPO_ROOT
    / "design/hermes-agent/groundtruth/new-vuls/feat__configurable_approval_mode_for_cron_jobs__approvals_cr-762f7e97-Batch-Runner-Variant.json"
)
SOURCE_ROOT = REPO_ROOT / "benchmark/python/hermes-agent"


def _regular_gate(
    gate_id: str,
    summary: str,
    steps: list[dict[str, str]],
    *,
    status: str = "complete",
) -> dict:
    return {
        "gate_id": gate_id,
        "mode": "predicate",
        "input": f"V{gate_id[1:8]}: the terminal command",
        "output": f"D{gate_id[1:8]}: pass or stop decision",
        "summary": summary,
        "steps": steps,
        "default": "continue to the next check",
        "on_error": "return an error before the sink",
        "reject_examples": [],
        "status": status,
    }


def _write_gate_store(
    store: Path, selections: list, semantics: list[dict]
) -> None:
    for selection, semantic in zip(selections, semantics, strict=True):
        path = gate_semantic_path(store, selection)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(semantic) + "\n", encoding="utf-8")


class CallChainSemanticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.resolved = resolve_chain(
            ground_truth_json=GROUND_TRUTH,
            coverage_items_csv=CALL_DEBUG / "d5-chain-coverage-items.csv",
            handler_sink_chains_csv=CALL_DEBUG / "handler-sink-chains.csv",
        )
        cls.selections = select_chain_gates(
            resolved=cls.resolved,
            chain_gates_csv=CALL_DEBUG / "chain-gates.csv",
            gate_index_csv=GATE_INDEX,
        )
        cls.gate_semantics = [
            _regular_gate(
                "G475abe7e64c3215f",
                "Rejects terminal command values that are not strings.",
                [
                    {
                        "id": "S1",
                        "op": "block-if",
                        "rule": "The terminal command is not a string.",
                    }
                ],
            ),
            _regular_gate(
                "G1ef41a32dc9cd89c",
                "Rejects foreground timeout requests that exceed the configured maximum.",
                [
                    {
                        "id": "S1",
                        "op": "block-if",
                        "rule": "Foreground mode has a requested timeout above the maximum.",
                    }
                ],
            ),
            _regular_gate(
                "Gc3e3e517e07d8993",
                "Rejects foreground shell forms intended for managed background work.",
                [
                    {
                        "id": "S1",
                        "op": "block-if",
                        "rule": "The command requests unmanaged background work.",
                    }
                ],
            ),
            _regular_gate(
                "Ga0ad79ab3d2e66d7",
                "Blocks commands matching an unconditional hardline pattern.",
                [
                    {
                        "id": "S1",
                        "op": "block-if",
                        "rule": "The normalized command matches a hardline pattern.",
                    }
                ],
            ),
            _regular_gate(
                "Gc54219160ab446b7",
                "Uses auxiliary review to approve, deny, or escalate a flagged command.",
                [
                    {
                        "id": "S1",
                        "op": "prompt",
                        "rule": "Obtain approve, deny, or escalate from auxiliary review.",
                    }
                ],
            ),
        ]
        cls.chain_slice = build_chain_slice(
            resolved=cls.resolved,
            selections=cls.selections,
            gate_semantics=cls.gate_semantics,
            project_revision="test-revision",
        )

    def test_endpoint_intersection_selects_unique_chain(self) -> None:
        self.assertEqual("C-54eabf84fd", self.resolved.chain_id)
        self.assertEqual("terminal", self.resolved.handler["tool_name"])
        self.assertEqual("prompt_dangerous_approval", self.resolved.sink["name"])

    def test_selects_exact_chain_gates_in_execution_order(self) -> None:
        self.assertEqual(
            [86, 35, 224, 178, 228],
            [item.gate_number for item in self.selections],
        )
        self.assertEqual(
            [
                "G475abe7e64c3215f",
                "G1ef41a32dc9cd89c",
                "Gc3e3e517e07d8993",
                "Ga0ad79ab3d2e66d7",
                "Gc54219160ab446b7",
            ],
            [item.gate_id for item in self.selections],
        )
        self.assertTrue(
            all(item.static_verdict != "needs-review" for item in self.selections)
        )
        self.assertEqual("branch-confirmed", self.selections[-1].static_verdict)

    def test_exact_chain_detector_inventory_is_6_rows_6_callsites_5_gates(
        self,
    ) -> None:
        with (CALL_DEBUG / "chain-gates.csv").open(
            newline="", encoding="utf-8"
        ) as handle:
            rows = [
                row
                for row in csv.DictReader(handle)
                if row["call_chain"] == self.resolved.call_chain
            ]
        callsites = {
            (
                row["gate_fn"],
                row["gate_file"],
                row["gate_line"],
                row["gate_in_func"],
            )
            for row in rows
        }
        eligible = {
            callsite
            for row in rows
            if row["taint_verdict"] in {"confirmed", "branch-confirmed"}
            for callsite in [
                (
                    row["gate_fn"],
                    row["gate_file"],
                    row["gate_line"],
                    row["gate_in_func"],
                )
            ]
        }
        self.assertEqual(6, len(rows))
        self.assertEqual(6, len(callsites))
        self.assertEqual(5, len(eligible))

    def test_slice_has_only_ordering_inputs_and_aggregate_status(self) -> None:
        payload = self.chain_slice.to_dict()
        self.assertEqual("call-chain-slice/v2", payload["schema_version"])
        self.assertEqual(5, len(payload["selected_gates"]))
        self.assertEqual(5, len(payload["gate_semantics"]))
        self.assertEqual([], payload["unresolved"])
        self.assertEqual("complete", payload["status"])
        self.assertNotIn("composition_requirements", payload)
        self.assertNotIn("absorbed_gates", payload)

    def test_loads_exact_per_gate_artifacts_and_rejects_wrong_identity(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            store = Path(raw_tmp) / "gate-semantics"
            _write_gate_store(store, self.selections, self.gate_semantics)
            self.assertEqual(
                self.gate_semantics, load_gate_semantics(store, self.selections)
            )
            wrong_path = gate_semantic_path(store, self.selections[0])
            wrong = dict(self.gate_semantics[0], gate_id="Gwrong")
            wrong_path.write_text(json.dumps(wrong) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                ChainAssemblyError, "gate semantic identity mismatch"
            ):
                load_gate_semantics(store, self.selections)

    def test_cli_defaults_separate_gate_and_call_chain_outputs(self) -> None:
        args = build_parser().parse_args([])
        self.assertEqual(GATE_OUTPUT, args.gate_semantics_dir)
        self.assertEqual(CALL_OUTPUT, args.out_dir)
        self.assertIsNone(args.gate_index)

    def test_pipeline_rejects_overlapping_artifact_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            shared = Path(raw_tmp) / "semantics"
            with self.assertRaisesRegex(ChainAssemblyError, "must not overlap"):
                run_pipeline(
                    source_root=SOURCE_ROOT,
                    ground_truth_json=GROUND_TRUTH,
                    coverage_items_csv=CALL_DEBUG / "d5-chain-coverage-items.csv",
                    handler_sink_chains_csv=CALL_DEBUG / "handler-sink-chains.csv",
                    chain_gates_csv=CALL_DEBUG / "chain-gates.csv",
                    gate_index_csv=GATE_INDEX,
                    gate_semantics_dir=shared,
                    out_dir=shared,
                    generation_command="test",
                )

    def test_final_ir_is_an_ordered_verbatim_gate_sequence(self) -> None:
        ir = build_call_chain_semantic_ir(self.chain_slice)
        self.assertEqual(
            [], validate_call_chain_semantic_ir(ir, chain_slice=self.chain_slice)
        )
        self.assertEqual("call-chain-semantic-ir/v2", ir["schema_version"])
        self.assertEqual(
            self.gate_semantics,
            [gate["semantic"] for gate in ir["gates"]],
        )
        self.assertEqual(
            [
                "confirmed",
                "confirmed",
                "confirmed",
                "confirmed",
                "branch-confirmed",
            ],
            [gate["static_verdict"] for gate in ir["gates"]],
        )
        self.assertEqual(
            [
                "tools/terminal_tool.py:1670",
                "tools/terminal_tool.py:1714",
                "tools/terminal_tool.py:1726",
                "tools/approval.py:937",
                "tools/approval.py:1020",
            ],
            [gate["callsite"] for gate in ir["gates"]],
        )
        for removed in (
            "composition",
            "absorbed_gates",
            "reach_sink_summary",
            "terminals",
            "boundary_excluded_refs",
            "reach_sink_facts",
        ):
            self.assertNotIn(removed, ir)

    def test_rejects_modified_order_semantic_status_and_size(self) -> None:
        ir = build_call_chain_semantic_ir(self.chain_slice)
        ir["gates"][0], ir["gates"][1] = ir["gates"][1], ir["gates"][0]
        errors = validate_call_chain_semantic_ir(ir, chain_slice=self.chain_slice)
        self.assertTrue(any("deterministic field gates" in error for error in errors))

        changed = build_call_chain_semantic_ir(self.chain_slice)
        changed["gates"][-1]["semantic"]["steps"].pop()
        changed["status"] = "partial"
        errors = validate_call_chain_semantic_ir(
            changed, chain_slice=self.chain_slice, hard_token_limit=10
        )
        self.assertTrue(any("deterministic field gates" in error for error in errors))
        self.assertTrue(any("deterministic field status" in error for error in errors))
        self.assertTrue(any("hard limit" in error for error in errors))

    def test_unknown_gate_atom_propagates_to_chain(self) -> None:
        partial_semantics = json.loads(json.dumps(self.gate_semantics))
        partial_semantics[3]["steps"].append(
            {
                "id": "S2",
                "op": "unknown",
                "rule": "An external matcher remains unresolved.",
            }
        )
        partial_semantics[3]["status"] = "partial"
        chain_slice = build_chain_slice(
            resolved=self.resolved,
            selections=self.selections,
            gate_semantics=partial_semantics,
            project_revision="test-revision",
        )
        ir = build_call_chain_semantic_ir(chain_slice)
        self.assertEqual("partial", ir["status"])
        self.assertEqual(1, len(ir["unresolved"]))
        self.assertIn("Ga0ad79ab3d2e66d7:S2", ir["unresolved"][0])

    def test_v3_profiles_preserve_policy_inventory_binding_and_partial_status(self) -> None:
        profiled = self.gate_semantics[:2]
        profile_inputs = [
            (
                "tools.terminal_tool._foreground_background_guidance",
                "Gc3e3e517e07d8993",
                "V336abee89173",
            ),
            (
                "tools.approval.detect_hardline_command",
                "Ga0ad79ab3d2e66d7",
                "Vca6c0f412dee",
            ),
            (
                "tools.approval._smart_approve",
                "Gc54219160ab446b7",
                "V023401491015",
            ),
        ]
        for qualified, gate_id, value_id in profile_inputs:
            profile = build_behavior_profile(
                {
                    "gate_id": gate_id,
                    "gate": {
                        "mode": "predicate",
                        "qualified_function": qualified,
                        "call_expression": qualified.rsplit(".", 1)[-1]
                        + "(command)",
                    },
                    "checked_value": {"value_id": value_id},
                },
                SOURCE_ROOT,
            )
            self.assertIsNotNone(profile)
            profiled.append(profile.semantic_ir)

        chain_slice = build_chain_slice(
            resolved=self.resolved,
            selections=self.selections,
            gate_semantics=profiled,
            project_revision="test-revision",
        )
        ir = build_call_chain_semantic_ir(chain_slice)

        self.assertEqual("partial", ir["status"])
        self.assertEqual(
            ["external-decision:auxiliary-llm-approval-response"],
            ir["unresolved"],
        )
        self.assertEqual(
            [
                "V475abe7",
                "V1ef41a3",
                "V336abee89173",
                "Vca6c0f412dee",
                "V023401491015",
            ],
            [item["input_value_id"] for item in ir["values"][0]["gate_bindings"]],
        )
        self.assertEqual(
            11,
            sum(len(policy["rules"]) for policy in profiled[2]["policies"]),
        )
        self.assertEqual(12, len(profiled[3]["policies"][0]["rules"]))
        self.assertEqual("partial", profiled[4]["completeness"]["dependencies"])

    def test_schemas_have_expected_titles(self) -> None:
        slice_schema = json.loads(SLICE_SCHEMA_PATH.read_text())
        semantic_schema = json.loads(SEMANTIC_SCHEMA_PATH.read_text())
        self.assertEqual("CallChainSliceV2", slice_schema["title"])
        self.assertEqual("CallChainSemanticIRV2", semantic_schema["title"])
        validate(instance=self.chain_slice.to_dict(), schema=slice_schema)
        validate(
            instance=build_call_chain_semantic_ir(self.chain_slice),
            schema=semantic_schema,
        )

    def test_end_to_end_assembly_writes_reproducible_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            gate_store = tmp / "gate-semantics"
            out = tmp / "call-chain-semantics"
            _write_gate_store(gate_store, self.selections, self.gate_semantics)
            manifest = run_pipeline(
                source_root=SOURCE_ROOT,
                ground_truth_json=GROUND_TRUTH,
                coverage_items_csv=CALL_DEBUG / "d5-chain-coverage-items.csv",
                handler_sink_chains_csv=CALL_DEBUG / "handler-sink-chains.csv",
                chain_gates_csv=CALL_DEBUG / "chain-gates.csv",
                gate_index_csv=GATE_INDEX,
                gate_semantics_dir=gate_store,
                out_dir=out,
                generation_command="python -m src.call_chain_semantics.main --test",
            )
            self.assertEqual(1, manifest["counts"]["semantic_records"])
            self.assertEqual(0, manifest["counts"]["assembly_failures"])
            self.assertNotIn("model", manifest)
            self.assertNotIn("prompt_version", manifest)
            self.assertNotIn("gate_inputs", manifest["outputs"])
            self.assertEqual(str(gate_store), manifest["inputs"]["gate_semantics_dir"])
            self.assertEqual(5, len(manifest["inputs"]["gate_semantics"]))
            selected = out / "selected/C-54eabf84fd"
            semantic = json.loads((selected / "semantic.json").read_text())
            audit = json.loads((selected / "audit.json").read_text())
            self.assertEqual(5, len(semantic["gates"]))
            self.assertNotIn("raw_responses", audit)
            self.assertNotIn("model", audit)
            report = (out / "chain-index.md").read_text(encoding="utf-8")
            self.assertTrue(
                report.startswith(
                    "# Ordered Call-Chain Gate Semantics\n\n> Generation command:"
                )
            )


if __name__ == "__main__":
    unittest.main()

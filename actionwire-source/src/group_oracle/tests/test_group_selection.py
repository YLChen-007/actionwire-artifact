from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from src.group_oracle.__main__ import build_parser
from src.group_oracle.contracts import GroupOracleError
from src.group_oracle.pipeline import _select_input_groups, run_group_oracle
from src.group_oracle.prompts import PEER_SYSTEM, SEED_SYSTEM
from src.group_oracle.tests.test_group_oracle import (
    HC, HSG, NO_HSG, SemanticFakeRunner, chain, fixture_inputs,
)


SECOND_GROUP = "HSG-" + "e" * 16
SECOND_HC = "HC-" + "f" * 16


def two_group_inputs():
    inputs = fixture_inputs(manual_evidence=True)
    member = replace(chain("other", "3"), handler_criterion_id=SECOND_HC)
    second = {
        **inputs.security_groups[0],
        "handler_sink_group_id": SECOND_GROUP,
        "handler_criterion_id": SECOND_HC,
        "chain_count": 1,
        "chain_refs": [{"project": member.project, "chain_id": member.chain_id}],
        "projects": [member.project],
    }
    return replace(
        inputs,
        handler_criteria={
            **inputs.handler_criteria,
            SECOND_HC: {
                **inputs.handler_criteria[HC], "handler_criterion_id": SECOND_HC,
            },
        },
        security_groups=(*inputs.security_groups, second),
        chains={**inputs.chains, member.key: member},
        evidence_by_group={**inputs.evidence_by_group, SECOND_GROUP: ()},
    )


class GroupSelectionTests(unittest.TestCase):
    def run_selected(self, out_dir, inputs, *, group_ids, runner=None, publish=True, reuse_prior=True):
        runner = runner or SemanticFakeRunner()
        with patch("src.group_oracle.pipeline.load_oracle_inputs", return_value=inputs):
            return run_group_oracle(
                specs=[],
                handler_root=out_dir.parent / "handlers",
                sink_root=out_dir.parent / "sinks",
                evidence_registry=out_dir.parent / "evidence.json",
                out_dir=out_dir,
                generation_command="python -m src.group_oracle --all --group-id " + HSG,
                runner=runner,
                group_ids=group_ids,
                reuse_prior=reuse_prior,
                publish=publish,
            )

    def test_selected_run_only_infers_requested_group_and_preserves_all_members(self):
        inputs = two_group_inputs()
        runner = SemanticFakeRunner()
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "selected"
            result = self.run_selected(out, inputs, group_ids=[HSG], runner=runner)
            rows = [json.loads(line) for line in (out / "oracles.jsonl").read_text().splitlines()]
            self.assertEqual([HSG], [row["group_id"] for row in rows])
            self.assertEqual(
                inputs.security_groups[0]["chain_refs"],
                [
                    {"project": ref["project"], "chain_id": ref["chain_id"]}
                    for ref in rows[0]["member_chain_refs"]
                ],
            )
            self.assertEqual("", (out / "excluded-groups.jsonl").read_text())
            scope = result["manifest"]["selection_scope"]
            self.assertEqual("selected-groups", scope["mode"])
            self.assertEqual([HSG], scope["group_ids"])
            self.assertEqual(2, scope["full_input_counts"]["eligible_security_groups"])
            self.assertEqual(3, scope["full_input_counts"]["eligible_chains"])
            self.assertEqual(1, result["manifest"]["counts"]["group_oracles"])
            self.assertEqual(2, result["manifest"]["counts"]["eligible_chains"])
        self.assertEqual(
            [HSG], [payload["group_id"] for system, payload in runner.calls if system == SEED_SYSTEM]
        )
        peer_payloads = [payload for system, payload in runner.calls if system == PEER_SYSTEM]
        self.assertEqual(1, len(peer_payloads))
        self.assertEqual(["external:C-" + "2" * 12], peer_payloads[0]["subject_chain_refs"])

    def test_full_run_retains_exclusions_and_default_scope(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "all"
            result = self.run_selected(out, fixture_inputs(), group_ids=None)
            self.assertEqual("all", result["manifest"]["selection_scope"]["mode"])
            self.assertEqual(1, result["manifest"]["counts"]["excluded_no_security_impact_groups"])
            self.assertEqual(NO_HSG, json.loads((out / "excluded-groups.jsonl").read_text())["group_id"])

    def test_unknown_ineligible_and_empty_selection_fail_before_inference(self):
        with tempfile.TemporaryDirectory() as raw:
            for group_ids in (["HSG-" + "0" * 16], [NO_HSG], [], HSG):
                with self.subTest(group_ids=group_ids):
                    runner = SemanticFakeRunner()
                    with self.assertRaises(GroupOracleError):
                        self.run_selected(Path(raw) / "selected", fixture_inputs(), group_ids=group_ids, runner=runner)
                    self.assertEqual([], runner.calls)

    def test_selection_deduplicates_ids_and_does_not_mutate_inputs(self):
        inputs = two_group_inputs()
        selected, scope = _select_input_groups(inputs, [HSG, HSG])
        self.assertEqual([HSG], scope["group_ids"])
        self.assertEqual(1, len(selected.security_groups))
        self.assertEqual(2, len(inputs.security_groups))
        self.assertEqual(1, len(inputs.excluded_groups))
        self.assertEqual(3, len(inputs.chains))
        for key, member in selected.chains.items():
            self.assertIs(inputs.chains[key], member)

    def test_canonical_publication_is_rejected(self):
        root = Path(__file__).resolve().parents[3]
        runner = SemanticFakeRunner()
        with self.assertRaisesRegex(GroupOracleError, "canonical"):
            self.run_selected(root / "output/cross-project/group-oracles", fixture_inputs(), group_ids=[HSG], runner=runner)
        self.assertEqual([], runner.calls)

    def test_existing_unselected_group_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "selected"
            out.mkdir()
            path = out / "oracles.jsonl"
            original = json.dumps({"group_id": SECOND_GROUP}) + "\n"
            path.write_text(original)
            runner = SemanticFakeRunner()
            with self.assertRaisesRegex(GroupOracleError, "unselected groups"):
                self.run_selected(out, two_group_inputs(), group_ids=[HSG], runner=runner)
            self.assertEqual(original, path.read_text())
            self.assertEqual([], runner.calls)

    def test_existing_exclusions_are_not_discarded(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "selected"
            out.mkdir()
            (out / "excluded-groups.jsonl").write_text(json.dumps({"group_id": NO_HSG}) + "\n")
            with self.assertRaisesRegex(GroupOracleError, "unselected groups"):
                self.run_selected(out, fixture_inputs(), group_ids=[HSG])

    def test_cli_accepts_repeated_group_ids(self):
        args = build_parser().parse_args(["--all", "--group-id", HSG, "--group-id", SECOND_GROUP])
        self.assertEqual([HSG, SECOND_GROUP], args.group_ids)

    def test_cli_parses_observed_gates_only_mode(self):
        self.assertFalse(build_parser().parse_args(["--all"]).observed_gates_only)
        args = build_parser().parse_args(["--all", "--observed-gates-only", "--group-id", HSG])
        self.assertTrue(args.observed_gates_only)
        self.assertEqual([HSG], args.group_ids)

    def test_observed_only_mode_rejects_correction_ledger_before_loading_it(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            runner = SemanticFakeRunner()
            with patch("src.group_oracle.pipeline.load_correction_ledger") as ledger:
                with self.assertRaisesRegex(GroupOracleError, "observed.*correction|correction.*observed"):
                    run_group_oracle(
                        specs=[], handler_root=root / "handlers", sink_root=root / "sinks",
                        evidence_registry=root / "evidence.json", out_dir=root / "oracle",
                        generation_command="python -m src.group_oracle --all --observed-gates-only",
                        runner=runner, observed_gates_only=True, correction_ledger=root / "ledger.json",
                    )
                ledger.assert_not_called()
            self.assertEqual([], runner.calls)

    def test_fresh_run_skips_prior_snapshot_and_continuity(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "selected"
            inputs = fixture_inputs(manual_evidence=True)
            self.run_selected(out, inputs, group_ids=[HSG])
            runner = SemanticFakeRunner()
            with patch("src.group_oracle.pipeline._prior_group_snapshot") as prior:
                result = self.run_selected(
                    out, inputs, group_ids=[HSG], runner=runner, reuse_prior=False
                )
                prior.assert_not_called()
            self.assertTrue(runner.calls)
            self.assertEqual(0, result["manifest"]["counts"]["content_bound_reused_groups"])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Focused regression tests for D5-to-chain coverage matching."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

import render_d5_chain_coverage as coverage


class EmptySourceIndex:
    def functions_at_line(self, _file: str, _line: int) -> list[object]:
        return []


SOURCE_INDEX = EmptySourceIndex()


def gate(
    fn: str,
    line: int,
    *,
    file: str = "tools/example.py",
    kind: str = "dominance",
    verdict: str = "confirmed",
) -> coverage.GateRef:
    return coverage.GateRef(
        kind=kind,
        fn=fn,
        file=file,
        line=line,
        in_func="handler",
        role="in-condition",
        verdict=verdict,
    )


class SinkMatchingTest(unittest.TestCase):
    def test_open_does_not_match_popen(self) -> None:
        self.assertFalse(
            coverage.sink_symbol_in_text("open", "subprocess.Popen(command)")
        )

    def test_receiver_specific_read_text_does_not_cross_match(self) -> None:
        self.assertFalse(
            coverage.sink_symbol_in_text(
                "skill_md.read_text", "target_file.read_text(encoding='utf-8')"
            )
        )

    def test_generic_codeql_receiver_matches_gt_method(self) -> None:
        self.assertTrue(
            coverage.sink_symbol_in_text(
                "Attribute.send_message_event",
                "self._client.send_message_event(room_id, event_type, content)",
            )
        )

    def test_explicit_representative_sink_is_labeled(self) -> None:
        chain = coverage.Chain(
            chain_id="C-test",
            source="main-taint-valid",
            handler_func="browser_navigate",
            depth=2,
            sink_label="camofox_navigate",
            sink_file="tools/browser_tool.py",
            sink_line=2389,
            call_chain="browser_navigate->camofox_navigate",
            gates=[],
        )
        matches, note = coverage.sink_matches(
            "Issue-8034",
            {"name": "Camofox tab-create REST control boundary"},
            [chain],
        )
        self.assertEqual(matches, {"C-test": "semantic-representative"})
        self.assertTrue(note)

    def test_ghsa_representative_sinks_select_distinct_handler_boundaries(
        self,
    ) -> None:
        eval_chain = coverage.Chain(
            chain_id="C-eval",
            source="main-taint-valid",
            handler_func="browser_console",
            depth=2,
            sink_label="_run_browser_command",
            sink_file="tools/browser_tool.py",
            sink_line=2585,
            call_chain="browser_console->_browser_eval->_run_browser_command",
            gates=[],
        )
        snapshot_chain = coverage.Chain(
            chain_id="C-snapshot",
            source="main-taint-valid",
            handler_func="browser_snapshot",
            depth=1,
            sink_label="_run_browser_command",
            sink_file="tools/browser_tool.py",
            sink_line=2282,
            call_chain="browser_snapshot->_run_browser_command",
            gates=[],
        )

        eval_matches, eval_note = coverage.sink_matches(
            "GHSA-browser-eval",
            {
                "name": (
                    "agent-browser Runtime.evaluate pipeline to Chromium "
                    "network navigation"
                )
            },
            [eval_chain, snapshot_chain],
        )
        snapshot_matches, snapshot_note = coverage.sink_matches(
            "GHSA-browser-eval",
            {"name": "browser_snapshot tool-result disclosure pipeline"},
            [eval_chain, snapshot_chain],
        )

        self.assertEqual(eval_matches, {"C-eval": "semantic-representative"})
        self.assertEqual(
            snapshot_matches,
            {"C-snapshot": "semantic-representative"},
        )
        self.assertTrue(eval_note)
        self.assertTrue(snapshot_note)


class GateMatchingTest(unittest.TestCase):
    def test_absent_gate_wording_is_recognized(self) -> None:
        for name in ["missing URL gate", "handler lacks a gate", "lacking URL gate"]:
            with self.subTest(name=name):
                self.assertTrue(coverage.describes_absent_gate({"name": name}))

    def test_missing_gate_cannot_be_covered_by_defect_site_call(self) -> None:
        item = {
            "name": "missing post-eval current URL gate",
            "type": "dominance",
            "location": "tools/browser_tool.py:2544",
            "evidence": "result = _run_browser_command(...)\nif result.get('success'):",
        }
        kind, candidate = coverage.best_gate_match(
            item,
            {"status": "confirmed"},
            [gate("get", 2544, file="tools/browser_tool.py")],
            SOURCE_INDEX,  # type: ignore[arg-type]
        )
        self.assertEqual(kind, "")
        self.assertIsNone(candidate)

    def test_exact_location_beats_incidental_evidence_symbol(self) -> None:
        item = {
            "name": "read_file_tool binary extension guard",
            "type": "dominance",
            "location": "tools/file_tools.py:850",
            "evidence": "if has_binary_extension(str(_resolved)):",
        }
        kind, candidate = coverage.best_gate_match(
            item,
            {"status": "confirmed"},
            [
                gate("str", 807, file="tools/file_tools.py"),
                gate("has_binary_extension", 850, file="tools/file_tools.py"),
                gate("str", 850, file="tools/file_tools.py"),
            ],
            SOURCE_INDEX,  # type: ignore[arg-type]
        )
        self.assertEqual(kind, "exact-location")
        self.assertEqual(candidate.fn, "has_binary_extension")

    def test_evidence_symbol_is_bounded_to_nearby_location(self) -> None:
        item = {
            "name": "categorized fall-through rejection",
            "type": "dominance",
            "location": "tools/skills_tool.py:972",
            "evidence": "lookup_error = _skill_lookup_path_error(local_name)",
        }
        kind = coverage.gate_match_kind(
            item,
            {"status": "confirmed"},
            gate("_skill_lookup_path_error", 888, file="tools/skills_tool.py"),
            SOURCE_INDEX,  # type: ignore[arg-type]
        )
        self.assertEqual(kind, "")

        debug_kind, checks, reason = coverage.gate_match_debug(
            item,
            {"status": "confirmed"},
            gate("_skill_lookup_path_error", 888, file="tools/skills_tool.py"),
            SOURCE_INDEX,  # type: ignore[arg-type]
        )
        self.assertEqual(debug_kind, "")
        self.assertIn("evidence_contains_gate_symbol=true", checks)
        self.assertIn("more than 8 lines", reason)

    def test_versioned_location_allows_stale_symbol_match(self) -> None:
        item = {
            "name": "file_path traversal component check",
            "type": "dominance",
            "location": "tools/skills_tool.py:1126 (commit 77a1650c78a4cb1)",
            "evidence": "if has_traversal_component(file_path):",
        }
        kind = coverage.gate_match_kind(
            item,
            {"status": "confirmed"},
            gate("has_traversal_component", 1197, file="tools/skills_tool.py"),
            SOURCE_INDEX,  # type: ignore[arg-type]
        )
        self.assertEqual(kind, "stale-location-symbol")

    def test_nested_gate_matches_only_its_named_parent(self) -> None:
        item = {
            "name": "nested predicate",
            "type": "dominance",
            "location": "tools/example.py:20",
        }
        metadata = {
            "status": "nested-in-gate",
            "reason": "nested-in-gate(L1): parent gate outer_check(confirmed)",
        }
        self.assertEqual(
            coverage.gate_match_kind(
                item,
                metadata,
                gate("outer_check", 40),
                SOURCE_INDEX,  # type: ignore[arg-type]
            ),
            "nested-in-gate(L1)",
        )
        self.assertEqual(
            coverage.gate_match_kind(
                item,
                metadata,
                gate("unrelated_check", 40),
                SOURCE_INDEX,  # type: ignore[arg-type]
            ),
            "",
        )

    def test_source_subtree_is_matched_automatically_through_import_alias(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "handler.py").write_text(
                "from policy import policy_root as _policy_impl\n"
                "\n"
                "def wrapper(value):\n"
                "    return _policy_impl(value)\n",
                encoding="utf-8",
            )
            (root / "policy.py").write_text(
                "def helper(value):\n"
                "    return bool(value)\n"
                "\n"
                "def policy_root(value):\n"
                "    if not value:\n"
                "        return False\n"
                "    return helper(value)\n",
                encoding="utf-8",
            )
            (root / "unrelated.py").write_text(
                "def unrelated(value):\n"
                "    return bool(value)\n",
                encoding="utf-8",
            )
            source_index = coverage.SourceIndex(root)
            nested_index = coverage.NestedGateIndex(root)
            parent = gate("wrapper", 3, file="handler.py")

            inline_kind = coverage.gate_match_kind(
                {
                    "name": "inline rejection",
                    "kind": "adhoc",
                    "type": "dominance",
                    "location": "policy.py:5",
                },
                {"status": "no-candidate"},
                parent,
                source_index,
                nested_index,
            )
            helper_kind = coverage.gate_match_kind(
                {
                    "name": "helper decision",
                    "kind": "function",
                    "type": "dominance",
                    "location": "policy.py:1",
                },
                {"status": "no-candidate"},
                parent,
                source_index,
                nested_index,
            )
            unrelated_kind = coverage.gate_match_kind(
                {
                    "name": "unrelated decision",
                    "kind": "function",
                    "type": "dominance",
                    "location": "unrelated.py:1",
                },
                {"status": "no-candidate"},
                parent,
                source_index,
                nested_index,
            )

        self.assertEqual(inline_kind, "nested-in-gate(L0)")
        self.assertEqual(helper_kind, "nested-in-gate(L1)")
        self.assertEqual(unrelated_kind, "")

    def test_transform_exact_location_matches_without_stale_metadata(self) -> None:
        item = {
            "name": "SlackAdapter.format_message",
            "type": "transform",
            "location": "tools/send_message_tool.py:478",
            "evidence": "message = slack_adapter.format_message(message)",
        }
        kind = coverage.gate_match_kind(
            item,
            {"status": "no-candidate"},
            gate(
                "format_message",
                478,
                file="tools/send_message_tool.py",
                kind="transform",
            ),
            SOURCE_INDEX,  # type: ignore[arg-type]
        )
        self.assertEqual(kind, "exact-location")

    def test_nested_transform_matches_current_source_owner(self) -> None:
        item = {
            "name": "Slack entity-preservation before escaping",
            "kind": "adhoc",
            "type": "transform",
            "location": "gateway/platforms/slack.py:1169",
        }

        class SlackSourceIndex:
            def functions_at_line(
                self, _file: str, _line: int
            ) -> list[tuple[str, SimpleNamespace]]:
                return [
                    (
                        "gateway/platforms/slack.py",
                        SimpleNamespace(simple_name="format_message"),
                    )
                ]

        kind = coverage.gate_match_kind(
            item,
            {"status": "no-candidate"},
            gate(
                "format_message",
                478,
                file="tools/send_message_tool.py",
                kind="transform",
            ),
            SlackSourceIndex(),  # type: ignore[arg-type]
        )
        self.assertEqual(kind, "transform-parent")

    def test_function_transform_matches_current_source_owner_as_call(self) -> None:
        item = {
            "name": "BaseEnvironment._wrap_command quote embedding",
            "kind": "function",
            "type": "transform",
            "location": "tools/environments/base.py:387",
        }

        class EnvironmentSourceIndex:
            def functions_at_line(
                self, _file: str, _line: int
            ) -> list[tuple[str, SimpleNamespace]]:
                return [
                    (
                        "tools/environments/base.py",
                        SimpleNamespace(simple_name="_wrap_command"),
                    )
                ]

        kind = coverage.gate_match_kind(
            item,
            {"status": "no-candidate"},
            gate(
                "_wrap_command",
                774,
                file="tools/environments/base.py",
                kind="transform",
            ),
            EnvironmentSourceIndex(),  # type: ignore[arg-type]
        )
        self.assertEqual(kind, "transform-call")

    def test_discord_slack_gate_scope_uses_execution_path(self) -> None:
        slack_chain = coverage.Chain(
            chain_id="C-slack",
            source="main-taint-valid",
            handler_func="send_message_tool",
            depth=4,
            sink_label="session.post",
            sink_file="tools/send_message_tool.py",
            sink_line=1042,
            call_chain=(
                "send_message_tool@send_message_tool.py->"
                "_send_slack@send_message_tool.py->session.post"
            ),
            gates=[],
        )
        mattermost_chain = coverage.Chain(
            chain_id="C-mattermost",
            source="main-taint-valid",
            handler_func="send_message_tool",
            depth=4,
            sink_label="session.post",
            sink_file="tools/send_message_tool.py",
            sink_line=1364,
            call_chain=(
                "send_message_tool@send_message_tool.py->"
                "_send_mattermost@send_message_tool.py->session.post"
            ),
            gates=[],
        )
        for name in [
            "SlackAdapter.format_message",
            "Slack entity-preservation before escaping",
        ]:
            with self.subTest(name=name):
                item = {"name": name}
                self.assertTrue(
                    coverage.gate_scope_allows(
                        "Discord-Mention", item, slack_chain
                    )
                )
                self.assertFalse(
                    coverage.gate_scope_allows(
                        "Discord-Mention", item, mattermost_chain
                    )
                )


class SourceDebugTest(unittest.TestCase):
    def test_rust_ground_truth_location_is_parsed_for_debugging(self) -> None:
        self.assertEqual(
            coverage.parse_locations(
                "agent-browser@0.26.0/cli/src/native/browser.rs:765"
            ),
            [
                coverage.LocationRef(
                    "agent-browser@0.26.0/cli/src/native/browser.rs", 765
                )
            ],
        )

    def test_source_debug_exposes_location_and_evidence_line_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "tools/example.py"
            source.parent.mkdir()
            source.write_text(
                "def handler(url):\n"
                "    if not is_safe_url(url):\n"
                "        return False\n",
                encoding="utf-8",
            )
            fields = coverage.source_debug_fields(
                {
                    "location": "tools/example.py:2",
                    "evidence": (
                        "if not is_safe_url(url):\n    return False\nmissing_line()"
                    ),
                },
                root,
                {},
            )

        self.assertEqual(fields["source_file_status"], "tools/example.py=present")
        self.assertEqual(fields["source_line_status"], "tools/example.py:2=present")
        self.assertEqual(fields["evidence_lines_total"], "3")
        self.assertEqual(fields["evidence_lines_found_in_file"], "2")
        self.assertEqual(fields["evidence_lines_found_near_location"], "2")
        self.assertEqual(fields["missing_evidence_lines"], "missing_line()")
        self.assertEqual(fields["evidence_symbols"], "is_safe_url; missing_line")


class SummaryOverviewTest(unittest.TestCase):
    def test_summary_overview_reports_matching_and_source_evidence(self) -> None:
        item_rows = [
            {
                "json_id": "example",
                "item_kind": "handler",
                "item_index": "1",
                "coverage_status": "covered",
                "match_kind": "tool-handler-root",
            },
            {
                "json_id": "example",
                "item_kind": "gate",
                "item_index": "1",
                "coverage_status": "covered",
                "match_kind": "exact-location",
            },
            {
                "json_id": "example",
                "item_kind": "gate",
                "item_index": "2",
                "coverage_status": "uncovered",
                "match_kind": "",
            },
            {
                "json_id": "example",
                "item_kind": "gate",
                "item_index": "3",
                "coverage_status": "unsupported",
                "match_kind": "",
            },
            {
                "json_id": "example",
                "item_kind": "gate",
                "item_index": "4",
                "coverage_status": "absent-in-source",
                "match_kind": "",
            },
            {
                "json_id": "example",
                "item_kind": "sink",
                "item_index": "1",
                "coverage_status": "covered",
                "match_kind": "semantic-representative",
            },
            {
                "json_id": "example",
                "item_kind": "sink",
                "item_index": "2",
                "coverage_status": "uncovered",
                "match_kind": "",
            },
        ]
        debug_rows = []
        for row in item_rows:
            debug_rows.append(
                {
                    "json_id": row["json_id"],
                    "item_kind": row["item_kind"],
                    "item_index": row["item_index"],
                    "gt_name": f"{row['item_kind']}-{row['item_index']}",
                    "source_file_status": "tools/example.py=present",
                    "evidence_lines_total": "2",
                    "evidence_lines_found_in_file": "2",
                }
            )
        debug_rows[-2].update(
            {
                "gt_name": "Runtime.evaluate",
                "source_file_status": (
                    "agent-browser@0.26.0/cli/src/native/browser.rs=missing"
                ),
                "evidence_lines_found_in_file": "0",
            }
        )
        debug_rows[-1]["evidence_lines_found_in_file"] = "1"

        lines = coverage.summary_overview_lines(item_rows, debug_rows)
        rendered = "\n".join(lines)

        self.assertIn(
            "Ground-truth items: **7** (handlers **1**, gates **4**, sinks **2**)",
            rendered,
        )
        self.assertIn("Handler matching: **1/1**", rendered)
        self.assertIn(
            "covered on a sink-matched chain **1**, uncovered **1**, "
            "unsupported types **1**, required but absent **1**",
            rendered,
        )
        self.assertIn("Sink chain matching: **1/2**", rendered)
        self.assertIn("| Gates | 4/4 | 4 | 0 | 0 |", rendered)
        self.assertIn("| Sinks | 1/2 | 0 | 1 | 1 |", rendered)
        self.assertIn("external Rust `agent-browser` implementation", rendered)
        self.assertIn("`semantic-representative` mapping", rendered)


class SummaryVerdictTest(unittest.TestCase):
    def test_reports_no_supported_gates_for_nonempty_gt(self) -> None:
        self.assertEqual(
            coverage.summary_verdict(
                {
                    "all_full": False,
                    "supported_full": True,
                    "chain_count": 13,
                    "gate_total": 3,
                    "supported_gate_total": 0,
                }
            ),
            "no-supported-gates",
        )

    def test_no_chain_takes_precedence(self) -> None:
        self.assertEqual(
            coverage.summary_verdict(
                {
                    "all_full": False,
                    "supported_full": False,
                    "chain_count": 0,
                    "gate_total": 3,
                    "supported_gate_total": 0,
                }
            ),
            "no-chain",
        )


class DetectorVerdictRenderingTest(unittest.TestCase):
    def test_renders_confirmed_and_branch_confirmed_like_gate_report(self) -> None:
        self.assertEqual(
            coverage.render_detector_verdicts("confirmed"),
            "✅ confirmed",
        )
        self.assertEqual(
            coverage.render_detector_verdicts("branch-confirmed"),
            "🔷 branch-confirmed",
        )

    def test_aggregates_distinct_selected_candidate_verdicts_in_fixed_order(
        self,
    ) -> None:
        self.assertEqual(
            coverage.aggregate_detector_verdicts(
                [
                    gate("branch_gate", 2, verdict="branch-confirmed"),
                    gate("confirmed_gate", 1),
                    gate("duplicate_confirmed_gate", 3),
                ]
            ),
            "confirmed; branch-confirmed",
        )
        self.assertEqual(
            coverage.render_detector_verdicts("confirmed; branch-confirmed"),
            "✅ confirmed; 🔷 branch-confirmed",
        )

    def test_blank_when_no_detector_candidate_matched(self) -> None:
        self.assertEqual(coverage.aggregate_detector_verdicts([]), "")
        self.assertEqual(coverage.render_detector_verdicts(""), "")

    def test_distribution_counts_each_gt_gate_once_by_aggregated_value(
        self,
    ) -> None:
        item_rows = [
            {"item_kind": "handler", "detector_verdict": ""},
            {"item_kind": "gate", "detector_verdict": "confirmed"},
            {"item_kind": "gate", "detector_verdict": "confirmed"},
            {"item_kind": "gate", "detector_verdict": "branch-confirmed"},
            {
                "item_kind": "gate",
                "detector_verdict": "confirmed; branch-confirmed",
            },
            {"item_kind": "gate", "detector_verdict": ""},
            {"item_kind": "sink", "detector_verdict": ""},
        ]

        rendered = "\n".join(
            coverage.detector_verdict_distribution_lines(item_rows)
        )

        self.assertIn("| ✅ confirmed | 2 | 40.0% |", rendered)
        self.assertIn("| 🔷 branch-confirmed | 1 | 20.0% |", rendered)
        self.assertIn(
            "| ✅ confirmed; 🔷 branch-confirmed | 1 | 20.0% |",
            rendered,
        )
        self.assertIn("| _No matched detector verdict_ | 1 | 20.0% |", rendered)
        self.assertIn("| **Total** | **5** | **100.0%** |", rendered)


class SnapshotFallbackTest(unittest.TestCase):
    def test_default_ground_truth_uses_new_vuls_only(self) -> None:
        specs = coverage.report_specs(coverage.DEFAULT_GROUND_TRUTH_ROOT)
        self.assertEqual(len(specs), 9)
        self.assertTrue(all(spec.path.parent.name == "new-vuls" for spec in specs))
        self.assertNotIn("Issue-8033", {spec.gt_id for spec in specs})

    def test_reconstructs_normalized_gt_lists(self) -> None:
        data = coverage.data_from_item_snapshot(
            [
                {
                    "item_kind": "sink",
                    "item_index": "2",
                    "gt_name": "client.post",
                    "gt_type": "api",
                    "gt_location": "tools/example.py:20",
                },
                {
                    "item_kind": "handler",
                    "item_index": "1",
                    "gt_name": "example_tool",
                    "gt_type": "handler-entry",
                    "gt_location": "tools/example.py:5",
                },
            ]
        )
        self.assertEqual(
            data["d5_tool_handler_entry"],
            [
                {
                    "name": "example_tool",
                    "type": "handler-entry",
                    "location": "tools/example.py:5",
                }
            ],
        )
        self.assertEqual(
            data["d5_sink_points"],
            [
                {
                    "name": "client.post",
                    "kind": "api",
                    "location": "tools/example.py:20",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()

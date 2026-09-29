#!/usr/bin/env python3
"""Tests for the paper-metrics collector."""

from __future__ import annotations

import contextlib
import csv
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import get_paper_metrics as metrics  # noqa: E402


def gate(uid: str, mode: str) -> dict[str, str]:
    return {"gate_uid": uid, "mode": mode}


def handler(tool: str, line: str = "10") -> dict[str, str]:
    return {
        "tool_name": tool,
        "form": "function",
        "handler_func": f"{tool}_handler",
        "file": "tools/example.py",
        "line": line,
        "forwarded_body": "-",
    }


def criterion_mapping(
    project: str,
    handler_suffix: str,
    criterion_suffix: str,
) -> dict[str, object]:
    return {
        "schema_version": "handler-type-mapping/v2",
        "project": project,
        "handler_id": f"H-{handler_suffix:0>16}",
        "handler_criterion_id": f"HC-{criterion_suffix:0>16}",
    }


def sink_mapping(
    project: str,
    chain_suffix: str,
    criterion_suffix: str,
    sink_type_suffix: str,
) -> dict[str, object]:
    return {
        "schema_version": "sink-type-mapping/v1",
        "project": project,
        "revision": metrics.get_project(project).analysis_revision,
        "chain_id": f"C-{chain_suffix:0>12}",
        "handler_criterion_id": f"HC-{criterion_suffix:0>16}",
        "sink_type_id": f"ST-{sink_type_suffix:0>16}",
    }


def chain(
    name: str,
    *,
    line: str = "20",
    column: str = "8",
    tool: str = "terminal",
    source: str = "args",
    sink_argument: str = "path",
) -> dict[str, str]:
    return {
        "project_id": "hermes-agent",
        "tool_name": tool,
        "handler_file": "tools/tool.py",
        "handler_line": "10",
        "source_parameter": source,
        "call_chain": f"1#execute@tool.py->{name}@example.py",
        "sink_label": "open",
        "sink_file": "tools/example.py",
        "sink_line": line,
        "sink_column": column,
        "sink_argument": sink_argument,
    }


def cache_document() -> dict[str, object]:
    return {
        "schema_version": metrics.METRICS_CACHE_SCHEMA,
        "generation_command": metrics.REFRESH_COMMAND,
        "static_analysis_timing": metrics.STATIC_ANALYSIS_TIMING,
        "projects": [
            {
                "project": project_id,
                "analysis_revision": metrics.get_project(
                    project_id
                ).analysis_revision,
                "metrics": {
                    "dom": index,
                    "filt": 0,
                    "trans": 0,
                    "cap": 1,
                    "handlers": 2,
                    "sinks": 1,
                    "call_chains": 3,
                    "static_analysis_minutes": float(index),
                },
                "provenance": {
                    "kind": "test",
                    "static_analysis_time_source": "test measurement",
                },
            }
            for index, project_id in enumerate(metrics.PROJECT_IDS, 1)
        ],
    }


class CountingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = metrics.get_project("hermes-agent")

    def test_gate_counts_use_distinct_uid_and_mode_mapping(self) -> None:
        rows = [
            gate("G1", "predicate"),
            gate("G1", "predicate"),
            gate("G2", "filter"),
            gate("G3", "transform"),
        ]
        self.assertEqual(
            {"dom": 1, "filt": 1, "trans": 1},
            metrics.count_gate_modes(rows),
        )

    def test_gate_uid_cannot_change_mode(self) -> None:
        with self.assertRaisesRegex(metrics.MetricsError, "conflicting modes"):
            metrics.count_gate_modes(
                [gate("G1", "predicate"), gate("G1", "transform")]
            )

    def test_unknown_gate_mode_fails(self) -> None:
        with self.assertRaisesRegex(metrics.MetricsError, "unknown mode"):
            metrics.count_gate_modes([gate("G1", "capability")])

    def test_handlers_are_deduplicated(self) -> None:
        self.assertEqual(
            2,
            metrics.count_handlers([handler("one"), handler("one"), handler("two")]),
        )

    def test_distinct_criteria_count_unique_hcs_per_project(self) -> None:
        rows = [
            criterion_mapping("hermes-agent", "1", "a"),
            criterion_mapping("hermes-agent", "2", "a"),
            criterion_mapping("hermes-agent", "3", "b"),
            criterion_mapping("nanobot", "4", "a"),
        ]
        self.assertEqual(
            {"hermes-agent": 2, "nanobot": 1},
            metrics.count_distinct_criteria(
                rows, ("hermes-agent", "nanobot")
            ),
        )

    def test_distinct_criteria_rejects_stale_mapping_schema(self) -> None:
        row = criterion_mapping("hermes-agent", "1", "a")
        row["schema_version"] = "handler-type-mapping/v1"
        with self.assertRaisesRegex(metrics.MetricsError, "mapping/v2"):
            metrics.count_distinct_criteria([row], ("hermes-agent",))

    def test_distinct_criteria_rejects_duplicate_handler_mapping(self) -> None:
        row = criterion_mapping("hermes-agent", "1", "a")
        with self.assertRaisesRegex(metrics.MetricsError, "duplicates handler"):
            metrics.count_distinct_criteria([row, row], ("hermes-agent",))

    def test_distinct_criteria_requires_every_expected_project(self) -> None:
        with self.assertRaisesRegex(metrics.MetricsError, "nanobot"):
            metrics.count_distinct_criteria(
                [criterion_mapping("hermes-agent", "1", "a")],
                ("hermes-agent", "nanobot"),
            )

    def test_handler_criterion_summary_counts_singletons_and_handlers(self) -> None:
        rows = [
            criterion_mapping("hermes-agent", "1", "a"),
            criterion_mapping("hermes-agent", "2", "a"),
            criterion_mapping("hermes-agent", "3", "b"),
            criterion_mapping("nanobot", "4", "c"),
        ]
        summary = metrics.count_handler_criterion_summary(
            rows, ("hermes-agent", "nanobot")
        )
        self.assertEqual(3, summary.total_criteria)
        self.assertEqual(2, summary.singleton_criteria)
        self.assertEqual(4, summary.total_handlers)
        self.assertEqual(2, summary.singleton_handlers)
        self.assertAlmostEqual(66.666, summary.singleton_criterion_percentage, 2)
        self.assertEqual(50.0, summary.singleton_handler_percentage)

    def test_hc_st_groups_are_distinct_per_project_and_globally(self) -> None:
        rows = [
            sink_mapping("hermes-agent", "1", "a", "1"),
            sink_mapping("hermes-agent", "2", "a", "1"),
            sink_mapping("hermes-agent", "3", "b", "2"),
            sink_mapping("nanobot", "4", "a", "1"),
        ]
        counts, summary = metrics.count_hc_st_groups(
            rows, ("hermes-agent", "nanobot")
        )
        self.assertEqual({"hermes-agent": 2, "nanobot": 1}, counts)
        self.assertEqual(2, summary.total_groups)
        self.assertEqual(4, summary.mapped_chains)

    def test_hc_st_groups_reject_duplicate_chain_mapping(self) -> None:
        row = sink_mapping("hermes-agent", "1", "a", "1")
        with self.assertRaisesRegex(metrics.MetricsError, "duplicates chain"):
            metrics.count_hc_st_groups([row, row], ("hermes-agent",))

    def test_hc_st_groups_reject_stale_schema_and_revision(self) -> None:
        stale_schema = sink_mapping("hermes-agent", "1", "a", "1")
        stale_schema["schema_version"] = "sink-type-mapping/v0"
        with self.assertRaisesRegex(metrics.MetricsError, "mapping/v1"):
            metrics.count_hc_st_groups([stale_schema], ("hermes-agent",))

        stale_revision = sink_mapping("hermes-agent", "2", "a", "1")
        stale_revision["revision"] = "stale"
        with self.assertRaisesRegex(metrics.MetricsError, "does not match"):
            metrics.count_hc_st_groups([stale_revision], ("hermes-agent",))

    def test_hc_st_groups_reject_malformed_hc_and_st_ids(self) -> None:
        bad_hc = sink_mapping("hermes-agent", "1", "a", "1")
        bad_hc["handler_criterion_id"] = "HC-invalid"
        with self.assertRaisesRegex(metrics.MetricsError, "handler_criterion_id"):
            metrics.count_hc_st_groups([bad_hc], ("hermes-agent",))

        bad_st = sink_mapping("hermes-agent", "2", "a", "1")
        bad_st["sink_type_id"] = "ST-invalid"
        with self.assertRaisesRegex(metrics.MetricsError, "sink_type_id"):
            metrics.count_hc_st_groups([bad_st], ("hermes-agent",))

    def test_hc_st_groups_allow_zero_for_selected_project(self) -> None:
        counts, summary = metrics.count_hc_st_groups(
            [sink_mapping("hermes-agent", "1", "a", "1")],
            ("nanobot",),
        )
        self.assertEqual({"nanobot": 0}, counts)
        self.assertEqual(0, summary.total_groups)
        self.assertEqual(0, summary.mapped_chains)

    def test_chains_and_sink_locations_are_deduplicated_independently(self) -> None:
        rows = [
            chain("chain-a"),
            chain("chain-a"),
            chain("chain-b"),
            chain("chain-c", column="9"),
        ]
        self.assertEqual(
            (3, 2, 0), metrics.count_chains_and_sinks(rows, self.spec)
        )

    def test_each_sink_location_is_a_distinct_witness_record(self) -> None:
        self.assertEqual(
            (2, 2, 0),
            metrics.count_chains_and_sinks(
                [chain("chain-a"), chain("chain-a", line="21")],
                self.spec,
            ),
        )

    def test_each_handler_source_is_a_distinct_witness_record(self) -> None:
        self.assertEqual(
            (2, 1, 0),
            metrics.count_chains_and_sinks(
                [chain("chain-a"), chain("chain-a", tool="read", source="path")],
                self.spec,
            ),
        )

    def test_foreign_project_chain_fails(self) -> None:
        row = chain("chain-a")
        row["project_id"] = "another-project"
        with self.assertRaisesRegex(metrics.MetricsError, "another-project"):
            metrics.count_chains_and_sinks([row], self.spec)

    def test_single_sink_argument_is_not_a_capability(self) -> None:
        rows = [chain("chain-a"), chain("chain-a"), chain("chain-b")]
        self.assertEqual(
            (2, 1, 0), metrics.count_chains_and_sinks(rows, self.spec)
        )

    def test_distinct_sink_arguments_make_one_capability(self) -> None:
        rows = [
            chain("chain-a", sink_argument="path"),
            chain("chain-a", sink_argument="encoding"),
        ]
        self.assertEqual(
            (1, 1, 1), metrics.count_chains_and_sinks(rows, self.spec)
        )

    def test_sink_arguments_are_unioned_across_canonical_chains(self) -> None:
        rows = [
            chain("chain-a", sink_argument="path"),
            chain("chain-b", sink_argument="encoding"),
        ]
        self.assertEqual(
            (2, 1, 1), metrics.count_chains_and_sinks(rows, self.spec)
        )

    def test_capabilities_are_counted_per_concrete_sink(self) -> None:
        rows = [
            chain("chain-a", line="20", sink_argument="path;encoding"),
            chain("chain-b", line="21", sink_argument="path"),
            chain("chain-c", line="22", sink_argument="path;content"),
        ]
        self.assertEqual(
            (3, 3, 2), metrics.count_chains_and_sinks(rows, self.spec)
        )

    def test_empty_or_malformed_sink_argument_fails(self) -> None:
        for value in ("", "path;;encoding", ";path", "path;"):
            with self.subTest(value=value), self.assertRaisesRegex(
                metrics.MetricsError, "sink_argument"
            ):
                metrics.count_chains_and_sinks(
                    [chain("chain-a", sink_argument=value)], self.spec
                )


class ValidationTests(unittest.TestCase):
    def test_csv_requires_expected_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.csv"
            with path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["gate_uid"])
                writer.writeheader()
                writer.writerow({"gate_uid": "G1"})
            with self.assertRaisesRegex(metrics.MetricsError, "missing required"):
                metrics.read_csv_rows(path, metrics.GATE_FIELDS, "gate catalog")

    def test_manifest_rejects_slice_failures(self) -> None:
        spec = metrics.get_project("hermes-agent")
        manifest = {
            "project": spec.project_id,
            "revision": spec.analysis_revision,
            "counts": {
                "slice_failures": 1,
                "eligible_catalog_gates": 3,
                "all_candidate_rows": 9,
            },
        }
        with self.assertRaisesRegex(metrics.MetricsError, "refusing partial"):
            metrics.validate_gate_manifest(manifest, spec, 3)

    def test_collection_times_only_the_four_gate_static_work(self) -> None:
        spec = metrics.get_project("hermes-agent")
        manifest = {
            "project": spec.project_id,
            "revision": spec.analysis_revision,
            "counts": {
                "slice_failures": 0,
                "eligible_catalog_gates": 1,
                "all_candidate_rows": 1,
            },
        }
        with mock.patch.object(
            metrics, "infer_gates", return_value=manifest
        ), mock.patch.object(metrics, "infer_call_chains") as infer_chains, mock.patch.object(
            metrics, "run_query"
        ) as run_query, mock.patch.object(
            metrics,
            "read_csv_rows",
            side_effect=[
                [gate("G1", "predicate")],
                [handler("terminal")],
                [chain("sink")],
            ],
        ), mock.patch.object(
            metrics, "perf_counter", side_effect=[10.0, 190.0]
        ):
            payload = metrics.collect_project_metrics(
                spec, distinct_criteria=1, hc_st_groups=1
            )

        self.assertEqual(3.0, payload["metrics"]["static_analysis_minutes"])
        infer_chains.assert_called_once()
        self.assertEqual(1, run_query.call_count)
        timing = payload["provenance"]["static_analysis_timing"]
        self.assertIn("tool-handler inventory", timing["excluded"])
        self.assertEqual(
            ["infer_gates", "infer_call_chains"],
            timing["implementation_stages"],
        )


class CacheTests(unittest.TestCase):
    def test_cache_requires_current_schema(self) -> None:
        document = cache_document()
        document["schema_version"] = "paper-metrics-cache/v0"
        with self.assertRaisesRegex(metrics.MetricsError, "cache/v3"):
            metrics._validate_cache_document(document)

    def test_cache_accepts_fewer_capabilities_than_sinks(self) -> None:
        document = cache_document()
        document["projects"][0]["metrics"]["cap"] = 0
        metrics._validate_cache_document(document)

    def test_cache_rejects_more_capabilities_than_sinks(self) -> None:
        document = cache_document()
        document["projects"][0]["metrics"]["cap"] = 2
        with self.assertRaisesRegex(metrics.MetricsError, "Cap. <= Sinks"):
            metrics._validate_cache_document(document)

    def test_cache_requires_positive_static_analysis_time(self) -> None:
        document = cache_document()
        document["projects"][0]["metrics"]["static_analysis_minutes"] = 0
        with self.assertRaisesRegex(metrics.MetricsError, "positive finite"):
            metrics._validate_cache_document(document)

    def test_cache_requires_current_timing_contract(self) -> None:
        document = cache_document()
        document["static_analysis_timing"] = {
            **metrics.STATIC_ANALYSIS_TIMING,
            "excluded": [],
        }
        with self.assertRaisesRegex(metrics.MetricsError, "timing contract"):
            metrics._validate_cache_document(document)

    def test_cache_requires_timing_provenance_per_project(self) -> None:
        document = cache_document()
        document["projects"][0]["provenance"].pop(
            "static_analysis_time_source"
        )
        with self.assertRaisesRegex(metrics.MetricsError, "time_source"):
            metrics._validate_cache_document(document)

    def test_cache_requires_complete_canonical_project_coverage(self) -> None:
        document = cache_document()
        document["projects"] = document["projects"][:-1]
        with self.assertRaisesRegex(metrics.MetricsError, "canonical order"):
            metrics._validate_cache_document(document)

    def test_cache_rejects_stale_project_revision(self) -> None:
        document = cache_document()
        document["projects"][0]["analysis_revision"] = "stale"
        with self.assertRaisesRegex(metrics.MetricsError, "--refresh"):
            metrics._validate_cache_document(document)

    def test_cache_does_not_store_dynamic_criterion_count(self) -> None:
        document = cache_document()
        document["projects"][0]["metrics"]["distinct_criteria"] = 99
        with self.assertRaisesRegex(metrics.MetricsError, "dynamic metric"):
            metrics._validate_cache_document(document)

    def test_cache_does_not_store_dynamic_hc_st_group_count(self) -> None:
        document = cache_document()
        document["projects"][0]["metrics"]["hc_st_groups"] = 99
        with self.assertRaisesRegex(metrics.MetricsError, "dynamic metric"):
            metrics._validate_cache_document(document)

    def test_selected_project_load_uses_cache_and_current_criteria(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache.json"
            path.write_text(json.dumps(cache_document()), encoding="utf-8")
            with mock.patch.object(
                metrics,
                "load_distinct_criteria_counts",
                return_value={project_id: 7 for project_id in metrics.PROJECT_IDS},
            ), mock.patch.object(
                metrics,
                "load_hc_st_group_counts",
                return_value=(
                    {project_id: 8 for project_id in metrics.PROJECT_IDS},
                    metrics.HandlerSinkGroupSummary(8, 12),
                ),
            ):
                payloads = metrics.load_cached_metrics(["AstrBot"], cache_path=path)
        self.assertEqual(["AstrBot"], [row["project"] for row in payloads])
        self.assertEqual(7, payloads[0]["metrics"]["distinct_criteria"])
        self.assertEqual(8, payloads[0]["metrics"]["hc_st_groups"])
        self.assertEqual("validated-cache", payloads[0]["provenance"]["static_metrics_source"])

    def test_refresh_failure_leaves_existing_cache_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache.json"
            original = json.dumps(cache_document(), indent=2)
            path.write_text(original, encoding="utf-8")
            with mock.patch.object(
                metrics, "collect_metrics", side_effect=RuntimeError("query failed")
            ), mock.patch.object(metrics, "write_metrics_cache") as write:
                with self.assertRaisesRegex(RuntimeError, "query failed"):
                    metrics.refresh_metrics(["AstrBot"], cache_path=path)
            write.assert_not_called()
            self.assertEqual(original, path.read_text(encoding="utf-8"))

    def test_selected_refresh_replaces_only_selected_cached_project(self) -> None:
        document = cache_document()
        fresh = dict(document["projects"][3])
        fresh["metrics"] = {
            **fresh["metrics"],
            "dom": 99,
            "distinct_criteria": 8,
            "hc_st_groups": 9,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with mock.patch.object(metrics, "collect_metrics", return_value=[fresh]):
                rendered = metrics.refresh_metrics(["AstrBot"], cache_path=path)
            updated = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(99, updated["projects"][3]["metrics"]["dom"])
        self.assertEqual(1, updated["projects"][0]["metrics"]["dom"])
        self.assertNotIn("distinct_criteria", updated["projects"][3]["metrics"])
        self.assertNotIn("hc_st_groups", updated["projects"][3]["metrics"])
        self.assertEqual(8, rendered[0]["metrics"]["distinct_criteria"])
        self.assertEqual(9, rendered[0]["metrics"]["hc_st_groups"])
        self.assertEqual(
            "fresh-codeql", rendered[0]["provenance"]["static_metrics_source"]
        )

    def test_atomic_writer_persists_complete_validated_cache(self) -> None:
        document = cache_document()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache.json"
            metrics.write_metrics_cache(document["projects"], path)
            loaded = metrics.load_static_metrics_cache(path)
        self.assertEqual(list(metrics.PROJECT_IDS), [row["project"] for row in loaded])

    def test_manifest_rejects_catalog_count_mismatch(self) -> None:
        spec = metrics.get_project("hermes-agent")
        manifest = {
            "project": spec.project_id,
            "revision": spec.analysis_revision,
            "counts": {
                "slice_failures": 0,
                "eligible_catalog_gates": 4,
                "all_candidate_rows": 9,
            },
        }
        with self.assertRaisesRegex(metrics.MetricsError, "count mismatch"):
            metrics.validate_gate_manifest(manifest, spec, 3)


class RenderingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = {
            "project": "hermes-agent",
            "analysis_revision": "abc",
            "metrics": {
                "dom": 1,
                "filt": 2,
                "trans": 3,
                "cap": 4,
                "handlers": 5,
                "sinks": 4,
                "call_chains": 6,
                "distinct_criteria": 7,
                "static_analysis_minutes": 1.5,
                "hc_st_groups": 8,
                "generic_candidates": 9,
            },
            "provenance": {},
        }

    def test_default_project_order_matches_the_paper(self) -> None:
        self.assertEqual(
            (
                "hermes-agent",
                "nanobot",
                "chatgpt-on-wechat",
                "AstrBot",
                "QwenPaw",
                "poco-agent",
                "openclaw",
                "nanoclaw",
                "openclaw-cn",
                "mercury-agent",
                "droidclaw",
                "lettabot",
            ),
            metrics.PROJECT_IDS,
        )

    def test_table_uses_exact_paper_headers(self) -> None:
        second = {
            **self.payload,
            "project": "AstrBot",
            "metrics": {**self.payload["metrics"], "handlers": 7},
        }
        rendered = metrics.render_table([self.payload, second])
        self.assertIn(
            "| Project | Dom. | Filt. | Trans. | Cap. | Handlers | Sinks | Call Chains | Handler Types | Call Chain Oracles | Static Analysis Cost Time (min) | Generic Candidates |",
            rendered,
        )
        self.assertIn(
            "| hermes-agent | 1 | 2 | 3 | 4 | 5 | 4 | 6 | 7 | 8 | 1.5 | 9 |", rendered
        )
        self.assertIn(
            "| AstrBot | 1 | 2 | 3 | 4 | 7 | 4 | 6 | 7 | 8 | 1.5 | 9 |", rendered
        )
        self.assertIn(
            "| **Total** | **2** | **4** | **6** | **8** | **12** | **8** | **12** | -- | -- | **3.0** | **18** |",
            rendered,
        )

    def test_current_generic_candidate_partition_totals_78(self) -> None:
        counts = metrics.load_generic_candidate_counts()
        self.assertEqual(78, sum(counts.values()))
        self.assertEqual(
            {
                "hermes-agent": 16,
                "nanobot": 7,
                "chatgpt-on-wechat": 8,
                "AstrBot": 7,
                "QwenPaw": 3,
                "poco-agent": 0,
                "openclaw": 8,
                "nanoclaw": 4,
                "openclaw-cn": 15,
                "mercury-agent": 6,
                "droidclaw": 1,
                "lettabot": 3,
            },
            counts,
        )

    def test_json_has_normalized_metric_keys(self) -> None:
        rendered = json.dumps({"projects": [self.payload]})
        decoded = json.loads(rendered)
        project = decoded["projects"][0]
        self.assertEqual(4, project["metrics"]["cap"])
        self.assertLessEqual(project["metrics"]["cap"], project["metrics"]["sinks"])
        self.assertEqual(7, project["metrics"]["distinct_criteria"])
        self.assertEqual(1.5, project["metrics"]["static_analysis_minutes"])
        self.assertEqual(8, project["metrics"]["hc_st_groups"])

    def test_handler_criterion_summary_is_rendered_for_result_markdown(self) -> None:
        summary = metrics.HandlerCriterionSummary(
            total_criteria=108,
            singleton_criteria=43,
            total_handlers=301,
            singleton_handlers=43,
        )
        rendered = metrics.render_handler_criterion_summary(summary)
        self.assertIn("43 are singleton criteria (39.8%)", rendered)
        self.assertIn("43 of the 301 resolved handlers (14.3%)", rendered)

    def test_generated_section_replacement_preserves_manual_content(self) -> None:
        document = (
            "# Manual heading\n\n"
            + metrics.GENERATED_SECTION_START
            + "\n\nold generated content\n\n"
            + metrics.GENERATED_SECTION_END
            + "\n\nManual analysis that must survive.\n"
        )
        updated = metrics.replace_generated_section(document, "new generated content")
        self.assertTrue(updated.startswith("# Manual heading\n\n"))
        self.assertIn("new generated content", updated)
        self.assertNotIn("old generated content", updated)
        self.assertTrue(updated.endswith("Manual analysis that must survive.\n"))

    def test_generated_section_replacement_requires_unique_markers(self) -> None:
        with self.assertRaisesRegex(metrics.MetricsError, "start marker"):
            metrics.replace_generated_section("manual only", "generated")
        duplicate = (
            metrics.GENERATED_SECTION_START
            + metrics.GENERATED_SECTION_START
            + metrics.GENERATED_SECTION_END
        )
        with self.assertRaisesRegex(metrics.MetricsError, "start marker"):
            metrics.replace_generated_section(duplicate, "generated")

    def test_result_writer_updates_only_marked_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.md"
            path.write_text(
                "manual before\n"
                + metrics.GENERATED_SECTION_START
                + "\nold\n"
                + metrics.GENERATED_SECTION_END
                + "\nmanual after\n",
                encoding="utf-8",
            )
            path.chmod(0o640)
            metrics.write_result_document("new", path)
            updated = path.read_text(encoding="utf-8")
            updated_mode = path.stat().st_mode & 0o7777
        self.assertEqual(
            "manual before\n"
            + metrics.GENERATED_SECTION_START
            + "\n\nnew\n\n"
            + metrics.GENERATED_SECTION_END
            + "\nmanual after\n",
            updated,
        )
        self.assertEqual(0o640, updated_mode)

    def test_selected_markdown_prints_without_replacing_full_result(self) -> None:
        stdout = io.StringIO()
        with mock.patch.object(
            metrics, "load_cached_metrics", return_value=[self.payload]
        ), mock.patch.object(
            metrics,
            "load_handler_criterion_summary",
            return_value=metrics.HandlerCriterionSummary(3, 1, 4, 1),
        ), mock.patch.object(
            metrics,
            "load_hc_st_group_counts",
            return_value=({}, metrics.HandlerSinkGroupSummary(2, 3)),
        ), mock.patch.object(metrics, "write_result_document") as write:
            with contextlib.redirect_stdout(stdout):
                status = metrics.main(["--project", "hermes-agent"])
        self.assertEqual(0, status)
        self.assertIn("| hermes-agent |", stdout.getvalue())
        write.assert_not_called()

    def test_default_markdown_updates_result_without_stdout(self) -> None:
        stdout = io.StringIO()
        with mock.patch.object(
            metrics, "load_cached_metrics", return_value=[self.payload]
        ), mock.patch.object(
            metrics,
            "load_handler_criterion_summary",
            return_value=metrics.HandlerCriterionSummary(3, 1, 4, 1),
        ), mock.patch.object(
            metrics,
            "load_hc_st_group_counts",
            return_value=({}, metrics.HandlerSinkGroupSummary(2, 3)),
        ), mock.patch.object(metrics, "write_result_document") as write:
            with contextlib.redirect_stdout(stdout):
                status = metrics.main([])
        self.assertEqual(0, status)
        self.assertEqual("", stdout.getvalue())
        write.assert_called_once()
        self.assertIn("| **Total**", write.call_args.args[0])
        self.assertIn("| -- | -- | **1.5** |", write.call_args.args[0])

    def test_stdout_previews_markdown_without_writing_result(self) -> None:
        stdout = io.StringIO()
        with mock.patch.object(
            metrics, "load_cached_metrics", return_value=[self.payload]
        ), mock.patch.object(
            metrics,
            "load_handler_criterion_summary",
            return_value=metrics.HandlerCriterionSummary(3, 1, 4, 1),
        ), mock.patch.object(
            metrics,
            "load_hc_st_group_counts",
            return_value=({}, metrics.HandlerSinkGroupSummary(2, 3)),
        ), mock.patch.object(metrics, "write_result_document") as write:
            with contextlib.redirect_stdout(stdout):
                status = metrics.main(["--stdout"])
        self.assertEqual(0, status)
        self.assertIn("| **Total**", stdout.getvalue())
        write.assert_not_called()

    def test_main_emits_json_for_selected_projects_without_duplicates(self) -> None:
        stdout = io.StringIO()
        selected_payload = {**self.payload, "project": "AstrBot"}
        with mock.patch.object(
            metrics, "load_cached_metrics", return_value=[selected_payload]
        ) as load_cache, mock.patch.object(
            metrics,
            "load_handler_criterion_summary",
            return_value=metrics.HandlerCriterionSummary(3, 1, 4, 1),
        ) as summary, mock.patch.object(
            metrics,
            "load_hc_st_group_counts",
            return_value=({}, metrics.HandlerSinkGroupSummary(2, 3)),
        ) as group_summary, mock.patch.object(metrics, "collect_metrics") as collect:
            with contextlib.redirect_stdout(stdout):
                status = metrics.main(
                    [
                        "--project",
                        "AstrBot",
                        "--project",
                        "AstrBot",
                        "--format",
                        "json",
                    ]
                )
        self.assertEqual(0, status)
        load_cache.assert_called_once_with(["AstrBot"])
        summary.assert_called_once_with(expected_projects=["AstrBot"])
        group_summary.assert_called_once_with(expected_projects=["AstrBot"])
        collect.assert_not_called()
        decoded = json.loads(stdout.getvalue())
        self.assertEqual("AstrBot", decoded["projects"][0]["project"])
        self.assertEqual(6, decoded["projects"][0]["metrics"]["call_chains"])
        self.assertEqual(
            25.0,
            decoded["handler_criterion_summary"][
                "singleton_handler_percentage"
            ],
        )
        self.assertEqual(2, decoded["handler_sink_group_summary"]["total_groups"])

    def test_refresh_option_invokes_fresh_collection_path(self) -> None:
        stdout = io.StringIO()
        with mock.patch.object(
            metrics, "refresh_metrics", return_value=[self.payload]
        ) as refresh, mock.patch.object(
            metrics,
            "load_handler_criterion_summary",
            return_value=metrics.HandlerCriterionSummary(3, 1, 4, 1),
        ) as summary, mock.patch.object(
            metrics,
            "load_hc_st_group_counts",
            return_value=({}, metrics.HandlerSinkGroupSummary(2, 3)),
        ) as group_summary, mock.patch.object(
            metrics, "load_cached_metrics"
        ) as load_cache, mock.patch.object(metrics, "write_result_document") as write:
            with contextlib.redirect_stdout(stdout):
                status = metrics.main(["--refresh"])
        self.assertEqual(0, status)
        refresh.assert_called_once_with(list(metrics.PROJECT_IDS))
        summary.assert_called_once_with(expected_projects=list(metrics.PROJECT_IDS))
        group_summary.assert_called_once_with(
            expected_projects=list(metrics.PROJECT_IDS)
        )
        load_cache.assert_not_called()
        write.assert_called_once()

    def test_main_reports_refresh_failure_without_partial_stdout(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            metrics, "refresh_metrics", side_effect=RuntimeError("query failed")
        ):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = metrics.main(["--refresh"])
        self.assertEqual(1, status)
        self.assertEqual("", stdout.getvalue())
        self.assertIn("query failed", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

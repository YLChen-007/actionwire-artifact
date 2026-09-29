from __future__ import annotations

import json
import os
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from src.coverage_comparison.contracts import CoverageComparisonError
from src.coverage_comparison.ground_truth import (
    GROUND_TRUTH_LEDGER,
    _gt_files,
    _lettabot_chains,
    _normalize_match_identity,
    _publish_ground_truth_artifacts,
    _parse_match_response,
    _read_ground_truth_ledger,
    _static_oracle_chain_map,
    _validate_ground_truth_ledger,
    bind_ground_truth,
    deduplicate_ground_truth,
    discover_ground_truth,
)
from src.coverage_comparison.prompts import GROUND_TRUTH_MATCH_SYSTEM
from src.projects import ProjectSpec, get_project, list_projects


def _spec(root: Path, *, project: str = "fixture") -> ProjectSpec:
    return ProjectSpec(
        project_id=project,
        source_root=root / "source",
        analysis_revision="revision",
        codeql_database=root / "database",
        design_root=root / "design",
        output_root=root / "output",
        ground_truth_root=root / "design/groundtruth",
        codeql_adapter="fixture",
        source_language="python",
        codeql_language="python",
        query_pack=root / "query-pack",
    )


def _report(name: str, *, gate_type: str = "missing-check") -> dict:
    return {
        "report_name": name,
        "llm_to_tool_pattern_match": "match",
        "d5_gate_type": gate_type,
        "d5_tool_handler_entry": [{"name": "tool"}],
        "d5_sink_points": [
            {
                "name": "sink",
                "location": "source.py:1",
                "problematic_parameter": "value",
            }
        ],
    }


class GroundTruthDiscoveryTests(unittest.TestCase):
    def test_nonrecursive_symlink_layout_avoids_nested_loops(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "target"
            target.mkdir()
            (target / "one.json").write_text(
                json.dumps(_report("one")), encoding="utf-8"
            )
            nested = target / "nested"
            nested.mkdir()
            (nested / "ignored.json").write_text(
                json.dumps(_report("ignored")), encoding="utf-8"
            )
            (nested / "loop").symlink_to(target, target_is_directory=True)
            design = root / "design"
            design.mkdir()
            (design / "groundtruth").symlink_to(target, target_is_directory=True)

            files = _gt_files(_spec(root).resolved())

            self.assertEqual(["one.json"], [path.name for path in files])

    def test_duplicate_sources_preserve_path_digest_pairing(self) -> None:
        rows = [
            {
                "project": "fixture",
                "revision": "revision",
                "report_name": "same",
                "path": "z-copy.json",
                "sha256": "z-digest",
                "raw": _report("same"),
            },
            {
                "project": "fixture",
                "revision": "revision",
                "report_name": "same",
                "path": "a-reviewed.json",
                "sha256": "a-digest",
                "raw": _report("same"),
            },
        ]

        [merged] = deduplicate_ground_truth(rows)

        self.assertEqual(["a-reviewed.json", "z-copy.json"], merged["source_files"])
        self.assertEqual(["a-digest", "z-digest"], merged["source_sha256"])
        self.assertEqual(
            [rows[1]["raw"], rows[0]["raw"]],
            merged["variant_raws"],
        )

    def test_conflicting_duplicate_boundaries_fail(self) -> None:
        left = _report("same")
        right = _report("same", gate_type="wrong-check")
        rows = [
            {
                "project": "fixture",
                "revision": "revision",
                "report_name": "same",
                "path": "a.json",
                "sha256": "a",
                "raw": left,
            },
            {
                "project": "fixture",
                "revision": "revision",
                "report_name": "same",
                "path": "b.json",
                "sha256": "b",
                "raw": right,
            },
        ]
        with self.assertRaisesRegex(CoverageComparisonError, "conflicting duplicate"):
            deduplicate_ground_truth(rows)

    def test_stale_static_oracle_chain_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            oracle = root / "design/fixture/inventory/fixture-static-oracle.json"
            trace = root / "design/fixture/call-chain/debug/oracle-matcher-trace.json"
            oracle.parent.mkdir(parents=True)
            trace.parent.mkdir(parents=True)
            oracle.write_text(
                json.dumps(
                    {
                        "eligible_sink_records": [
                            {"record_id": "record", "report_path": "new-vuls/one.json"}
                        ]
                    }
                ),
                encoding="utf-8",
            )
            trace.write_text(
                json.dumps(
                    [{"record_id": "record", "selected_chain_ids": ["C-stale"]}]
                ),
                encoding="utf-8",
            )
            with patch.dict(
                "src.coverage_comparison.ground_truth._STATIC_ORACLES",
                {"fixture": oracle.relative_to(root)},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    CoverageComparisonError, "stale matcher chain"
                ):
                    _static_oracle_chain_map(root, "fixture", [])

    def test_match_prompt_rejects_same_chain_proximity(self) -> None:
        self.assertIn(
            "Merely sharing a handler, sink, capability family",
            GROUND_TRUTH_MATCH_SYSTEM,
        )
        self.assertIn("semantic equivalence", GROUND_TRUTH_MATCH_SYSTEM.lower())

    def test_match_parser_accepts_first_complete_validatable_object(self) -> None:
        first = {
            "report_id": "GT-" + "1" * 16,
            "candidate_id": "CAND-" + "2" * 16,
            "verdict": "no-match",
        }
        self.assertEqual(
            first, _parse_match_response(json.dumps(first) + json.dumps(first))
        )

    def test_match_identity_normalization_preserves_verdict(self) -> None:
        value = {
            "report_id": "GT-wrong",
            "candidate_id": "CAND-wrong",
            "verdict": "match",
            "same_controlled_security_invariant": True,
            "reason": "same invariant",
        }
        normalized, changes = _normalize_match_identity(
            value,
            report_id="GT-" + "1" * 16,
            candidate_id="CAND-" + "2" * 16,
        )
        self.assertEqual("match", normalized["verdict"])
        self.assertTrue(normalized["same_controlled_security_invariant"])
        self.assertEqual("report_id,candidate_id", changes)

    def test_ledger_requires_exact_project_filename_set(self) -> None:
        discovered = [
            {
                "project": "fixture",
                "path": "design/fixture/groundtruth/new-vuls/one.json",
            }
        ]
        _validate_ground_truth_ledger(discovered, {("fixture", "one.json"): {"row": 2}})
        with self.assertRaisesRegex(
            CoverageComparisonError, "ledger/directory mismatch"
        ):
            _validate_ground_truth_ledger(
                discovered, {("fixture", "two.json"): {"row": 2}}
            )

    def test_lettabot_binding_uses_exact_handler_root_and_controlled_argument(
        self,
    ) -> None:
        raw = {
            "d5_tool_handler_entry": [
                {"name": "Task", "location": "vendor/Task.ts:410"}
            ]
        }
        rows = [
            {
                "chain_id": "C-match",
                "tool_name": "Task",
                "handler_file": "vendor/Task.ts",
                "handler_line": "410",
                "sink_argument": "prompt;subagent_type",
            },
            {
                "chain_id": "C-wrong-parameter",
                "tool_name": "Task",
                "handler_file": "vendor/Task.ts",
                "handler_line": "410",
                "sink_argument": "prompt",
            },
            {
                "chain_id": "C-wrong-root",
                "tool_name": "Task",
                "handler_file": "vendor/Other.ts",
                "handler_line": "410",
                "sink_argument": "prompt;subagent_type",
            },
        ]
        self.assertEqual({"C-match"}, _lettabot_chains(raw, rows))

    def test_ground_truth_publication_replaces_stale_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            coverage = root / "coverage"
            staging = root / "staging"
            for base, value, subject in (
                (coverage, "old", "old-subject"),
                (staging, "new", "new-subject"),
            ):
                base.mkdir()
                for name in (
                    "ground-truth-coverage.jsonl",
                    "ground-truth-coverage.md",
                    "ground-truth-manifest.json",
                ):
                    (base / name).write_text(value, encoding="utf-8")
                sidecar = base / "repository/ground-truth" / subject / "chat.json"
                sidecar.parent.mkdir(parents=True)
                sidecar.write_text(value, encoding="utf-8")

            _publish_ground_truth_artifacts(staging, coverage)

            self.assertFalse(
                (coverage / "repository/ground-truth/old-subject").exists()
            )
            self.assertEqual(
                "new",
                (coverage / "repository/ground-truth/new-subject/chat.json").read_text(
                    encoding="utf-8"
                ),
            )

    def test_ground_truth_publication_failure_restores_prior_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            coverage = root / "coverage"
            staging = root / "staging"
            for base, value, subject in (
                (coverage, "old", "old-subject"),
                (staging, "new", "new-subject"),
            ):
                base.mkdir()
                for name in (
                    "ground-truth-coverage.jsonl",
                    "ground-truth-coverage.md",
                    "ground-truth-manifest.json",
                ):
                    (base / name).write_text(value, encoding="utf-8")
                sidecar = base / "repository/ground-truth" / subject / "chat.json"
                sidecar.parent.mkdir(parents=True)
                sidecar.write_text(value, encoding="utf-8")
            real_replace = os.replace
            calls = 0

            def fail_once(source: Path, destination: Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 6:
                    raise OSError("publication failure")
                real_replace(source, destination)

            with (
                patch(
                    "src.coverage_comparison.ground_truth.os.replace",
                    side_effect=fail_once,
                ),
                self.assertRaisesRegex(OSError, "publication failure"),
            ):
                _publish_ground_truth_artifacts(staging, coverage)

            self.assertEqual(
                "old",
                (coverage / "ground-truth-coverage.md").read_text(encoding="utf-8"),
            )
            self.assertTrue(
                (coverage / "repository/ground-truth/old-subject/chat.json").is_file()
            )
            self.assertFalse(
                (coverage / "repository/ground-truth/new-subject").exists()
            )


class CurrentCorpusAcceptanceTests(unittest.TestCase):
    def test_current_corpus_and_revision_bound_denominator(self) -> None:
        specs = [get_project(project_id) for project_id in list_projects()]
        discovered, _ = discover_ground_truth(specs)
        repo_root = Path(__file__).resolve().parents[3]
        ledger, _ = _read_ground_truth_ledger(repo_root, GROUND_TRUTH_LEDGER)
        _validate_ground_truth_ledger(discovered, ledger)
        deduplicated = deduplicate_ground_truth(discovered)
        reports, _ = bind_ground_truth(specs, deduplicated)
        status_counts = Counter(report.boundary_status for report in reports)

        self.assertEqual(46, len(ledger))
        self.assertEqual(46, len(discovered))
        self.assertEqual(46, len(deduplicated))
        self.assertEqual(43, status_counts.get("eligible", 0))
        self.assertEqual(0, status_counts.get("fixed-at-analysis-revision", 0))
        self.assertEqual(1, status_counts.get("not-present-at-analysis-revision", 0))
        self.assertEqual(2, status_counts.get("out-of-model", 0))
        self.assertEqual(0, status_counts.get("no-current-structural-chain", 0))
        self.assertTrue(
            all(
                report.chain_ids
                for report in reports
                if report.boundary_status == "eligible"
            )
        )
        hermes_code_execution = next(
            report
            for report in reports
            if report.project == "hermes-agent"
            and report.report_name == "CVE-Project-Code-Execution-Mode-Bypass"
        )
        self.assertEqual(
            ("C-10420d9585cc",),
            hermes_code_execution.chain_ids,
        )
        for report_name in (
            "Remote-Code-Execution-Pattern-Bypass",
            "Batch-Runner-Variant",
        ):
            report = next(
                row
                for row in reports
                if row.project == "hermes-agent" and report_name in row.report_name
            )
            self.assertEqual(("C-14d19d5cfffa",), report.chain_ids)
        lettabot = next(
            report
            for report in reports
            if report.project == "lettabot"
            and report.report_name == "type-p-task-subagent-permission-bypass-variant"
        )
        self.assertEqual(
            ("C-a7c7342f7e5d", "C-c9803bb10895"),
            lettabot.chain_ids,
        )

    def test_archived_corrected_v2_reassess_regressions(self) -> None:
        root = Path(
            "output/cross-project/archive/coverage-v6/"
            "coverage-comparison-corrected-v2"
        )
        dispositions = {
            row["report_id"]: row
            for row in (
                json.loads(line)
                for line in (root / "correction-dispositions.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
                if line.strip()
            )
        }
        expected = {
            "GT-b5784fc039d3c2b6": "wrong-check",
            "GT-972149e20567600a": "missing-check",
            "GT-926a392790b47c19": "wrong-check",
        }
        for report_id, decision in expected.items():
            with self.subTest(report_id=report_id):
                row = dispositions[report_id]
                self.assertEqual("corrected-match", row["disposition"])
                self.assertTrue(
                    any(
                        value.endswith(f":{decision}")
                        for value in row["final_decisions"]
                    )
                )

        self.assertEqual(20, len(dispositions))
        self.assertEqual(
            {"corrected-match": 14, "evidence-insufficient": 6},
            dict(Counter(row["disposition"] for row in dispositions.values())),
        )
        self.assertEqual(
            "corrected-match", dispositions["GT-6ac3205f7f0611f1"]["disposition"]
        )
        self.assertEqual(
            "evidence-insufficient",
            dispositions["GT-08747d323940c2bf"]["disposition"],
        )
        self.assertEqual(
            "corrected-match", dispositions["GT-e718ba1614c17fc9"]["disposition"]
        )
        for report_id in ("GT-228613a4d41e4934", "GT-8760b9fa6b53a205"):
            self.assertEqual(
                "evidence-insufficient", dispositions[report_id]["disposition"]
            )
            self.assertTrue(
                any(
                    value.endswith(":unknown")
                    for value in dispositions[report_id]["final_decisions"]
                )
            )


if __name__ == "__main__":
    unittest.main()

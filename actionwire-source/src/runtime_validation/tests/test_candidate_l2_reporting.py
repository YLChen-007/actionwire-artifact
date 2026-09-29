from __future__ import annotations

import argparse
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_CANDIDATES = REPO_ROOT / "output/cross-project/coverage-comparison/candidates.jsonl"
SOURCE_CAMPAIGN = REPO_ROOT / "output/cross-project/runtime-auto-l2"


def _renderer_module():
    path = REPO_ROOT / "scripts/render_candidate_l2_gt_analysis.py"
    spec = importlib.util.spec_from_file_location("candidate_l2_renderer_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _batch_module():
    path = REPO_ROOT / "scripts/run_candidate_l2_campaign.py"
    spec = importlib.util.spec_from_file_location("candidate_l2_batch_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


class CandidateL2ReportingTest(unittest.TestCase):
    def test_batch_child_command_uses_the_supplied_candidate_file(self) -> None:
        module = _batch_module()
        candidates = Path("/tmp/candidate-l2-test/candidates.jsonl")
        argv = module.command(
            "droidclaw",
            "CAND-02629879756e5c81",
            candidates,
            Path("/tmp/candidate-l2-test/out"),
        )
        position = argv.index("--candidates")
        self.assertEqual(str(candidates), argv[position + 1])

    def test_renderer_accepts_progress_beyond_the_original_five(self) -> None:
        renderer = _renderer_module()
        candidate_rows = _rows(SOURCE_CANDIDATES)
        ledger = _rows(SOURCE_CAMPAIGN / "batch-ledger.jsonl")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = renderer.render(
                argparse.Namespace(
                    candidates=SOURCE_CANDIDATES,
                    campaign=SOURCE_CAMPAIGN,
                    out_dir=root / "baseline",
                )
            )
            campaign = root / "campaign"
            for candidate in candidate_rows:
                candidate_id = candidate["candidate_id"]
                source = (
                    SOURCE_CAMPAIGN
                    / candidate_id
                    / "candidates"
                    / candidate_id
                    / "candidate-result.json"
                )
                result = json.loads(source.read_text(encoding="utf-8"))
                if candidate_id == "CAND-925c9d1319c3ccbd":
                    result["disposition"] = "runtime-confirmed"
                destination = campaign / candidate_id / "candidates" / candidate_id
                destination.mkdir(parents=True)
                (destination / "candidate-result.json").write_text(
                    json.dumps(result), encoding="utf-8"
                )
            for row in ledger:
                if row["candidate_id"] == "CAND-925c9d1319c3ccbd":
                    row["disposition"] = "runtime-confirmed"
            (campaign / "batch-ledger.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in ledger), encoding="utf-8"
            )
            output = root / "analysis"
            manifest = renderer.render(
                argparse.Namespace(
                    candidates=SOURCE_CANDIDATES,
                    campaign=campaign,
                    out_dir=output,
                )
            )
            self.assertEqual(
                baseline["runtime_confirmed_report_count"] + 1,
                manifest["runtime_confirmed_report_count"],
            )
            self.assertEqual(5, manifest["candidate_missing_report_count"])
            self.assertEqual(3, manifest["non_applicable_report_count"])

    def test_renderer_still_rejects_a_noncanonical_candidate_partition(self) -> None:
        renderer = _renderer_module()
        with tempfile.TemporaryDirectory() as directory:
            candidates = Path(directory) / "candidates.jsonl"
            candidates.write_text(
                "\n".join(
                    json.dumps(row) for row in _rows(SOURCE_CANDIDATES)[:-1]
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "78-row/78-ID"):
                renderer.render(
                    argparse.Namespace(
                        candidates=candidates,
                        campaign=SOURCE_CAMPAIGN,
                        out_dir=Path(directory) / "analysis",
                    )
                )

    def test_renderer_publishes_per_project_eligible_outcomes(self) -> None:
        renderer = _renderer_module()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "analysis"
            manifest = renderer.render(
                argparse.Namespace(
                    candidates=SOURCE_CANDIDATES,
                    campaign=SOURCE_CAMPAIGN,
                    out_dir=output,
                )
            )
            summary = (output / "summary.md").read_text(encoding="utf-8")
            section = summary.split("## Per-project eligible report outcomes", 1)[1]
            section = section.split("## Runtime-confirmed ground truths", 1)[0]
            rows = [
                [cell.strip() for cell in line.split("|")[1:-1]]
                for line in section.splitlines()
                if line.startswith("|")
            ]
            self.assertEqual(
                ["Project", "Runtime-confirmed", "Not runtime-confirmed", "Eligible total"],
                rows[0],
            )
            data = {row[0]: tuple(row[1:]) for row in rows[2:]}
            self.assertEqual(11, len(data))
            self.assertEqual(("5", "0", "5"), data["mercury-agent"])
            self.assertEqual(("1", "0", "1"), data["droidclaw"])
            self.assertEqual(("1", "0", "1"), data["lettabot"])
            self.assertEqual(("0", "9", "9"), data["hermes-agent"])
            self.assertEqual(
                manifest["runtime_confirmed_report_count"],
                sum(int(row[0]) for row in data.values()),
            )
            self.assertEqual(
                43 - manifest["runtime_confirmed_report_count"],
                sum(int(row[1]) for row in data.values()),
            )
            self.assertEqual(43, sum(int(row[2]) for row in data.values()))

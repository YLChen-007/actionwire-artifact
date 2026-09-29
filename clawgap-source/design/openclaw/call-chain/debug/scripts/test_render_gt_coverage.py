from __future__ import annotations

import csv
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("render_gt_coverage.py")
SPEC = importlib.util.spec_from_file_location("openclaw_render_gt_coverage", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


REVISION = "d842b28a1517f95aae2a5bcd97f2f726e42b93d8"


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


class CoverageFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.gt = root / "groundtruth"
        self.pipeline = root / "pipeline"
        self.out = root / "out"
        report = self.gt / "new-vuls/example.json"
        _write_json(report, {"d5_sink_points": [{"name": "fetch"}]})
        self.lock = MODULE._current_lock(self.gt)
        self.lock_path = root / "lock.json"
        self.inventory_path = root / "inventory.json"
        self.oracle_path = root / "oracle.json"
        _write_json(self.lock_path, self.lock)
        _write_json(
            self.inventory_path,
            {
                "counts": {
                    "reports": MODULE.EXPECTED_REPORTS,
                    "sink_references": MODULE.EXPECTED_SINK_REFERENCES,
                },
                "records": [
                    {"record_id": "eligible", "eligible": True, "anchor_status": "rebased"},
                    {"record_id": "later", "eligible": False, "anchor_status": "not-present"},
                    {"record_id": "extension", "eligible": False, "anchor_status": "out-of-model"},
                ],
            },
        )
        self.eligible = {
            "record_id": "eligible",
            "report_path": "new-vuls/example.json",
            "capability_class": "network-egress",
            "sink_file": "src/agents/tools/web-fetch.ts",
            "sink_line": 10,
            "gate_expectation": "expected_missing",
            "tool_names": ["web_fetch"],
            "existing_gate_names": [],
            "expected_missing_gate_names": ["requiredUrlPolicy"],
        }
        self.write_oracle([self.eligible])
        self.write_pipeline()

    def write_oracle(self, records: list[dict[str, object]]) -> None:
        _write_json(
            self.oracle_path,
            {
                "revision": REVISION,
                "corpus_sha256": self.lock["corpus_sha256"],
                "eligible_records": records,
            },
        )

    def write_pipeline(self, *, duplicate_constraint: bool = False) -> None:
        call_root = self.pipeline / "static/call-chains"
        chain = {
            "chain_id": "C-1",
            "sink_id": "S-1",
            "tool_name": "web_fetch",
            "sink_file": "src/agents/tools/web-fetch.ts",
            "sink_line": "10",
        }
        constraint = {"sink_id": "S-1", "capability_class": "network-egress"}
        _write_csv(
            call_root / "handler-sink-chains.csv",
            list(chain),
            [chain],
        )
        _write_csv(
            call_root / "sink-constraints.csv",
            list(constraint),
            [constraint, dict(constraint)] if duplicate_constraint else [constraint],
        )
        _write_csv(
            call_root / "chain-gates.csv",
            ["chain_id", "gate_name"],
            [{"chain_id": "C-1", "gate_name": "normalizeUrl"}],
        )
        _write_csv(
            self.pipeline / "gate-semantics/gate-index.csv",
            ["gate_name"],
            [{"gate_name": "normalizeUrl"}],
        )
        _write_json(
            self.pipeline / "static/gates/manifest.json",
            {"counts": {"slice_failures": 0}},
        )

    def render(self) -> dict[str, object]:
        return MODULE.render(
            oracle_path=self.oracle_path,
            lock_path=self.lock_path,
            inventory_path=self.inventory_path,
            gt_root=self.gt,
            pipeline_output=self.pipeline,
            out_dir=self.out,
            command="python design/openclaw/call-chain/debug/scripts/render_gt_coverage.py",
        )


class RenderGtCoverageTest(unittest.TestCase):
    def test_hash_drift_requires_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = CoverageFixture(Path(temp))
            report = fixture.gt / "new-vuls/example.json"
            _write_json(report, {"d5_sink_points": [{"name": "fetch"}, {"name": "spawn"}]})
            with self.assertRaisesRegex(ValueError, "ground-truth hash drift"):
                fixture.render()

    def test_expected_missing_is_not_matched_by_unrelated_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            summary = CoverageFixture(Path(temp)).render()
            self.assertEqual({"PASS": 1}, summary["statuses"])

    def test_duplicate_constraint_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = CoverageFixture(Path(temp))
            fixture.write_pipeline(duplicate_constraint=True)
            with self.assertRaisesRegex(ValueError, "constraint cardinality failure: S-1"):
                fixture.render()

    def test_not_present_and_out_of_model_rows_are_not_detector_misses(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fixture = CoverageFixture(Path(temp))
            summary = fixture.render()
            self.assertEqual(1, summary["eligible_records"])
            coverage = json.loads((fixture.out / "gt-coverage.json").read_text(encoding="utf-8"))
            self.assertEqual({"PASS": 1}, coverage["statuses"])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Checked-in QwenPaw GT coverage regression."""

from __future__ import annotations

import csv
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import render_gt_coverage


REPO_ROOT = Path(__file__).resolve().parents[5]


class QwenPawGTCoverageTest(unittest.TestCase):
    def test_checked_in_static_output_satisfies_pinned_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(io.StringIO()):
            out_dir = Path(directory)
            result = render_gt_coverage.main(
                [
                    "--pipeline-output",
                    str(REPO_ROOT / "output/QwenPaw"),
                    "--out-dir",
                    str(out_dir),
                ]
            )
            with (out_dir / "gt-coverage.csv").open(
                newline="", encoding="utf-8"
            ) as handle:
                failures = [
                    row for row in csv.DictReader(handle) if row["status"] == "fail"
                ]
            report = (out_dir / "gt-coverage.md").read_text(encoding="utf-8")
        self.assertEqual(0, result)
        self.assertEqual([], failures)
        self.assertIn(
            "design/QwenPaw/qwenpaw-v1.1.10-acceptance.json",
            report.splitlines()[2],
        )


if __name__ == "__main__":
    unittest.main()

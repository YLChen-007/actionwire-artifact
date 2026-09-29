from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.coverage_comparison.contracts import CoverageComparisonError
from src.coverage_comparison.v15 import publish_v15


def manifest(root: Path, mode: str) -> None:
    root.mkdir()
    (root / "manifest.json").write_text(
        json.dumps({"analysis_mode": mode}), encoding="utf-8"
    )
    (root / mode).write_text(mode, encoding="utf-8")


class V15PublicationTests(unittest.TestCase):
    def test_publication_keeps_rollback_archive_and_removes_journal(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            active, stage, archive = root / "active", root / "stage", root / "archive"
            manifest(active, "old")
            manifest(stage, "new")
            with patch(
                "src.coverage_comparison.v15.validate_v15_artifacts",
                return_value={},
            ):
                publish_v15(active_root=active, stage_root=stage, archive_root=archive)
            self.assertTrue((active / "new").is_file())
            self.assertTrue((archive / "old").is_file())
            self.assertFalse((root / ".coverage-v15-publication-journal.json").exists())

    def test_validation_failure_restores_active_and_staging(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            active, stage, archive = root / "active", root / "stage", root / "archive"
            manifest(active, "old")
            manifest(stage, "new")
            with (
                patch(
                    "src.coverage_comparison.v15.validate_v15_artifacts",
                    side_effect=CoverageComparisonError("invalid staging"),
                ),
                self.assertRaisesRegex(CoverageComparisonError, "invalid staging"),
            ):
                publish_v15(active_root=active, stage_root=stage, archive_root=archive)
            self.assertTrue((active / "old").is_file())
            self.assertTrue((stage / "new").is_file())
            self.assertFalse(archive.exists())
            self.assertFalse((root / ".coverage-v15-publication-journal.json").exists())


if __name__ == "__main__":
    unittest.main()

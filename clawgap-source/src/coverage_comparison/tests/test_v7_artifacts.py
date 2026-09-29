from __future__ import annotations

import unittest
from pathlib import Path

from src.coverage_comparison.v15 import validate_v15_artifacts


ROOT = Path(__file__).resolve().parents[3]


def artifact_root() -> Path:
    canonical = ROOT / "output/cross-project/coverage-comparison"
    staging = ROOT / "output/cross-project/coverage-comparison-v15-staging"
    for candidate in (staging, canonical):
        if not (candidate / "manifest.json").is_file():
            continue
        import json

        if json.loads((candidate / "manifest.json").read_text()).get(
            "analysis_mode"
        ) == "canonical-trained-detector/v15":
            return candidate
    return canonical


class CanonicalV15ArtifactTests(unittest.TestCase):
    def test_current_v15_artifact_is_complete(self) -> None:
        result = validate_v15_artifacts(artifact_root())
        self.assertEqual(78, result["generic_candidates"])
        self.assertEqual(82, result["training_candidates"])
        self.assertEqual(74, result["clusters"])
        self.assertEqual((38, 43), (result["generic_training_found"], result["training_found"]))

    def test_manifest_is_training_labeled(self) -> None:
        result = validate_v15_artifacts(artifact_root())
        self.assertEqual(
            "43/43 training-regression overlay; generic held-out input is separate",
            result["manifest"]["training_claim"],
        )

    def test_corrected_history_is_ledger_only(self) -> None:
        import json

        root = artifact_root()
        requirements = [
            json.loads(line)
            for line in (root / "canonical-requirements.jsonl").read_text().splitlines()
            if line.strip()
        ]
        active_sources = {
            (row["group_id"], source["legacy_requirement_id"])
            for row in requirements
            for source in row["provenance"]["sources"]
        }
        v7_root = ROOT / "output/cross-project/archive/coverage-comparison-v7"
        if not v7_root.is_dir():
            v7_root = ROOT / "output/cross-project/coverage-comparison"
        v7_sources = {
            (row["group_id"], source["legacy_requirement_id"])
            for line in (v7_root / "canonical-requirements.jsonl").read_text().splitlines()
            if line.strip()
            for row in [json.loads(line)]
            for source in row["provenance"]["sources"]
        }
        corrected = ROOT / "output/cross-project/group-oracles-corrected-v2/oracles.jsonl"
        corrected_ids = set()
        for line in corrected.read_text().splitlines():
            if not line.strip():
                continue
            oracle = json.loads(line)
            corrected_ids.update(
                (oracle["group_id"], row["requirement_id"])
                for row in oracle["requirements"]
            )
        base = ROOT / "output/cross-project/group-oracles/oracles.jsonl"
        base_ids = set()
        for line in base.read_text().splitlines():
            if not line.strip():
                continue
            oracle = json.loads(line)
            base_ids.update(
                (oracle["group_id"], row["requirement_id"])
                for row in oracle["requirements"]
            )
        self.assertFalse(((corrected_ids - base_ids) & active_sources) - v7_sources)


if __name__ == "__main__":
    unittest.main()

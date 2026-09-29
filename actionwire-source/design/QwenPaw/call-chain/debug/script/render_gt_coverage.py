#!/usr/bin/env python3
"""Render QwenPaw revision-pinned GT acceptance."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT))

from src.pipeline.static_acceptance import main_for_project  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    return main_for_project(
        title="QwenPaw v1.1.10",
        generation_script="design/QwenPaw/call-chain/debug/script/render_gt_coverage.py",
        default_oracle=ROOT / "design/QwenPaw/qwenpaw-v1.1.10-acceptance.json",
        default_ground_truth=ROOT / "design/QwenPaw/groundtruth",
        default_source_root=ROOT / "benchmark/python/QwenPaw",
        default_pipeline_output=ROOT / "output/QwenPaw",
        default_out_dir=ROOT / "design/QwenPaw/call-chain/debug",
        argv=argv,
    )


if __name__ == "__main__":
    raise SystemExit(main())

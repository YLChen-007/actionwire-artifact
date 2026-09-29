#!/usr/bin/env python3
"""Render nanobot revision-pinned GT acceptance."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT))

from src.pipeline.static_acceptance import main_for_project  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    return main_for_project(
        title="nanobot v0.1.4.post5",
        generation_script="design/nanobot/call-chain/debug/script/render_gt_coverage.py",
        default_oracle=ROOT / "design/nanobot/nanobot-v0.1.4.post5-acceptance.json",
        default_ground_truth=ROOT / "design/nanobot/groundtruth",
        default_source_root=ROOT / "benchmark/python/nanobot",
        default_pipeline_output=ROOT / "output/nanobot",
        default_out_dir=ROOT / "design/nanobot/call-chain/debug",
        argv=argv,
    )


if __name__ == "__main__":
    raise SystemExit(main())

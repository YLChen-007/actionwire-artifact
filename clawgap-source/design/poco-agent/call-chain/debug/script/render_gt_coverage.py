#!/usr/bin/env python3
"""Render poco-agent revision-pinned GT acceptance."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT))

from src.pipeline.static_acceptance import main_for_project  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    return main_for_project(
        title="poco-agent v0.5.4",
        generation_script="design/poco-agent/call-chain/debug/script/render_gt_coverage.py",
        default_oracle=ROOT / "design/poco-agent/poco-agent-v0.5.4-acceptance.json",
        default_ground_truth=ROOT / "design/poco-agent/groundtruth",
        default_source_root=ROOT / "benchmark/python/poco-agent",
        default_pipeline_output=ROOT / "output/poco-agent",
        default_out_dir=ROOT / "design/poco-agent/call-chain/debug",
        argv=argv,
    )


if __name__ == "__main__":
    raise SystemExit(main())

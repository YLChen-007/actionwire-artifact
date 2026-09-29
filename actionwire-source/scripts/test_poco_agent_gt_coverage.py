#!/usr/bin/env python3
"""Rebuild poco-agent static stages and enforce its pinned GT oracle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.pipeline.static_acceptance_runner import (  # noqa: E402
    AcceptanceRunnerError,
    run_project_acceptance,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pipeline-output", type=Path)
    parser.add_argument("--keep-temp", action="store_true")
    args = parser.parse_args()
    try:
        result, retained = run_project_acceptance(
            project_id="poco-agent",
            oracle_path=ROOT / "design/poco-agent/poco-agent-v0.5.4-acceptance.json",
            renderer=ROOT / "design/poco-agent/call-chain/debug/script/render_gt_coverage.py",
            pipeline_output=args.pipeline_output,
            keep_temp=args.keep_temp,
        )
    except (AcceptanceRunnerError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(str(exc))
        return 1
    print("poco-agent GT regression passed:")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if retained:
        print(f"Temporary evidence retained at: {retained}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

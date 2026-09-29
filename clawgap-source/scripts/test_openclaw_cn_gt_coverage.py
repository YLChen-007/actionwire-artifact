#!/usr/bin/env python3
"""Rebuild OpenClaw-CN static stages and enforce its locked exact-chain oracle."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str | Path]) -> None:
    rendered = [str(value) for value in command]
    print("+ " + " ".join(rendered), flush=True)
    subprocess.run(rendered, cwd=ROOT, check=True)


def render_reports(output: Path, coverage: Path) -> None:
    run(
        [
            sys.executable,
            "design/openclaw-cn/call-chain/debug/scripts/render_gt_coverage.py",
            "--pipeline-output",
            output,
            "--out-dir",
            coverage,
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pipeline-output", type=Path)
    args = parser.parse_args()
    try:
        run(
            [
                sys.executable,
                "design/openclaw-cn/inventory/debug/scripts/generate_inventory.py",
            ]
        )
        run(
            [
                sys.executable,
                "design/openclaw-cn/handler-entry/debug/scripts/generate_handler_entry_data.py",
            ]
        )
        run(
            [
                sys.executable,
                "design/openclaw-cn/sink/debug/scripts/generate_sink_data.py",
            ]
        )
        if args.pipeline_output:
            with tempfile.TemporaryDirectory(prefix="openclaw-cn-gt-coverage-") as temp:
                render_reports(args.pipeline_output.resolve(), Path(temp) / "coverage")
        else:
            with tempfile.TemporaryDirectory(prefix="openclaw-cn-gt-regression-") as temp:
                output = Path(temp) / "output"
                base = [
                    sys.executable,
                    "-m",
                    "src.pipeline",
                    "--project",
                    "openclaw-cn",
                    "--output-root",
                    output,
                ]
                run([*base, "infer-gates"])
                run([*base, "infer-call-chains"])
                render_reports(output, Path(temp) / "coverage")
    except subprocess.CalledProcessError as exc:
        return exc.returncode or 1
    print("OpenClaw-CN GT regression passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

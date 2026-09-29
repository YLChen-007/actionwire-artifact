#!/usr/bin/env python3
"""Rebuild OpenClaw static stages and enforce its locked GT oracle."""

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
            "design/openclaw/call-chain/debug/scripts/render_gt_coverage.py",
            "--pipeline-output",
            output,
            "--out-dir",
            coverage,
        ]
    )
    run(
        [
            sys.executable,
            "design/openclaw/call-chain/debug/scripts/render_d5_chain_coverage.py",
            "--ground-truth-dir",
            "design/openclaw/groundtruth/new-vuls",
            "--pipeline-output",
            output,
            "--out-dir",
            coverage,
            "--fail-on-eligible-gap",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pipeline-output", type=Path)
    args = parser.parse_args()
    try:
        run([sys.executable, "design/openclaw/inventory/debug/scripts/generate_inventory.py"])
        if args.pipeline_output:
            output = args.pipeline_output.resolve()
            with tempfile.TemporaryDirectory(prefix="openclaw-gt-coverage-") as temp:
                render_reports(output, Path(temp) / "coverage")
        else:
            with tempfile.TemporaryDirectory(prefix="openclaw-gt-regression-") as temp:
                output = Path(temp) / "output"
                coverage = Path(temp) / "coverage"
                base = [
                    sys.executable,
                    "-m",
                    "src.pipeline",
                    "--project",
                    "openclaw",
                    "--output-root",
                    output,
                ]
                run([*base, "infer-gates"])
                run([*base, "infer-call-chains"])
                render_reports(output, coverage)
    except subprocess.CalledProcessError as exc:
        return exc.returncode or 1
    print("OpenClaw GT regression passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

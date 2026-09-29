#!/usr/bin/env python3
"""Rebuild and verify LettaBot's real-database static adapter evidence."""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str | Path]) -> None:
    rendered = [str(value) for value in command]
    print("+ " + shlex.join(rendered), flush=True)
    subprocess.run(rendered, cwd=ROOT, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pipeline-output", type=Path)
    args = parser.parse_args()
    try:
        with tempfile.TemporaryDirectory(prefix="lettabot-adapter-") as temp:
            report = Path(temp) / "report"
            if args.pipeline_output:
                output = args.pipeline_output.resolve()
            else:
                output = Path(temp) / "output"
                base = [
                    sys.executable,
                    "-m",
                    "src.pipeline",
                    "--project",
                    "lettabot",
                    "--output-root",
                    output,
                ]
                run([*base, "infer-gates"])
                run([*base, "infer-call-chains"])
            run(
                [
                    sys.executable,
                    "design/lettabot/handler-entry/debug/scripts/generate_handler_entry_data.py",
                    "--out-dir",
                    report / "handlers",
                ]
            )
            run(
                [
                    sys.executable,
                    "design/lettabot/sink/debug/scripts/generate_sink_data.py",
                    "--out-dir",
                    report / "sinks",
                ]
            )
            run(
                [
                    sys.executable,
                    "design/lettabot/call-chain/debug/scripts/render_adapter_coverage.py",
                    "--pipeline-output",
                    output,
                    "--out-dir",
                    report,
                ]
            )
    except subprocess.CalledProcessError as exc:
        return exc.returncode or 1
    print("LettaBot adapter regression passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

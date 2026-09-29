#!/usr/bin/env python3
"""Rebuild QwenPaw static stages and enforce its pinned GT oracle."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.pipeline.static_acceptance_runner import (  # noqa: E402
    AcceptanceRunnerError,
    run_project_acceptance,
)
from src.pipeline.codeql import CodeQLPipelineError, run_query  # noqa: E402
from src.projects import get_project  # noqa: E402


ORACLE = ROOT / "design/QwenPaw/qwenpaw-v1.1.10-acceptance.json"


def validate_required_handler_entries() -> int:
    """Check revision-pinned handler identities against the real QwenPaw DB."""
    spec = get_project("QwenPaw")
    oracle = json.loads(ORACLE.read_text(encoding="utf-8"))
    required = oracle.get("required_handler_entries", [])
    if not isinstance(required, list) or not required:
        raise AcceptanceRunnerError("QwenPaw oracle has no required_handler_entries")

    with tempfile.TemporaryDirectory(prefix="qwenpaw-handler-regression-") as directory:
        rows = run_query(
            spec.codeql_database,
            "get_tool_handlers.ql",
            Path(directory) / "tool-handler-entries.csv",
        )

    failures: list[str] = []
    for expected in required:
        if not isinstance(expected, dict):
            raise AcceptanceRunnerError(
                "QwenPaw required_handler_entries contains a non-object"
            )
        identity = {
            key: str(expected.get(key, ""))
            for key in ("tool_name", "handler_func", "file")
        }
        if not all(identity.values()):
            raise AcceptanceRunnerError(
                f"incomplete QwenPaw required handler identity: {expected!r}"
            )
        matches = [
            row
            for row in rows
            if all(row.get(key) == value for key, value in identity.items())
        ]
        if len(matches) != 1:
            failures.append(f"{identity} -> matches={len(matches)}")
    if failures:
        raise AcceptanceRunnerError(
            "QwenPaw required handler regression failed:\n" + "\n".join(failures)
        )
    return len(required)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pipeline-output", type=Path)
    parser.add_argument("--keep-temp", action="store_true")
    args = parser.parse_args()
    try:
        result, retained = run_project_acceptance(
            project_id="QwenPaw",
            oracle_path=ORACLE,
            renderer=ROOT / "design/QwenPaw/call-chain/debug/script/render_gt_coverage.py",
            pipeline_output=args.pipeline_output,
            keep_temp=args.keep_temp,
        )
        result["required_handler_entries"] = validate_required_handler_entries()
    except (
        AcceptanceRunnerError,
        CodeQLPipelineError,
        FileNotFoundError,
        json.JSONDecodeError,
    ) as exc:
        print(str(exc))
        return 1
    print("QwenPaw GT regression passed:")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if retained:
        print(f"Temporary evidence retained at: {retained}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

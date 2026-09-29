#!/usr/bin/env python3
"""Regenerate Hermes D5 evidence in a temp directory and enforce its baseline."""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.projects import get_project  # noqa: E402

CODEQL = ROOT / "bin/codeql"
QL_ROOT = ROOT / "src/ql"
SOURCE_ROOT = ROOT / "benchmark/python/hermes-agent"
DATABASE = ROOT / "codeql-db/hermes-agent-db"
BASELINE = (
    ROOT / "design/hermes-agent/call-chain/baseline/d5-covered-items-v1.json"
)
CALL_DEBUG = ROOT / "design/hermes-agent/call-chain/debug"
GATE_DEBUG = ROOT / "design/hermes-agent/gate/debug"
HANDLER_DEBUG = ROOT / "design/hermes-agent/handler-entry/debug"
GROUND_TRUTH = ROOT / "design/hermes-agent/groundtruth/new-vuls"
BASELINE_REVISION = get_project("hermes-agent").analysis_revision

sys.path.insert(0, str(CALL_DEBUG / "script"))

from hermes_d5_baseline import (  # noqa: E402
    BaselineError,
    compare_coverage,
    load_baseline,
    read_items,
)


def run(
    command: Sequence[str | Path], *, echo_stdout: bool = True
) -> subprocess.CompletedProcess[str]:
    rendered = [str(part) for part in command]
    print(f"+ {shlex.join(rendered)}", flush=True)
    completed = subprocess.run(
        rendered,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        detail = (completed.stderr or completed.stdout)[-12000:]
        raise RuntimeError(
            f"command failed ({completed.returncode}): {shlex.join(rendered)}\n{detail}"
        )
    if echo_stdout and completed.stdout.strip():
        print(completed.stdout.rstrip())
    return completed


def run_query(database: Path, query: str, output_csv: Path, temp_root: Path) -> None:
    bqrs = temp_root / f"{Path(query).stem}.bqrs"
    run(
        [
            CODEQL,
            "query",
            "run",
            f"--database={database}",
            f"--additional-packs={QL_ROOT}",
            "-o",
            bqrs,
            QL_ROOT / query,
        ]
    )
    decoded = run(
        [CODEQL, "bqrs", "decode", "--format=csv", bqrs],
        echo_stdout=False,
    )
    output_csv.write_text(decoded.stdout, encoding="utf-8")


def compare_items(items_csv: Path, baseline_path: Path) -> dict[str, object]:
    baseline = load_baseline(baseline_path)
    return compare_coverage(
        read_items(items_csv),
        baseline,
        analysis_revision=BASELINE_REVISION,
    )


def full_regeneration(
    *,
    database: Path,
    source_root: Path,
    baseline_path: Path,
    keep_temp: bool,
) -> tuple[dict[str, object], Path | None]:
    for path, label in (
        (CODEQL, "CodeQL executable"),
        (database, "Hermes CodeQL database"),
        (source_root, "Hermes source root"),
        (baseline_path, "Hermes D5 baseline"),
        (GROUND_TRUTH, "Hermes ground-truth directory"),
    ):
        if not path.exists():
            raise FileNotFoundError(f"{label} does not exist: {path}")

    baseline = load_baseline(baseline_path)
    if baseline.get("analysis_revision") != BASELINE_REVISION:
        raise BaselineError(
            "runner/baseline revision mismatch: "
            f"{BASELINE_REVISION} != {baseline.get('analysis_revision')}"
        )

    temp_root = Path(tempfile.mkdtemp(prefix="hermes-d5-baseline-"))
    retained: Path | None = temp_root if keep_temp else None
    try:
        handler_sink = temp_root / "handler-sink-chains.csv"
        gate_candidates = temp_root / "gate-candidates.csv"
        transform_candidates = temp_root / "transform-candidates.csv"
        handler_entries = temp_root / "tool-handler-entries.csv"
        chain_gates = temp_root / "chain-gates.csv"

        run_query(database, "get_handler_to_sink.ql", handler_sink, temp_root)
        run_query(database, "get_gates.ql", gate_candidates, temp_root)
        run_query(database, "fte_transform.ql", transform_candidates, temp_root)
        run_query(database, "get_tool_handlers.ql", handler_entries, temp_root)

        run(
            [
                sys.executable,
                CALL_DEBUG / "script/render_chain_gates_coverage.py",
                "--rebuild-chain-gates",
                "--handler-sink-chains",
                handler_sink,
                "--gate-candidates",
                gate_candidates,
                "--transform-candidates",
                transform_candidates,
                "--chain-gates",
                chain_gates,
                "--out",
                temp_root / "chain-gates-coverage.md",
                "--handler-sink-out",
                temp_root / "handler-sink-coverage.md",
                "--exclude-needs-review-out",
                temp_root / "chain-gates-coverage-exclude-needs-review.md",
                "--source-root",
                source_root,
            ]
        )

        snapshot = temp_root / "d5-gt-items-snapshot.csv"
        shutil.copyfile(CALL_DEBUG / "d5-gt-items-snapshot.csv", snapshot)
        items_csv = temp_root / "d5-chain-coverage-items.csv"
        run(
            [
                sys.executable,
                CALL_DEBUG / "script/render_d5_chain_coverage.py",
                "--chain-gates",
                chain_gates,
                "--aux-chains",
                CALL_DEBUG / "handler-sink-discord-bridge.csv",
                "--gate-candidates",
                gate_candidates,
                "--transform-candidates",
                transform_candidates,
                "--taint-gt",
                GATE_DEBUG / "taintC-per-gate.csv",
                "--transform-coverage",
                GATE_DEBUG / "transform-gt-coverage.csv",
                "--handler-entries",
                handler_entries,
                "--ground-truth-dir",
                GROUND_TRUTH,
                "--out-csv",
                temp_root / "d5-chain-coverage.csv",
                "--out-items-csv",
                items_csv,
                "--out-debug-csv",
                temp_root / "d5-chain-coverage-debug.csv",
                "--out-md",
                temp_root / "d5-chain-coverage.md",
                "--gt-items-snapshot",
                snapshot,
                "--source-root",
                source_root,
            ]
        )
        return compare_items(items_csv, baseline_path), retained
    finally:
        if not keep_temp:
            shutil.rmtree(temp_root)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the pinned Hermes CodeQL queries and require current D5 item "
            "coverage to be a superset of the approved baseline."
        )
    )
    parser.add_argument("--database", type=Path, default=DATABASE)
    parser.add_argument("--source-root", type=Path, default=SOURCE_ROOT)
    parser.add_argument("--baseline", type=Path, default=BASELINE)
    parser.add_argument(
        "--items-csv",
        type=Path,
        help="Compare an existing per-item CSV without rerunning CodeQL.",
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Retain regenerated temporary evidence for debugging.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        retained: Path | None = None
        if args.items_csv is not None:
            result = compare_items(args.items_csv.resolve(), args.baseline.resolve())
        else:
            result, retained = full_regeneration(
                database=args.database.resolve(),
                source_root=args.source_root.resolve(),
                baseline_path=args.baseline.resolve(),
                keep_temp=args.keep_temp,
            )
    except (BaselineError, FileNotFoundError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print("Hermes D5 baseline passed:")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if retained is not None:
        print(f"Temporary evidence retained at: {retained}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

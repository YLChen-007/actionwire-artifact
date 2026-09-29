#!/usr/bin/env python3
"""Regenerate AstrBot static stages in temp and enforce its GT oracle."""

from __future__ import annotations

import argparse
import csv
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.projects import ProjectSpec, get_project  # noqa: E402


PROJECT_ID = "AstrBot"
ORACLE = ROOT / "design/AstrBot/astrbot-4.25.2-acceptance.json"
GROUND_TRUTH = ROOT / "design/AstrBot/groundtruth/new-vuls"
RENDERER = ROOT / "design/AstrBot/call-chain/debug/script/render_gt_coverage.py"


def run(command: Sequence[str | Path]) -> subprocess.CompletedProcess[str]:
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
        detail = "\n".join(
            value.rstrip()
            for value in (completed.stdout, completed.stderr)
            if value.strip()
        )
        raise RuntimeError(
            f"command failed ({completed.returncode}): {shlex.join(rendered)}\n"
            + detail[-16000:]
        )
    if completed.stdout.strip():
        print(completed.stdout.rstrip())
    return completed


def validate_oracle(spec: ProjectSpec, oracle_path: Path) -> dict[str, object]:
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    if oracle.get("project_id") != spec.project_id:
        raise RuntimeError(
            "AstrBot oracle project mismatch: "
            f"{oracle.get('project_id')!r} != {spec.project_id!r}"
        )
    if oracle.get("analysis_revision") != spec.analysis_revision:
        raise RuntimeError(
            "AstrBot oracle revision mismatch: "
            f"{oracle.get('analysis_revision')!r} != {spec.analysis_revision!r}"
        )
    return oracle


def pipeline_command(
    spec: ProjectSpec, output_root: Path, stage: str
) -> list[str | Path]:
    return [
        sys.executable,
        "-m",
        "src.pipeline",
        "--project",
        spec.project_id,
        "--source-root",
        spec.source_root,
        "--database",
        spec.codeql_database,
        "--output-root",
        output_root,
        "--revision",
        spec.analysis_revision,
        stage,
    ]


def evaluate(
    spec: ProjectSpec,
    *,
    pipeline_output: Path,
    report_dir: Path,
    oracle_path: Path,
) -> dict[str, object]:
    run(
        [
            sys.executable,
            RENDERER,
            "--oracle",
            oracle_path,
            "--ground-truth",
            GROUND_TRUTH,
            "--source-root",
            spec.source_root,
            "--pipeline-output",
            pipeline_output,
            "--out-dir",
            report_dir,
        ]
    )
    with (report_dir / "gt-coverage.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        rows = list(csv.DictReader(handle))
    statuses = Counter(row["status"] for row in rows)
    return {
        "project": spec.project_id,
        "revision": spec.analysis_revision,
        "rows": len(rows),
        "statuses": dict(sorted(statuses.items())),
    }


def full_regeneration(
    spec: ProjectSpec,
    *,
    oracle_path: Path,
    keep_temp: bool,
) -> tuple[dict[str, object], Path | None]:
    for path, label in (
        (spec.source_root, "AstrBot source root"),
        (spec.codeql_database, "AstrBot CodeQL database"),
        (oracle_path, "AstrBot acceptance oracle"),
        (GROUND_TRUTH, "AstrBot raw ground truth"),
        (RENDERER, "AstrBot GT renderer"),
    ):
        if not path.exists():
            raise FileNotFoundError(f"{label} does not exist: {path}")
    validate_oracle(spec, oracle_path)

    temp_root = Path(tempfile.mkdtemp(prefix="astrbot-gt-regression-"))
    retained: Path | None = temp_root if keep_temp else None
    try:
        pipeline_output = temp_root / "pipeline-output"
        run(pipeline_command(spec, pipeline_output, "infer-gates"))
        run(pipeline_command(spec, pipeline_output, "infer-call-chains"))
        result = evaluate(
            spec,
            pipeline_output=pipeline_output,
            report_dir=temp_root / "coverage",
            oracle_path=oracle_path,
        )
        return result, retained
    finally:
        if not keep_temp:
            shutil.rmtree(temp_root)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", type=Path, default=ORACLE)
    parser.add_argument(
        "--pipeline-output",
        type=Path,
        help="Evaluate existing static outputs without rerunning CodeQL.",
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Retain temporary pipeline output and coverage reports for debugging.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    spec = get_project(PROJECT_ID)
    oracle_path = args.oracle.absolute()
    try:
        validate_oracle(spec, oracle_path)
        retained: Path | None = None
        if args.pipeline_output is not None:
            with tempfile.TemporaryDirectory(
                prefix="astrbot-gt-coverage-"
            ) as directory:
                result = evaluate(
                    spec,
                    pipeline_output=args.pipeline_output.resolve(),
                    report_dir=Path(directory),
                    oracle_path=oracle_path,
                )
        else:
            result, retained = full_regeneration(
                spec,
                oracle_path=oracle_path,
                keep_temp=args.keep_temp,
            )
    except (FileNotFoundError, json.JSONDecodeError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print("AstrBot GT regression passed:")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if retained is not None:
        print(f"Temporary evidence retained at: {retained}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

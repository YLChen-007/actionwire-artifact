"""Fixed-database runner for revision-pinned project acceptance oracles."""

from __future__ import annotations

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

from src.projects import ProjectSpec, get_project


REPO_ROOT = Path(__file__).resolve().parents[2]


class AcceptanceRunnerError(RuntimeError):
    """Raised when a fixed-DB acceptance command fails."""


def _run(command: Sequence[str | Path]) -> None:
    rendered = [str(part) for part in command]
    print(f"+ {shlex.join(rendered)}", flush=True)
    completed = subprocess.run(
        rendered,
        cwd=REPO_ROOT,
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
        raise AcceptanceRunnerError(
            f"command failed ({completed.returncode}): {shlex.join(rendered)}\n"
            + detail[-16000:]
        )
    if completed.stdout.strip():
        print(completed.stdout.rstrip())


def _validate(spec: ProjectSpec, oracle_path: Path) -> dict[str, object]:
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    if oracle.get("project_id") != spec.project_id:
        raise AcceptanceRunnerError(
            f"oracle project mismatch: {oracle.get('project_id')!r} != {spec.project_id!r}"
        )
    if oracle.get("analysis_revision") != spec.analysis_revision:
        raise AcceptanceRunnerError(
            "oracle revision mismatch: "
            f"{oracle.get('analysis_revision')!r} != {spec.analysis_revision!r}"
        )
    return oracle


def _stage_command(
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


def _evaluate(
    spec: ProjectSpec,
    *,
    oracle_path: Path,
    renderer: Path,
    pipeline_output: Path,
    report_dir: Path,
) -> dict[str, object]:
    _run(
        [
            sys.executable,
            renderer,
            "--oracle",
            oracle_path,
            "--ground-truth",
            spec.ground_truth_root,
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
        statuses = Counter(row["status"] for row in csv.DictReader(handle))
    return {
        "project": spec.project_id,
        "revision": spec.analysis_revision,
        "statuses": dict(sorted(statuses.items())),
    }


def run_project_acceptance(
    *,
    project_id: str,
    oracle_path: Path,
    renderer: Path,
    pipeline_output: Path | None = None,
    keep_temp: bool = False,
) -> tuple[dict[str, object], Path | None]:
    spec = get_project(project_id)
    oracle_path = oracle_path.absolute()
    renderer = renderer.absolute()
    for path, label in (
        (spec.source_root, "source root"),
        (spec.codeql_database, "CodeQL database"),
        (spec.ground_truth_root, "ground-truth inventory"),
        (oracle_path, "acceptance oracle"),
        (renderer, "coverage renderer"),
    ):
        if not path.exists():
            raise AcceptanceRunnerError(f"{label} does not exist: {path}")
    _validate(spec, oracle_path)

    temp_root = Path(
        tempfile.mkdtemp(prefix=f"{project_id.lower()}-gt-regression-")
    )
    retained: Path | None = temp_root if keep_temp else None
    try:
        generated_output = pipeline_output.resolve() if pipeline_output else temp_root / "pipeline-output"
        if pipeline_output is None:
            _run(_stage_command(spec, generated_output, "infer-gates"))
            _run(_stage_command(spec, generated_output, "infer-call-chains"))
        result = _evaluate(
            spec,
            oracle_path=oracle_path,
            renderer=renderer,
            pipeline_output=generated_output,
            report_dir=temp_root / "coverage",
        )
        return result, retained
    finally:
        if not keep_temp:
            shutil.rmtree(temp_root)

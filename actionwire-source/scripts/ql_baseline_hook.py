#!/usr/bin/env python3
"""Run project static regressions once per Claude turn after QL edits."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable


STATE_DIRECTORY = "clawgap-ql-baseline-hooks"


def repository_root() -> Path:
    configured = os.environ.get("CLAUDE_PROJECT_DIR", "").strip()
    return Path(configured).resolve() if configured else Path(__file__).resolve().parents[1]


def ql_target(root: Path, raw_path: object) -> str | None:
    if not isinstance(raw_path, (str, os.PathLike)):
        return None
    value = str(raw_path).strip()
    if not value:
        return None
    path = Path(value)
    resolved = (root / path).resolve() if not path.is_absolute() else path.resolve()
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError:
        return None
    if relative == "src/ql/qlpack.yml":
        return relative
    if relative.startswith("src/ql/") and resolved.suffix in {".ql", ".qll"}:
        return relative
    return None


def marker_path(
    root: Path,
    payload: dict[str, object],
    *,
    state_root: Path | None = None,
) -> Path | None:
    identity = payload.get("session_id") or payload.get("transcript_path")
    if not isinstance(identity, str) or not identity.strip():
        return None
    digest = hashlib.sha256(
        f"{root.resolve()}\0{identity.strip()}".encode("utf-8")
    ).hexdigest()
    directory = state_root or Path(tempfile.gettempdir()) / STATE_DIRECTORY
    return directory / f"{digest}.json"


def mark_ql_edit(
    root: Path,
    payload: dict[str, object],
    *,
    state_root: Path | None = None,
) -> str | None:
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return None
    relative = ql_target(
        root,
        tool_input.get("file_path") or tool_input.get("path"),
    )
    marker = marker_path(root, payload, state_root=state_root)
    if relative is None or marker is None:
        return None

    modified_paths: set[str] = set()
    if marker.is_file():
        try:
            previous = json.loads(marker.read_text(encoding="utf-8"))
            modified_paths.update(previous.get("modified_paths", []))
        except (json.JSONDecodeError, OSError, TypeError, AttributeError):
            pass
    modified_paths.add(relative)
    marker.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    marker.write_text(
        json.dumps(
            {
                "project_root": str(root.resolve()),
                "modified_paths": sorted(modified_paths),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return relative


def _run_baseline(root: Path) -> subprocess.CompletedProcess[str]:
    commands = [
        [sys.executable, str(root / "scripts/test_hermes_d5_baseline.py")],
        [
            sys.executable,
            str(root / "scripts/test_chatgpt_on_wechat_gt_coverage.py"),
        ],
        [sys.executable, str(root / "scripts/test_astrbot_gt_coverage.py")],
        [sys.executable, str(root / "scripts/test_qwenpaw_gt_coverage.py")],
        [sys.executable, str(root / "scripts/test_nanobot_gt_coverage.py")],
        [sys.executable, str(root / "scripts/test_poco_agent_gt_coverage.py")],
    ]
    stdout: list[str] = []
    stderr: list[str] = []
    for command in commands:
        completed = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        stdout.append(completed.stdout)
        stderr.append(completed.stderr)
        if completed.returncode:
            return subprocess.CompletedProcess(
                command,
                completed.returncode,
                "\n".join(stdout),
                "\n".join(stderr),
            )
    return subprocess.CompletedProcess(
        commands,
        0,
        "\n".join(stdout),
        "\n".join(stderr),
    )


def run_marked_baseline(
    root: Path,
    payload: dict[str, object],
    *,
    state_root: Path | None = None,
    runner: Callable[[Path], subprocess.CompletedProcess[str]] = _run_baseline,
) -> int:
    marker = marker_path(root, payload, state_root=state_root)
    if marker is None or not marker.is_file():
        return 0

    try:
        state = json.loads(marker.read_text(encoding="utf-8"))
        modified_paths = state.get("modified_paths", [])
    except (json.JSONDecodeError, OSError, TypeError, AttributeError):
        modified_paths = []
    rendered_paths = ", ".join(str(path) for path in modified_paths) or "QL files"

    try:
        completed = runner(root)
    except OSError as exc:
        print(
            "QL static regressions could not run after modifying "
            f"{rendered_paths}: {exc}",
            file=sys.stderr,
        )
        return 2

    combined = "\n".join(
        value.rstrip() for value in (completed.stdout, completed.stderr) if value.strip()
    )
    if completed.returncode:
        print(
            f"QL static regressions failed after modifying {rendered_paths}.\n"
            + combined[-16000:],
            file=sys.stderr,
        )
        return 2

    marker.unlink(missing_ok=True)
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "Stop",
                    "additionalContext": (
                        "[ql-regression] All six project regressions passed "
                        "once for this turn "
                        f"after changes to {rendered_paths}."
                    ),
                }
            },
            ensure_ascii=False,
        )
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("mark", "run-if-marked"))
    return parser.parse_args()


def read_payload() -> dict[str, object]:
    try:
        value = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def main() -> int:
    args = parse_args()
    payload = read_payload()
    root = repository_root()
    if args.mode == "mark":
        mark_ql_edit(root, payload)
        return 0
    return run_marked_baseline(root, payload)


if __name__ == "__main__":
    raise SystemExit(main())

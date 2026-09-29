"""Small target process used to test injected runtime instrumentation."""

from __future__ import annotations

import os
import subprocess
import sys


BLOCKED = {"/dev/zero", "/dev/urandom"}


def _is_blocked_device(filepath: str) -> bool:
    return os.path.expanduser(filepath) in BLOCKED


def _run_bash(path: str, marker: str) -> subprocess.Popen[str]:
    script = (
        "from pathlib import Path; import sys; "
        "Path(sys.argv[2]).write_text('called', encoding='utf-8'); print(sys.argv[1])"
    )
    return subprocess.Popen(
        [sys.executable, "-c", script, path, marker],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _handle_read_file(args: dict[str, str], marker: str) -> str:
    path = args["path"]
    if _is_blocked_device(path):
        return "blocked"
    process = _run_bash(path, marker)
    stdout, _ = process.communicate(timeout=5)
    return stdout.strip()


def main() -> int:
    mode, value, marker = sys.argv[1:4]
    if mode == "handler":
        print(_handle_read_file({"path": value}, marker))
    elif mode == "unrelated":
        process = _run_bash(value, marker)
        process.communicate(timeout=5)
    else:
        raise ValueError(f"unknown mode: {mode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

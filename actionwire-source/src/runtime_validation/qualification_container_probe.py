"""Fail-closed in-container reset and immutability probe."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any


QUALIFICATION_ROOT = Path("/tmp/qualification")
CANARY_PATH = Path("/run/clawgap-baseline-canary")
PROJECT_ROOT = Path("/opt/clawgap")


def _credential_variables() -> list[str]:
    markers = ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "CREDENTIAL")
    return sorted(
        key
        for key in os.environ
        if any(marker in key.upper() for marker in markers)
        and not key.startswith("CLAWGAP_")
    )


def _binding_path(project_root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute():
        raise ValueError(f"absolute binding path is not supported: {relative}")
    if path.parts and path.parts[0] == "benchmark":
        return PROJECT_ROOT / path
    return project_root / path


def _verify_bindings(project_root: Path, sections: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for section, binding in sections.items():
        for row in binding.get("files", []):
            path = _binding_path(project_root, str(row["path"]))
            try:
                actual = __import__("hashlib").sha256(path.read_bytes()).hexdigest()
            except OSError as exc:
                errors.append(f"{section}:{row['path']}:{type(exc).__name__}")
                continue
            if actual != row["sha256"]:
                errors.append(f"{section}:{row['path']}:sha256-drift")
    return errors


def _unexpected_processes() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    self_pid = os.getpid()
    parent_pid = os.getppid()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid in {1, self_pid, parent_pid}:
            continue
        try:
            raw = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(
                "utf-8", "replace"
            ).strip()
        except OSError:
            continue
        if raw and not raw.startswith("sh -c test -d"):
            rows.append({"pid": pid, "command": raw[:300]})
    return rows


def main() -> int:
    try:
        request = json.loads(sys.stdin.read())
        if not isinstance(request, dict) or request.get("schema_version") != "clawgap-qualification-container-probe/v1":
            raise ValueError("unsupported probe request")
        project_root = PROJECT_ROOT / Path(str(request["source_root"]))
        errors = _verify_bindings(project_root, request.get("bindings", {}))
        credential_variables = _credential_variables()
        if credential_variables:
            errors.append("credential-variables-inherited")
        expected_canary = str(request.get("canary", ""))
        try:
            actual_canary = CANARY_PATH.read_text(encoding="utf-8")
        except OSError:
            actual_canary = ""
            errors.append("baseline-canary-unavailable")
        if expected_canary and actual_canary != expected_canary:
            errors.append("baseline-canary-drift")
        pair_root = QUALIFICATION_ROOT / str(request.get("pair_id", ""))
        if str(pair_root.resolve()).startswith(str(QUALIFICATION_ROOT.resolve()) + "/"):
            if pair_root.exists():
                shutil.rmtree(pair_root)
            if pair_root.exists():
                errors.append("pair-state-removal-failed")
        else:
            errors.append("invalid-pair-root")
        processes = _unexpected_processes()
        if processes:
            errors.append("target-process-remained")
        result = {
            "schema_version": "clawgap-qualification-container-probe-result/v1",
            "status": "passed" if not errors else "failed",
            "errors": errors,
            "credential_variables": credential_variables,
            "unexpected_processes": processes,
            "source_root": str(project_root),
            "network": "none",
            "root_filesystem": "read-only",
        }
    except Exception as exc:
        result = {
            "schema_version": "clawgap-qualification-container-probe-result/v1",
            "status": "failed",
            "errors": [f"{type(exc).__name__}: {exc}"],
            "credential_variables": [],
            "unexpected_processes": [],
        }
    sys.stdout.write(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Pinned dependency and native-driver readiness preflight."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.projects import get_project

from .adapters import adapter_ids, get_adapter
from .contracts import ValidationError, atomic_write_json, atomic_write_text, sha256_file


@dataclass(frozen=True)
class ProvisionRequest:
    campaign_dir: Path
    install: bool = True


DEPENDENCIES = {
    "lettabot": ("npm", "package-lock.json", ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"]),
    "mercury-agent": ("npm", "package-lock.json", ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"]),
    "nanoclaw": ("pnpm", "pnpm-lock.yaml", ["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"]),
    "openclaw": ("pnpm", "pnpm-lock.yaml", ["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"]),
    "openclaw-cn": ("pnpm", "pnpm-lock.yaml", ["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"]),
}


def _version(command: str) -> str:
    path = shutil.which(command)
    if path is None:
        return "unavailable"
    completed = subprocess.run(
        [path, "--version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False
    )
    return completed.stdout.strip() or f"exit-{completed.returncode}"


def provision_drivers(request: ProvisionRequest) -> dict[str, Any]:
    root = request.campaign_dir.resolve()
    if not (root / "campaign.json").is_file():
        raise ValidationError(f"campaign.json is unavailable under {root}")
    logs = root / "provisioning-logs"
    logs.mkdir(parents=True, exist_ok=True)
    projects: list[dict[str, Any]] = []
    for project_id, (manager, lock_name, command) in DEPENDENCIES.items():
        project_root = get_project(project_id).source_root
        package_path = project_root / "package.json"
        lock_path = project_root / lock_name
        if not package_path.is_file() or not lock_path.is_file():
            raise ValidationError(f"pinned dependency manifest is unavailable for {project_id}")
        installed_before = (project_root / "node_modules").is_dir()
        completed: subprocess.CompletedProcess[str] | None = None
        if request.install and not installed_before:
            completed = subprocess.run(
                command,
                cwd=project_root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            atomic_write_text(logs / f"{project_id}.log", completed.stdout[-100_000:])
        installed = (project_root / "node_modules").is_dir()
        ready = installed and (completed is None or completed.returncode == 0)
        projects.append(
            {
                "project": project_id,
                "manager": manager,
                "command": command,
                "installed_before": installed_before,
                "installed": installed,
                "ready": ready,
                "exit_code": completed.returncode if completed is not None else None,
                "package_json_sha256": sha256_file(package_path),
                "lockfile": lock_name,
                "lockfile_sha256": sha256_file(lock_path),
            }
        )
    droid = get_project("droidclaw").source_root
    projects.append(
        {
            "project": "droidclaw",
            "manager": "bun-direct",
            "command": [],
            "installed_before": False,
            "installed": True,
            "ready": (droid / "src/actions.ts").is_file() and shutil.which("bun") is not None,
            "exit_code": None,
            "package_json_sha256": sha256_file(droid / "package.json"),
            "lockfile": None,
            "lockfile_sha256": None,
        }
    )
    adapters = []
    for adapter_id in adapter_ids():
        adapter = get_adapter(adapter_id)
        adapters.append(
            {
                "adapter": adapter_id,
                "project": adapter.project_id,
                "driver": adapter.driver is not None,
                "supported_tools": list(adapter.supported_tools),
            }
        )
    report = {
        "schema_version": "clawgap-runtime-driver-provisioning/v1",
        "campaign": str(root),
        "install_requested": request.install,
        "ready": all(row["ready"] for row in projects) and all(row["driver"] for row in adapters),
        "runtimes": {
            "python": _version("python"),
            "node": _version("node"),
            "bun": _version("bun"),
            "npm": _version("npm"),
            "pnpm": _version("pnpm"),
        },
        "browser": {
            "mode": "isolated-loopback-fixture",
            "cached_chromium": any(Path.home().joinpath(".cache/ms-playwright").glob("chromium*")),
        },
        "effect_policy": {
            "process": "intercept",
            "adb": "recording-fake",
            "filesystem": "temporary-root-only",
            "network": "loopback-only",
            "messaging": "capture-only",
            "subagent": "capture-only",
        },
        "projects": projects,
        "adapters": adapters,
    }
    atomic_write_json(root / "driver-provisioning.json", report)
    return report

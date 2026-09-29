"""Deterministic trial enumeration from the registered handler inventories."""

from __future__ import annotations

import csv
import hashlib
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from src.projects import ProjectSpec, get_project, list_projects

from .contracts import BaselineError, canonical_json, digest


@dataclass(frozen=True)
class HandlerTrial:
    trial_id: str
    project: str
    revision: str
    source_root: str
    source_sha256: str
    inventory_path: str
    inventory_sha256: str
    ordinal: int
    tool_name: str
    form: str
    handler_func: str
    file: str
    line: int
    forwarded_body: str

    def record(self) -> dict[str, object]:
        return asdict(self)


def sha256_tree(root: Path) -> str:
    """Hash paths, modes, symlink targets, and regular-file bytes without following links."""
    root = root.resolve()
    value = hashlib.sha256()
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(directory)
        dirnames[:] = sorted(name for name in dirnames if name != ".git")
        for name in sorted(dirnames + filenames):
            path = current / name
            relative = path.relative_to(root).as_posix()
            stat = path.lstat()
            value.update(relative.encode("utf-8") + b"\0")
            value.update(oct(stat.st_mode & 0o7777).encode("ascii") + b"\0")
            if path.is_symlink():
                value.update(b"L\0" + os.readlink(path).encode("utf-8") + b"\0")
            elif path.is_file():
                value.update(b"F\0")
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        value.update(chunk)
            else:
                value.update(b"D\0")
    return value.hexdigest()


def _read_rows(spec: ProjectSpec) -> tuple[Path, list[dict[str, str]]]:
    path = spec.design_root / "handler-entry/debug/tool-handler-entries.csv"
    if not path.is_file():
        raise BaselineError(f"missing handler inventory: {path}")
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    expected = {"tool_name", "form", "handler_func", "file", "line", "forwarded_body"}
    if not rows or any(set(row) != expected for row in rows):
        raise BaselineError(f"invalid handler inventory schema: {path}")
    return path, rows


def build_inventory(
    specs: Iterable[ProjectSpec] | None = None,
) -> list[HandlerTrial]:
    selected = list(specs) if specs is not None else [get_project(name) for name in list_projects()]
    repo_root = Path(__file__).resolve().parents[2]
    trials: list[HandlerTrial] = []
    seen: set[str] = set()
    for spec in sorted((row.resolved() for row in selected), key=lambda row: row.project_id):
        path, rows = _read_rows(spec)
        inventory_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        source_sha = sha256_tree(spec.source_root)
        ordered = sorted(
            rows,
            key=lambda row: (
                row["tool_name"], row["file"], int(row["line"]), row["handler_func"],
                row["form"], row["forwarded_body"],
            ),
        )
        for ordinal, row in enumerate(ordered, 1):
            identity = [
                spec.project_id, spec.analysis_revision, row["tool_name"], row["form"],
                row["handler_func"], row["file"], int(row["line"]), row["forwarded_body"],
            ]
            trial_id = "HB-" + digest(identity)[:16]
            if trial_id in seen:
                raise BaselineError(f"duplicate trial identity: {trial_id}")
            seen.add(trial_id)
            trials.append(
                HandlerTrial(
                    trial_id=trial_id,
                    project=spec.project_id,
                    revision=spec.analysis_revision,
                    source_root=str(spec.source_root),
                    source_sha256=source_sha,
                    inventory_path=str(path.relative_to(repo_root)),
                    inventory_sha256=inventory_sha,
                    ordinal=ordinal,
                    tool_name=row["tool_name"],
                    form=row["form"],
                    handler_func=row["handler_func"],
                    file=row["file"],
                    line=int(row["line"]),
                    forwarded_body=row["forwarded_body"],
                )
            )
    return trials


def inventory_digest(trials: Iterable[HandlerTrial]) -> str:
    return digest([row.record() for row in trials])


def inventory_jsonl(trials: Iterable[HandlerTrial]) -> str:
    return "".join(canonical_json(row.record()) + "\n" for row in trials)

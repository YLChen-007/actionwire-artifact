"""Project orchestration for shared handler-specification extraction."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Mapping, Sequence

from src.projects import ProjectSpec, get_project, list_projects

from .core import AdapterResult, build_inventory, read_handlers, write_artifacts
from .python_adapters import extract_python_project
from .typescript_adapters import extract_typescript_project


def default_handler_inventory(spec: ProjectSpec) -> Path:
    return spec.design_root / "handler-entry/debug/tool-handler-entries.csv"


def default_output_directory(spec: ProjectSpec) -> Path:
    return spec.output_root / "handler-specifications"


def reproduction_command(arguments: Sequence[str]) -> str:
    return shlex.join(["python", "-m", "src.handler_specifications", *arguments])


def build_project_inventory(
    spec: ProjectSpec,
    *,
    handler_inventory: Path | None = None,
    command: str | None = None,
) -> dict:
    spec = spec.resolved()
    handler_csv = (handler_inventory or default_handler_inventory(spec)).resolve()
    handlers = read_handlers(handler_csv)
    command = command or reproduction_command(["--project", spec.project_id])
    if spec.source_language == "python":
        results: Mapping[str, AdapterResult] = extract_python_project(
            spec,
            handlers,
            command,
            handler_csv,
        )
    elif spec.source_language == "typescript":
        results = extract_typescript_project(spec, handlers)
    else:
        raise ValueError(
            f"{spec.project_id}: unsupported source language {spec.source_language!r}"
        )
    return build_inventory(spec, handler_csv, results, command)


def build_all_inventories() -> list[tuple[ProjectSpec, dict]]:
    """Validate and build every registered project without writing anything."""

    command = reproduction_command(["--all"])
    built: list[tuple[ProjectSpec, dict]] = []
    for project_id in list_projects():
        spec = get_project(project_id)
        built.append((spec, build_project_inventory(spec, command=command)))
    return built


def write_project_inventory(
    spec: ProjectSpec,
    inventory: Mapping,
    *,
    output_directory: Path | None = None,
) -> tuple[Path, Path]:
    return write_artifacts(
        inventory,
        (output_directory or default_output_directory(spec)).resolve(),
    )


def generate_all() -> list[tuple[Path, Path]]:
    # Extraction and schema validation for all projects completes before the
    # first canonical artifact is replaced. Thus a source/adapter failure
    # cannot leave an incomplete all-project generation.
    built = build_all_inventories()
    return [write_project_inventory(spec, inventory) for spec, inventory in built]


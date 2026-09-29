"""Shared contracts and deterministic rendering for handler specifications."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import tempfile
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from src.projects import ProjectSpec


SCHEMA_VERSION = "clawgap/tool-handler-specifications/v2"
HANDLER_FIELDS = [
    "tool_name",
    "form",
    "handler_func",
    "file",
    "line",
    "forwarded_body",
]


class SpecificationError(ValueError):
    """Raised when a source-backed tool specification cannot be resolved safely."""


@dataclass(frozen=True, order=True)
class HandlerEntry:
    tool_name: str
    form: str
    handler_func: str
    file: str
    line: int
    forwarded_body: str


@dataclass(frozen=True)
class AdapterResult:
    """One canonical model-facing specification returned by a project adapter."""

    tool_name: str
    interface_kind: str
    function: Mapping[str, Any] | None
    evidence: Sequence[Mapping[str, Any]]
    runtime_rules: Sequence[Mapping[str, Any]] = ()
    status: str = "resolved"
    reason_code: str | None = None
    reason: str | None = None
    consumed_files: Sequence[str] = ()


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def repo_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(repo_root()).as_posix()
    except ValueError:
        return resolved.as_posix()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_within(root: Path, relative: str, *, label: str = "source") -> Path:
    """Resolve a repository-relative source path without permitting escapes."""

    base = root.resolve()
    candidate = (base / relative).resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise SpecificationError(f"{label} path escapes root: {relative}") from exc
    if not candidate.is_file():
        raise SpecificationError(f"{label} file does not exist: {candidate}")
    return candidate


def read_handlers(path: Path) -> list[HandlerEntry]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != HANDLER_FIELDS:
            raise SpecificationError(
                f"unexpected columns in {path}: {reader.fieldnames}; expected {HANDLER_FIELDS}"
            )
        entries: set[HandlerEntry] = set()
        for row_number, row in enumerate(reader, 2):
            try:
                line = int(row["line"])
            except (TypeError, ValueError) as exc:
                raise SpecificationError(f"invalid line at {path}:{row_number}") from exc
            if line < 1 or not row["tool_name"] or not row["handler_func"]:
                raise SpecificationError(
                    f"invalid handler row at {path}:{row_number}: {row}"
                )
            entry = HandlerEntry(
                tool_name=row["tool_name"],
                form=row["form"],
                handler_func=row["handler_func"],
                file=row["file"],
                line=line,
                forwarded_body=row["forwarded_body"],
            )
            if entry in entries:
                raise SpecificationError(
                    f"duplicate handler row at {path}:{row_number}: {entry}"
                )
            entries.add(entry)
    return sorted(entries)


def group_handlers(entries: Iterable[HandlerEntry]) -> dict[str, list[HandlerEntry]]:
    grouped: dict[str, list[HandlerEntry]] = defaultdict(list)
    for entry in entries:
        grouped[entry.tool_name].append(entry)
    return {name: sorted(grouped[name]) for name in sorted(grouped)}


def evidence_record(
    source_root: Path,
    relative_file: str,
    line: int,
    *,
    kind: str,
    detail: str | None = None,
) -> dict[str, Any]:
    path = ensure_within(source_root, relative_file)
    record: dict[str, Any] = {
        "kind": kind,
        "file": repo_path(path),
        "line": line,
        "sha256": sha256_file(path),
    }
    if detail:
        record["detail"] = detail
    return record


def validate_function(tool_name: str, function: Mapping[str, Any] | None) -> None:
    if function is None:
        return
    if set(function) != {"name", "description", "parameters"}:
        raise SpecificationError(
            f"{tool_name}: function must contain exactly name, description, parameters"
        )
    if function["name"] != tool_name:
        raise SpecificationError(
            f"{tool_name}: function name mismatch: {function['name']!r}"
        )
    if not isinstance(function["description"], str) or not function["description"].strip():
        raise SpecificationError(f"{tool_name}: function description must be non-empty")
    parameters = function["parameters"]
    if not isinstance(parameters, Mapping) or parameters.get("type") != "object":
        raise SpecificationError(f"{tool_name}: parameters must be an object schema")
    if not isinstance(parameters.get("properties", {}), Mapping):
        raise SpecificationError(f"{tool_name}: parameters.properties must be an object")
    try:
        json.dumps(function, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise SpecificationError(f"{tool_name}: function is not JSON serializable") from exc


def _dedupe_evidence(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for record in records:
        normalized = dict(record)
        key = json.dumps(normalized, sort_keys=True, ensure_ascii=False)
        unique[key] = normalized
    return sorted(
        unique.values(),
        key=lambda item: (
            str(item.get("file", "")),
            int(item.get("line", 0)),
            str(item.get("kind", "")),
            str(item.get("detail", "")),
        ),
    )


def build_inventory(
    spec: ProjectSpec,
    handler_csv: Path,
    adapter_results: Mapping[str, AdapterResult],
    reproduction_command: str,
) -> dict[str, Any]:
    spec = spec.resolved()
    handlers = read_handlers(handler_csv)
    grouped = group_handlers(handlers)
    expected = set(grouped)
    actual = set(adapter_results)
    if expected != actual:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise SpecificationError(
            f"{spec.project_id}: adapter coverage mismatch; missing={missing}, extra={extra}"
        )

    tools: list[dict[str, Any]] = []
    all_evidence: list[Mapping[str, Any]] = []
    for tool_name in sorted(grouped):
        result = adapter_results[tool_name]
        if result.tool_name != tool_name:
            raise SpecificationError(
                f"{spec.project_id}: adapter returned {result.tool_name!r} for {tool_name!r}"
            )
        if result.status not in {"resolved", "unresolved"}:
            raise SpecificationError(f"{tool_name}: invalid resolution status {result.status!r}")
        if result.status == "resolved" and result.function is None:
            raise SpecificationError(f"{tool_name}: resolved record has no function")
        if result.status == "unresolved" and result.function is not None:
            raise SpecificationError(f"{tool_name}: unresolved record has a function")
        if result.status == "unresolved" and not result.reason_code:
            raise SpecificationError(f"{tool_name}: unresolved record has no reason_code")
        validate_function(tool_name, result.function)
        evidence = _dedupe_evidence(result.evidence)
        if not evidence:
            raise SpecificationError(f"{tool_name}: no source evidence")
        all_evidence.extend(evidence)
        resolution: dict[str, Any] = {"status": result.status}
        if result.reason_code:
            resolution["reason_code"] = result.reason_code
        if result.reason:
            resolution["reason"] = result.reason
        tools.append(
            {
                "tool_name": tool_name,
                "interface_kind": result.interface_kind,
                "handlers": [asdict(entry) for entry in grouped[tool_name]],
                "function": dict(result.function) if result.function is not None else None,
                "runtime_rules": [dict(rule) for rule in result.runtime_rules],
                "resolution": resolution,
                "evidence": evidence,
            }
        )

    resolved = sum(tool["resolution"]["status"] == "resolved" for tool in tools)
    unresolved = len(tools) - resolved
    source_files: dict[str, str] = {}
    for handler in handlers:
        source_path = ensure_within(
            spec.source_root,
            handler.file,
            label=f"{spec.project_id} handler source",
        )
        source_files[repo_path(source_path)] = sha256_file(source_path)
    for record in _dedupe_evidence(all_evidence):
        source_files[str(record["file"])] = str(record["sha256"])
    for result in adapter_results.values():
        for relative_file in result.consumed_files:
            source_path = ensure_within(
                spec.source_root,
                relative_file,
                label=f"{spec.project_id} consumed source",
            )
            source_files[repo_path(source_path)] = sha256_file(source_path)
    inventory = {
        "schema_version": SCHEMA_VERSION,
        "project": {
            "id": spec.project_id,
            "source_language": spec.source_language,
            "codeql_language": spec.codeql_language,
            "analysis_revision": spec.analysis_revision,
            "source_root": repo_path(spec.source_root),
            "output_root": repo_path(spec.output_root),
        },
        "reproduction_command": reproduction_command,
        "inputs": {
            "handler_inventory": {
                "path": repo_path(handler_csv),
                "sha256": sha256_file(handler_csv),
                "rows": len(handlers),
            },
            "source_files": [
                {"path": path, "sha256": digest}
                for path, digest in sorted(source_files.items())
            ],
        },
        "counts": {
            "handler_rows": len(handlers),
            "unique_tools": len(tools),
            "resolved": resolved,
            "unresolved": unresolved,
        },
        "tools": tools,
    }
    validate_inventory(inventory)
    return inventory


def validate_inventory(inventory: Mapping[str, Any]) -> None:
    if inventory.get("schema_version") != SCHEMA_VERSION:
        raise SpecificationError(f"unexpected schema_version: {inventory.get('schema_version')!r}")
    project = inventory.get("project")
    counts = inventory.get("counts")
    tools = inventory.get("tools")
    if not isinstance(project, Mapping) or not project.get("id"):
        raise SpecificationError("inventory.project.id is required")
    if not isinstance(counts, Mapping) or not isinstance(tools, list):
        raise SpecificationError("inventory counts/tools are malformed")
    if counts.get("unique_tools") != len(tools):
        raise SpecificationError("counts.unique_tools does not match tools")
    if counts.get("resolved", 0) + counts.get("unresolved", 0) != len(tools):
        raise SpecificationError("resolved/unresolved counts do not match tools")
    names = [tool.get("tool_name") for tool in tools if isinstance(tool, Mapping)]
    if names != sorted(names) or len(names) != len(set(names)):
        raise SpecificationError("tools must be unique and sorted by tool_name")


def _fenced(text: str, language: str = "") -> str:
    runs = []
    current = 0
    for char in text:
        if char == "`":
            current += 1
            runs.append(current)
        else:
            current = 0
    fence = "`" * max(3, (max(runs) + 1) if runs else 3)
    return f"{fence}{language}\n{text}\n{fence}"


def render_markdown(inventory: Mapping[str, Any]) -> str:
    project = inventory["project"]
    counts = inventory["counts"]
    lines = [
        f"# {project['id']} Tool Handler Specifications",
        "",
        "> Reproduction command (repository root): "
        f"`{inventory['reproduction_command']}`",
        "",
        "> Generated file. Do not edit by hand.",
        "",
        f"- Analysis revision: `{project['analysis_revision']}`",
        f"- Source language: `{project['source_language']}`",
        f"- Handler rows: **{counts['handler_rows']}**",
        f"- Unique tools: **{counts['unique_tools']}**",
        f"- Resolved: **{counts['resolved']}**",
        f"- Explicitly unresolved: **{counts['unresolved']}**",
        "",
    ]
    for tool in inventory["tools"]:
        lines.extend(
            [
                f"## `{tool['tool_name']}`",
                "",
                f"- Interface kind: `{tool['interface_kind']}`",
                f"- Resolution: `{tool['resolution']['status']}`",
                "- Handlers: "
                + "; ".join(
                    f"`{handler['handler_func']}` ({handler['form']}) at "
                    f"`{handler['file']}:{handler['line']}`"
                    for handler in tool["handlers"]
                ),
            ]
        )
        if tool["resolution"]["status"] == "unresolved":
            lines.extend(
                [
                    f"- Reason code: `{tool['resolution']['reason_code']}`",
                    f"- Reason: {tool['resolution'].get('reason', '')}",
                    "",
                ]
            )
        else:
            function = tool["function"]
            lines.extend(
                [
                    "",
                    "### Description",
                    "",
                    _fenced(function["description"], "text"),
                    "",
                    "### Parameters",
                    "",
                    _fenced(
                        json.dumps(
                            function["parameters"],
                            ensure_ascii=False,
                            indent=2,
                            sort_keys=True,
                        ),
                        "json",
                    ),
                    "",
                ]
            )
        lines.extend(["### Evidence", ""])
        for evidence in tool["evidence"]:
            detail = f" — {evidence['detail']}" if evidence.get("detail") else ""
            lines.append(
                f"- `{evidence['file']}:{evidence['line']}` "
                f"(`{evidence['kind']}`, sha256 `{evidence['sha256']}`){detail}"
            )
        lines.extend(["", "### Runtime rules", ""])
        if tool["runtime_rules"]:
            lines.extend(
                [
                    _fenced(
                        json.dumps(
                            tool["runtime_rules"],
                            ensure_ascii=False,
                            indent=2,
                            sort_keys=True,
                        ),
                        "json",
                    ),
                    "",
                ]
            )
        else:
            lines.extend(["None.", ""])
    return "\n".join(lines).rstrip() + "\n"


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_artifacts(inventory: Mapping[str, Any], output_dir: Path) -> tuple[Path, Path]:
    validate_inventory(inventory)
    out_json = output_dir / "tool-handler-specifications.json"
    out_md = output_dir / "tool-handler-specifications.md"
    # Materialize both serializations before replacing either canonical file.
    # A schema/render failure therefore leaves an existing artifact pair intact.
    json_content = json.dumps(
        inventory, ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n"
    markdown_content = render_markdown(inventory)
    _atomic_write(out_json, json_content)
    _atomic_write(out_md, markdown_content)
    return out_json, out_md

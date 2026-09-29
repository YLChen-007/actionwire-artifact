"""Revision-bound acceptance audit for curated new-vulnerability ground truth."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import tempfile
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence
from xml.etree import ElementTree

from jsonschema import validate as validate_schema

from src.gate_semantics.contracts import estimate_tokens
from src.group_oracle.corrections import (
    load_correction_ledger,
    resolve_correction_requirement_ids,
)
from src.projects import ProjectSpec

from .contracts import (
    CANDIDATE_SCHEMA_VERSION,
    COMPARISON_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION,
    SCHEMA_DIR,
    CoverageComparisonError,
    canonical_json,
    parse_json_response,
    sha256_file,
)
from .prompts import (
    GROUND_TRUTH_MATCH_SYSTEM,
    GROUND_TRUTH_REPAIR_SYSTEM,
    build_ground_truth_match_user,
    build_ground_truth_repair_user,
    contains_credentials,
    redact_credentials,
)
from .versions import (
    CORRECTION_DISPOSITION_SCHEMA_VERSION,
    GROUND_TRUTH_PROMPT_VERSION,
    GT_AUDIT_SCHEMA_VERSION,
    GT_CHAT_SCHEMA_VERSION,
    GT_MANIFEST_SCHEMA_VERSION,
)

DEFAULT_INPUT_TOKEN_LIMIT = 96_000
Runner = Callable[[str, str], str]
GROUND_TRUTH_LEDGER = Path(
    "design/study/vuls-new-found/all-new-xclaw-vulnerabilities.xlsx"
)

_XLSX_MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_XLSX_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_XLSX_PACKAGE_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_GROUND_TRUTH_PUBLISH_PATHS = (
    Path("ground-truth-coverage.jsonl"),
    Path("ground-truth-coverage.md"),
    Path("ground-truth-manifest.json"),
    Path("repository/ground-truth"),
)

_HERMES_TOOL_ALIASES = {
    "read_file": "_handle_read_file",
    "send_message": "send_message_tool",
    "skill_view": "_skill_view_with_bump",
    "terminal": "_handle_terminal",
}

_PYTHON_ACCEPTANCE = {
    "AstrBot": Path("design/AstrBot/astrbot-4.25.2-acceptance.json"),
    "QwenPaw": Path("design/QwenPaw/qwenpaw-v1.1.10-acceptance.json"),
    "chatgpt-on-wechat": Path(
        "design/chatgpt-on-wechat/groundtruth/cowagent-2.0.8-acceptance.json"
    ),
    "nanobot": Path("design/nanobot/nanobot-v0.1.4.post5-acceptance.json"),
    "poco-agent": Path("design/poco-agent/poco-agent-v0.5.4-acceptance.json"),
}

_STATIC_ORACLES = {
    "droidclaw": Path("design/droidclaw/inventory/droidclaw-static-oracle.json"),
    "mercury-agent": Path(
        "design/mercury-agent/inventory/mercury-agent-static-oracle.json"
    ),
    "nanoclaw": Path("design/nanoclaw/inventory/nanoclaw-static-oracle.json"),
    "openclaw-cn": Path("design/openclaw-cn/inventory/openclaw-cn-static-oracle.json"),
}


@dataclass(frozen=True)
class GroundTruthReport:
    report_id: str
    project: str
    revision: str
    report_name: str
    source_files: tuple[str, ...]
    source_sha256: tuple[str, ...]
    raw: dict[str, Any]
    boundary_status: str
    boundary_reason: str
    chain_ids: tuple[str, ...]
    rebase_evidence: tuple[str, ...]


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CoverageComparisonError(
            f"invalid ground-truth input {path}: {exc}"
        ) from exc


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise CoverageComparisonError(f"{path}:{number}: expected object")
        rows.append(value)
    return rows


def _xlsx_column(reference: str) -> int:
    letters = "".join(character for character in reference if character.isalpha())
    if not letters:
        raise CoverageComparisonError(f"invalid XLSX cell reference: {reference!r}")
    output = 0
    for character in letters.upper():
        output = output * 26 + ord(character) - ord("A") + 1
    return output


def _xlsx_text(node: ElementTree.Element) -> str:
    return "".join(child.text or "" for child in node.iter(f"{{{_XLSX_MAIN_NS}}}t"))


def _xlsx_member(target: str) -> str:
    path = PurePosixPath(target.lstrip("/"))
    if not target.startswith("/"):
        path = PurePosixPath("xl") / path
    if ".." in path.parts:
        raise CoverageComparisonError(
            "ground-truth ledger has an unsafe worksheet path"
        )
    return str(path)


def _read_ground_truth_ledger(
    repo_root: Path, ledger_path: Path
) -> tuple[dict[tuple[str, str], dict[str, Any]], dict[str, Any]]:
    resolved = (
        ledger_path.resolve()
        if ledger_path.is_absolute()
        else (repo_root / ledger_path).resolve()
    )
    try:
        relative = resolved.relative_to(repo_root)
    except ValueError as exc:
        raise CoverageComparisonError(
            "ground-truth ledger must remain inside the repository"
        ) from exc
    if not resolved.is_file():
        raise CoverageComparisonError(f"missing ground-truth ledger: {relative}")
    try:
        with zipfile.ZipFile(resolved) as archive:
            shared: list[str] = []
            if "xl/sharedStrings.xml" in archive.namelist():
                shared_root = ElementTree.fromstring(
                    archive.read("xl/sharedStrings.xml")
                )
                shared = [
                    _xlsx_text(node)
                    for node in shared_root.findall(f"{{{_XLSX_MAIN_NS}}}si")
                ]
            workbook = ElementTree.fromstring(archive.read("xl/workbook.xml"))
            sheets = workbook.findall(
                f"{{{_XLSX_MAIN_NS}}}sheets/{{{_XLSX_MAIN_NS}}}sheet"
            )
            selected = [
                sheet
                for sheet in sheets
                if sheet.attrib.get("name") == "all-new-xclaw-vulnerabilities"
                and sheet.attrib.get("state", "visible") == "visible"
            ]
            if len(selected) != 1:
                raise CoverageComparisonError(
                    "ground-truth ledger must contain one visible "
                    "all-new-xclaw-vulnerabilities sheet"
                )
            relationship_id = selected[0].attrib.get(f"{{{_XLSX_REL_NS}}}id")
            relationships = ElementTree.fromstring(
                archive.read("xl/_rels/workbook.xml.rels")
            )
            targets = {
                row.attrib.get("Id"): row.attrib.get("Target")
                for row in relationships.findall(
                    f"{{{_XLSX_PACKAGE_REL_NS}}}Relationship"
                )
            }
            target = targets.get(relationship_id)
            if not target:
                raise CoverageComparisonError(
                    "ground-truth ledger worksheet relationship is missing"
                )
            worksheet = ElementTree.fromstring(archive.read(_xlsx_member(target)))
    except (KeyError, zipfile.BadZipFile, ElementTree.ParseError, ValueError) as exc:
        if isinstance(exc, CoverageComparisonError):
            raise
        raise CoverageComparisonError(
            f"invalid ground-truth ledger {relative}: {exc}"
        ) from exc

    rows: list[tuple[int, dict[int, str]]] = []
    for row in worksheet.findall(
        f".//{{{_XLSX_MAIN_NS}}}sheetData/{{{_XLSX_MAIN_NS}}}row"
    ):
        values: dict[int, str] = {}
        row_number = int(row.attrib.get("r", len(rows) + 1))
        for cell in row.findall(f"{{{_XLSX_MAIN_NS}}}c"):
            column = _xlsx_column(cell.attrib.get("r", ""))
            cell_type = cell.attrib.get("t")
            if cell_type == "inlineStr":
                value = _xlsx_text(cell)
            else:
                value_node = cell.find(f"{{{_XLSX_MAIN_NS}}}v")
                value = "" if value_node is None else value_node.text or ""
                if cell_type == "s" and value:
                    try:
                        value = shared[int(value)]
                    except (IndexError, ValueError) as exc:
                        raise CoverageComparisonError(
                            f"ground-truth ledger has an invalid shared string at row {row_number}"
                        ) from exc
            values[column] = value.strip()
        if any(values.values()):
            rows.append((row_number, values))
    if not rows:
        raise CoverageComparisonError("ground-truth ledger is empty")
    _, header_values = rows[0]
    columns: dict[str, int] = {}
    for column, value in header_values.items():
        if not value:
            continue
        if value in columns:
            raise CoverageComparisonError(
                f"ground-truth ledger contains duplicate column {value!r}"
            )
        columns[value] = column
    required = {"project", "json-path"}
    if not required <= set(columns):
        raise CoverageComparisonError(
            f"ground-truth ledger lacks columns: {sorted(required - set(columns))}"
        )
    entries: dict[tuple[str, str], dict[str, Any]] = {}
    for row_number, values in rows[1:]:
        project = values.get(columns["project"], "").strip()
        raw_path = values.get(columns["json-path"], "").strip()
        if not project or not raw_path:
            raise CoverageComparisonError(
                f"ground-truth ledger row {row_number} needs project and json-path"
            )
        filename = Path(raw_path).name
        if not filename or Path(filename).suffix.lower() != ".json":
            raise CoverageComparisonError(
                f"ground-truth ledger row {row_number} has an invalid JSON path"
            )
        key = (project, filename)
        if key in entries:
            raise CoverageComparisonError(
                f"ground-truth ledger contains duplicate report {key}"
            )
        entries[key] = {"row": row_number, "json_path": raw_path}
    return entries, {
        "path": str(relative),
        "sha256": sha256_file(resolved),
        "reports": len(entries),
    }


def _validate_ground_truth_ledger(
    discovered: Sequence[Mapping[str, Any]],
    entries: Mapping[tuple[str, str], Mapping[str, Any]],
) -> None:
    actual: list[tuple[str, str]] = [
        (str(row["project"]), Path(str(row["path"])).name) for row in discovered
    ]
    if len(actual) != len(set(actual)):
        raise CoverageComparisonError(
            "curated ground-truth directories contain duplicate project/filename identities"
        )
    actual_set = set(actual)
    expected_set = set(entries)
    if actual_set != expected_set:
        missing = sorted(expected_set - actual_set)
        extra = sorted(actual_set - expected_set)
        raise CoverageComparisonError(
            "ground-truth ledger/directory mismatch; "
            f"missing={missing[:10]}, extra={extra[:10]}"
        )


def _stable_report_id(project: str, report_name: str) -> str:
    value = canonical_json([project, report_name]).encode("utf-8")
    return "GT-" + hashlib.sha256(value).hexdigest()[:16]


def _gt_files(spec: ProjectSpec) -> list[Path]:
    design_root = spec.design_root
    preferred = design_root / "groundtruth/new-vuls"
    if preferred.is_dir():
        root = preferred
    else:
        # Mercury's registered groundtruth symlink already resolves directly to new-vuls.
        root = design_root / "groundtruth"
    if not root.is_dir():
        return []
    # Do not recurse: malformed secondary symlink loops have existed in this corpus.
    return sorted(path for path in root.glob("*.json") if path.is_file())


def discover_ground_truth(
    specs: Sequence[ProjectSpec],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    discovered: list[dict[str, Any]] = []
    digests: dict[str, str] = {}
    for spec in sorted(
        (row.resolved() for row in specs), key=lambda row: row.project_id
    ):
        for path in _gt_files(spec):
            value = _read_json(path)
            if not isinstance(value, dict):
                raise CoverageComparisonError(
                    f"ground-truth report must be an object: {path}"
                )
            report_name = value.get("report_name")
            if not isinstance(report_name, str) or not report_name.strip():
                raise CoverageComparisonError(
                    f"ground-truth report lacks report_name: {path}"
                )
            rel = str(path.relative_to(Path(__file__).resolve().parents[2]))
            digest = sha256_file(path)
            digests[rel] = digest
            discovered.append(
                {
                    "project": spec.project_id,
                    "revision": spec.analysis_revision,
                    "report_name": report_name,
                    "path": rel,
                    "sha256": digest,
                    "raw": value,
                }
            )
    return discovered, digests


def _semantic_core(raw: Mapping[str, Any]) -> dict[str, Any]:
    handlers = sorted(
        {
            row.get("name", "")
            for row in raw.get("d5_tool_handler_entry", [])
            if isinstance(row, dict)
        }
    )
    sinks = sorted(
        {
            (
                row.get("name", ""),
                str(row.get("location", "")).split(" @ ", 1)[0],
                row.get("problematic_parameter", ""),
            )
            for row in raw.get("d5_sink_points", [])
            if isinstance(row, dict)
        }
    )
    return {
        "llm_to_tool_pattern_match": raw.get("llm_to_tool_pattern_match"),
        "gate_type": raw.get("d5_gate_type"),
        "handlers": handlers,
        "sinks": sinks,
        "defect_locations": sorted(raw.get("d5_defect_location") or []),
    }


def deduplicate_ground_truth(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[(row["project"], row["report_name"])].append(row)
    output: list[dict[str, Any]] = []
    for key, variants in sorted(groups.items()):
        cores = [_semantic_core(row["raw"]) for row in variants]
        identities = {
            _json_key(
                {
                    "llm_to_tool_pattern_match": core["llm_to_tool_pattern_match"],
                    "gate_type": core["gate_type"],
                }
            )
            for core in cores
        }
        if len(identities) != 1:
            raise CoverageComparisonError(
                f"{key[0]}:{key[1]} has conflicting duplicate semantic identities"
            )
        # Prefer the reviewed non-copy/non-backup report, but preserve all variant evidence.
        selected = min(
            variants,
            key=lambda row: (
                "backup" in Path(row["path"]).stem.lower()
                or "copy" in Path(row["path"]).stem.lower(),
                row["path"],
            ),
        )
        merged = dict(selected)
        ordered_variants = sorted(variants, key=lambda row: row["path"])
        # These arrays are positional: keep each digest beside the path it hashes.
        merged["source_files"] = [row["path"] for row in ordered_variants]
        merged["source_sha256"] = [row["sha256"] for row in ordered_variants]
        # Keep every duplicate's raw anchors for revision rebasing.  The selected
        # report remains the sole source of the semantic invariant, but a reviewed
        # backup/copy can contain a more precise current handler or terminal-sink
        # anchor than the primary file.  Dropping those anchors caused exact current
        # chains to disappear before the strict semantic candidate comparison.
        merged["variant_raws"] = [row["raw"] for row in ordered_variants]
        merged["duplicate_semantic_variant"] = (
            len({_json_key(core) for core in cores}) > 1
        )
        output.append(merged)
    return output


def _json_key(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _structural_rows(spec: ProjectSpec) -> list[dict[str, str]]:
    path = spec.output_root / "static/call-chains/handler-sink-chains.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if any(row["project_id"] != spec.project_id for row in rows):
        raise CoverageComparisonError(f"{spec.project_id}: structural project mismatch")
    return rows


def _chain_lookup(rows: Sequence[Mapping[str, str]]) -> dict[str, Mapping[str, str]]:
    result = {row["chain_id"]: row for row in rows}
    if len(result) != len(rows):
        raise CoverageComparisonError("duplicate structural chain IDs")
    return result


def _match_current_chain(
    rows: Sequence[Mapping[str, str]],
    *,
    tools: Iterable[str],
    sink_file: str,
    sink_line: str,
) -> list[str]:
    tool_set = set(tools)
    return sorted(
        row["chain_id"]
        for row in rows
        if row["tool_name"] in tool_set
        and row["sink_file"] == sink_file
        and row["sink_line"] == str(sink_line)
    )


def _python_boundaries(repo_root: Path, project: str) -> dict[str, tuple[str, str]]:
    path = _PYTHON_ACCEPTANCE.get(project)
    if path is None:
        return {}
    payload = _read_json(repo_root / path)
    output: dict[str, tuple[str, str]] = {}
    for dimension in payload.get("dimensions", []):
        status = str(dimension.get("current_status", "affected"))
        scope = str(dimension.get("model_scope", "handler-to-sink"))
        if "fixed" in status:
            boundary = "fixed-at-analysis-revision"
        elif "not-present" in status:
            boundary = "not-present-at-analysis-revision"
        elif scope == "out-of-model" or "outside-model" in status:
            boundary = "out-of-model"
        else:
            boundary = "eligible"
        reason = str(dimension.get("reason", status))
        for report_name in dimension.get("source_reports", []):
            output[report_name] = (boundary, reason)
    return output


def _python_chain_map(
    repo_root: Path, project: str, rows: Sequence[Mapping[str, str]]
) -> dict[str, set[str]]:
    acceptance = _PYTHON_ACCEPTANCE.get(project)
    if acceptance is None:
        return {}
    payload = _read_json(repo_root / acceptance)
    by_report: dict[str, set[str]] = defaultdict(set)
    for dimension in payload.get("dimensions", []):
        chains: set[str] = set()
        for flow in dimension.get("flows", []):
            tool = flow.get("handler")
            for point in flow.get("sink_points", []):
                sink_file, sink_line = str(point).rsplit(":", 1)
                chains.update(
                    _match_current_chain(
                        rows, tools=[tool], sink_file=sink_file, sink_line=sink_line
                    )
                )
        # CowAgent's older contract stores handler/sink directly on the dimension.
        tool = dimension.get("handler")
        for point in dimension.get("sink_points", []):
            sink_file, sink_line = str(point).rsplit(":", 1)
            chains.update(
                _match_current_chain(
                    rows, tools=[tool], sink_file=sink_file, sink_line=sink_line
                )
            )
        for report_name in dimension.get("source_reports", []):
            by_report[report_name].update(chains)
    return by_report


def _static_oracle_chain_map(
    repo_root: Path, project: str, rows: Sequence[Mapping[str, str]]
) -> tuple[dict[str, set[str]], list[str]]:
    oracle_path = _STATIC_ORACLES[project]
    payload = _read_json(repo_root / oracle_path)
    trace_path = (
        repo_root / f"design/{project}/call-chain/debug/oracle-matcher-trace.json"
    )
    trace = _read_json(trace_path)
    if project == "droidclaw":
        trace_records = [
            {"record_id": record["record_id"], **trace}
            for record in payload.get("eligible_sink_records", [])
        ]
    elif isinstance(trace, list):
        trace_records = trace
    else:
        trace_records = trace.get("records", [])
    trace_by_id = {
        record.get("record_id", record.get("oracle_record_id")): record
        for record in trace_records
    }
    by_report: dict[str, set[str]] = defaultdict(set)
    evidence = [str(oracle_path), str(trace_path.relative_to(repo_root))]
    structural = _chain_lookup(rows)
    for record in payload.get("eligible_sink_records", []):
        report_paths = record.get("report_paths") or [record.get("report_path")]
        trace_row = trace_by_id.get(record["record_id"])
        if trace_row is None:
            raise CoverageComparisonError(
                f"{project}:{record['record_id']}: missing matcher trace"
            )
        selected = (
            trace_row.get("selected_chain_ids")
            or trace_row.get("candidate_chain_ids")
            or []
        )
        for chain_id in selected:
            if chain_id not in structural:
                raise CoverageComparisonError(
                    f"{project}: stale matcher chain {chain_id}"
                )
        for report_path in report_paths:
            if report_path:
                by_report[Path(report_path).stem].update(selected)
    return by_report, evidence


def _openclaw_binding(
    repo_root: Path, rows: Sequence[Mapping[str, str]]
) -> tuple[dict[str, set[str]], dict[str, tuple[str, str]], list[str]]:
    inventory_path = repo_root / "design/openclaw/inventory/debug/sink-inventory.json"
    trace_path = (
        repo_root / "design/openclaw/call-chain/debug/oracle-matcher-trace.json"
    )
    inventory = _read_json(inventory_path)
    trace = _read_json(trace_path)
    trace_by_id = {row["record_id"]: row for row in trace["records"]}
    structural = _chain_lookup(rows)
    chains: dict[str, set[str]] = defaultdict(set)
    boundary: dict[str, tuple[str, str]] = {}
    name_by_stem = {
        path.stem: _read_json(path).get("report_name", path.stem)
        for path in (repo_root / "design/openclaw/groundtruth/new-vuls").glob("*.json")
    }
    for record in inventory["records"]:
        report_path = record["report_path"]
        if not report_path.startswith("new-vuls/"):
            continue
        report_stem = Path(report_path).stem
        if report_stem not in name_by_stem:
            continue
        report_name = name_by_stem[report_stem]
        if record["mapping_status"] == "excluded-boundary":
            boundary[report_name] = ("out-of-model", record["status_reason"])
            continue
        if record["anchor_status"] == "not-present":
            boundary[report_name] = (
                "not-present-at-analysis-revision",
                record["status_reason"],
            )
            continue
        trace_row = trace_by_id.get(record["record_id"])
        if trace_row is None:
            continue
        selected = trace_row.get("selected_chain_ids", [])
        if any(chain_id not in structural for chain_id in selected):
            raise CoverageComparisonError(
                f"openclaw:{record['record_id']}: stale matcher chain"
            )
        chains[report_name].update(selected)
    return (
        chains,
        boundary,
        [
            str(inventory_path.relative_to(repo_root)),
            str(trace_path.relative_to(repo_root)),
        ],
    )


def _hermes_chains(
    raw: Mapping[str, Any],
    rows: Sequence[Mapping[str, str]],
    *,
    revision: str,
    binding: Mapping[str, Any] | None = None,
) -> set[str]:
    binding = binding or raw.get("coverage_chain_binding")
    if binding is not None:
        if not isinstance(binding, dict) or set(binding) != {
            "schema_version",
            "revision",
            "handler",
            "effect_sink",
            "expected_policy_sink",
        }:
            raise CoverageComparisonError("Hermes coverage chain binding fields mismatch")
        if (
            binding["schema_version"] != "coverage-chain-binding/v1"
            or binding["revision"] != revision
        ):
            raise CoverageComparisonError("Hermes coverage chain binding revision drift")
        handler = binding["handler"]
        sink = binding["effect_sink"]
        expected_policy_sink = binding["expected_policy_sink"]
        if (
            not isinstance(handler, dict)
            or set(handler) != {"tool_name", "file", "line", "source_parameter"}
            or not isinstance(sink, dict)
            or set(sink) != {"name", "file", "line", "problematic_parameter"}
            or not isinstance(expected_policy_sink, dict)
            or set(expected_policy_sink)
            != {"name", "file", "line", "problematic_parameter"}
        ):
            raise CoverageComparisonError("Hermes coverage chain binding shape is invalid")
        matched = {
            row["chain_id"]
            for row in rows
            if row["tool_name"] == handler["tool_name"]
            and row["handler_file"] == handler["file"]
            and int(row["handler_line"]) == handler["line"]
            and row["source_parameter"] == handler["source_parameter"]
            and row["sink_label"] == sink["name"]
            and row["sink_file"] == sink["file"]
            and int(row["sink_line"]) == sink["line"]
            and row["sink_argument"] == sink["problematic_parameter"]
        }
        if len(matched) != 1:
            raise CoverageComparisonError(
                "Hermes coverage chain binding must resolve exactly one current chain"
            )
        return matched
    tools = {
        _HERMES_TOOL_ALIASES.get(record.get("name"), record.get("name"))
        for record in raw.get("d5_tool_handler_entry", [])
        if isinstance(record, dict)
    }
    chains: set[str] = set()
    for sink in raw.get("d5_sink_points", []):
        if not isinstance(sink, dict):
            continue
        location = str(sink.get("location", "")).split(" @ ", 1)[0]
        try:
            sink_file, sink_line = location.rsplit(":", 1)
        except ValueError:
            continue
        chains.update(
            _match_current_chain(
                rows, tools=tools, sink_file=sink_file, sink_line=sink_line
            )
        )
    return chains


def _lettabot_chains(
    raw: Mapping[str, Any], rows: Sequence[Mapping[str, str]]
) -> set[str]:
    handler_anchors: set[tuple[str, str, str]] = set()
    for record in raw.get("d5_tool_handler_entry", []):
        if not isinstance(record, dict):
            continue
        location = str(record.get("location", "")).split(" @ ", 1)[0]
        try:
            handler_file, handler_line = location.rsplit(":", 1)
        except ValueError:
            continue
        name = record.get("name")
        if isinstance(name, str) and name:
            handler_anchors.add((name, handler_file, handler_line))
    return {
        row["chain_id"]
        for row in rows
        if (
            row.get("tool_name", ""),
            row.get("handler_file", ""),
            row.get("handler_line", ""),
        )
        in handler_anchors
        and "subagent_type" in row.get("sink_argument", "").split(";")
    }


def bind_ground_truth(
    specs: Sequence[ProjectSpec], rows: Sequence[Mapping[str, Any]]
) -> tuple[list[GroundTruthReport], dict[str, str]]:
    repo_root = Path(__file__).resolve().parents[2]
    binding_path = Path(__file__).with_name("coverage-chain-bindings-v9.json")
    binding_registry = _read_json(binding_path)
    if (
        binding_registry.get("schema_version")
        != "coverage-chain-binding-registry/v1"
        or binding_registry.get("analysis_mode")
        != "canonical-trained-detector/v9"
        or not isinstance(binding_registry.get("bindings"), list)
    ):
        raise CoverageComparisonError("coverage chain binding registry is invalid")
    bindings_by_report = {
        row["report_id"]: {
            key: value for key, value in row.items() if key != "report_id"
        }
        for row in binding_registry["bindings"]
    }
    if len(bindings_by_report) != len(binding_registry["bindings"]):
        raise CoverageComparisonError("coverage chain bindings contain duplicate reports")
    by_spec = {spec.project_id: spec.resolved() for spec in specs}
    structural = {project: _structural_rows(spec) for project, spec in by_spec.items()}
    python_maps = {
        project: _python_chain_map(repo_root, project, structural[project])
        for project in _PYTHON_ACCEPTANCE
        if project in structural
    }
    boundaries = {
        project: _python_boundaries(repo_root, project)
        for project in _PYTHON_ACCEPTANCE
        if project in structural
    }
    static_maps: dict[str, dict[str, set[str]]] = {}
    evidence: dict[str, str] = {}
    for project in _STATIC_ORACLES:
        mapping, paths = _static_oracle_chain_map(
            repo_root, project, structural[project]
        )
        static_maps[project] = mapping
        for path in paths:
            evidence[path] = sha256_file(repo_root / path)
    openclaw_map, openclaw_boundaries, paths = _openclaw_binding(
        repo_root, structural["openclaw"]
    )
    boundaries["openclaw"] = openclaw_boundaries
    for path in paths:
        evidence[path] = sha256_file(repo_root / path)
    for path in _PYTHON_ACCEPTANCE.values():
        evidence[str(path)] = sha256_file(repo_root / path)
    for path in _STATIC_ORACLES.values():
        evidence[str(path)] = sha256_file(repo_root / path)
    evidence[str(binding_path.relative_to(repo_root))] = sha256_file(binding_path)

    output: list[GroundTruthReport] = []
    for row in rows:
        project = row["project"]
        raw = row["raw"]
        report_name = row["report_name"]
        status, reason = boundaries.get(project, {}).get(
            report_name,
            (
                "out-of-model"
                if raw.get("llm_to_tool_pattern_match") == "not-in-model"
                else "eligible",
                "raw report boundary"
                if raw.get("llm_to_tool_pattern_match") == "not-in-model"
                else "revision-pinned in-model report",
            ),
        )
        if project in python_maps:
            chains = python_maps[project].get(report_name, set())
            rebase = [str(_PYTHON_ACCEPTANCE[project])]
        elif project in static_maps:
            chains = static_maps[project].get(report_name, set())
            rebase = [
                str(_STATIC_ORACLES[project]),
                f"design/{project}/call-chain/debug/oracle-matcher-trace.json",
            ]
        elif project == "openclaw":
            chains = openclaw_map.get(report_name, set())
            rebase = paths
        elif project == "hermes-agent":
            variant_raws = row.get("variant_raws", [raw])
            chains = {
                chain_id
                for variant_raw in variant_raws
                for chain_id in _hermes_chains(
                    variant_raw,
                    structural[project],
                    revision=row["revision"],
                    binding=bindings_by_report.get(
                        _stable_report_id(project, report_name)
                    ),
                )
            }
            rebase = ["current output/hermes structural chain identity"]
        elif project == "lettabot":
            variant_raws = row.get("variant_raws", [raw])
            chains = {
                chain_id
                for variant_raw in variant_raws
                for chain_id in _lettabot_chains(variant_raw, structural[project])
            }
            rebase = ["current output/lettabot structural chain identity"]
        else:
            chains = set()
            rebase = []
        if status == "eligible" and not chains:
            status = "no-current-structural-chain"
            reason = "no exact revision-bound current handler-to-sink chain represents the report"
        output.append(
            GroundTruthReport(
                report_id=_stable_report_id(project, report_name),
                project=project,
                revision=row["revision"],
                report_name=report_name,
                source_files=tuple(row["source_files"]),
                source_sha256=tuple(row["source_sha256"]),
                raw=raw,
                boundary_status=status,
                boundary_reason=reason,
                chain_ids=tuple(sorted(chains)),
                rebase_evidence=tuple(sorted(rebase)),
            )
        )
    return sorted(output, key=lambda row: (row.project, row.report_name)), evidence


def _report_invariant(report: GroundTruthReport) -> dict[str, Any]:
    raw = report.raw
    return {
        "report_name": report.report_name,
        "gate_type": raw.get("d5_gate_type"),
        "defect_locations": raw.get("d5_defect_location"),
        "missing_check": raw.get("d5_gate_missing_check"),
        "existing_gate_status": raw.get("d5_gate_exist_current_version"),
        "verdict_reason": raw.get("verdict_reason"),
        "affected_gate_policies": [
            {
                "name": row.get("name"),
                "policy": row.get("policy"),
                "is_defect_site": row.get("is_defect_site"),
            }
            for row in raw.get("d5_gate_points", [])
            if isinstance(row, dict)
        ],
        "controlled_sink_facets": [
            {
                "name": row.get("name"),
                "problematic_parameter": row.get("problematic_parameter"),
            }
            for row in raw.get("d5_sink_points", [])
            if isinstance(row, dict)
        ],
    }


def _candidate_prompt_record(candidate: Mapping[str, Any]) -> dict[str, Any]:
    output = {
        "candidate_id": candidate["candidate_id"],
        "failure_mode": candidate["failure_mode"],
        "requirement_id": candidate["requirement_id"],
        "requirement_rule": candidate["requirement_rule"],
        "requirement_applicability": candidate["requirement_applicability"],
        "reason": candidate["reason"],
        "gate_ids": candidate["gate_ids"],
        "provenance": candidate.get("provenance", {}),
        "source_context": candidate.get("source_context", {}),
    }
    if candidate.get("overlap_group_requirements"):
        output["overlap_group_requirements"] = candidate[
            "overlap_group_requirements"
        ]
    return output


def _validate_match(
    value: Mapping[str, Any], *, report_id: str, candidate_id: str
) -> dict[str, Any]:
    if set(value) != {
        "report_id",
        "candidate_id",
        "verdict",
        "same_controlled_security_invariant",
        "reason",
    }:
        raise CoverageComparisonError("ground-truth match response fields mismatch")
    if value["report_id"] != report_id or value["candidate_id"] != candidate_id:
        raise CoverageComparisonError("ground-truth match response identity mismatch")
    verdict = value["verdict"]
    same = value["same_controlled_security_invariant"]
    reason = value["reason"]
    if verdict not in {"match", "no-match"} or not isinstance(same, bool):
        raise CoverageComparisonError("invalid ground-truth match verdict")
    if not isinstance(reason, str) or not reason.strip():
        raise CoverageComparisonError("ground-truth match reason is empty")
    if (verdict == "match") != same:
        raise CoverageComparisonError("ground-truth match boolean/verdict disagreement")
    return {
        "candidate_id": candidate_id,
        "verdict": verdict,
        "same_controlled_security_invariant": same,
        "reason": " ".join(reason.split()),
    }


def _parse_match_response(raw: str) -> dict[str, Any]:
    try:
        return parse_json_response(raw)
    except CoverageComparisonError as original:
        text = raw.strip()
        if text.startswith("```json"):
            text = text[7:].lstrip()
        decoder = json.JSONDecoder()
        try:
            value, _ = decoder.raw_decode(text)
        except json.JSONDecodeError:
            raise original
        if not isinstance(value, dict):
            raise original
        return value


def _normalize_match_identity(
    value: Mapping[str, Any], *, report_id: str, candidate_id: str
) -> tuple[dict[str, Any], str | None]:
    """Normalize copy-only pair identifiers without changing the match verdict."""
    output = dict(value)
    changes = []
    if output.get("report_id") != report_id:
        output["report_id"] = report_id
        changes.append("report_id")
    if output.get("candidate_id") != candidate_id:
        output["candidate_id"] = candidate_id
        changes.append("candidate_id")
    return output, ",".join(changes) if changes else None


def _match_call(
    *, runner: Runner, user: str, report_id: str, candidate_id: str
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    exchanges: list[dict[str, str]] = []
    raw = redact_credentials(runner(GROUND_TRUTH_MATCH_SYSTEM, user))
    exchanges.append(
        {"system": GROUND_TRUTH_MATCH_SYSTEM, "user": user, "response": raw}
    )
    try:
        parsed, normalization = _normalize_match_identity(
            _parse_match_response(raw),
            report_id=report_id,
            candidate_id=candidate_id,
        )
        if normalization is not None:
            exchanges[-1]["normalization"] = normalization
        return _validate_match(
            parsed,
            report_id=report_id,
            candidate_id=candidate_id,
        ), exchanges
    except Exception as first:
        repair_user = build_ground_truth_repair_user(
            user, raw, f"{type(first).__name__}: {first}"
        )
        repaired = redact_credentials(runner(GROUND_TRUTH_REPAIR_SYSTEM, repair_user))
        exchanges.append(
            {
                "system": GROUND_TRUTH_REPAIR_SYSTEM,
                "user": repair_user,
                "response": repaired,
            }
        )
        try:
            parsed, normalization = _normalize_match_identity(
                _parse_match_response(repaired),
                report_id=report_id,
                candidate_id=candidate_id,
            )
            if normalization is not None:
                exchanges[-1]["normalization"] = normalization
            return _validate_match(
                parsed,
                report_id=report_id,
                candidate_id=candidate_id,
            ), exchanges
        except Exception as second:
            invalidate = getattr(runner, "invalidate_prompts", None)
            if callable(invalidate):
                invalidate(
                    [
                        (GROUND_TRUTH_MATCH_SYSTEM, user),
                        (GROUND_TRUTH_REPAIR_SYSTEM, repair_user),
                    ]
                )
            raise CoverageComparisonError(
                f"{report_id}:{candidate_id}: unrepaired ground-truth response: {second}"
            ) from second


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _path_exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _publish_ground_truth_artifacts(
    staging: Path,
    coverage_root: Path,
    publish_paths: Sequence[Path] = _GROUND_TRUTH_PUBLISH_PATHS,
) -> None:
    missing = [str(path) for path in publish_paths if not _path_exists(staging / path)]
    if missing:
        raise CoverageComparisonError(f"ground-truth staging is incomplete: {missing}")
    backup = coverage_root.parent / f".{coverage_root.name}.ground-truth.previous"
    if _path_exists(backup):
        raise CoverageComparisonError(
            f"stale ground-truth publication backup exists: {backup}"
        )
    backup.mkdir(parents=True)
    moved_old: list[Path] = []
    installed: list[Path] = []
    try:
        for relative in publish_paths:
            destination = coverage_root / relative
            if not _path_exists(destination):
                continue
            prior = backup / relative
            prior.parent.mkdir(parents=True, exist_ok=True)
            os.replace(destination, prior)
            moved_old.append(relative)
        for relative in publish_paths:
            source = staging / relative
            destination = coverage_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, destination)
            installed.append(relative)
    except Exception:
        for relative in reversed(installed):
            destination = coverage_root / relative
            source = staging / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            if _path_exists(destination):
                os.replace(destination, source)
        for relative in reversed(moved_old):
            prior = backup / relative
            destination = coverage_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if _path_exists(prior):
                os.replace(prior, destination)
        shutil.rmtree(backup)
        raise
    shutil.rmtree(backup)
    shutil.rmtree(staging)


def _render(
    command: str,
    rows: Sequence[Mapping[str, Any]],
    *,
    baseline_counts: Mapping[str, Any] | None = None,
    baseline_label: str = "Blind baseline",
    dispositions: Sequence[Mapping[str, Any]] = (),
) -> str:
    counts = Counter(row["status"] for row in rows)
    by_project: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        by_project[row["project"]][row["status"]] += 1
    lines = [
        "# Coverage-Comparison Ground-Truth Acceptance",
        "",
        f"> Generation command: `{command}`",
        "",
        "## Results",
        "",
        f"Unique reports: **{len(rows)}**; required eligible reports: "
        f"**{counts['covered'] + counts['missed']}**; semantically covered: "
        f"**{counts['covered']}**; missed: **{counts['missed']}**.",
        "",
        "A report is covered only when a pinned current chain represents it and at least one "
        "candidate on that chain expresses the same controlled security invariant.",
        "",
        "| Project | Reports | Covered | Missed | Fixed | Not present | Out of model | No chain |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for project, counter in sorted(by_project.items()):
        lines.append(
            f"| `{project}` | {sum(counter.values())} | {counter['covered']} | "
            f"{counter['missed']} | {counter['fixed-at-analysis-revision']} | "
            f"{counter['not-present-at-analysis-revision']} | {counter['out-of-model']} | "
            f"{counter['no-current-structural-chain']} |"
        )
    lines += [
        "",
        "## Per-report Audit",
        "",
        "| Project | Report | Status | Chains | Candidate matches | Reason |",
        "|---|---|---|---:|---:|---|",
    ]
    for row in rows:
        reason = str(row["reason"]).replace("|", "\\|")
        lines.append(
            f"| `{row['project']}` | `{row['report_name']}` | `{row['status']}` | "
            f"{len(row['chain_ids'])} | {len(row['matched_candidate_ids'])} | {reason} |"
        )
    if baseline_counts is not None:
        disposition_counts = Counter(row["disposition"] for row in dispositions)
        lines += [
            "",
            "## Post-hoc Correction v2",
            "",
            "This v2 result is ground-truth-informed corrective analysis over an explicitly "
            "post-hoc benchmark overlay and does not replace the original blind experiment.",
            "",
            f"{baseline_label}: **{baseline_counts['covered_reports']}/"
            f"{baseline_counts['eligible_reports']}** covered. Corrected v2: "
            f"**{counts['covered']}/{counts['covered'] + counts['missed']}** covered.",
            "",
            "Correction dispositions: "
            + ", ".join(
                f"`{key}` **{value}**"
                for key, value in sorted(disposition_counts.items())
            )
            + ".",
        ]
    return "\n".join(lines) + "\n"


def _correction_dispositions(
    *,
    ledger: Mapping[str, Any],
    coverage_root: Path,
    coverage_manifest: Mapping[str, Any],
    audit_rows: Sequence[Mapping[str, Any]],
    candidates: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    group_root = Path(str(coverage_manifest["corrected_group_root"]))
    oracles = {
        row["group_id"]: row for row in _read_jsonl(group_root / "oracles.jsonl")
    }
    baseline_group_root = Path(ledger["baseline"]["group_root"])
    baseline_oracles = {
        row["group_id"]: row
        for row in _read_jsonl(baseline_group_root / "oracles.jsonl")
    }
    assessments = {
        (row["project"], row["chain_id"], row["requirement_id"]): row
        for row in _read_jsonl(coverage_root / "requirement-assessments.jsonl")
    }
    challenge_path = coverage_root / "requirement-challenges.jsonl"
    challenges = {
        (row["project"], row["chain_id"], row["requirement_id"]): row
        for row in _read_jsonl(challenge_path)
    }
    candidates_by_key: dict[tuple[str, str, str], list[Mapping[str, Any]]] = (
        defaultdict(list)
    )
    for candidate in candidates:
        candidates_by_key[
            (candidate["project"], candidate["chain_id"], candidate["requirement_id"])
        ].append(candidate)
    audit_by_id = {row["report_id"]: row for row in audit_rows}
    correction_locators_by_group: dict[str, set[str]] = defaultdict(set)
    for correction in ledger["corrections"]:
        for group in correction["groups"]:
            correction_locators_by_group[group["group_id"]].update(
                correction["evidence_locators"]
            )
    requirement_dimension = {
        (group_id, requirement["requirement_id"]): requirement["dimension"]
        for group_id, oracle in oracles.items()
        for requirement in oracle["requirements"]
    }
    schema = _read_json(SCHEMA_DIR / "coverage-correction-disposition-v7.schema.json")
    output: list[dict[str, Any]] = []
    for correction in sorted(ledger["corrections"], key=lambda row: row["report_id"]):
        report = audit_by_id[correction["report_id"]]
        group_ids = sorted(row["group_id"] for row in correction["groups"])
        requirement_ids = resolve_correction_requirement_ids(
            correction,
            corrected_oracles=oracles,
            baseline_oracles=baseline_oracles,
        )
        if not requirement_ids:
            raise CoverageComparisonError(
                f"{correction['report_id']}: correction produced no requirement"
            )
        primary_decisions: list[str] = []
        challenge_decisions: list[str] = []
        final_decisions: list[str] = []
        related_candidates: list[str] = []
        unknown = False
        for chain_id in correction["chain_ids"]:
            for requirement_id in sorted(requirement_ids):
                key = (correction["project"], chain_id, requirement_id)
                assessment = assessments.get(key)
                if assessment is None:
                    continue
                final_decisions.append(
                    f"{chain_id}:{requirement_id}:{assessment['decision']}"
                )
                unknown = unknown or assessment["decision"] == "unknown"
                challenge = challenges.get(key)
                if challenge is None:
                    primary_decisions.append(
                        f"{chain_id}:{requirement_id}:{assessment['decision']}"
                    )
                else:
                    primary_decisions.append(
                        f"{chain_id}:{requirement_id}:"
                        f"{challenge['primary_assessment']['decision']}"
                    )
                    challenge_decisions.append(
                        f"{chain_id}:{requirement_id}:"
                        f"{challenge['challenge_assessment']['decision']}"
                    )
                related_candidates.extend(
                    candidate["candidate_id"]
                    for candidate in candidates_by_key.get(key, [])
                )
        related_candidates = sorted(set(related_candidates))
        if not unknown:
            for chain_id in correction["chain_ids"]:
                for group_id in group_ids:
                    locators = correction_locators_by_group[group_id]
                    unknown = unknown or any(
                        project == correction["project"]
                        and candidate_chain == chain_id
                        and assessment["decision"] == "unknown"
                        and requirement_dimension.get((group_id, requirement_id))
                        in locators
                        for (
                            project,
                            candidate_chain,
                            requirement_id,
                        ), assessment in assessments.items()
                    )
        matched = sorted(set(report["matched_candidate_ids"]) & set(related_candidates))
        if matched:
            disposition = "corrected-match"
            reason = (
                "A correction-bound candidate strictly matches the curated invariant."
            )
        elif unknown:
            disposition = "evidence-insufficient"
            reason = (
                "The corrected requirement remains unknown because the current bound evidence "
                "is insufficient for a defensible verdict."
            )
        else:
            disposition = "unresolved-error"
            reason = "No correction-bound strict match or evidence-sufficient unknown was produced."
        row = {
            "schema_version": CORRECTION_DISPOSITION_SCHEMA_VERSION,
            "report_id": correction["report_id"],
            "project": correction["project"],
            "report_name": correction["report_name"],
            "action": correction["action"],
            "group_ids": group_ids,
            "chain_ids": sorted(correction["chain_ids"]),
            "corrected_requirement_ids": sorted(requirement_ids),
            "primary_decisions": sorted(primary_decisions),
            "challenge_decisions": sorted(challenge_decisions),
            "final_decisions": sorted(final_decisions),
            "candidate_ids": related_candidates,
            "matched_candidate_ids": matched,
            "disposition": disposition,
            "reason": reason,
        }
        validate_schema(instance=row, schema=schema)
        output.append(row)
    return output


def run_ground_truth_audit(
    *,
    specs: Sequence[ProjectSpec],
    coverage_root: Path,
    generation_command: str,
    runner: Runner,
    ledger_path: Path = GROUND_TRUTH_LEDGER,
    challenge_covered: bool = False,
    baseline_root: Path | None = None,
    correction_ledger: Path | None = None,
    input_token_limit: int = DEFAULT_INPUT_TOKEN_LIMIT,
) -> dict[str, Any]:
    discovered, gt_digests = discover_ground_truth(specs)
    repo_root = Path(__file__).resolve().parents[2]
    ledger_entries, ledger_binding = _read_ground_truth_ledger(repo_root, ledger_path)
    _validate_ground_truth_ledger(discovered, ledger_entries)
    deduplicated = deduplicate_ground_truth(discovered)
    if len(deduplicated) != len(ledger_entries):
        raise CoverageComparisonError(
            "ground-truth ledger rows do not have unique project/report_name identities"
        )
    reports, rebase_digests = bind_ground_truth(specs, deduplicated)
    no_chain = [
        f"{report.project}:{report.report_name}"
        for report in reports
        if report.boundary_status == "no-current-structural-chain"
    ]
    if no_chain:
        raise CoverageComparisonError(
            "eligible ground-truth reports lack current structural chains: "
            + ", ".join(no_chain)
        )
    manifest_path = coverage_root / "manifest.json"
    manifest = _read_json(manifest_path)
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise CoverageComparisonError(
            "ground-truth audit requires the canonical coverage v7 manifest"
        )
    correction_mode = any(
        (challenge_covered, baseline_root is not None, correction_ledger is not None)
    )
    if correction_mode and not (
        challenge_covered
        and baseline_root is not None
        and correction_ledger is not None
    ):
        raise CoverageComparisonError(
            "corrected ground-truth audit requires challenge-covered, baseline-root, "
            "and correction-ledger together"
        )
    correction_payload: dict[str, Any] | None = None
    correction_binding: dict[str, Any] | None = None
    baseline_counts: Mapping[str, Any] | None = None
    baseline_label = "Blind baseline"
    if correction_mode:
        correction_payload, correction_binding = load_correction_ledger(
            correction_ledger
        )
        if (
            baseline_root.resolve()
            != Path(correction_payload["baseline"]["coverage_root"]).resolve()
        ):
            raise CoverageComparisonError(
                "baseline-root disagrees with correction ledger"
            )
        if coverage_root.resolve() == baseline_root.resolve():
            raise CoverageComparisonError(
                "corrected audit must not overwrite baseline coverage"
            )
        if (
            manifest.get("analysis_mode") != "coverage-post-hoc-correction/v7"
            or manifest.get("challenge_policy")
            != "coverage-independent-challenge/v7"
            or manifest.get("correction", {}).get("sha256")
            != correction_binding["sha256"]
        ):
            raise CoverageComparisonError(
                "coverage root is not bound to this correction mode"
            )
        baseline_counts = _read_json(baseline_root / "ground-truth-manifest.json")[
            "counts"
        ]
        baseline_label = (
            "Rollback-adjusted post-hoc baseline "
            f"(`{correction_binding['baseline_provenance']['overlay_id']}`)"
        )
    candidates_path = coverage_root / "candidates.jsonl"
    comparisons_path = coverage_root / "comparisons.jsonl"
    candidates = _read_jsonl(candidates_path)
    comparisons = _read_jsonl(comparisons_path)
    comparison_schema = _read_json(SCHEMA_DIR / "coverage-comparison-v7.schema.json")
    candidate_schema = _read_json(SCHEMA_DIR / "coverage-candidate-v7.schema.json")
    for comparison in comparisons:
        validate_schema(instance=comparison, schema=comparison_schema)
        if comparison.get("schema_version") != COMPARISON_SCHEMA_VERSION:
            raise CoverageComparisonError("unsupported comparison schema")
    for candidate in candidates:
        if candidate.get("schema_version") != CANDIDATE_SCHEMA_VERSION:
            raise CoverageComparisonError("unsupported candidate schema")
        validate_schema(instance=candidate, schema=candidate_schema)
    comparison_by_key = {(row["project"], row["chain_id"]): row for row in comparisons}
    if len(comparison_by_key) != len(comparisons):
        raise CoverageComparisonError(
            "duplicate comparison identities in acceptance input"
        )
    candidates_by_key: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    candidate_ids: set[str] = set()
    for candidate in candidates:
        key = (candidate["project"], candidate["chain_id"])
        if candidate["candidate_id"] in candidate_ids:
            raise CoverageComparisonError(
                "duplicate candidate identities in acceptance input"
            )
        if key not in comparison_by_key:
            raise CoverageComparisonError(f"candidate has no comparison: {key}")
        candidate_ids.add(candidate["candidate_id"])
        candidates_by_key[key].append(candidate)
    if manifest.get("counts", {}).get("eligible_comparisons") != len(comparisons):
        raise CoverageComparisonError("coverage manifest comparison count is stale")
    if manifest.get("counts", {}).get("candidates") != len(candidates):
        raise CoverageComparisonError("coverage manifest candidate count is stale")
    for report in reports:
        if report.boundary_status != "eligible":
            continue
        for chain_id in report.chain_ids:
            comparison = comparison_by_key.get((report.project, chain_id))
            if comparison is None:
                raise CoverageComparisonError(
                    f"{report.report_id}: eligible current chain has no comparison: {chain_id}"
                )
            if comparison["revision"] != report.revision:
                raise CoverageComparisonError(
                    f"{report.report_id}: comparison revision disagreement"
                )
    rows: list[dict[str, Any]] = []
    chats: list[tuple[str, list[dict[str, str]]]] = []
    for report in reports:
        assessments: list[dict[str, Any]] = []
        if report.boundary_status == "eligible":
            for chain_id in report.chain_ids:
                comparison = comparison_by_key.get((report.project, chain_id))
                if comparison is None:
                    continue
                chain_summary = {
                    "chain_id": chain_id,
                    "handler_id": comparison["handler_id"],
                    "sink_id": comparison["sink_id"],
                    "handler_criterion_id": comparison["handler_criterion_id"],
                    "sink_type_id": comparison["sink_type_id"],
                    "controlled_argument": comparison["controlled_argument"],
                    "call_shape": comparison["call_shape"],
                }
                for candidate in sorted(
                    candidates_by_key.get((report.project, chain_id), []),
                    key=lambda row: row["candidate_id"],
                ):
                    user = build_ground_truth_match_user(
                        report_id=report.report_id,
                        project=report.project,
                        revision=report.revision,
                        report=_report_invariant(report),
                        chain=chain_summary,
                        candidate=_candidate_prompt_record(candidate),
                    )
                    if (
                        estimate_tokens(
                            {"system": GROUND_TRUTH_MATCH_SYSTEM, "user": user}
                        )
                        > input_token_limit
                    ):
                        raise CoverageComparisonError(
                            f"{report.report_id}:{candidate['candidate_id']}: audit prompt overflow"
                        )
                    assessment, exchanges = _match_call(
                        runner=runner,
                        user=user,
                        report_id=report.report_id,
                        candidate_id=candidate["candidate_id"],
                    )
                    assessment["chain_id"] = chain_id
                    assessments.append(assessment)
                    chats.append(
                        (f"{report.report_id}-{candidate['candidate_id']}", exchanges)
                    )
        matched = sorted(
            row["candidate_id"] for row in assessments if row["verdict"] == "match"
        )
        if report.boundary_status != "eligible":
            status = report.boundary_status
            reason = report.boundary_reason
        elif matched:
            status = "covered"
            reason = "at least one current-chain candidate expresses the same security invariant"
        else:
            status = "missed"
            reason = (
                "current chain has no generated candidate"
                if not assessments
                else "all current-chain candidates express different security invariants"
            )
        rows.append(
            {
                "schema_version": GT_AUDIT_SCHEMA_VERSION,
                "report_id": report.report_id,
                "project": report.project,
                "revision": report.revision,
                "report_name": report.report_name,
                "source_files": list(report.source_files),
                "source_sha256": list(report.source_sha256),
                "boundary_status": report.boundary_status,
                "chain_ids": list(report.chain_ids),
                "rebase_evidence": list(report.rebase_evidence),
                "candidate_assessments": assessments,
                "matched_candidate_ids": matched,
                "status": status,
                "reason": reason,
            }
        )
    dispositions: list[dict[str, Any]] = []
    if correction_payload is not None:
        dispositions = _correction_dispositions(
            ledger=correction_payload,
            coverage_root=coverage_root,
            coverage_manifest=manifest,
            audit_rows=rows,
            candidates=candidates,
        )
        unresolved = [
            row["report_id"]
            for row in dispositions
            if row["disposition"] == "unresolved-error"
        ]
        if unresolved:
            raise CoverageComparisonError(
                "source-correct v2 audit has unresolved correction errors: "
                + ", ".join(unresolved)
            )
    recall_floor = manifest.get("source_validation", {}).get(
        "strict_ground_truth_recall_floor"
    )
    if recall_floor is not None:
        eligible_count = sum(row["status"] in {"covered", "missed"} for row in rows)
        covered_count = sum(row["status"] == "covered" for row in rows)
        if eligible_count != recall_floor.get("eligible_reports"):
            raise CoverageComparisonError(
                "source-validated recall denominator drift: "
                f"expected {recall_floor.get('eligible_reports')}, got {eligible_count}"
            )
        if covered_count < recall_floor.get("covered_reports", 0):
            raise CoverageComparisonError(
                "source validation regressed strict ground-truth recall: "
                f"required at least {recall_floor.get('covered_reports')}/"
                f"{eligible_count}, got {covered_count}/{eligible_count}"
            )
    report_md = _render(
        generation_command,
        rows,
        baseline_counts=baseline_counts,
        baseline_label=baseline_label,
        dispositions=dispositions,
    )
    current_audit_payload = getattr(runner, "current_audit_payload", None)
    if callable(current_audit_payload):
        transport = current_audit_payload()
    elif callable(getattr(runner, "audit_payload", None)):
        transport = runner.audit_payload()
    else:
        transport = {"transport": "injected-runner", "available_tools": []}
    manifest = {
        "schema_version": GT_MANIFEST_SCHEMA_VERSION,
        "prompt_version": GROUND_TRUTH_PROMPT_VERSION,
        "generation_command": generation_command,
        "inputs": {
            "coverage_manifest": sha256_file(manifest_path),
            "candidates": sha256_file(candidates_path),
            "comparisons": sha256_file(comparisons_path),
            "ground_truth_ledger": ledger_binding,
            "ground_truth": gt_digests,
            "rebase_evidence": rebase_digests,
        },
        "counts": {
            "ledger_reports": len(ledger_entries),
            "physical_files": len(discovered),
            "unique_reports": len(rows),
            "eligible_reports": sum(
                row["status"] in {"covered", "missed"} for row in rows
            ),
            "covered_reports": sum(row["status"] == "covered" for row in rows),
            "missed_reports": sum(row["status"] == "missed" for row in rows),
            "fixed_reports": sum(
                row["status"] == "fixed-at-analysis-revision" for row in rows
            ),
            "not_present_reports": sum(
                row["status"] == "not-present-at-analysis-revision" for row in rows
            ),
            "out_of_model_reports": sum(
                row["status"] == "out-of-model" for row in rows
            ),
            "no_chain_reports": sum(
                row["status"] == "no-current-structural-chain" for row in rows
            ),
            "candidate_pair_assessments": sum(
                len(row["candidate_assessments"]) for row in rows
            ),
            "model_calls": sum(len(exchange) for _, exchange in chats),
            "repair_calls": sum(len(exchange) - 1 for _, exchange in chats),
        },
        "transport": transport,
    }
    if correction_binding is not None:
        manifest["analysis_mode"] = "coverage-post-hoc-correction/v7"
        manifest["post_hoc_ground_truth_informed"] = True
        manifest["correction"] = correction_binding
        manifest["outputs"] = {
            "correction_dispositions": str(
                coverage_root / "correction-dispositions.jsonl"
            )
        }
        manifest["counts"]["correction_dispositions"] = len(dispositions)
        manifest["counts"]["corrected_matches"] = sum(
            row["disposition"] == "corrected-match" for row in dispositions
        )
        manifest["counts"]["evidence_insufficient"] = sum(
            row["disposition"] == "evidence-insufficient" for row in dispositions
        )
        manifest["counts"]["unresolved_corrections"] = 0
    if any(
        contains_credentials(canonical_json(value))
        for value in (rows, dispositions, manifest)
    ):
        raise CoverageComparisonError("credential-shaped data in ground-truth audit")
    coverage_root.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{coverage_root.name}.ground-truth-staging-",
            dir=coverage_root.parent,
        )
    )
    try:
        _write_text(
            staging / "ground-truth-coverage.jsonl",
            "".join(canonical_json(row) + "\n" for row in rows),
        )
        _write_text(staging / "ground-truth-coverage.md", report_md)
        _write_text(
            staging / "ground-truth-manifest.json",
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        )
        publish_paths = list(_GROUND_TRUTH_PUBLISH_PATHS)
        if correction_payload is not None:
            _write_text(
                staging / "correction-dispositions.jsonl",
                "".join(canonical_json(row) + "\n" for row in dispositions),
            )
            publish_paths.append(Path("correction-dispositions.jsonl"))
        sidecar_root = staging / "repository/ground-truth"
        sidecar_root.mkdir(parents=True)
        for subject, exchanges in chats:
            _write_text(
                sidecar_root / subject / "chat.json",
                json.dumps(
                    {
                        "schema_version": GT_CHAT_SCHEMA_VERSION,
                        "stage": "ground-truth",
                        "subject": subject,
                        "exchanges": exchanges,
                    },
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n",
            )
        unsafe = [
            str(path.relative_to(staging))
            for path in sorted(item for item in staging.rglob("*") if item.is_file())
            if contains_credentials(path.read_text(encoding="utf-8"))
        ]
        if unsafe:
            raise CoverageComparisonError(
                "credential-shaped data would enter ground-truth artifacts: "
                + ", ".join(unsafe)
            )
        _publish_ground_truth_artifacts(staging, coverage_root, publish_paths)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return {"rows": rows, "manifest": manifest, "report": report_md}

#!/usr/bin/env python3
"""Map D5 ground-truth handler, gate, and sink points onto call chains."""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import heapq
import json
import re
import shlex
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from render_chain_gates_coverage import (
    DEFAULT_SOURCE_ROOTS,
    SourceIndex,
    build_chain_gates,
    parse_call_chain,
)


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = Path(__file__).resolve().parents[5]
DEBUG_DIR = SCRIPT_DIR.parent
GATE_DEBUG_DIR = DEBUG_DIR.parent.parent / "gate" / "debug"
HANDLER_DEBUG_DIR = DEBUG_DIR.parent.parent / "handler-entry" / "debug"

DEFAULT_MAIN_CHAIN_GATES = DEBUG_DIR / "chain-gates.csv"
DEFAULT_AUX_CHAINS = DEBUG_DIR / "handler-sink-discord-bridge.csv"
DEFAULT_GATE_CANDIDATES = GATE_DEBUG_DIR / "gate-candidates.csv"
DEFAULT_TRANSFORM_CANDIDATES = GATE_DEBUG_DIR / "transform-candidates.csv"
DEFAULT_TAINT_GT = GATE_DEBUG_DIR / "taintC-per-gate.csv"
DEFAULT_TRANSFORM_COVERAGE = GATE_DEBUG_DIR / "transform-gt-coverage.csv"
DEFAULT_HANDLER_ENTRIES = HANDLER_DEBUG_DIR / "tool-handler-entries.csv"
DEFAULT_OUT_CSV = DEBUG_DIR / "d5-chain-coverage.csv"
DEFAULT_OUT_ITEMS_CSV = DEBUG_DIR / "d5-chain-coverage-items.csv"
DEFAULT_OUT_DEBUG_CSV = DEBUG_DIR / "d5-chain-coverage-debug.csv"
DEFAULT_OUT_MD = DEBUG_DIR / "d5-chain-coverage.md"
DEFAULT_GT_ITEMS_SNAPSHOT = DEBUG_DIR / "d5-gt-items-snapshot.csv"

TARGET_ROOT = Path(
    "/root/my-project/agent-research/clawgap/benchmark/python/hermes-agent"
)
DEFAULT_GROUND_TRUTH_ROOT = DEBUG_DIR.parent.parent / "groundtruth" / "new-vuls"

ABSENT_GATE_NAME_RE = re.compile(
    r"\b(?:absent|lack(?:s|ing)?|missing)\b", re.IGNORECASE
)
VERSIONED_LOCATION_RE = re.compile(r"\bcommit\s+[0-9a-f]{7,40}\b", re.IGNORECASE)
NEAR_LOCATION_MAX_LINES = 8
GATE_MATCH_PRIORITY = {
    "exact-location": 60,
    "near-location-symbol": 50,
    "stale-location-symbol": 40,
    "gate-symbol": 30,
    "transform-call": 30,
    "transform-parent": 30,
    "host-parent": 20,
    "evidence-symbol": 10,
}
MAX_NESTED_GATE_DEPTH = 6


@dataclass(frozen=True)
class ReportSpec:
    gt_id: str
    path: Path


REPORT_FILES = [
    ("220-skill-view", "Issue-hermes-agent-220-skill-view-name-traversal.json"),
    ("38035-matrix", "Issue-hermes-agent-38035-matrix-adapter-markdown.json"),
    (
        "GHSA-browser-eval",
        "Advisory-GHSA-qmwg-qprg-3j38-browser-eval-private-nav.json",
    ),
    (
        "762f7e97-batch-runner",
        "feat__configurable_approval_mode_for_cron_jobs__approvals_cr-762f7e97-Batch-Runner-Variant.json",
    ),
    ("Device-Blocking", "CVE-2026-Device-Blocking-Expanduser-Bypass.json"),
    (
        "6a320e8b-messaging-creds",
        "fix_security___block_sandbox_backend_creds_from_subprocess_e-6a320e8b-MessagingCreds-Exploit-TP.json",
    ),
    (
        "Discord-Mention",
        "CVE-2026-Discord-Mention-Bypass-Mattermost-Slack.json",
    ),
    (
        "fd335a4e-rce-pattern",
        "fix__add_missing_dangerous_command_patterns_in_approval_py-fd335a4e-Remote-Code-Execution-Pattern-Bypass.json",
    ),
    ("Code-Execution-Mode", "CVE-Project-Code-Execution-Mode-Bypass.json"),
]


def report_specs(ground_truth_root: Path) -> list[ReportSpec]:
    return [
        ReportSpec(gt_id, ground_truth_root / filename)
        for gt_id, filename in REPORT_FILES
    ]


@dataclass(frozen=True)
class LocationRef:
    file: str
    line: int


@dataclass(frozen=True)
class GateRef:
    kind: str
    fn: str
    file: str
    line: int
    in_func: str
    role: str
    verdict: str


@dataclass(frozen=True)
class NestedGateMatch:
    level: int
    parent_file: str
    parent_fn: str
    child_file: str
    child_fn: str
    path: tuple[str, ...]

    @property
    def kind(self) -> str:
        return f"nested-in-gate(L{self.level})"

    @property
    def note(self) -> str:
        return (
            f"{self.kind}: confirmed parent {self.parent_fn}@{self.parent_file}; "
            f"source subtree {' -> '.join(self.path)} reaches "
            f"{self.child_fn}@{self.child_file}"
        )


@dataclass
class Chain:
    chain_id: str
    source: str
    handler_func: str
    depth: int
    sink_label: str
    sink_file: str
    sink_line: int
    call_chain: str
    gates: list[GateRef]


@dataclass(frozen=True)
class RepresentativeRule:
    file: str
    sink_label: str
    note: str
    line: int = 0


REPRESENTATIVE_SINKS: dict[tuple[str, str], RepresentativeRule] = {
    (
        "GHSA-browser-eval",
        "agent-browser Runtime.evaluate pipeline to Chromium network navigation",
    ): RepresentativeRule(
        "tools/browser_tool.py",
        "_run_browser_command",
        "The Python chain stops at the eval command handoff; agent-browser forwards that expression to Chromium Runtime.evaluate downstream.",
        line=2585,
    ),
    (
        "GHSA-browser-eval",
        "browser_snapshot tool-result disclosure pipeline",
    ): RepresentativeRule(
        "tools/browser_tool.py",
        "_run_browser_command",
        "The chain stops where browser_snapshot retrieves the active-page snapshot; the later response construction discloses that result to the tool caller.",
        line=2282,
    ),
    (
        "Issue-8034",
        "Camofox tab-create REST control boundary",
    ): RepresentativeRule(
        "tools/browser_tool.py",
        "camofox_navigate",
        "The chain terminates at the dynamically dispatched Camofox navigation helper that performs tab creation.",
        line=2389,
    ),
    (
        "Issue-8034",
        "Camofox existing-tab navigate REST control boundary",
    ): RepresentativeRule(
        "tools/browser_tool.py",
        "camofox_navigate",
        "The chain terminates at the dynamically dispatched Camofox navigation helper that performs existing-tab navigation.",
        line=2389,
    ),
    (
        "Discord-Mention",
        "aiohttp.ClientSession.post Mattermost live adapter /api/v4/posts",
    ): RepresentativeRule(
        "plugins/platforms/mattermost/adapter.py",
        "self._api_post",
        "The bridge chain stops at Mattermost's _api_post wrapper for the live posts endpoint.",
        line=188,
    ),
}

REPRESENTATIVE_SINKS.update(
    {
        (
            "Issue-8033",
            "FirecrawlWebSearchProvider.extract -> Firecrawl.scrape",
        ): RepresentativeRule(
            "tools/web_tools.py",
            "scrape",
            "The Firecrawl implementation moved into tools/web_tools.py and invokes scrape through asyncio.to_thread.",
            line=1294,
        ),
        (
            "Issue-8033",
            "ExaWebSearchProvider.extract -> Exa.get_contents",
        ): RepresentativeRule(
            "tools/web_tools.py",
            "_get_exa_client().get_contents",
            "The Exa provider implementation moved into tools/web_tools.py.",
            line=938,
        ),
        (
            "Issue-8033",
            "ParallelWebSearchProvider.extract -> AsyncParallel.beta.extract",
        ): RepresentativeRule(
            "tools/web_tools.py",
            "Attribute.extract",
            "The Parallel provider implementation moved into tools/web_tools.py.",
            line=1003,
        ),
    }
)


CHAIN_FIELDS = [
    "json_id",
    "json_file",
    "chain_id",
    "chain_source",
    "handler_func",
    "depth",
    "sink_label",
    "sink_file",
    "sink_line",
    "matched_gt_sinks",
    "covered_gates",
    "covered_gate_evidence",
    "missing_supported_gates",
    "unsupported_gates",
    "covers_all_handler_entries",
    "covers_all_gt_gates",
    "covers_all_gt_sinks",
    "covers_all_report_gt",
    "call_chain",
]

ITEM_FIELDS = [
    "json_id",
    "json_file",
    "item_kind",
    "item_index",
    "gt_name",
    "gt_type",
    "gt_location",
    "coverage_status",
    "match_kind",
    "detector_verdict",
    "chain_count",
    "chain_ids",
    "matched_evidence",
    "notes",
]
DEBUG_FIELDS = [
    "json_id",
    "json_file",
    "item_kind",
    "item_index",
    "gt_name",
    "gt_type",
    "gt_location",
    "gt_evidence",
    "stage",
    "metadata_status",
    "metadata_reason",
    "expected_transform_fn",
    "handler_aliases",
    "parsed_locations",
    "evidence_symbols",
    "describes_absent_gate",
    "source_file_status",
    "source_line_status",
    "source_lines",
    "evidence_lines_total",
    "evidence_lines_found_in_file",
    "evidence_lines_found_near_location",
    "missing_evidence_lines",
    "chain_id",
    "chain_source",
    "handler_func",
    "sink_label",
    "sink_file",
    "sink_line",
    "call_chain",
    "candidate_kind",
    "candidate_fn",
    "candidate_file",
    "candidate_line",
    "candidate_in_func",
    "candidate_role",
    "candidate_verdict",
    "checks",
    "decision",
    "match_kind",
    "selected",
    "rejection_reason",
]
GT_SNAPSHOT_FIELDS = [
    "json_id",
    "item_kind",
    "item_index",
    "gt_name",
    "gt_type",
    "gt_location",
]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def int_or_zero(value: str | int | None) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def normalize_path(value: str) -> str:
    value = value.replace("\\", "/")
    for marker in ["tools/", "agent/", "gateway/", "plugins/", "hermes_cli/"]:
        index = value.find(marker)
        if index >= 0:
            return value[index:]
    return value.lstrip("/")


def parse_locations(value: str) -> list[LocationRef]:
    refs: list[LocationRef] = []
    pattern = re.compile(r"([A-Za-z0-9_@./-]+\.(?:py|js|rs)):(\d+)")
    for file_name, line in pattern.findall(value or ""):
        ref = LocationRef(normalize_path(file_name), int(line))
        if ref not in refs:
            refs.append(ref)
    return refs


def callable_symbols(value: str) -> list[str]:
    return sorted(set(re.findall(r"\b(?:def\s+)?([A-Za-z_]\w*)\s*\(", value or "")))


def evidence_code_lines(value: str) -> list[str]:
    lines: list[str] = []
    for raw_line in (value or "").splitlines():
        line = raw_line.strip()
        if not line or line in {"---", "..."}:
            continue
        if line not in lines:
            lines.append(line)
    return lines


def source_debug_fields(
    item: dict[str, object],
    source_root: Path | None,
    source_cache: dict[Path, list[str]],
) -> dict[str, str]:
    refs = parse_locations(str(item.get("location", "")))
    evidence_lines = evidence_code_lines(str(item.get("evidence", "")))
    parsed_locations = join_values([f"{ref.file}:{ref.line}" for ref in refs])
    if not refs:
        return {
            "parsed_locations": "",
            "evidence_symbols": join_values(
                callable_symbols(str(item.get("evidence", "")))
            ),
            "source_file_status": "no-location",
            "source_line_status": "no-location",
            "source_lines": "",
            "evidence_lines_total": str(len(evidence_lines)),
            "evidence_lines_found_in_file": "0",
            "evidence_lines_found_near_location": "0",
            "missing_evidence_lines": join_values(evidence_lines),
        }

    file_status: list[str] = []
    line_status: list[str] = []
    source_lines: list[str] = []
    available_files: list[list[str]] = []
    nearby_lines: list[str] = []
    for ref in refs:
        path = source_root / ref.file if source_root is not None else None
        if path is None or not path.is_file():
            file_status.append(f"{ref.file}=missing")
            line_status.append(f"{ref.file}:{ref.line}=unavailable")
            continue

        file_status.append(f"{ref.file}=present")
        lines = source_cache.get(path)
        if lines is None:
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                lines = []
            source_cache[path] = lines
        available_files.append(lines)

        if 1 <= ref.line <= len(lines):
            line_status.append(f"{ref.file}:{ref.line}=present")
            source_lines.append(f"{ref.file}:{ref.line}={lines[ref.line - 1].strip()}")
            start = max(0, ref.line - 1 - NEAR_LOCATION_MAX_LINES)
            end = min(len(lines), ref.line + NEAR_LOCATION_MAX_LINES)
            nearby_lines.extend(line.strip() for line in lines[start:end])
        else:
            line_status.append(f"{ref.file}:{ref.line}=out-of-range")

    found_in_file = [
        evidence_line
        for evidence_line in evidence_lines
        if any(
            evidence_line in {line.strip() for line in lines}
            for lines in available_files
        )
    ]
    nearby_line_set = set(nearby_lines)
    found_nearby = [
        evidence_line
        for evidence_line in evidence_lines
        if evidence_line in nearby_line_set
    ]
    missing = [
        evidence_line
        for evidence_line in evidence_lines
        if evidence_line not in found_in_file
    ]
    return {
        "parsed_locations": parsed_locations,
        "evidence_symbols": join_values(
            callable_symbols(str(item.get("evidence", "")))
        ),
        "source_file_status": join_values(file_status),
        "source_line_status": join_values(line_status),
        "source_lines": join_values(source_lines),
        "evidence_lines_total": str(len(evidence_lines)),
        "evidence_lines_found_in_file": str(len(found_in_file)),
        "evidence_lines_found_near_location": str(len(found_nearby)),
        "missing_evidence_lines": join_values(missing),
    }


@dataclass(frozen=True)
class _NestedCall:
    dotted_name: str
    line: int


@dataclass(frozen=True)
class _NestedFunction:
    file: str
    module: str
    qualname: str
    simple_name: str
    start_line: int
    end_line: int
    calls: tuple[_NestedCall, ...]
    local_imports: tuple[tuple[str, str, str], ...]
    sole_return_call: str


class _NestedCallCollector(ast.NodeVisitor):
    def __init__(self, module: str) -> None:
        self.module = module
        self.calls: list[_NestedCall] = []
        self.imports: dict[str, tuple[str, str]] = {}

    def visit_Call(self, node: ast.Call) -> None:
        dotted_name = self._dotted_name(node.func)
        if dotted_name:
            self.calls.append(_NestedCall(dotted_name, node.lineno))
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bound = alias.asname or alias.name.split(".", 1)[0]
            self.imports[bound] = (alias.name, "")

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        imported_module = _resolve_import_module(
            self.module, node.module or "", node.level
        )
        for alias in node.names:
            if alias.name == "*":
                continue
            self.imports[alias.asname or alias.name] = (
                imported_module,
                alias.name,
            )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    @staticmethod
    def _dotted_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = _NestedCallCollector._dotted_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""


class _NestedFunctionCollector(ast.NodeVisitor):
    def __init__(self, file: str, module: str) -> None:
        self.file = file
        self.module = module
        self.class_stack: list[str] = []
        self.function_stack: list[str] = []
        self.functions: list[_NestedFunction] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_stack.append(node.name)
        for child in node.body:
            self.visit(child)
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        call_collector = _NestedCallCollector(self.module)
        for child in node.body:
            call_collector.visit(child)

        statements = list(node.body)
        if (
            statements
            and isinstance(statements[0], ast.Expr)
            and isinstance(statements[0].value, ast.Constant)
            and isinstance(statements[0].value.value, str)
        ):
            statements = statements[1:]
        sole_return_call = ""
        if (
            len(statements) == 1
            and isinstance(statements[0], ast.Return)
            and isinstance(statements[0].value, ast.Call)
        ):
            sole_return_call = _NestedCallCollector._dotted_name(
                statements[0].value.func
            )

        qualname = ".".join(
            [*self.class_stack, *self.function_stack, node.name]
        )
        self.functions.append(
            _NestedFunction(
                file=self.file,
                module=self.module,
                qualname=qualname,
                simple_name=node.name,
                start_line=node.lineno,
                end_line=getattr(node, "end_lineno", node.lineno),
                calls=tuple(call_collector.calls),
                local_imports=tuple(
                    (alias, target_module, symbol)
                    for alias, (target_module, symbol) in sorted(
                        call_collector.imports.items()
                    )
                ),
                sole_return_call=sole_return_call,
            )
        )

        self.function_stack.append(node.name)
        for child in node.body:
            if isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                self.visit(child)
        self.function_stack.pop()


def _module_name(file: str) -> str:
    path = Path(file)
    parts = list(path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _resolve_import_module(current_module: str, imported: str, level: int) -> str:
    if not level:
        return imported
    package = current_module.split(".")[:-1]
    keep = max(0, len(package) - (level - 1))
    base = package[:keep]
    if imported:
        base.extend(imported.split("."))
    return ".".join(base)


class NestedGateIndex:
    """Resolve confirmed gate functions to GT-owned functions below them."""

    def __init__(self, root: Path | None) -> None:
        self.root = root
        self.functions: dict[tuple[str, str], _NestedFunction] = {}
        self.functions_by_file: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self.functions_by_module: dict[
            str, list[tuple[str, str]]
        ] = defaultdict(list)
        self.functions_by_simple: dict[str, list[tuple[str, str]]] = defaultdict(
            list
        )
        self.module_imports: dict[str, dict[str, tuple[str, str]]] = {}
        self.graph: dict[
            tuple[str, str], list[tuple[tuple[str, str], int]]
        ] = defaultdict(list)
        self._candidate_root_cache: dict[
            tuple[str, str, int], set[tuple[str, str]]
        ] = {}
        self._item_target_cache: dict[
            tuple[str, str, str, str, str], set[tuple[str, str]]
        ] = {}
        self._match_cache: dict[
            tuple[tuple[str, str, str, str, str], tuple[str, str, int]],
            NestedGateMatch | None,
        ] = {}
        if root is not None:
            self._build()

    def _build(self) -> None:
        assert self.root is not None
        for path in self.root.rglob("*.py"):
            if ".venv" in path.parts or "__pycache__" in path.parts:
                continue
            file = path.relative_to(self.root).as_posix()
            module = _module_name(file)
            try:
                tree = ast.parse(
                    path.read_text(encoding="utf-8"), filename=str(path)
                )
            except (OSError, SyntaxError, UnicodeDecodeError):
                continue

            module_collector = _NestedCallCollector(module)
            for node in tree.body:
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    module_collector.visit(node)
            self.module_imports[file] = dict(module_collector.imports)

            collector = _NestedFunctionCollector(file, module)
            collector.visit(tree)
            for function in collector.functions:
                key = (file, function.qualname)
                self.functions[key] = function
                self.functions_by_file[file].append(key)
                self.functions_by_module[module].append(key)
                self.functions_by_simple[function.simple_name].append(key)

        for key, function in self.functions.items():
            edges: dict[tuple[str, str], int] = {}
            for call in function.calls:
                weight = (
                    0
                    if call.dotted_name == function.sole_return_call
                    and self._is_import_alias_call(function, call.dotted_name)
                    else 1
                )
                for target in self._resolve_call(function, call.dotted_name):
                    edges[target] = min(edges.get(target, weight), weight)
            self.graph[key] = sorted(
                edges.items(),
                key=lambda value: (
                    value[1],
                    value[0][0],
                    value[0][1],
                ),
            )

    def _imports_for(self, function: _NestedFunction) -> dict[str, tuple[str, str]]:
        imports = dict(self.module_imports.get(function.file, {}))
        imports.update(
            {
                alias: (target_module, symbol)
                for alias, target_module, symbol in function.local_imports
            }
        )
        return imports

    def _is_import_alias_call(
        self, function: _NestedFunction, dotted_name: str
    ) -> bool:
        return "." not in dotted_name and dotted_name in self._imports_for(function)

    def _resolve_import_target(
        self, target_module: str, symbol: str
    ) -> set[tuple[str, str]]:
        return {
            key
            for key in self.functions_by_module.get(target_module, [])
            if self.functions[key].simple_name == symbol
            or self.functions[key].qualname == symbol
        }

    def _resolve_call(
        self, function: _NestedFunction, dotted_name: str
    ) -> set[tuple[str, str]]:
        parts = dotted_name.split(".")
        imports = self._imports_for(function)
        first = parts[0]

        if first in imports:
            target_module, imported_symbol = imports[first]
            if imported_symbol:
                symbol = ".".join([imported_symbol, *parts[1:]])
            else:
                symbol = ".".join(parts[1:])
            if symbol:
                return self._resolve_import_target(target_module, symbol)

        if len(parts) == 1:
            return {
                key
                for key in self.functions_by_file.get(function.file, [])
                if self.functions[key].simple_name == first
            }

        if first in {"self", "cls"} and len(parts) == 2:
            class_prefix = function.qualname.rpartition(".")[0]
            expected = (
                f"{class_prefix}.{parts[1]}" if class_prefix else parts[1]
            )
            return {
                key
                for key in self.functions_by_file.get(function.file, [])
                if self.functions[key].qualname == expected
            }

        expected = ".".join(parts)
        return {
            key
            for key in self.functions_by_file.get(function.file, [])
            if self.functions[key].qualname == expected
        }

    def _functions_at_line(
        self, file_hint: str, line: int
    ) -> list[tuple[str, str]]:
        file = normalize_path(file_hint)
        candidates = [
            key
            for key in self.functions_by_file.get(file, [])
            if self.functions[key].start_line <= line <= self.functions[key].end_line
        ]
        candidates.sort(
            key=lambda key: (
                self.functions[key].end_line - self.functions[key].start_line,
                -self.functions[key].start_line,
            )
        )
        return candidates[:1]

    def _candidate_roots(self, gate: GateRef) -> set[tuple[str, str]]:
        file = normalize_path(gate.file)
        cache_key = (file, gate.fn, gate.line)
        if cache_key in self._candidate_root_cache:
            return self._candidate_root_cache[cache_key]
        simple_name = gate.fn.rsplit(".", 1)[-1]
        roots = {
            key
            for key in self.functions_by_file.get(file, [])
            if self.functions[key].simple_name == simple_name
            or self.functions[key].qualname == gate.fn
        }
        if roots:
            self._candidate_root_cache[cache_key] = roots
            return roots

        owners = self._functions_at_line(file, gate.line)
        for owner in owners:
            targets = self._resolve_call(self.functions[owner], gate.fn)
            if targets:
                self._candidate_root_cache[cache_key] = targets
                return targets
        self._candidate_root_cache[cache_key] = set()
        return set()

    def _named_function_targets(
        self, item: dict[str, object], files: set[str]
    ) -> set[tuple[str, str]]:
        name = str(item.get("name", ""))
        name_symbols = set(re.findall(r"[A-Za-z_]\w*", name))
        matches = {
            key
            for symbol in name_symbols
            for key in self.functions_by_simple.get(symbol, [])
        }
        if not matches:
            evidence_symbols = set(
                callable_symbols(str(item.get("evidence", "")))
            )
            matches = {
                key
                for symbol in evidence_symbols
                for key in self.functions_by_simple.get(symbol, [])
            }
        same_file_matches = {
            key for key in matches if self.functions[key].file in files
        }
        return same_file_matches or matches

    def _item_targets(
        self, item: dict[str, object]
    ) -> set[tuple[str, str]]:
        cache_key = self._item_key(item)
        if cache_key in self._item_target_cache:
            return self._item_target_cache[cache_key]
        refs = parse_locations(str(item.get("location", "")))
        files = {normalize_path(ref.file) for ref in refs}
        if str(item.get("kind", "")) == "function":
            named = self._named_function_targets(item, files)
            if named:
                self._item_target_cache[cache_key] = named
                return named
        targets = {
            key
            for ref in refs
            for key in self._functions_at_line(ref.file, ref.line)
        }
        self._item_target_cache[cache_key] = targets
        return targets

    @staticmethod
    def _item_key(
        item: dict[str, object]
    ) -> tuple[str, str, str, str, str]:
        return (
            str(item.get("name", "")),
            str(item.get("kind", "")),
            str(item.get("type", "")),
            str(item.get("location", "")),
            str(item.get("evidence", "")),
        )

    def _shortest_path(
        self,
        roots: set[tuple[str, str]],
        targets: set[tuple[str, str]],
    ) -> tuple[int, tuple[str, str], tuple[str, str], tuple[str, ...]] | None:
        heap: list[
            tuple[int, tuple[str, str], tuple[str, str], tuple[str, ...]]
        ] = []
        best: dict[tuple[str, str], int] = {}
        for root in sorted(roots):
            label = self.functions[root].simple_name
            heapq.heappush(heap, (0, root, root, (label,)))
            best[root] = 0

        while heap:
            distance, root, current, path = heapq.heappop(heap)
            if distance != best.get(current):
                continue
            if current in targets:
                return distance, root, current, path
            for successor, weight in self.graph.get(current, []):
                next_distance = distance + weight
                if next_distance > MAX_NESTED_GATE_DEPTH:
                    continue
                if next_distance >= best.get(successor, MAX_NESTED_GATE_DEPTH + 1):
                    continue
                best[successor] = next_distance
                heapq.heappush(
                    heap,
                    (
                        next_distance,
                        root,
                        successor,
                        (*path, self.functions[successor].simple_name),
                    ),
                )
        return None

    def match(
        self, item: dict[str, object], gate: GateRef
    ) -> NestedGateMatch | None:
        if str(item.get("type", "")) != "dominance":
            return None
        item_key = self._item_key(item)
        gate_key = (normalize_path(gate.file), gate.fn, gate.line)
        cache_key = (item_key, gate_key)
        if cache_key in self._match_cache:
            return self._match_cache[cache_key]
        roots = self._candidate_roots(gate)
        targets = self._item_targets(item)
        result = self._shortest_path(roots, targets)
        if result is None:
            self._match_cache[cache_key] = None
            return None
        level, root, target, path = result
        root_fn = self.functions[root]
        target_fn = self.functions[target]
        match = NestedGateMatch(
            level=level,
            parent_file=root_fn.file,
            parent_fn=root_fn.simple_name,
            child_file=target_fn.file,
            child_fn=target_fn.simple_name,
            path=path,
        )
        self._match_cache[cache_key] = match
        return match


def same_file(left: str, right: str) -> bool:
    left = normalize_path(left)
    right = normalize_path(right)
    return left == right or left.endswith("/" + right) or right.endswith("/" + left)


def normalize_symbol(value: str) -> str:
    return re.sub(r"[^a-z0-9_]", "", value.lower())


def normalize_gate_symbol(value: str) -> str:
    return normalize_symbol(value).lstrip("_")


def sink_symbol(label: str) -> str:
    return label.rsplit(".", 1)[-1].replace("()", "")


def sink_symbol_in_text(label: str, text: str) -> bool:
    cleaned_label = label.replace("()", "")
    lowered_text = text.lower()
    if "." in cleaned_label and cleaned_label.lower() in lowered_text:
        return True

    simple = sink_symbol(label)
    receiver = cleaned_label.rsplit(".", 1)[0] if "." in cleaned_label else ""
    if receiver in {"Attribute", "Call", "BinaryExpr"}:
        return bool(
            re.search(
                rf"(?<![A-Za-z0-9_]){re.escape(simple)}(?![A-Za-z0-9_])",
                text,
                flags=re.IGNORECASE,
            )
        )

    dotted = re.findall(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", text)
    same_simple_dotted = [
        value for value in dotted if value.rsplit(".", 1)[-1].lower() == simple.lower()
    ]
    if same_simple_dotted:
        return any(
            normalize_symbol(value) == normalize_symbol(cleaned_label)
            for value in same_simple_dotted
        )

    return bool(
        re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(simple)}(?![A-Za-z0-9_])",
            text,
            flags=re.IGNORECASE,
        )
    )


def chain_id(call_chain: str) -> str:
    return "C-" + hashlib.sha1(call_chain.encode("utf-8")).hexdigest()[:10]


def gate_ref(row: dict[str, str]) -> GateRef:
    return GateRef(
        kind=row.get("gate_kind", "dominance") or "dominance",
        fn=row["gate_fn"],
        file=row["gate_file"],
        line=int_or_zero(row["gate_line"]),
        in_func=row["gate_in_func"],
        role=row["guard_kind"],
        verdict=row["taint_verdict"],
    )


def normalize_aux_chain(row: dict[str, str]) -> dict[str, str]:
    hops = parse_call_chain(row["call_chain"])
    handler_file = hops[0][1] if hops else ""
    return {
        "handler_func": row["root"],
        "handler_file": handler_file,
        "handler_line": "",
        "depth": row["depth"],
        "sink_label": row["sink_label"],
        "sink_file": row["sink_file"],
        "sink_line": row["sink_line"],
        "call_chain": row["call_chain"],
    }


def chains_from_rows(rows: list[dict[str, str]], source: str) -> list[Chain]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[row["call_chain"]].append(row)

    chains: list[Chain] = []
    for call_chain, group in grouped.items():
        first = group[0]
        gates = [gate_ref(row) for row in group if row.get("gate_fn")]
        gates = list(dict.fromkeys(gates))
        chains.append(
            Chain(
                chain_id=chain_id(call_chain),
                source=source,
                handler_func=first["handler_func"],
                depth=int_or_zero(first["depth"]),
                sink_label=first["sink_label"],
                sink_file=first["sink_file"],
                sink_line=int_or_zero(first["sink_line"]),
                call_chain=call_chain,
                gates=gates,
            )
        )
    return chains


def load_chains(args: argparse.Namespace, source_index: SourceIndex) -> list[Chain]:
    main = chains_from_rows(read_csv(args.chain_gates), "main-taint-valid")

    auxiliary: list[Chain] = []
    if args.aux_chains.exists():
        aux_rows = [normalize_aux_chain(row) for row in read_csv(args.aux_chains)]
        annotated = build_chain_gates(
            aux_rows,
            read_csv(args.gate_candidates),
            read_csv(args.transform_candidates),
            source_index,
        )
        auxiliary = chains_from_rows(annotated, "send-message-bridge")

    by_call_chain: dict[str, Chain] = {chain.call_chain: chain for chain in main}
    for chain in auxiliary:
        by_call_chain.setdefault(chain.call_chain, chain)
    return sorted(
        by_call_chain.values(),
        key=lambda chain: (
            chain.handler_func,
            chain.sink_file,
            chain.sink_line,
            chain.depth,
            chain.call_chain,
        ),
    )


def handler_aliases(
    tool_name: str, handler_entries: dict[str, set[str]], entry: dict[str, object]
) -> set[str]:
    aliases = set(handler_entries.get(tool_name, set()))
    aliases.add(tool_name)
    evidence = str(entry.get("evidence", ""))
    aliases.update(re.findall(r"\bdef\s+([A-Za-z_]\w*)", evidence))
    return aliases


def sink_matches(
    gt_id: str,
    item: dict[str, object],
    chains: list[Chain],
) -> tuple[dict[str, str], str]:
    name = str(item.get("name", ""))
    location = str(item.get("location", ""))
    refs = parse_locations(location)
    combined = " ".join(
        [
            name,
            str(item.get("evidence", "")),
            str(item.get("problematic_parameter", "")),
        ]
    )
    matches: dict[str, str] = {}

    for chain in chains:
        if any(
            same_file(ref.file, chain.sink_file) and ref.line == chain.sink_line
            for ref in refs
        ):
            matches[chain.chain_id] = "exact-location"

    if matches:
        return matches, ""

    representative = REPRESENTATIVE_SINKS.get((gt_id, name))
    if representative:
        for chain in chains:
            if not same_file(representative.file, chain.sink_file):
                continue
            if normalize_symbol(representative.sink_label) != normalize_symbol(
                chain.sink_label
            ):
                continue
            if representative.line and representative.line != chain.sink_line:
                continue
            matches[chain.chain_id] = "semantic-representative"
        return matches, representative.note if matches else ""

    for chain in chains:
        for ref in refs:
            if not same_file(ref.file, chain.sink_file):
                continue
            if sink_symbol_in_text(chain.sink_label, combined):
                matches[chain.chain_id] = "same-file-symbol"
                break

    return matches, ""


def sink_match_debug(
    gt_id: str,
    item: dict[str, object],
    chain: Chain,
    matches: dict[str, str],
) -> tuple[str, str, str]:
    name = str(item.get("name", ""))
    refs = parse_locations(str(item.get("location", "")))
    combined = " ".join(
        [
            name,
            str(item.get("evidence", "")),
            str(item.get("problematic_parameter", "")),
        ]
    )
    exact_location = any(
        same_file(ref.file, chain.sink_file) and ref.line == chain.sink_line
        for ref in refs
    )
    same_file_ref = any(same_file(ref.file, chain.sink_file) for ref in refs)
    symbol_match = sink_symbol_in_text(chain.sink_label, combined)
    representative = REPRESENTATIVE_SINKS.get((gt_id, name))
    representative_file = bool(
        representative and same_file(representative.file, chain.sink_file)
    )
    representative_symbol = bool(
        representative
        and normalize_symbol(representative.sink_label)
        == normalize_symbol(chain.sink_label)
    )
    representative_line = bool(
        representative
        and (not representative.line or representative.line == chain.sink_line)
    )
    match_kind = matches.get(chain.chain_id, "")
    checks = join_values(
        [
            f"exact_location={str(exact_location).lower()}",
            f"representative_configured={str(representative is not None).lower()}",
            f"representative_file={str(representative_file).lower()}",
            f"representative_symbol={str(representative_symbol).lower()}",
            f"representative_line={str(representative_line).lower()}",
            f"same_file_ref={str(same_file_ref).lower()}",
            f"sink_symbol_in_gt_text={str(symbol_match).lower()}",
        ]
    )
    if match_kind:
        return match_kind, checks, ""
    if any(kind == "exact-location" for kind in matches.values()):
        reason = "another chain satisfied the higher-priority exact-location rule"
    elif representative is not None:
        reason = "configured representative file, symbol, or line did not match"
    elif not same_file_ref:
        reason = "no GT location refers to the candidate sink file"
    elif not symbol_match:
        reason = "candidate sink symbol was not found in GT name/evidence/parameter"
    else:
        reason = "candidate did not satisfy a sink matching rule"
    return "", checks, reason


def parent_gate_aliases(reason: str) -> set[str]:
    aliases = set(re.findall(r"gate\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)", reason))
    aliases.update(re.findall(r"\(=([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)", reason))
    return aliases


def nested_kind_from_reason(reason: str) -> str:
    level = re.search(r"nested-in-gate\(L(\d+)\)", reason)
    return f"nested-in-gate(L{level.group(1)})" if level else "nested-in-gate"


def gate_match_priority(kind: str) -> int:
    if kind.startswith("nested-in-gate"):
        return 30
    return GATE_MATCH_PRIORITY[kind]


def describes_absent_gate(item: dict[str, object]) -> bool:
    """Return true when the GT item explicitly describes a required-but-absent gate."""
    return bool(ABSENT_GATE_NAME_RE.search(str(item.get("name", ""))))


def source_owner_functions(
    item: dict[str, object], source_index: SourceIndex
) -> set[str]:
    """Return current-source functions that own the GT item's locations."""
    return {
        source_fn.simple_name
        for ref in parse_locations(str(item.get("location", "")))
        for _source_file, source_fn in source_index.functions_at_line(
            ref.file, ref.line
        )
    }


def gate_match_kind(
    item: dict[str, object],
    metadata: dict[str, str],
    gate: GateRef,
    source_index: SourceIndex,
    nested_index: NestedGateIndex | None = None,
) -> str:
    if describes_absent_gate(item):
        return ""

    gt_type = str(item.get("type", ""))
    expected_kind = "transform" if gt_type == "transform" else "dominance"
    if gate.kind != expected_kind or gate.verdict not in {
        "confirmed",
        "branch-confirmed",
    }:
        return ""

    refs = parse_locations(str(item.get("location", "")))
    exact_location = any(
        same_file(ref.file, gate.file) and ref.line == gate.line for ref in refs
    )
    if gt_type == "transform":
        if exact_location:
            return "exact-location"

        expected_fn = metadata.get("expected_transform_fn", "")
        if expected_fn and gate.fn == expected_fn:
            status = metadata.get("status", "")
            return (
                "transform-parent"
                if status == "nested-in-transform"
                else "transform-call"
            )

        normalized_fn = normalize_gate_symbol(gate.fn)
        if any(
            normalize_gate_symbol(owner_fn) == normalized_fn
            for owner_fn in source_owner_functions(item, source_index)
        ):
            return (
                "transform-call"
                if str(item.get("kind", "")) == "function"
                else "transform-parent"
            )
        return ""

    status = metadata.get("status", "")
    if status == "nested-in-gate":
        if gate.fn in parent_gate_aliases(metadata.get("reason", "")):
            return nested_kind_from_reason(metadata.get("reason", ""))

    if exact_location:
        return "exact-location"

    name = str(item.get("name", ""))
    normalized_fn = normalize_gate_symbol(gate.fn)
    normalized_name = normalize_gate_symbol(name)
    if len(normalized_fn) >= 5 and normalized_fn in normalized_name:
        return "gate-symbol"

    for ref in refs:
        for _source_file, source_fn in source_index.functions_at_line(
            ref.file, ref.line
        ):
            if normalize_gate_symbol(source_fn.simple_name) == normalized_fn:
                return "host-parent"

    evidence_symbols = set(callable_symbols(str(item.get("evidence", ""))))
    if any(normalize_gate_symbol(value) == normalized_fn for value in evidence_symbols):
        if not refs:
            return "evidence-symbol"
        same_file_refs = [ref for ref in refs if same_file(ref.file, gate.file)]
        if any(
            abs(ref.line - gate.line) <= NEAR_LOCATION_MAX_LINES
            for ref in same_file_refs
        ):
            return "near-location-symbol"
        if same_file_refs and VERSIONED_LOCATION_RE.search(
            str(item.get("location", ""))
        ):
            return "stale-location-symbol"

    if nested_index is not None:
        nested_match = nested_index.match(item, gate)
        if nested_match is not None:
            return nested_match.kind
    return ""


def gate_match_debug(
    item: dict[str, object],
    metadata: dict[str, str],
    gate: GateRef,
    source_index: SourceIndex,
    nested_index: NestedGateIndex | None = None,
) -> tuple[str, str, str]:
    gt_type = str(item.get("type", ""))
    expected_kind = "transform" if gt_type == "transform" else "dominance"
    refs = parse_locations(str(item.get("location", "")))
    normalized_fn = normalize_gate_symbol(gate.fn)
    normalized_name = normalize_gate_symbol(str(item.get("name", "")))
    symbols = callable_symbols(str(item.get("evidence", "")))
    same_file_refs = [ref for ref in refs if same_file(ref.file, gate.file)]
    parent_aliases = parent_gate_aliases(metadata.get("reason", ""))
    owner_functions = source_owner_functions(item, source_index)

    exact_location = any(
        same_file(ref.file, gate.file) and ref.line == gate.line for ref in refs
    )
    name_symbol = len(normalized_fn) >= 5 and normalized_fn in normalized_name
    host_parent = any(
        normalize_gate_symbol(source_fn.simple_name) == normalized_fn
        for ref in refs
        for _source_file, source_fn in source_index.functions_at_line(
            ref.file, ref.line
        )
    )
    evidence_symbol = any(
        normalize_gate_symbol(value) == normalized_fn for value in symbols
    )
    near_location = any(
        abs(ref.line - gate.line) <= NEAR_LOCATION_MAX_LINES for ref in same_file_refs
    )
    versioned_location = bool(
        VERSIONED_LOCATION_RE.search(str(item.get("location", "")))
    )
    expected_transform_fn = metadata.get("expected_transform_fn", "")
    transform_owner_match = any(
        normalize_gate_symbol(owner_fn) == normalized_fn
        for owner_fn in owner_functions
    )
    automatic_nested = (
        nested_index.match(item, gate) if nested_index is not None else None
    )
    checks = join_values(
        [
            f"expected_kind={expected_kind}",
            f"candidate_kind_matches={str(gate.kind == expected_kind).lower()}",
            "candidate_verdict_supported="
            + str(gate.verdict in {"confirmed", "branch-confirmed"}).lower(),
            f"explicit_absent_name={str(describes_absent_gate(item)).lower()}",
            f"exact_location={str(exact_location).lower()}",
            f"name_contains_gate_symbol={str(name_symbol).lower()}",
            f"location_owned_by_gate_fn={str(host_parent).lower()}",
            f"evidence_contains_gate_symbol={str(evidence_symbol).lower()}",
            f"evidence_same_file={str(bool(same_file_refs)).lower()}",
            f"evidence_within_{NEAR_LOCATION_MAX_LINES}_lines={str(near_location).lower()}",
            f"versioned_location={str(versioned_location).lower()}",
            "nested_parent_aliases=" + ",".join(sorted(parent_aliases)),
            f"expected_transform_fn={expected_transform_fn}",
            "transform_fn_matches="
            + str(
                bool(expected_transform_fn) and gate.fn == expected_transform_fn
            ).lower(),
            "source_owner_functions=" + ",".join(sorted(owner_functions)),
            f"transform_source_owner_matches={str(transform_owner_match).lower()}",
            "automatic_nested_match="
            + (automatic_nested.kind if automatic_nested is not None else ""),
            "automatic_nested_path="
            + (
                "->".join(automatic_nested.path)
                if automatic_nested is not None
                else ""
            ),
        ]
    )
    match_kind = gate_match_kind(
        item, metadata, gate, source_index, nested_index
    )
    if match_kind:
        return match_kind, checks, ""
    if describes_absent_gate(item):
        reason = "GT name explicitly describes a required-but-absent gate"
    elif gate.kind != expected_kind:
        reason = f"candidate kind {gate.kind!r} != expected {expected_kind!r}"
    elif gate.verdict not in {"confirmed", "branch-confirmed"}:
        reason = f"candidate verdict {gate.verdict!r} is not eligible"
    elif gt_type == "transform":
        expected = (
            f"metadata transform {expected_transform_fn!r}"
            if expected_transform_fn
            else "no metadata transform"
        )
        owners = sorted(owner_functions)
        reason = (
            f"candidate transform {gate.fn!r} matched neither {expected} "
            f"nor source owner functions {owners!r}"
        )
    elif metadata.get("status") == "nested-in-gate" and automatic_nested is None:
        reason = (
            f"candidate {gate.fn!r} is not one of the metadata parent aliases "
            f"{sorted(parent_aliases)!r}, and no source-derived subtree path matched"
        )
    elif evidence_symbol and refs and not same_file_refs:
        reason = "evidence symbol matched, but the candidate is in a different file"
    elif (
        evidence_symbol
        and same_file_refs
        and not near_location
        and not versioned_location
    ):
        reason = (
            f"evidence symbol matched, but the candidate is more than "
            f"{NEAR_LOCATION_MAX_LINES} lines from the unversioned GT location"
        )
    else:
        reason = (
            "no exact-location, name-symbol, owner, evidence-symbol, "
            "or source-derived nested-in-gate rule matched"
        )
    return "", checks, reason


def best_gate_match(
    item: dict[str, object],
    metadata: dict[str, str],
    gates: list[GateRef],
    source_index: SourceIndex,
    nested_index: NestedGateIndex | None = None,
) -> tuple[str, GateRef | None]:
    matches: list[tuple[int, int, str, GateRef]] = []
    for position, gate in enumerate(gates):
        kind = gate_match_kind(
            item, metadata, gate, source_index, nested_index
        )
        if kind:
            matches.append((gate_match_priority(kind), -position, kind, gate))
    if not matches:
        return "", None
    _priority, _position, kind, gate = max(matches, key=lambda match: match[:2])
    return kind, gate


def gate_scope_allows(gt_id: str, item: dict[str, object], chain: Chain) -> bool:
    name = str(item.get("name", ""))
    if gt_id == "Discord-Mention" and name.startswith(("Slack", "_send_slack")):
        return (
            "_send_slack@" in chain.call_chain
            or "SlackAdapter." in chain.call_chain
            or (
                same_file(chain.sink_file, "tools/send_message_tool.py")
                and chain.sink_line == 1042
            )
            or same_file(chain.sink_file, "gateway/platforms/slack.py")
        )
    return True


def effective_gate_metadata(
    gt_id: str,
    item: dict[str, object],
    taint_rows: dict[tuple[str, str], dict[str, str]],
    transform_rows: dict[tuple[str, str], dict[str, str]],
) -> dict[str, str]:
    name = str(item.get("name", ""))
    gt_type = str(item.get("type", ""))
    if gt_type == "transform":
        return transform_rows.get((gt_id, name), {"status": "no-candidate"})
    if gt_type == "dominance":
        return taint_rows.get((gt_id, name), {"status": "no-candidate"})
    return {
        "status": "unsupported",
        "reason": f"gate type {gt_type} is not in chain-gates.csv",
    }


def join_values(values: list[str]) -> str:
    return "; ".join(values)


def aggregate_detector_verdicts(gates: list[GateRef]) -> str:
    order = {"confirmed": 0, "branch-confirmed": 1}
    verdicts = {gate.verdict for gate in gates if gate.verdict}
    return join_values(
        sorted(verdicts, key=lambda value: (order.get(value, len(order)), value))
    )


def render_detector_verdicts(value: str) -> str:
    labels = {
        "confirmed": "✅ confirmed",
        "branch-confirmed": "🔷 branch-confirmed",
    }
    return join_values(
        [
            labels.get(verdict.strip(), "⚠️ needs-review")
            for verdict in value.split(";")
            if verdict.strip()
        ]
    )


def detector_verdict_distribution_lines(
    item_rows: list[dict[str, str]],
) -> list[str]:
    gate_rows = [row for row in item_rows if row["item_kind"] == "gate"]
    counts = Counter(row.get("detector_verdict", "") for row in gate_rows)
    preferred_values = [
        "confirmed",
        "branch-confirmed",
        "confirmed; branch-confirmed",
    ]
    ordered_values = [
        value for value in preferred_values if counts.get(value, 0)
    ] + sorted(
        value
        for value in counts
        if value and value not in preferred_values
    )
    if counts.get("", 0):
        ordered_values.append("")

    lines = [
        "### Detector Verdict Distribution",
        "",
        "> Counting unit: one GT gate item. Multi-chain matches use the gate's "
        "aggregated verdict value; a blank value means no detector candidate "
        "was selected.",
        "",
        "| Detector verdict value | GT gates | Share of all GT gates |",
        "|---|---:|---:|",
    ]
    total = len(gate_rows)
    for value in ordered_values:
        label = (
            render_detector_verdicts(value)
            if value
            else "_No matched detector verdict_"
        )
        share = (counts[value] / total * 100) if total else 0
        lines.append(f"| {label} | {counts[value]} | {share:.1f}% |")
    lines.append(f"| **Total** | **{total}** | **{100.0 if total else 0:.1f}%** |")
    return lines


def debug_base_row(
    spec: ReportSpec,
    item_kind: str,
    item_index: int,
    item: dict[str, object],
    gt_type: str,
    source_fields: dict[str, str],
    metadata: dict[str, str] | None = None,
    aliases: set[str] | None = None,
) -> dict[str, str]:
    row = {field: "" for field in DEBUG_FIELDS}
    row.update(
        {
            "json_id": spec.gt_id,
            "json_file": repo_path(spec.path),
            "item_kind": item_kind,
            "item_index": str(item_index),
            "gt_name": str(item.get("name", "")),
            "gt_type": gt_type,
            "gt_location": str(item.get("location", "")),
            "gt_evidence": str(item.get("evidence", "")),
            "metadata_status": (metadata or {}).get("status", ""),
            "metadata_reason": (metadata or {}).get("reason", ""),
            "expected_transform_fn": (metadata or {}).get("expected_transform_fn", ""),
            "handler_aliases": join_values(sorted(aliases or set())),
            "describes_absent_gate": str(describes_absent_gate(item)).lower(),
            **source_fields,
        }
    )
    return row


def chain_debug_fields(chain: Chain) -> dict[str, str]:
    return {
        "chain_id": chain.chain_id,
        "chain_source": chain.source,
        "handler_func": chain.handler_func,
        "sink_label": chain.sink_label,
        "sink_file": chain.sink_file,
        "sink_line": str(chain.sink_line),
        "call_chain": chain.call_chain,
    }


def gate_candidate_debug_fields(gate: GateRef) -> dict[str, str]:
    return {
        "candidate_kind": gate.kind,
        "candidate_fn": gate.fn,
        "candidate_file": gate.file,
        "candidate_line": str(gate.line),
        "candidate_in_func": gate.in_func,
        "candidate_role": gate.role,
        "candidate_verdict": gate.verdict,
    }


def md_escape(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def repo_path(path: Path) -> str:
    absolute_path = path.absolute()
    try:
        return absolute_path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(absolute_path)


def compact_ids(ids: list[str], limit: int = 8) -> str:
    if len(ids) <= limit:
        return ", ".join(f"`{value}`" for value in ids)
    shown = ", ".join(f"`{value}`" for value in ids[:limit])
    return f"{shown}, +{len(ids) - limit} more"


def summary_verdict(summary: dict[str, object]) -> str:
    if bool(summary["all_full"]):
        return "full"
    if int(summary["chain_count"]) == 0:
        return "no-chain"
    if int(summary["gate_total"]) > 0 and int(summary["supported_gate_total"]) == 0:
        return "no-supported-gates"
    if bool(summary["supported_full"]):
        return "supported-full"
    return "partial"


def unique_debug_item_rows(
    debug_rows: list[dict[str, str]],
) -> dict[tuple[str, str, str], dict[str, str]]:
    rows: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in debug_rows:
        key = (row["json_id"], row["item_kind"], row["item_index"])
        rows.setdefault(key, row)
    return rows


def source_evidence_counts(
    debug_rows: list[dict[str, str]],
) -> dict[str, dict[str, int]]:
    unique_rows = unique_debug_item_rows(debug_rows)
    result: dict[str, dict[str, int]] = {}
    for item_kind in ["handler", "gate", "sink"]:
        rows = [
            row
            for (_json_id, kind, _index), row in unique_rows.items()
            if kind == item_kind
        ]
        counts = {
            "total": len(rows),
            "files_present": 0,
            "full_evidence": 0,
            "partial_evidence": 0,
            "no_exact_evidence": 0,
        }
        for row in rows:
            file_status = row["source_file_status"]
            if file_status != "no-location" and "=missing" not in file_status:
                counts["files_present"] += 1
            evidence_total = int_or_zero(row["evidence_lines_total"])
            evidence_found = int_or_zero(row["evidence_lines_found_in_file"])
            if evidence_total and evidence_found == evidence_total:
                counts["full_evidence"] += 1
            elif evidence_found:
                counts["partial_evidence"] += 1
            else:
                counts["no_exact_evidence"] += 1
        result[item_kind] = counts
    return result


def summary_overview_lines(
    item_rows: list[dict[str, str]],
    debug_rows: list[dict[str, str]],
) -> list[str]:
    kind_totals = Counter(row["item_kind"] for row in item_rows)
    status_counts = Counter(
        (row["item_kind"], row["coverage_status"]) for row in item_rows
    )
    source_counts = source_evidence_counts(debug_rows)
    lines = [
        f"- Ground-truth items: **{len(item_rows)}** "
        f"(handlers **{kind_totals['handler']}**, gates **{kind_totals['gate']}**, "
        f"sinks **{kind_totals['sink']}**).",
        f"- Handler matching: **{status_counts['handler', 'covered']}/"
        f"{kind_totals['handler']}**.",
        "- Gate detector matching: "
        f"covered on a sink-matched chain **{status_counts['gate', 'covered']}**, "
        f"uncovered **{status_counts['gate', 'uncovered']}**, "
        f"unsupported types **{status_counts['gate', 'unsupported']}**, "
        f"required but absent **{status_counts['gate', 'absent-in-source']}**.",
        f"- Sink chain matching: **{status_counts['sink', 'covered']}/"
        f"{kind_totals['sink']}**.",
    ]
    lines.extend(["", *detector_verdict_distribution_lines(item_rows)])
    lines.extend(
        [
            "",
            "### Current-Source Evidence Verification",
            "",
            "| Kind | Files present | Full evidence found | Partial | No exact evidence |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for item_kind, label in [
        ("handler", "Handlers"),
        ("gate", "Gates"),
        ("sink", "Sinks"),
    ]:
        counts = source_counts[item_kind]
        lines.append(
            f"| {label} | {counts['files_present']}/{counts['total']} | "
            f"{counts['full_evidence']} | {counts['partial_evidence']} | "
            f"{counts['no_exact_evidence']} |"
        )

    item_rows_by_key = {
        (row["json_id"], row["item_kind"], row["item_index"]): row for row in item_rows
    }
    missing_source_items: list[tuple[str, str, bool]] = []
    for key, row in unique_debug_item_rows(debug_rows).items():
        for status in row["source_file_status"].split("; "):
            if not status.endswith("=missing"):
                continue
            missing_file = status.removesuffix("=missing")
            match_kind = item_rows_by_key.get(key, {}).get("match_kind", "")
            missing_source_items.append(
                (
                    missing_file,
                    row["gt_name"],
                    "semantic-representative" in match_kind,
                )
            )

    lines.append("")
    if len(missing_source_items) == 1:
        missing_file, gt_name, semantic_representative = missing_source_items[0]
        if "agent-browser" in missing_file and missing_file.endswith(".rs"):
            note = (
                "The missing sink source file is the external Rust "
                "`agent-browser` implementation, which is not vendored under "
                "the Hermes benchmark source."
            )
        else:
            note = (
                f"The source file `{missing_file}` for `{gt_name}` is not "
                "present under the analyzed source root."
            )
        if semantic_representative:
            note += (
                " Its Python handoff is still matched through the "
                "`semantic-representative` mapping."
            )
        lines.append(note)
    elif missing_source_items:
        lines.append(
            "Source files outside or missing from the analyzed root: "
            + ", ".join(
                f"`{file_name}` (`{gt_name}`)"
                for file_name, gt_name, _semantic in missing_source_items
            )
            + "."
        )
    return lines


def render_markdown(
    summaries: list[dict[str, object]],
    item_rows: list[dict[str, str]],
    chain_rows: list[dict[str, str]],
    debug_rows: list[dict[str, str]],
    out_csv: Path,
    out_items_csv: Path,
    out_debug_csv: Path,
    missing_gate_metadata: list[tuple[str, str]],
    stale_gate_metadata: list[tuple[str, str]],
    generation_command: str,
    snapshot_gt_ids: list[str],
) -> str:
    lines = [
        "# D5 Ground-Truth Call-Chain Coverage",
        "",
        "> Generated file. Do not edit by hand.",
        ">",
        f"> Generation command: `{generation_command}`",
        ">",
        f"> Per-chain CSV: [`{out_csv.name}`]({out_csv.name}); per-item CSV: [`{out_items_csv.name}`]({out_items_csv.name}); full matcher trace: [`{out_debug_csv.name}`]({out_debug_csv.name}).",
        "> Main evidence is `chain-gates.csv`; `handler-sink-discord-bridge.csv` supplies explicit send-message bridge chains.",
        *(
            [
                ">",
                "> Ground-truth JSON symlinks were unavailable; normalized GT items were loaded from the pre-existing per-item snapshot for: "
                + ", ".join(f"`{gt_id}`" for gt_id in snapshot_gt_ids)
                + ".",
            ]
            if snapshot_gt_ids
            else []
        ),
        *(
            [
                ">",
                f"> Current GT gate rows without upstream taint metadata: **{len(missing_gate_metadata)}** "
                f"({compact_metadata_keys(missing_gate_metadata)}). They use direct matching plus the source-derived `nested-in-gate(Lk)` fallback and remain visible in coverage.",
            ]
            if missing_gate_metadata
            else []
        ),
        *(
            [
                ">",
                f"> JSON is authoritative. Ignored **{len(stale_gate_metadata)}** stale upstream metadata rows "
                f"({compact_metadata_keys(stale_gate_metadata)}).",
            ]
            if stale_gate_metadata
            else []
        ),
        "",
        "## Summary",
        "",
    ]
    lines.extend(summary_overview_lines(item_rows, debug_rows))
    lines.extend(
        [
            "",
            "### Per-JSON Coverage",
            "",
            "| JSON | Matching chains | Handler | Gates | Supported gates | Sinks | Union result |",
            "|---|---:|---:|---:|---:|---:|---|",
        ]
    )
    for summary in summaries:
        verdict = summary_verdict(summary)
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{summary['json_id']}`",
                    str(summary["chain_count"]),
                    f"{summary['handler_covered']}/{summary['handler_total']}",
                    f"{summary['gate_covered']}/{summary['gate_total']}",
                    f"{summary['supported_gate_covered']}/{summary['supported_gate_total']}",
                    f"{summary['sink_covered']}/{summary['sink_total']}",
                    f"`{verdict}`",
                ]
            )
            + " |"
        )

    debug_stage_counts = Counter(row["stage"] for row in debug_rows)
    debug_decision_counts = Counter(row["decision"] for row in debug_rows)
    lines.extend(
        [
            "",
            "## Intermediate Debug Trace",
            "",
            f"- Full trace rows: **{len(debug_rows)}** in [`{out_debug_csv.name}`]({out_debug_csv.name}).",
            "- Stages: "
            + ", ".join(
                f"`{stage}`={count}"
                for stage, count in sorted(debug_stage_counts.items())
            )
            + ".",
            "- Decisions: "
            + ", ".join(
                f"`{decision}`={count}"
                for decision, count in sorted(debug_decision_counts.items())
            )
            + ".",
            "- Every row retains the GT evidence block, parsed locations and callable symbols, current source line/evidence presence, metadata lookup, chain and candidate identity, every boolean matching check, the final selection flag, and a rejection reason.",
        ]
    )

    items_by_json: dict[str, list[dict[str, str]]] = defaultdict(list)
    chains_by_json: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in item_rows:
        items_by_json[row["json_id"]].append(row)
    for row in chain_rows:
        chains_by_json[row["json_id"]].append(row)

    for summary in summaries:
        gt_id = str(summary["json_id"])
        lines.extend(
            [
                "",
                f"## `{gt_id}`",
                "",
                f"JSON: `{summary['json_file']}`",
                "",
                "### Ground-Truth Items",
                "",
                "| Kind | # | GT item | Type | Status | Match | Verdict | Chains |",
                "|---|---:|---|---|---|---|---|---|",
            ]
        )
        for row in items_by_json[gt_id]:
            ids = [value for value in row["chain_ids"].split(";") if value]
            lines.append(
                "| "
                + " | ".join(
                    [
                        row["item_kind"],
                        row["item_index"],
                        md_escape(row["gt_name"]),
                        md_escape(row["gt_type"]),
                        f"`{row['coverage_status']}`",
                        md_escape(row["match_kind"]),
                        render_detector_verdicts(row["detector_verdict"]),
                        compact_ids(ids),
                    ]
                )
                + " |"
            )

        lines.extend(
            [
                "",
                "### Matching Chains",
                "",
                "| Chain | Source | Depth | Terminal sink | GT sinks | GT gates | Detector evidence | Call chain |",
                "|---|---|---:|---|---|---|---|---|",
            ]
        )
        if not chains_by_json[gt_id]:
            lines.append("|  |  |  |  |  |  |  | No chain matched a GT sink. |")
        for row in chains_by_json[gt_id]:
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{row['chain_id']}`",
                        row["chain_source"],
                        row["depth"],
                        md_escape(
                            f"{row['sink_label']}@{row['sink_file']}:{row['sink_line']}"
                        ),
                        md_escape(row["matched_gt_sinks"]),
                        md_escape(row["covered_gates"]),
                        md_escape(row["covered_gate_evidence"]),
                        md_escape(row["call_chain"]),
                    ]
                )
                + " |"
            )

    lines.extend(
        [
            "",
            "## Matching Rules",
            "",
            "- Handler entries use `tool-handler-entries.csv` to map model-facing tool names to actual chain roots.",
            "- Sinks match by current file+line first, then same-file sink symbol. Explicit runtime-dispatch boundaries are labeled `semantic-representative`; they are never presented as exact matches.",
            "- Gates must be present on the same matched chain. The strongest match wins: exact callsite, nearby evidence symbol, explicitly versioned stale location, stable gate symbol, then parent ownership. Evidence-symbol matching does not attach a same-named call from a distant current location.",
            "- GT items explicitly named as a `missing`, `lacking`, or `absent` gate can never be covered by an incidental defect-site candidate. When aligned metadata marks the required gate `absent-in-source`, it stays in the full GT count but is excluded from supported/evaluable gate coverage.",
            "- Nested dominance gates are matched automatically when a confirmed candidate on the same sink-matched chain resolves to a source function whose bounded call subtree owns the GT gate. Import-alias forwarding wrappers are zero-cost aliases; inline gates are labeled `nested-in-gate(L0)` and called helpers `nested-in-gate(Lk)`. Legacy `taintC-per-gate.csv` parent metadata remains a fallback. Transform gates use `transform-gt-coverage.csv` parent ownership.",
            "- Transform GT whose expected parent function is not defined in the analyzed source is `absent-in-source`; it remains visible in the full GT count but is excluded from supported/evaluable gate coverage.",
            "- Capability, filter, and other gate types remain `unsupported` because `chain-gates.csv` currently contains dominance and transform gates only.",
            "- A per-chain `covers_all_report_gt` value is strict: one chain must cover every handler entry, every GT gate, and every GT sink. The summary additionally reports union-of-chains and supported-gate coverage.",
            "",
            "## Reproduce",
            "",
            "```bash",
            generation_command,
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def explicit_generation_command(args: argparse.Namespace) -> str:
    parts = [
        "python",
        "design/hermes-agent/call-chain/debug/script/render_d5_chain_coverage.py",
        "--chain-gates",
        repo_path(args.chain_gates),
        "--aux-chains",
        repo_path(args.aux_chains),
        "--gate-candidates",
        repo_path(args.gate_candidates),
        "--transform-candidates",
        repo_path(args.transform_candidates),
        "--taint-gt",
        repo_path(args.taint_gt),
        "--transform-coverage",
        repo_path(args.transform_coverage),
        "--handler-entries",
        repo_path(args.handler_entries),
        "--ground-truth-dir",
        repo_path(args.ground_truth_dir),
        "--out-csv",
        repo_path(args.out_csv),
        "--out-items-csv",
        repo_path(args.out_items_csv),
        "--out-debug-csv",
        repo_path(args.out_debug_csv),
        "--out-md",
        repo_path(args.out_md),
    ]
    if args.gt_items_snapshot is not None:
        parts.extend(["--gt-items-snapshot", repo_path(args.gt_items_snapshot)])
    if args.source_root is not None:
        parts.extend(["--source-root", repo_path(args.source_root)])
    return " ".join(shlex.quote(part) for part in parts)


def data_from_item_snapshot(rows: list[dict[str, str]]) -> dict[str, object]:
    fields_by_kind = {
        "handler": "d5_tool_handler_entry",
        "gate": "d5_gate_points",
        "sink": "d5_sink_points",
    }
    data: dict[str, object] = {field: [] for field in fields_by_kind.values()}
    for row in sorted(rows, key=lambda value: int_or_zero(value["item_index"])):
        field = fields_by_kind.get(row["item_kind"])
        if field is None:
            continue
        items = data[field]
        assert isinstance(items, list)
        item = {
            "name": row["gt_name"],
            "location": row["gt_location"],
        }
        item["kind" if row["item_kind"] == "sink" else "type"] = row["gt_type"]
        items.append(item)
    return data


def compact_metadata_keys(keys: list[tuple[str, str]]) -> str:
    counts = Counter(gt_id for gt_id, _ in keys)
    return ", ".join(f"`{gt_id}`={count}" for gt_id, count in sorted(counts.items()))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chain-gates", type=Path, default=DEFAULT_MAIN_CHAIN_GATES)
    parser.add_argument("--aux-chains", type=Path, default=DEFAULT_AUX_CHAINS)
    parser.add_argument("--gate-candidates", type=Path, default=DEFAULT_GATE_CANDIDATES)
    parser.add_argument(
        "--transform-candidates", type=Path, default=DEFAULT_TRANSFORM_CANDIDATES
    )
    parser.add_argument("--taint-gt", type=Path, default=DEFAULT_TAINT_GT)
    parser.add_argument(
        "--transform-coverage", type=Path, default=DEFAULT_TRANSFORM_COVERAGE
    )
    parser.add_argument("--handler-entries", type=Path, default=DEFAULT_HANDLER_ENTRIES)
    parser.add_argument(
        "--ground-truth-dir", type=Path, default=DEFAULT_GROUND_TRUTH_ROOT
    )
    parser.add_argument("--out-csv", type=Path, default=DEFAULT_OUT_CSV)
    parser.add_argument("--out-items-csv", type=Path, default=DEFAULT_OUT_ITEMS_CSV)
    parser.add_argument("--out-debug-csv", type=Path, default=DEFAULT_OUT_DEBUG_CSV)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    parser.add_argument(
        "--gt-items-snapshot",
        type=Path,
        default=DEFAULT_GT_ITEMS_SNAPSHOT,
        help=(
            "Existing per-item CSV used only when the configured GT JSON "
            "symlinks are unavailable. It is read before outputs are written."
        ),
    )
    parser.add_argument("--source-root", type=Path)
    args = parser.parse_args()
    generation_command = explicit_generation_command(args)
    configured_report_specs = report_specs(args.ground_truth_dir)

    snapshot_by_json: dict[str, list[dict[str, str]]] = defaultdict(list)
    if args.gt_items_snapshot is not None:
        for row in read_csv(args.gt_items_snapshot):
            snapshot_by_json[row["json_id"]].append(row)

    report_data: dict[str, dict[str, object]] = {}
    snapshot_gt_ids: list[str] = []
    for spec in configured_report_specs:
        if spec.path.exists():
            report_data[spec.gt_id] = json.loads(spec.path.read_text(encoding="utf-8"))
            continue
        snapshot_rows = snapshot_by_json.get(spec.gt_id, [])
        if not snapshot_rows:
            raise FileNotFoundError(
                f"Missing GT JSON {spec.path} and no --gt-items-snapshot rows "
                f"for {spec.gt_id}"
            )
        report_data[spec.gt_id] = data_from_item_snapshot(snapshot_rows)
        snapshot_gt_ids.append(spec.gt_id)

    source_roots = [args.source_root] if args.source_root else DEFAULT_SOURCE_ROOTS
    source_index = SourceIndex.from_first_existing(source_roots)
    nested_index = NestedGateIndex(source_index.root)
    chains = load_chains(args, source_index)
    chains_by_id = {chain.chain_id: chain for chain in chains}

    handler_entries: dict[str, set[str]] = defaultdict(set)
    for row in read_csv(args.handler_entries):
        handler_entries[row["tool_name"]].add(row["handler_func"])

    taint_rows = {
        (row["json"], row["gate_name"]): row for row in read_csv(args.taint_gt)
    }
    transform_rows = {
        (row["json"], row["gate_name"]): row
        for row in read_csv(args.transform_coverage)
    }

    item_rows: list[dict[str, str]] = []
    chain_rows: list[dict[str, str]] = []
    debug_rows: list[dict[str, str]] = []
    summaries: list[dict[str, object]] = []
    source_cache: dict[Path, list[str]] = {}

    for spec in configured_report_specs:
        data = report_data[spec.gt_id]
        entries = list(data.get("d5_tool_handler_entry", []))
        gates = list(data.get("d5_gate_points", []))
        sinks = list(data.get("d5_sink_points", []))

        aliases: set[str] = set()
        for entry in entries:
            aliases.update(
                handler_aliases(str(entry.get("name", "")), handler_entries, entry)
            )
        handler_chains = [chain for chain in chains if chain.handler_func in aliases]

        handler_item_matches: dict[int, list[str]] = {}
        for index, entry in enumerate(entries, 1):
            entry_aliases = handler_aliases(
                str(entry.get("name", "")), handler_entries, entry
            )
            ids = [
                chain.chain_id
                for chain in chains
                if chain.handler_func in entry_aliases
            ]
            handler_item_matches[index] = ids
            handler_debug_base = debug_base_row(
                spec,
                "handler",
                index,
                entry,
                "handler-entry",
                source_debug_fields(entry, source_index.root, source_cache),
                aliases=entry_aliases,
            )
            for chain in chains:
                matched = chain.handler_func in entry_aliases
                debug_row = dict(handler_debug_base)
                debug_row.update(chain_debug_fields(chain))
                debug_row.update(
                    {
                        "stage": "handler-candidate",
                        "candidate_kind": "handler-root",
                        "candidate_fn": chain.handler_func,
                        "checks": ("handler_func_in_aliases=" + str(matched).lower()),
                        "decision": "matched" if matched else "rejected",
                        "match_kind": "tool-handler-root" if matched else "",
                        "selected": str(matched).lower(),
                        "rejection_reason": (
                            ""
                            if matched
                            else (
                                f"handler function {chain.handler_func!r} is not "
                                f"in aliases {sorted(entry_aliases)!r}"
                            )
                        ),
                    }
                )
                debug_rows.append(debug_row)
            item_rows.append(
                {
                    "json_id": spec.gt_id,
                    "json_file": repo_path(spec.path),
                    "item_kind": "handler",
                    "item_index": str(index),
                    "gt_name": str(entry.get("name", "")),
                    "gt_type": "handler-entry",
                    "gt_location": str(entry.get("location", "")),
                    "coverage_status": "covered" if ids else "uncovered",
                    "match_kind": "tool-handler-root" if ids else "",
                    "detector_verdict": "",
                    "chain_count": str(len(ids)),
                    "chain_ids": ";".join(ids),
                    "matched_evidence": join_values(
                        sorted({chains_by_id[value].handler_func for value in ids})
                    ),
                    "notes": "",
                }
            )

        sink_item_matches: dict[int, dict[str, str]] = {}
        sink_notes: dict[int, str] = {}
        for index, sink in enumerate(sinks, 1):
            matches, note = sink_matches(spec.gt_id, sink, handler_chains)
            sink_item_matches[index] = matches
            sink_notes[index] = note
            sink_debug_base = debug_base_row(
                spec,
                "sink",
                index,
                sink,
                str(sink.get("kind", "")),
                source_debug_fields(sink, source_index.root, source_cache),
            )
            if not handler_chains:
                debug_row = dict(sink_debug_base)
                debug_row.update(
                    {
                        "stage": "sink-candidate",
                        "decision": "skipped",
                        "selected": "false",
                        "rejection_reason": "no handler-matched chain",
                    }
                )
                debug_rows.append(debug_row)
            for chain in handler_chains:
                match_kind, checks, rejection_reason = sink_match_debug(
                    spec.gt_id, sink, chain, matches
                )
                debug_row = dict(sink_debug_base)
                debug_row.update(chain_debug_fields(chain))
                debug_row.update(
                    {
                        "stage": "sink-candidate",
                        "candidate_kind": "sink",
                        "candidate_fn": chain.sink_label,
                        "candidate_file": chain.sink_file,
                        "candidate_line": str(chain.sink_line),
                        "checks": checks,
                        "decision": "matched" if match_kind else "rejected",
                        "match_kind": match_kind,
                        "selected": str(bool(match_kind)).lower(),
                        "rejection_reason": rejection_reason,
                    }
                )
                debug_rows.append(debug_row)
            kinds = sorted(set(matches.values()))
            status = "covered" if matches else "uncovered"
            item_rows.append(
                {
                    "json_id": spec.gt_id,
                    "json_file": repo_path(spec.path),
                    "item_kind": "sink",
                    "item_index": str(index),
                    "gt_name": str(sink.get("name", "")),
                    "gt_type": str(sink.get("kind", "")),
                    "gt_location": str(sink.get("location", "")),
                    "coverage_status": status,
                    "match_kind": join_values(kinds),
                    "detector_verdict": "",
                    "chain_count": str(len(matches)),
                    "chain_ids": ";".join(sorted(matches)),
                    "matched_evidence": join_values(
                        [
                            f"{chains_by_id[value].sink_label}@{chains_by_id[value].sink_file}:{chains_by_id[value].sink_line}"
                            for value in sorted(matches)
                        ]
                    ),
                    "notes": note,
                }
            )

        report_chain_ids = {
            chain_id_value
            for matches in sink_item_matches.values()
            for chain_id_value in matches
        }
        report_chains = [chains_by_id[value] for value in sorted(report_chain_ids)]

        gate_item_matches: dict[int, dict[str, str]] = {}
        gate_item_evidence: dict[int, dict[str, GateRef]] = {}
        gate_metadata: dict[int, dict[str, str]] = {}
        for index, gate in enumerate(gates, 1):
            metadata = effective_gate_metadata(
                spec.gt_id, gate, taint_rows, transform_rows
            )
            gate_metadata[index] = metadata
            gate_debug_base = debug_base_row(
                spec,
                "gate",
                index,
                gate,
                str(gate.get("type", "")),
                source_debug_fields(gate, source_index.root, source_cache),
                metadata=metadata,
            )
            matches: dict[str, str] = {}
            evidence: dict[str, GateRef] = {}
            if metadata.get("status") not in {"unsupported", "absent-in-source"}:
                for chain in report_chains:
                    if not gate_scope_allows(spec.gt_id, gate, chain):
                        continue
                    kind, candidate = best_gate_match(
                        gate,
                        metadata,
                        chain.gates,
                        source_index,
                        nested_index,
                    )
                    if kind and candidate:
                        matches[chain.chain_id] = kind
                        evidence[chain.chain_id] = candidate
            if metadata.get("status") in {"unsupported", "absent-in-source"}:
                debug_row = dict(gate_debug_base)
                debug_row.update(
                    {
                        "stage": "gate-metadata",
                        "decision": "skipped",
                        "selected": "false",
                        "rejection_reason": (
                            "metadata status "
                            f"{metadata.get('status')!r} skips candidate matching"
                        ),
                    }
                )
                debug_rows.append(debug_row)
            elif not report_chains:
                debug_row = dict(gate_debug_base)
                debug_row.update(
                    {
                        "stage": "gate-candidate",
                        "decision": "skipped",
                        "selected": "false",
                        "rejection_reason": "no sink-matched report chain",
                    }
                )
                debug_rows.append(debug_row)
            else:
                for chain in report_chains:
                    scope_allowed = gate_scope_allows(spec.gt_id, gate, chain)
                    if not scope_allowed:
                        debug_row = dict(gate_debug_base)
                        debug_row.update(chain_debug_fields(chain))
                        debug_row.update(
                            {
                                "stage": "gate-scope",
                                "checks": "scope_allowed=false",
                                "decision": "skipped",
                                "selected": "false",
                                "rejection_reason": (
                                    "gate-specific scope excludes this sink chain"
                                ),
                            }
                        )
                        debug_rows.append(debug_row)
                        continue
                    if not chain.gates:
                        debug_row = dict(gate_debug_base)
                        debug_row.update(chain_debug_fields(chain))
                        debug_row.update(
                            {
                                "stage": "gate-candidate",
                                "checks": "scope_allowed=true",
                                "decision": "rejected",
                                "selected": "false",
                                "rejection_reason": (
                                    "detector attached no gate candidate to this chain"
                                ),
                            }
                        )
                        debug_rows.append(debug_row)
                        continue

                    selected_candidate = evidence.get(chain.chain_id)
                    selected_kind = matches.get(chain.chain_id, "")
                    for candidate in chain.gates:
                        match_kind, checks, rejection_reason = gate_match_debug(
                            gate,
                            metadata,
                            candidate,
                            source_index,
                            nested_index,
                        )
                        selected = bool(
                            match_kind
                            and selected_kind == match_kind
                            and selected_candidate == candidate
                        )
                        if match_kind and not selected:
                            selected_text = (
                                f"{selected_candidate.fn}@{selected_candidate.file}:"
                                f"{selected_candidate.line} [{selected_kind}]"
                                if selected_candidate
                                else "none"
                            )
                            rejection_reason = (
                                "candidate matched but lost priority/order selection "
                                f"to {selected_text}"
                            )
                        debug_row = dict(gate_debug_base)
                        debug_row.update(chain_debug_fields(chain))
                        debug_row.update(gate_candidate_debug_fields(candidate))
                        debug_row.update(
                            {
                                "stage": "gate-candidate",
                                "checks": join_values(["scope_allowed=true", checks]),
                                "decision": (
                                    "matched"
                                    if selected
                                    else (
                                        "eligible-not-selected"
                                        if match_kind
                                        else "rejected"
                                    )
                                ),
                                "match_kind": match_kind,
                                "selected": str(selected).lower(),
                                "rejection_reason": rejection_reason,
                            }
                        )
                        debug_rows.append(debug_row)
            gate_item_matches[index] = matches
            gate_item_evidence[index] = evidence

            if metadata.get("status") == "unsupported":
                coverage_status = "unsupported"
            elif metadata.get("status") == "absent-in-source":
                coverage_status = "absent-in-source"
            else:
                coverage_status = "covered" if matches else "uncovered"
            automatic_nested_notes = sorted(
                {
                    nested_match.note
                    for chain_id_value, match_kind in matches.items()
                    if match_kind.startswith("nested-in-gate")
                    for nested_match in [
                        nested_index.match(
                            gate, evidence[chain_id_value]
                        )
                    ]
                    if nested_match is not None
                }
            )
            item_rows.append(
                {
                    "json_id": spec.gt_id,
                    "json_file": repo_path(spec.path),
                    "item_kind": "gate",
                    "item_index": str(index),
                    "gt_name": str(gate.get("name", "")),
                    "gt_type": str(gate.get("type", "")),
                    "gt_location": str(gate.get("location", "")),
                    "coverage_status": coverage_status,
                    "match_kind": join_values(sorted(set(matches.values()))),
                    "detector_verdict": aggregate_detector_verdicts(
                        list(evidence.values())
                    ),
                    "chain_count": str(len(matches)),
                    "chain_ids": ";".join(sorted(matches)),
                    "matched_evidence": join_values(
                        [
                            f"{value}:{evidence[value].fn}@{evidence[value].file}:{evidence[value].line} "
                            f"[{evidence[value].verdict}; {matches[value]}]"
                            for value in sorted(matches)
                        ]
                    ),
                    "notes": join_values(
                        [
                            value
                            for value in [
                                metadata.get("status", ""),
                                metadata.get("reason", ""),
                                (
                                    "GT describes a required-but-absent gate; "
                                    "detector candidates cannot cover it"
                                    if describes_absent_gate(gate)
                                    else ""
                                ),
                                *automatic_nested_notes,
                            ]
                            if value
                        ]
                    ),
                }
            )

        gate_names = [str(gate.get("name", "")) for gate in gates]
        sink_names = [str(sink.get("name", "")) for sink in sinks]
        supported_gate_indexes = {
            index
            for index, metadata in gate_metadata.items()
            if metadata.get("status") not in {"unsupported", "absent-in-source"}
        }

        for chain in sorted(
            report_chains,
            key=lambda value: (
                value.sink_file,
                value.sink_line,
                value.depth,
                value.call_chain,
            ),
        ):
            matched_sink_indexes = [
                index
                for index, matches in sink_item_matches.items()
                if chain.chain_id in matches
            ]
            covered_gate_indexes = [
                index
                for index, matches in gate_item_matches.items()
                if chain.chain_id in matches
            ]
            missing_supported = sorted(
                supported_gate_indexes - set(covered_gate_indexes)
            )
            unsupported = sorted(set(range(1, len(gates) + 1)) - supported_gate_indexes)
            all_handlers = all(
                chain.chain_id in ids for ids in handler_item_matches.values()
            )
            all_gates = len(covered_gate_indexes) == len(gates)
            all_sinks = len(matched_sink_indexes) == len(sinks)
            chain_rows.append(
                {
                    "json_id": spec.gt_id,
                    "json_file": repo_path(spec.path),
                    "chain_id": chain.chain_id,
                    "chain_source": chain.source,
                    "handler_func": chain.handler_func,
                    "depth": str(chain.depth),
                    "sink_label": chain.sink_label,
                    "sink_file": chain.sink_file,
                    "sink_line": str(chain.sink_line),
                    "matched_gt_sinks": join_values(
                        [
                            f"S{index}:{sink_names[index - 1]}"
                            for index in matched_sink_indexes
                        ]
                    ),
                    "covered_gates": join_values(
                        [
                            f"G{index}:{gate_names[index - 1]}"
                            for index in covered_gate_indexes
                        ]
                    ),
                    "covered_gate_evidence": join_values(
                        [
                            f"G{index}:{gate_item_evidence[index][chain.chain_id].fn}"
                            f"@{gate_item_evidence[index][chain.chain_id].file}:"
                            f"{gate_item_evidence[index][chain.chain_id].line} "
                            f"[{gate_item_matches[index][chain.chain_id]}]"
                            for index in covered_gate_indexes
                        ]
                    ),
                    "missing_supported_gates": join_values(
                        [
                            f"G{index}:{gate_names[index - 1]}"
                            for index in missing_supported
                        ]
                    ),
                    "unsupported_gates": join_values(
                        [f"G{index}:{gate_names[index - 1]}" for index in unsupported]
                    ),
                    "covers_all_handler_entries": str(all_handlers).lower(),
                    "covers_all_gt_gates": str(all_gates).lower(),
                    "covers_all_gt_sinks": str(all_sinks).lower(),
                    "covers_all_report_gt": str(
                        all_handlers and all_gates and all_sinks
                    ).lower(),
                    "call_chain": chain.call_chain,
                }
            )

        handler_covered = sum(bool(value) for value in handler_item_matches.values())
        gate_covered = sum(bool(value) for value in gate_item_matches.values())
        supported_gate_covered = sum(
            bool(gate_item_matches[index]) for index in supported_gate_indexes
        )
        sink_covered = sum(bool(value) for value in sink_item_matches.values())
        all_full = (
            handler_covered == len(entries)
            and gate_covered == len(gates)
            and sink_covered == len(sinks)
        )
        supported_full = (
            handler_covered == len(entries)
            and supported_gate_covered == len(supported_gate_indexes)
            and sink_covered == len(sinks)
        )
        summaries.append(
            {
                "json_id": spec.gt_id,
                "json_file": repo_path(spec.path),
                "chain_count": len(report_chains),
                "handler_covered": handler_covered,
                "handler_total": len(entries),
                "gate_covered": gate_covered,
                "gate_total": len(gates),
                "supported_gate_covered": supported_gate_covered,
                "supported_gate_total": len(supported_gate_indexes),
                "sink_covered": sink_covered,
                "sink_total": len(sinks),
                "all_full": all_full,
                "supported_full": supported_full,
            }
        )

    expected_gate_keys = {
        (spec.gt_id, str(gate.get("name", "")))
        for spec in configured_report_specs
        for gate in report_data[spec.gt_id].get("d5_gate_points", [])
    }
    known_gate_keys = set(taint_rows)
    missing_gate_metadata = sorted(expected_gate_keys - known_gate_keys)
    stale_gate_metadata = sorted(known_gate_keys - expected_gate_keys)
    write_csv(args.out_csv, CHAIN_FIELDS, chain_rows)
    write_csv(args.out_items_csv, ITEM_FIELDS, item_rows)
    write_csv(args.out_debug_csv, DEBUG_FIELDS, debug_rows)
    if args.gt_items_snapshot is not None:
        write_csv(
            args.gt_items_snapshot,
            GT_SNAPSHOT_FIELDS,
            [{field: row[field] for field in GT_SNAPSHOT_FIELDS} for row in item_rows],
        )
    args.out_md.write_text(
        render_markdown(
            summaries,
            item_rows,
            chain_rows,
            debug_rows,
            args.out_csv,
            args.out_items_csv,
            args.out_debug_csv,
            missing_gate_metadata,
            stale_gate_metadata,
            generation_command,
            snapshot_gt_ids,
        ),
        encoding="utf-8",
    )

    status_counts = Counter(row["coverage_status"] for row in item_rows)
    print(
        f"reports={len(summaries)} chains={len(chain_rows)} items={len(item_rows)} "
        f"debug_rows={len(debug_rows)} "
        f"status={dict(status_counts)} "
        f"missing_metadata={len(missing_gate_metadata)} "
        f"stale_metadata={len(stale_gate_metadata)}"
    )


if __name__ == "__main__":
    main()

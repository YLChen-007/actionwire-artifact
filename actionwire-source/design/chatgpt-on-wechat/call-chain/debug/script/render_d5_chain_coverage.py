#!/usr/bin/env python3
"""Map CowAgent D5 ground truth onto generic pipeline chains and gate semantics.

The raw reports describe several source revisions.  The CowAgent acceptance
oracle is therefore the authority for current 2.0.8 handler/sink anchors, while
the report JSON remains authoritative for individual D5 handler, gate, and
sink items.  Matches retain their provenance instead of silently treating a
stale line number as an exact current-source match.
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
import re
import shlex
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
DEBUG_DIR = SCRIPT_DIR.parent
REPO_ROOT = Path(__file__).resolve().parents[5]

DEFAULT_GROUND_TRUTH_DIR = REPO_ROOT / "design/chatgpt-on-wechat/groundtruth/new-vuls"
DEFAULT_ORACLE = (
    REPO_ROOT / "design/chatgpt-on-wechat/groundtruth/cowagent-2.0.8-acceptance.json"
)
DEFAULT_PIPELINE_OUTPUT = REPO_ROOT / "output/chatgpt-on-wechat"
DEFAULT_SOURCE_ROOT = REPO_ROOT / "benchmark/python/chatgpt-on-wechat"
DEFAULT_OUT_DIR = DEBUG_DIR

SUPPORTED_VERDICTS = {"confirmed", "branch-confirmed"}
LOCATION_RE = re.compile(r"([A-Za-z0-9_@./-]+\.py):(\d+)")
CALLABLE_RE = re.compile(r"\b(?:def\s+)?([A-Za-z_]\w*)\s*\(")
WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_/-]*")

STOP_WORDS = {
    "also",
    "agent",
    "allow",
    "and",
    "any",
    "before",
    "both",
    "branch",
    "call",
    "caller",
    "check",
    "command",
    "current",
    "derived",
    "directly",
    "each",
    "error",
    "execute",
    "execution",
    "fail",
    "false",
    "file",
    "from",
    "function",
    "gate",
    "into",
    "input",
    "line",
    "missing",
    "only",
    "parameter",
    "path",
    "policy",
    "result",
    "return",
    "same",
    "source",
    "string",
    "such",
    "that",
    "the",
    "then",
    "these",
    "this",
    "those",
    "tool",
    "toolresult",
    "true",
    "value",
    "when",
    "with",
    "without",
    "whose",
}

MISSING_CONTROL_PROFILES: dict[str, tuple[set[str], set[str]]] = {
    "mandatory-user-approval": (
        {"approval", "approve", "consent", "confirmation", "confirm"},
        {"mandatory", "require", "required", "user", "human"},
    ),
    "public-destination-validation": (
        {
            "destination",
            "loopback",
            "private",
            "public",
            "routable",
            "ssrf",
        },
        {"block", "deny", "reject", "safe", "validate", "validation"},
    ),
    "credential-file-alias-denial": (
        {"alias", "environ", "proc", "realpath", "samefile", "symlink"},
        {"block", "compare", "deny", "reject", "resolve", "validation"},
    ),
}


ITEM_FIELDS = [
    "report_id",
    "json_file",
    "dimension_id",
    "duplicate_of",
    "item_kind",
    "item_index",
    "gt_name",
    "gt_type",
    "gt_location",
    "existed_pre_patch",
    "source_anchor_status",
    "current_anchors",
    "coverage_status",
    "match_kind",
    "detector_verdict",
    "chain_count",
    "chain_ids",
    "matched_gate_uids",
    "matched_evidence",
    "notes",
]

CHAIN_FIELDS = [
    "report_id",
    "dimension_id",
    "duplicate_of",
    "chain_id",
    "tool_name",
    "handler_qualified_name",
    "source_parameter",
    "sink_id",
    "sink_api",
    "sink_file",
    "sink_line",
    "sink_argument",
    "constraint_id",
    "capability_class",
    "capability_card",
    "gate_count",
    "ordered_gates",
    "matched_gt_gates",
    "uncovered_existing_gates",
    "expected_missing_controls",
    "fabricated_controls",
    "chain_semantic_status",
    "report_verdict",
    "call_chain",
]

DEBUG_FIELDS = [
    "report_id",
    "dimension_id",
    "item_kind",
    "item_index",
    "gt_name",
    "gt_type",
    "gt_location",
    "chain_id",
    "candidate_gate_uid",
    "candidate_detector",
    "candidate_name",
    "candidate_file",
    "candidate_line",
    "candidate_verdict",
    "candidate_semantic_status",
    "score",
    "checks",
    "decision",
    "match_kind",
    "rejection_reason",
]


@dataclass(frozen=True)
class Location:
    file: str
    line: int


@dataclass(frozen=True)
class FunctionSpan:
    file: str
    name: str
    qualified_name: str
    start: int
    end: int


@dataclass(frozen=True)
class Chain:
    chain_id: str
    sink_id: str
    tool_name: str
    handler_qualified_name: str
    source_parameter: str
    sink_label: str
    sink_file: str
    sink_line: int
    sink_argument: str
    call_chain: str


@dataclass(frozen=True)
class GateCandidate:
    chain_id: str
    sequence: int
    detector: str
    gate_uid: str
    gate_id: str
    name: str
    file: str
    line: int
    enclosing_function: str
    verdict: str
    call_expression: str
    qualified_function: str
    semantic_status: str
    semantic_summary: str
    semantic_text: str


@dataclass(frozen=True)
class GateEvaluation:
    candidate: GateCandidate
    score: int
    match_kind: str
    checks: str
    rejection_reason: str


@dataclass
class AnalysisResult:
    item_rows: list[dict[str, str]]
    chain_rows: list[dict[str, str]]
    debug_rows: list[dict[str, str]]
    summaries: list[dict[str, Any]]
    stats: dict[str, Any]
    generation_command: str


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def normalize_path(value: str) -> str:
    value = value.replace("\\", "/")
    marker = value.find("agent/")
    if marker >= 0:
        return value[marker:]
    return value.lstrip("/")


def parse_locations(value: str) -> list[Location]:
    result: list[Location] = []
    for file_name, line in LOCATION_RE.findall(value or ""):
        location = Location(normalize_path(file_name), int(line))
        if location not in result:
            result.append(location)
    return result


def split_anchor(value: str) -> Location:
    file_name, line = value.rsplit(":", 1)
    return Location(normalize_path(file_name), int(line))


def same_file(left: str, right: str) -> bool:
    left = normalize_path(left)
    right = normalize_path(right)
    return left == right or left.endswith("/" + right) or right.endswith("/" + left)


def int_value(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def bool_text(value: object) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return ""


def join(values: Iterable[str]) -> str:
    return "; ".join(value for value in values if value)


def tokens(value: str) -> set[str]:
    result: set[str] = set()
    for word in WORD_RE.findall(value.lower()):
        for part in re.split(r"[_/\-]+", word):
            if len(part) >= 3 and part not in STOP_WORDS:
                result.add(part)
    return result


def callable_symbols(value: str) -> set[str]:
    return {match.lower().lstrip("_") for match in CALLABLE_RE.findall(value or "")}


def item_text(item: dict[str, Any]) -> str:
    return " ".join(
        str(item.get(key, ""))
        for key in ("name", "policy", "evidence", "problematic_parameter")
    )


def semantic_text(payload: dict[str, Any]) -> str:
    steps = payload.get("steps", [])
    return " ".join(
        [
            str(payload.get("summary", "")),
            str(payload.get("default", "")),
            str(payload.get("input", "")),
            str(payload.get("output", "")),
            *[
                " ".join(
                    [
                        str(step.get("op", "")),
                        str(step.get("rule", "")),
                        " ".join(str(value) for value in step.get("source_rules", [])),
                    ]
                )
                for step in steps
                if isinstance(step, dict)
            ],
        ]
    )


class SourceIndex:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.lines: dict[str, list[str]] = {}
        self.functions: dict[str, list[FunctionSpan]] = defaultdict(list)
        self._build()

    def _build(self) -> None:
        for path in self.root.rglob("*.py"):
            if any(
                part in {"__pycache__", ".agentfuzz-main-venv", "site-packages"}
                for part in path.parts
            ):
                continue
            relative = path.relative_to(self.root).as_posix()
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            self.lines[relative] = text.splitlines()
            try:
                tree = ast.parse(text, filename=str(path))
            except SyntaxError:
                continue
            self._collect_functions(relative, tree)

    def _collect_functions(self, file_name: str, tree: ast.AST) -> None:
        stack: list[str] = []

        class Visitor(ast.NodeVisitor):
            def visit_ClassDef(inner, node: ast.ClassDef) -> None:
                stack.append(node.name)
                inner.generic_visit(node)
                stack.pop()

            def visit_FunctionDef(inner, node: ast.FunctionDef) -> None:
                qualified = ".".join([*stack, node.name])
                self.functions[file_name].append(
                    FunctionSpan(
                        file=file_name,
                        name=node.name,
                        qualified_name=qualified,
                        start=node.lineno,
                        end=getattr(node, "end_lineno", node.lineno),
                    )
                )
                stack.append(node.name)
                inner.generic_visit(node)
                stack.pop()

            visit_AsyncFunctionDef = visit_FunctionDef

        Visitor().visit(tree)

    def owner(self, location: Location) -> str:
        candidates = [
            function
            for function in self.functions.get(location.file, [])
            if function.start <= location.line <= function.end
        ]
        if not candidates:
            return ""
        candidates.sort(key=lambda value: (value.end - value.start, -value.start))
        return candidates[0].name

    def anchor_status(self, item: dict[str, Any]) -> str:
        refs = parse_locations(str(item.get("location", "")))
        if not refs:
            return "no-location"
        evidence_lines = [
            line.strip()
            for line in str(item.get("evidence", "")).splitlines()
            if line.strip() and line.strip() not in {"...", "---"}
        ]
        states: list[str] = []
        for ref in refs:
            source_lines = self.lines.get(ref.file)
            if source_lines is None:
                states.append(f"{ref.file}=missing")
            elif not 1 <= ref.line <= len(source_lines):
                states.append(f"{ref.file}:{ref.line}=out-of-range")
            else:
                current = source_lines[ref.line - 1].strip()
                exact = not evidence_lines or current in evidence_lines
                states.append(
                    f"{ref.file}:{ref.line}="
                    + ("evidence-current" if exact else "evidence-stale")
                )
        return join(states)

    def evidence_current(self, item: dict[str, Any], location: Location) -> bool:
        source_lines = self.lines.get(location.file)
        if source_lines is None or not 1 <= location.line <= len(source_lines):
            return False
        current = source_lines[location.line - 1].strip()
        evidence = {
            line.strip()
            for line in str(item.get("evidence", "")).splitlines()
            if line.strip() and line.strip() not in {"...", "---"}
        }
        return bool(current and current in evidence)


def load_pipeline(
    pipeline_output: Path,
) -> tuple[
    list[Chain],
    dict[str, list[GateCandidate]],
    dict[str, list[dict[str, str]]],
    dict[str, str],
    dict[str, Any],
]:
    static = pipeline_output / "static/call-chains"
    chain_rows = read_csv(static / "handler-sink-chains.csv")
    gate_rows = read_csv(static / "chain-gates.csv")
    constraint_rows = read_csv(static / "sink-constraints.csv")
    manifest = json.loads(
        (pipeline_output / "pipeline-manifest.json").read_text(encoding="utf-8")
    )

    index_by_uid = {
        row["gate_uid"]: row
        for row in read_csv(pipeline_output / "gate-semantics/gate-index.csv")
    }
    semantic_by_id = {
        row["gate_id"]: row
        for row in read_jsonl(pipeline_output / "gate-semantics/gate-semantics.jsonl")
    }
    chain_semantic_status = {
        row["chain_id"]: str(row.get("status", ""))
        for row in read_jsonl(
            pipeline_output / "call-chain-semantics/call-chain-semantics.jsonl"
        )
    }

    chains = [
        Chain(
            chain_id=row["chain_id"],
            sink_id=row["sink_id"],
            tool_name=row["tool_name"],
            handler_qualified_name=row["handler_qualified_name"],
            source_parameter=row["source_parameter"],
            sink_label=row["sink_label"],
            sink_file=normalize_path(row["sink_file"]),
            sink_line=int_value(row["sink_line"]),
            sink_argument=row["sink_argument"],
            call_chain=row["call_chain"],
        )
        for row in chain_rows
    ]

    gates_by_chain: dict[str, list[GateCandidate]] = defaultdict(list)
    for row in gate_rows:
        if not row.get("gate_uid"):
            continue
        index = index_by_uid.get(row["gate_uid"], {})
        semantic = semantic_by_id.get(row["gate_id"], {})
        combined_text = " ".join(
            [
                row.get("gate_name", ""),
                index.get("qualified_function", ""),
                index.get("call_expression", ""),
                semantic_text(semantic),
            ]
        )
        gates_by_chain[row["chain_id"]].append(
            GateCandidate(
                chain_id=row["chain_id"],
                sequence=int_value(row["gate_seq"]),
                detector=row["detector"],
                gate_uid=row["gate_uid"],
                gate_id=row["gate_id"],
                name=row["gate_name"],
                file=normalize_path(row["gate_file"]),
                line=int_value(row["gate_line"]),
                enclosing_function=row["enclosing_function"],
                verdict=row["static_verdict"],
                call_expression=index.get("call_expression", ""),
                qualified_function=index.get("qualified_function", ""),
                semantic_status=str(semantic.get("status", "missing")),
                semantic_summary=str(semantic.get("summary", "")),
                semantic_text=combined_text,
            )
        )
    for values in gates_by_chain.values():
        values.sort(key=lambda value: (value.sequence, value.gate_uid))

    constraints: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in constraint_rows:
        constraints[row["sink_id"]].append(row)
    return chains, gates_by_chain, constraints, chain_semantic_status, manifest


def evaluate_gate(
    item: dict[str, Any],
    candidate: GateCandidate,
    source: SourceIndex,
) -> GateEvaluation:
    expected_detector = str(item.get("type", "dominance"))
    if expected_detector not in {"dominance", "filter", "transform"}:
        expected_detector = "dominance"

    refs = parse_locations(str(item.get("location", "")))
    same_file_refs = [ref for ref in refs if same_file(ref.file, candidate.file)]
    exact_refs = [ref for ref in same_file_refs if ref.line == candidate.line]
    near_distance = min(
        (abs(ref.line - candidate.line) for ref in same_file_refs), default=10_000
    )
    gt_tokens = tokens(item_text(item))
    candidate_tokens = tokens(candidate.semantic_text)
    overlap = sorted(gt_tokens & candidate_tokens)
    gt_symbols = callable_symbols(item_text(item))
    candidate_symbols = {
        candidate.name.lower().lstrip("_"),
        candidate.enclosing_function.lower().lstrip("_"),
        candidate.qualified_function.rsplit(".", 1)[-1].lower().lstrip("_"),
    }
    symbol_match = bool(gt_symbols & candidate_symbols)
    owner_match = any(
        source.owner(ref).lower().lstrip("_") in candidate_symbols
        for ref in same_file_refs
        if source.owner(ref)
    )
    current_evidence = any(source.evidence_current(item, ref) for ref in exact_refs)

    checks = join(
        [
            f"expected_detector={expected_detector}",
            f"detector_matches={str(candidate.detector == expected_detector).lower()}",
            f"eligible_verdict={str(candidate.verdict in SUPPORTED_VERDICTS).lower()}",
            f"same_file={str(bool(same_file_refs)).lower()}",
            f"exact_line={str(bool(exact_refs)).lower()}",
            f"current_evidence={str(current_evidence).lower()}",
            f"near_distance={near_distance if near_distance < 10_000 else ''}",
            f"symbol_match={str(symbol_match).lower()}",
            f"owner_match={str(owner_match).lower()}",
            "semantic_overlap=" + ",".join(overlap[:20]),
        ]
    )

    if candidate.detector != expected_detector:
        return GateEvaluation(
            candidate, 0, "", checks, "candidate detector type does not match GT"
        )
    if candidate.verdict not in SUPPORTED_VERDICTS:
        return GateEvaluation(
            candidate, 0, "", checks, "candidate verdict is not semantics-eligible"
        )
    if not same_file_refs:
        return GateEvaluation(
            candidate, 0, "", checks, "candidate is in a different source file"
        )

    if exact_refs and current_evidence:
        return GateEvaluation(candidate, 100, "exact-location", checks, "")
    if exact_refs and symbol_match:
        return GateEvaluation(candidate, 95, "exact-location-symbol", checks, "")
    if exact_refs and len(overlap) >= 2:
        return GateEvaluation(
            candidate,
            70 + min(len(overlap) * 2, 10),
            "exact-location-semantic",
            checks,
            "",
        )
    if exact_refs and not (current_evidence or symbol_match or overlap):
        return GateEvaluation(
            candidate,
            0,
            "",
            checks,
            "line number collides with semantically different current source",
        )
    if symbol_match:
        return GateEvaluation(candidate, 90, "gate-symbol", checks, "")
    if owner_match and len(overlap) >= 2:
        return GateEvaluation(
            candidate,
            65 + min(len(overlap) * 3, 15),
            "source-owner",
            checks,
            "",
        )
    if near_distance <= 12 and overlap:
        return GateEvaluation(
            candidate,
            65 + min(len(overlap) * 3, 15),
            "near-location-semantic",
            checks,
            "",
        )
    if len(overlap) >= 2:
        return GateEvaluation(
            candidate,
            55 + min(len(overlap) * 2, 10),
            "nested-in-gate",
            checks,
            "",
        )
    return GateEvaluation(
        candidate,
        0,
        "",
        checks,
        "no exact semantic, symbol, owner, near-location, or nested match",
    )


def candidate_distance(item: dict[str, Any], candidate: GateCandidate) -> int:
    return min(
        (
            abs(ref.line - candidate.line)
            for ref in parse_locations(str(item.get("location", "")))
            if same_file(ref.file, candidate.file)
        ),
        default=10_000,
    )


def missing_control_match(control: str, candidate: GateCandidate) -> tuple[bool, str]:
    if candidate.detector == "transform":
        return False, "transform-only candidate has no conditional rejection"
    profile = MISSING_CONTROL_PROFILES.get(control)
    candidate_tokens = tokens(candidate.semantic_text)
    if profile is None:
        required = tokens(control)
        matched = bool(required) and required <= candidate_tokens
        return matched, "required=" + ",".join(sorted(required))
    subject, action = profile
    subject_hits = sorted(subject & candidate_tokens)
    action_hits = sorted(action & candidate_tokens)
    matched = bool(subject_hits) and bool(action_hits)
    return matched, join(
        [
            "subject_hits=" + ",".join(subject_hits),
            "action_hits=" + ",".join(action_hits),
        ]
    )


def repo_path(path: Path) -> str:
    absolute = path.absolute()
    try:
        return str(absolute.relative_to(REPO_ROOT))
    except ValueError:
        return str(absolute)


def generation_command(args: argparse.Namespace) -> str:
    return shlex.join(
        [
            "python",
            "design/chatgpt-on-wechat/call-chain/debug/script/render_d5_chain_coverage.py",
            "--ground-truth-dir",
            repo_path(args.ground_truth_dir),
            "--oracle",
            repo_path(args.oracle),
            "--pipeline-output",
            repo_path(args.pipeline_output),
            "--source-root",
            repo_path(args.source_root),
            "--out-dir",
            repo_path(args.out_dir),
        ]
    )


def debug_row(
    report_id: str,
    dimension_id: str,
    item_kind: str,
    item_index: int,
    item: dict[str, Any],
    evaluation: GateEvaluation | None,
    *,
    chain_id: str = "",
    decision: str,
    match_kind: str = "",
    checks: str = "",
    rejection_reason: str = "",
) -> dict[str, str]:
    candidate = evaluation.candidate if evaluation is not None else None
    return {
        "report_id": report_id,
        "dimension_id": dimension_id,
        "item_kind": item_kind,
        "item_index": str(item_index),
        "gt_name": str(item.get("name", "")),
        "gt_type": str(item.get("type", item.get("kind", ""))),
        "gt_location": str(item.get("location", "")),
        "chain_id": chain_id or (candidate.chain_id if candidate else ""),
        "candidate_gate_uid": candidate.gate_uid if candidate else "",
        "candidate_detector": candidate.detector if candidate else "",
        "candidate_name": candidate.name if candidate else "",
        "candidate_file": candidate.file if candidate else "",
        "candidate_line": str(candidate.line) if candidate else "",
        "candidate_verdict": candidate.verdict if candidate else "",
        "candidate_semantic_status": candidate.semantic_status if candidate else "",
        "score": str(evaluation.score) if evaluation else "",
        "checks": checks or (evaluation.checks if evaluation else ""),
        "decision": decision,
        "match_kind": match_kind or (evaluation.match_kind if evaluation else ""),
        "rejection_reason": rejection_reason
        or (evaluation.rejection_reason if evaluation else ""),
    }


def analyze(args: argparse.Namespace) -> AnalysisResult:
    command = generation_command(args)
    oracle = json.loads(args.oracle.read_text(encoding="utf-8"))
    chains, gates_by_chain, constraints, chain_semantics, manifest = load_pipeline(
        args.pipeline_output
    )
    if manifest["project"]["id"] != oracle["project_id"]:
        raise ValueError("pipeline project does not match acceptance oracle")
    if manifest["project"]["revision"] != oracle["analysis_revision"]:
        raise ValueError("pipeline revision does not match acceptance oracle")

    source = SourceIndex(args.source_root)
    dimensions = {value["id"]: value for value in oracle["dimensions"]}
    report_dimension: dict[str, dict[str, Any]] = {}
    duplicate_of: dict[str, str] = {}
    for dimension in oracle["dimensions"]:
        duplicates = set(dimension.get("duplicate_reports", []))
        canonical = next(
            (
                report
                for report in dimension["source_reports"]
                if report not in duplicates
            ),
            dimension["source_reports"][0],
        )
        for report in dimension["source_reports"]:
            if report in report_dimension:
                raise ValueError(f"report mapped to multiple dimensions: {report}")
            report_dimension[report] = dimension
            if report in duplicates:
                duplicate_of[report] = canonical

    reports: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(args.ground_truth_dir.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        report_id = str(data.get("report_name", path.stem))
        if report_id not in report_dimension:
            raise ValueError(f"ground-truth report missing from oracle: {report_id}")
        reports.append((path, data))
    missing_reports = sorted(
        set(report_dimension) - {r[1].get("report_name") for r in reports}
    )
    if missing_reports:
        raise ValueError(
            "oracle reports missing from ground truth: " + ", ".join(missing_reports)
        )

    item_rows: list[dict[str, str]] = []
    chain_rows: list[dict[str, str]] = []
    debug_rows: list[dict[str, str]] = []
    summaries: list[dict[str, Any]] = []
    overall_target_sinks: set[Location] = set()
    overall_covered_sinks: set[Location] = set()
    overall_constrained_sinks: set[Location] = set()
    unique_missing_status: dict[tuple[str, str], str] = {}
    oracle_gap_keys: set[tuple[str, str]] = set()

    chains_by_location: dict[Location, list[Chain]] = defaultdict(list)
    for chain in chains:
        chains_by_location[Location(chain.sink_file, chain.sink_line)].append(chain)

    for json_path, data in reports:
        report_id = str(data["report_name"])
        dimension = report_dimension[report_id]
        dimension_id = str(dimension["id"])
        handler = str(dimension["handler"])
        duplicate = duplicate_of.get(report_id, "")
        target_locations = [split_anchor(value) for value in dimension["sink_points"]]
        overall_target_sinks.update(target_locations)
        report_chains = sorted(
            {
                chain.chain_id: chain
                for location in target_locations
                for chain in chains_by_location.get(location, [])
                if chain.tool_name == handler
            }.values(),
            key=lambda value: (value.sink_file, value.sink_line, value.chain_id),
        )
        for location in target_locations:
            matching = [
                chain
                for chain in chains_by_location.get(location, [])
                if chain.tool_name == handler
            ]
            if matching:
                overall_covered_sinks.add(location)
            if matching and all(
                len(constraints.get(chain.sink_id, [])) == 1 for chain in matching
            ):
                overall_constrained_sinks.add(location)

        attached_gates = [
            gate
            for chain in report_chains
            for gate in gates_by_chain.get(chain.chain_id, [])
        ]
        entries = list(data.get("d5_tool_handler_entry", []))
        gates = list(data.get("d5_gate_points", []))
        sinks = list(data.get("d5_sink_points", []))

        handler_covered = 0
        for index, entry in enumerate(entries, 1):
            entry_name = str(entry.get("name", ""))
            matching = [
                chain
                for chain in report_chains
                if chain.tool_name == entry_name or entry_name == handler
            ]
            status = "covered" if matching else "uncovered"
            handler_covered += int(bool(matching))
            item_rows.append(
                {
                    "report_id": report_id,
                    "json_file": repo_path(json_path),
                    "dimension_id": dimension_id,
                    "duplicate_of": duplicate,
                    "item_kind": "handler",
                    "item_index": str(index),
                    "gt_name": entry_name,
                    "gt_type": "tool-handler",
                    "gt_location": str(entry.get("location", "")),
                    "existed_pre_patch": "",
                    "source_anchor_status": source.anchor_status(entry),
                    "current_anchors": join(
                        sorted(
                            {f"{chain.handler_qualified_name}" for chain in matching}
                        )
                    ),
                    "coverage_status": status,
                    "match_kind": "tool-name" if matching else "",
                    "detector_verdict": "",
                    "chain_count": str(len(matching)),
                    "chain_ids": ";".join(chain.chain_id for chain in matching),
                    "matched_gate_uids": "",
                    "matched_evidence": join(
                        chain.handler_qualified_name for chain in matching
                    ),
                    "notes": "",
                }
            )
            debug_rows.append(
                debug_row(
                    report_id,
                    dimension_id,
                    "handler",
                    index,
                    entry,
                    None,
                    decision="matched" if matching else "rejected",
                    match_kind="tool-name" if matching else "",
                    checks=f"expected_tool={entry_name}; oracle_handler={handler}",
                    rejection_reason="" if matching else "no current chain for handler",
                )
            )

        sink_covered = 0
        for index, sink in enumerate(sinks, 1):
            raw_refs = parse_locations(str(sink.get("location", "")))
            exact = [
                chain
                for chain in report_chains
                if any(
                    same_file(ref.file, chain.sink_file) and ref.line == chain.sink_line
                    for ref in raw_refs
                )
            ]
            matching = exact or report_chains
            match_kind = "exact-location" if exact else "oracle-rebase"
            status = "covered" if matching else "uncovered"
            sink_covered += int(bool(matching))
            item_rows.append(
                {
                    "report_id": report_id,
                    "json_file": repo_path(json_path),
                    "dimension_id": dimension_id,
                    "duplicate_of": duplicate,
                    "item_kind": "sink",
                    "item_index": str(index),
                    "gt_name": str(sink.get("name", "")),
                    "gt_type": str(sink.get("kind", "")),
                    "gt_location": str(sink.get("location", "")),
                    "existed_pre_patch": "",
                    "source_anchor_status": source.anchor_status(sink),
                    "current_anchors": join(
                        sorted(
                            {
                                f"{chain.sink_file}:{chain.sink_line}"
                                for chain in matching
                            }
                        )
                    ),
                    "coverage_status": status,
                    "match_kind": match_kind if matching else "",
                    "detector_verdict": "",
                    "chain_count": str(len(matching)),
                    "chain_ids": ";".join(chain.chain_id for chain in matching),
                    "matched_gate_uids": "",
                    "matched_evidence": join(
                        f"{chain.sink_label}@{chain.sink_file}:{chain.sink_line}"
                        for chain in matching
                    ),
                    "notes": (
                        "raw report anchor is stale; current sink set comes from the "
                        "revision-pinned acceptance oracle"
                        if matching and not exact
                        else ""
                    ),
                }
            )
            for chain in report_chains:
                selected = chain in matching
                debug_rows.append(
                    debug_row(
                        report_id,
                        dimension_id,
                        "sink",
                        index,
                        sink,
                        None,
                        chain_id=chain.chain_id,
                        decision="matched" if selected else "rejected",
                        match_kind=match_kind if selected else "",
                        checks=join(
                            [
                                f"candidate={chain.sink_file}:{chain.sink_line}",
                                f"exact={str(chain in exact).lower()}",
                                f"oracle_target={str(Location(chain.sink_file, chain.sink_line) in target_locations).lower()}",
                                "constraint_count="
                                + str(len(constraints.get(chain.sink_id, []))),
                            ]
                        ),
                        rejection_reason=""
                        if selected
                        else "not selected by sink rule",
                    )
                )

        gate_matches: dict[int, dict[str, GateCandidate]] = {}
        gate_covered = 0
        existing_gate_total = 0
        existing_gate_covered = 0
        report_oracle_gaps: list[str] = []
        for index, gate in enumerate(gates, 1):
            existed = gate.get("existed_pre_patch")
            if existed is False:
                if dimension.get("expected_missing"):
                    status = "expected-missing-detail"
                    note = (
                        "fix/missing-control detail is absent in the target revision; "
                        "the dimension-level control is checked semantically below"
                    )
                elif (
                    gate.get("is_defect_site")
                    or "missing" in str(gate.get("name", "")).lower()
                ):
                    status = "oracle-gap"
                    note = "GT describes an absent security control not represented by oracle.expected_missing"
                    report_oracle_gaps.append(str(gate.get("name", "")))
                    oracle_gap_keys.add((dimension_id, str(gate.get("name", ""))))
                else:
                    status = "not-in-target-revision"
                    note = "post-report fix detail; excluded from existing-gate recall"
                item_rows.append(
                    {
                        "report_id": report_id,
                        "json_file": repo_path(json_path),
                        "dimension_id": dimension_id,
                        "duplicate_of": duplicate,
                        "item_kind": "gate",
                        "item_index": str(index),
                        "gt_name": str(gate.get("name", "")),
                        "gt_type": str(gate.get("type", "")),
                        "gt_location": str(gate.get("location", "")),
                        "existed_pre_patch": "false",
                        "source_anchor_status": source.anchor_status(gate),
                        "current_anchors": "",
                        "coverage_status": status,
                        "match_kind": "",
                        "detector_verdict": "",
                        "chain_count": "0",
                        "chain_ids": "",
                        "matched_gate_uids": "",
                        "matched_evidence": "",
                        "notes": note,
                    }
                )
                debug_rows.append(
                    debug_row(
                        report_id,
                        dimension_id,
                        "gate",
                        index,
                        gate,
                        None,
                        decision="classified",
                        checks="existed_pre_patch=false",
                        rejection_reason=note,
                    )
                )
                continue

            existing_gate_total += 1
            evaluations = [
                evaluate_gate(gate, candidate, source) for candidate in attached_gates
            ]
            eligible = [evaluation for evaluation in evaluations if evaluation.score]
            selected_by_chain: dict[str, GateCandidate] = {}
            for evaluation in sorted(
                eligible,
                key=lambda value: (
                    value.score,
                    -candidate_distance(gate, value.candidate),
                    -value.candidate.sequence,
                    value.candidate.gate_uid,
                ),
                reverse=True,
            ):
                selected_by_chain.setdefault(
                    evaluation.candidate.chain_id, evaluation.candidate
                )
            gate_matches[index] = selected_by_chain
            covered = bool(selected_by_chain)
            gate_covered += int(covered)
            existing_gate_covered += int(covered)
            selected_uids = {
                candidate.gate_uid for candidate in selected_by_chain.values()
            }
            selected_kinds = {
                evaluation.match_kind
                for evaluation in eligible
                if evaluation.candidate.gate_uid in selected_uids
            }
            item_rows.append(
                {
                    "report_id": report_id,
                    "json_file": repo_path(json_path),
                    "dimension_id": dimension_id,
                    "duplicate_of": duplicate,
                    "item_kind": "gate",
                    "item_index": str(index),
                    "gt_name": str(gate.get("name", "")),
                    "gt_type": str(gate.get("type", "")),
                    "gt_location": str(gate.get("location", "")),
                    "existed_pre_patch": bool_text(existed),
                    "source_anchor_status": source.anchor_status(gate),
                    "current_anchors": join(
                        sorted(
                            {
                                f"{candidate.file}:{candidate.line}"
                                for candidate in selected_by_chain.values()
                            }
                        )
                    ),
                    "coverage_status": "covered" if covered else "uncovered",
                    "match_kind": join(sorted(selected_kinds)),
                    "detector_verdict": join(
                        sorted(
                            {
                                candidate.verdict
                                for candidate in selected_by_chain.values()
                            }
                        )
                    ),
                    "chain_count": str(len(selected_by_chain)),
                    "chain_ids": ";".join(sorted(selected_by_chain)),
                    "matched_gate_uids": ";".join(sorted(selected_uids)),
                    "matched_evidence": join(
                        f"{candidate.gate_uid}:{candidate.name}@{candidate.file}:{candidate.line}"
                        for candidate in selected_by_chain.values()
                    ),
                    "notes": (
                        "GT transform has no eligible transform candidate on a matched chain"
                        if not covered and str(gate.get("type", "")) == "transform"
                        else ""
                    ),
                }
            )
            for evaluation in evaluations:
                selected = (
                    selected_by_chain.get(evaluation.candidate.chain_id)
                    == evaluation.candidate
                )
                reason = evaluation.rejection_reason
                if evaluation.score and not selected:
                    reason = "lower-priority matching candidate on the same chain"
                debug_rows.append(
                    debug_row(
                        report_id,
                        dimension_id,
                        "gate",
                        index,
                        gate,
                        evaluation,
                        decision=(
                            "matched"
                            if selected
                            else "eligible-not-selected"
                            if evaluation.score
                            else "rejected"
                        ),
                        rejection_reason=reason,
                    )
                )

        missing_results: dict[str, tuple[str, list[GateCandidate]]] = {}
        for missing_index, control in enumerate(
            dimension.get("expected_missing", []), 1
        ):
            fabricated: list[GateCandidate] = []
            for candidate in attached_gates:
                matched, checks = missing_control_match(control, candidate)
                debug_rows.append(
                    debug_row(
                        report_id,
                        dimension_id,
                        "expected-missing",
                        missing_index,
                        {"name": control, "type": "missing-control", "location": ""},
                        GateEvaluation(
                            candidate,
                            int(matched),
                            "semantic-profile" if matched else "",
                            checks,
                            "" if matched else "semantic profile not satisfied",
                        ),
                        decision="fabricated" if matched else "preserved",
                    )
                )
                if matched:
                    fabricated.append(candidate)
            status = "fabricated" if fabricated else "preserved"
            missing_results[control] = (status, fabricated)
            unique_missing_status[(dimension_id, control)] = status
            item_rows.append(
                {
                    "report_id": report_id,
                    "json_file": repo_path(json_path),
                    "dimension_id": dimension_id,
                    "duplicate_of": duplicate,
                    "item_kind": "expected-missing",
                    "item_index": str(missing_index),
                    "gt_name": control,
                    "gt_type": "missing-control",
                    "gt_location": "",
                    "existed_pre_patch": "false",
                    "source_anchor_status": "absent-by-definition",
                    "current_anchors": "",
                    "coverage_status": status,
                    "match_kind": "semantic-profile",
                    "detector_verdict": join(
                        sorted({candidate.verdict for candidate in fabricated})
                    ),
                    "chain_count": str(
                        len({candidate.chain_id for candidate in fabricated})
                    ),
                    "chain_ids": ";".join(
                        sorted({candidate.chain_id for candidate in fabricated})
                    ),
                    "matched_gate_uids": ";".join(
                        sorted({candidate.gate_uid for candidate in fabricated})
                    ),
                    "matched_evidence": join(
                        candidate.semantic_summary for candidate in fabricated
                    ),
                    "notes": (
                        "no attached gate semantic implements the missing control"
                        if not fabricated
                        else "an attached gate semantic appears to implement a control expected to be absent"
                    ),
                }
            )

        target_sink_covered = sum(
            bool(
                [
                    chain
                    for chain in chains_by_location.get(location, [])
                    if chain.tool_name == handler
                ]
            )
            for location in target_locations
        )
        target_constraints = sum(
            bool(matching)
            and all(len(constraints.get(chain.sink_id, [])) == 1 for chain in matching)
            for location in target_locations
            for matching in [
                [
                    chain
                    for chain in chains_by_location.get(location, [])
                    if chain.tool_name == handler
                ]
            ]
        )
        missing_ok = all(
            status == "preserved" for status, _ in missing_results.values()
        )
        structure_ok = (
            handler_covered == len(entries)
            and target_sink_covered == len(target_locations)
            and target_constraints == len(target_locations)
        )
        gates_ok = existing_gate_covered == existing_gate_total
        report_verdict = (
            "pass"
            if structure_ok and gates_ok and missing_ok and not report_oracle_gaps
            else "partial"
            if structure_ok
            else "fail"
        )
        if duplicate:
            report_verdict = "duplicate-" + report_verdict

        uncovered_gate_names = [
            str(gate.get("name", ""))
            for index, gate in enumerate(gates, 1)
            if gate.get("existed_pre_patch") is not False
            and not gate_matches.get(index)
        ]
        fabricated_controls = [
            control
            for control, (status, _) in missing_results.items()
            if status == "fabricated"
        ]
        for chain in report_chains:
            constraint_rows = constraints.get(chain.sink_id, [])
            constraint = constraint_rows[0] if len(constraint_rows) == 1 else {}
            ordered = gates_by_chain.get(chain.chain_id, [])
            matched_gt = [
                f"G{index}:{gate.get('name', '')}"
                for index, gate in enumerate(gates, 1)
                if chain.chain_id in gate_matches.get(index, {})
            ]
            chain_rows.append(
                {
                    "report_id": report_id,
                    "dimension_id": dimension_id,
                    "duplicate_of": duplicate,
                    "chain_id": chain.chain_id,
                    "tool_name": chain.tool_name,
                    "handler_qualified_name": chain.handler_qualified_name,
                    "source_parameter": chain.source_parameter,
                    "sink_id": chain.sink_id,
                    "sink_api": constraint.get("sink_api", chain.sink_label),
                    "sink_file": chain.sink_file,
                    "sink_line": str(chain.sink_line),
                    "sink_argument": chain.sink_argument,
                    "constraint_id": constraint.get("constraint_id", ""),
                    "capability_class": constraint.get("capability_class", ""),
                    "capability_card": constraint.get("capability_card", ""),
                    "gate_count": str(len(ordered)),
                    "ordered_gates": join(
                        f"{gate.sequence}:{gate.gate_uid}:{gate.name}@{gate.file}:{gate.line}"
                        for gate in ordered
                    ),
                    "matched_gt_gates": join(matched_gt),
                    "uncovered_existing_gates": join(uncovered_gate_names),
                    "expected_missing_controls": join(missing_results),
                    "fabricated_controls": join(fabricated_controls),
                    "chain_semantic_status": chain_semantics.get(
                        chain.chain_id, "missing"
                    ),
                    "report_verdict": report_verdict,
                    "call_chain": chain.call_chain,
                }
            )

        summaries.append(
            {
                "report_id": report_id,
                "json_file": repo_path(json_path),
                "dimension_id": dimension_id,
                "duplicate_of": duplicate,
                "chain_count": len(report_chains),
                "handler_covered": handler_covered,
                "handler_total": len(entries),
                "raw_sink_covered": sink_covered,
                "raw_sink_total": len(sinks),
                "current_sink_covered": target_sink_covered,
                "current_sink_total": len(target_locations),
                "constraint_covered": target_constraints,
                "existing_gate_covered": existing_gate_covered,
                "existing_gate_total": existing_gate_total,
                "expected_missing": len(missing_results),
                "missing_preserved": sum(
                    status == "preserved" for status, _ in missing_results.values()
                ),
                "oracle_gaps": report_oracle_gaps,
                "verdict": report_verdict,
            }
        )

    canonical_summaries = [
        summary for summary in summaries if not summary["duplicate_of"]
    ]
    existing_total = sum(
        summary["existing_gate_total"] for summary in canonical_summaries
    )
    existing_covered = sum(
        summary["existing_gate_covered"] for summary in canonical_summaries
    )
    stats = {
        "project_id": oracle["project_id"],
        "analysis_revision": oracle["analysis_revision"],
        "reports": len(summaries),
        "dimensions": len(dimensions),
        "duplicate_reports": len(duplicate_of),
        "structural_chains": len(chains),
        "target_sink_total": len(overall_target_sinks),
        "target_sink_covered": len(overall_covered_sinks),
        "target_sink_constrained": len(overall_constrained_sinks),
        "existing_gate_total": existing_total,
        "existing_gate_covered": existing_covered,
        "expected_missing_total": len(unique_missing_status),
        "expected_missing_preserved": sum(
            status == "preserved" for status in unique_missing_status.values()
        ),
        "oracle_gaps": len(oracle_gap_keys),
        "report_verdicts": dict(Counter(summary["verdict"] for summary in summaries)),
    }
    return AnalysisResult(
        item_rows=item_rows,
        chain_rows=chain_rows,
        debug_rows=debug_rows,
        summaries=summaries,
        stats=stats,
        generation_command=command,
    )


def md_escape(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def render_markdown(result: AnalysisResult, out_dir: Path) -> str:
    stats = result.stats
    lines = [
        "# CowAgent D5 Ground-Truth Call-Chain Coverage",
        "",
        "> Generated file. Do not edit by hand.",
        ">",
        f"> Generation command: `{result.generation_command}`",
        ">",
        "> Outputs: [`d5-chain-coverage.csv`](d5-chain-coverage.csv), "
        "[`d5-chain-coverage-items.csv`](d5-chain-coverage-items.csv), and "
        "[`d5-chain-coverage-debug.csv`](d5-chain-coverage-debug.csv).",
        "",
        f"Revision: `{stats['analysis_revision']}`.",
        "",
        "## Summary",
        "",
        f"- Reports: **{stats['reports']}**; unique vulnerability dimensions: **{stats['dimensions']}**; duplicate reports: **{stats['duplicate_reports']}**.",
        f"- Current sink points with handler chains: **{stats['target_sink_covered']}/{stats['target_sink_total']}**; exactly mapped constraints: **{stats['target_sink_constrained']}/{stats['target_sink_total']}**.",
        f"- Current existing GT gates: **{stats['existing_gate_covered']}/{stats['existing_gate_total']}** (canonical reports only).",
        f"- Expected-missing controls preserved: **{stats['expected_missing_preserved']}/{stats['expected_missing_total']}**.",
        f"- Oracle gaps: **{stats['oracle_gaps']}**.",
        "- Report verdicts: "
        + ", ".join(
            f"`{key}`={value}"
            for key, value in sorted(stats["report_verdicts"].items())
        )
        + ".",
        "",
        "### Per-report coverage",
        "",
        "| Report | Dimension | Chains | Handler | Current sinks | Constraints | Existing gates | Missing controls | Oracle gaps | Verdict |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for summary in result.summaries:
        report = summary["report_id"]
        if summary["duplicate_of"]:
            report += f" (duplicate of {summary['duplicate_of']})"
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{md_escape(report)}`",
                    f"`{summary['dimension_id']}`",
                    str(summary["chain_count"]),
                    f"{summary['handler_covered']}/{summary['handler_total']}",
                    f"{summary['current_sink_covered']}/{summary['current_sink_total']}",
                    f"{summary['constraint_covered']}/{summary['current_sink_total']}",
                    f"{summary['existing_gate_covered']}/{summary['existing_gate_total']}",
                    f"{summary['missing_preserved']}/{summary['expected_missing']}",
                    str(len(summary["oracle_gaps"])),
                    f"`{summary['verdict']}`",
                ]
            )
            + " |"
        )

    uncovered = [
        row
        for row in result.item_rows
        if row["coverage_status"] in {"uncovered", "fabricated", "oracle-gap"}
        and not row["duplicate_of"]
    ]
    lines.extend(
        [
            "",
            "## Coverage gaps",
            "",
            "| Report | Kind | GT item | Type | Status | Current evidence | Note |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    if not uncovered:
        lines.append("|  |  |  |  |  |  | No coverage gaps. |")
    for row in uncovered:
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{row['report_id']}`",
                    row["item_kind"],
                    md_escape(row["gt_name"]),
                    md_escape(row["gt_type"]),
                    f"`{row['coverage_status']}`",
                    md_escape(row["matched_evidence"] or row["current_anchors"]),
                    md_escape(row["notes"]),
                ]
            )
            + " |"
        )

    items_by_report: dict[str, list[dict[str, str]]] = defaultdict(list)
    chains_by_report: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in result.item_rows:
        items_by_report[row["report_id"]].append(row)
    for row in result.chain_rows:
        chains_by_report[row["report_id"]].append(row)

    for summary in result.summaries:
        report_id = summary["report_id"]
        lines.extend(
            [
                "",
                f"## `{report_id}`",
                "",
                f"JSON: `{summary['json_file']}`",
                "",
                "### Ground-truth items",
                "",
                "| Kind | # | GT item | Type | Pre-patch | Source anchor | Status | Match | Chains |",
                "|---|---:|---|---|---|---|---|---|---|",
            ]
        )
        for row in items_by_report[report_id]:
            lines.append(
                "| "
                + " | ".join(
                    [
                        row["item_kind"],
                        row["item_index"],
                        md_escape(row["gt_name"]),
                        md_escape(row["gt_type"]),
                        row["existed_pre_patch"],
                        md_escape(row["source_anchor_status"]),
                        f"`{row['coverage_status']}`",
                        md_escape(row["match_kind"]),
                        str(row["chain_count"]),
                    ]
                )
                + " |"
            )
        lines.extend(
            [
                "",
                "### Matching chains",
                "",
                "| Chain | Sink constraint | Capability | Gates | Matched GT gates | Semantic status | Call chain |",
                "|---|---|---|---:|---|---|---|",
            ]
        )
        for row in chains_by_report[report_id]:
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"`{row['chain_id']}`",
                        md_escape(
                            f"{row['constraint_id']} {row['sink_api']}@{row['sink_file']}:{row['sink_line']}"
                        ),
                        md_escape(row["capability_class"]),
                        row["gate_count"],
                        md_escape(row["matched_gt_gates"]),
                        f"`{row['chain_semantic_status']}`",
                        md_escape(row["call_chain"]),
                    ]
                )
                + " |"
            )

    decision_counts = Counter(row["decision"] for row in result.debug_rows)
    lines.extend(
        [
            "",
            "## Matching rules",
            "",
            "- The revision-pinned acceptance oracle selects current handler/sink anchors; every current sink must have at least one matching handler chain and exactly one deduplicated `sink_constraint`.",
            "- Raw JSON locations are checked against current source. A stale line can match only through same-file symbol, source-owner, nearby semantic, or nested semantic evidence; a line-number collision with unrelated current code is rejected.",
            "- Only `confirmed` and `branch-confirmed` candidates of the same gate type can cover an existing GT gate. Transform GT therefore cannot be covered by a dominance candidate.",
            "- `existed_pre_patch=false` rows are not counted as existing gates. Dimension-level missing controls are checked against full attached gate semantics using explicit control profiles; absence does not pass through an empty name filter.",
            "- Duplicate Vision reports are analyzed but excluded from canonical gate totals.",
            "",
            "## Intermediate debug trace",
            "",
            f"- Rows: **{len(result.debug_rows)}** in [`d5-chain-coverage-debug.csv`](d5-chain-coverage-debug.csv).",
            "- Decisions: "
            + ", ".join(
                f"`{key}`={value}" for key, value in sorted(decision_counts.items())
            )
            + ".",
            "",
            "## Reproduce",
            "",
            "```bash",
            result.generation_command,
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ground-truth-dir", type=Path, default=DEFAULT_GROUND_TRUTH_DIR
    )
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--pipeline-output", type=Path, default=DEFAULT_PIPELINE_OUTPUT)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument(
        "--fail-on-coverage-gap",
        action="store_true",
        help="Exit non-zero when a current existing gate, sink, constraint, or oracle mapping is incomplete.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = analyze(args)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.out_dir / "d5-chain-coverage.csv", CHAIN_FIELDS, result.chain_rows)
    write_csv(
        args.out_dir / "d5-chain-coverage-items.csv", ITEM_FIELDS, result.item_rows
    )
    write_csv(
        args.out_dir / "d5-chain-coverage-debug.csv", DEBUG_FIELDS, result.debug_rows
    )
    (args.out_dir / "d5-chain-coverage.md").write_text(
        render_markdown(result, args.out_dir), encoding="utf-8"
    )
    print(json.dumps(result.stats, indent=2, sort_keys=True))
    gaps = (
        result.stats["target_sink_covered"] != result.stats["target_sink_total"]
        or result.stats["target_sink_constrained"] != result.stats["target_sink_total"]
        or result.stats["existing_gate_covered"] != result.stats["existing_gate_total"]
        or result.stats["expected_missing_preserved"]
        != result.stats["expected_missing_total"]
        or result.stats["oracle_gaps"]
    )
    return 1 if args.fail_on_coverage_gap and gaps else 0


if __name__ == "__main__":
    raise SystemExit(main())

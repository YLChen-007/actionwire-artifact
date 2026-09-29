#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import csv
import re
import shlex
import warnings
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


DEFAULT_SOURCE_ROOTS = [
    Path("/root/my-project/agent-research/clawgap/benchmark/python/hermes-agent"),
    Path("benchmark/python/hermes-agent"),
]

CHAIN_GATES_FIELDS = [
    "handler_func",
    "handler_file",
    "handler_line",
    "depth",
    "sink_label",
    "sink_file",
    "sink_line",
    "gate_seq",
    "gate_kind",
    "gate_fn",
    "gate_file",
    "gate_line",
    "gate_in_func",
    "guard_kind",
    "taint_verdict",
    "call_chain",
]


GT_HANDLERS: list[tuple[str, str]] = [
    ("_skill_view_with_bump", "skill_view 路径穿越 (220 / Issue-220)"),
    ("browser_console", "GHSA browser-eval"),
    ("browser_navigate", "Issue-8034 browser SSRF"),
    ("_handle_terminal", "762f7e97 / 6a320e8b / fd335a4e terminal RCE"),
    ("execute_code", "Code-Execution-Mode"),
    ("_handle_read_file", "Device-Blocking / Issue-8035"),
    ("web_extract_tool", "Issue-8033 web_extract SSRF"),
    ("_handle_vision_analyze", "Issue-8033 vision SSRF"),
    ("send_message_tool", "38035 Matrix / Discord-Mention"),
]


def md_escape(value: object) -> str:
    return str(value).replace("|", "\\|")


def int_or_zero(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        return 0


def simple_func_name(func_name: str) -> str:
    return func_name.rsplit(".", 1)[-1]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def chain_key(row: dict[str, str]) -> tuple[str, ...]:
    return (
        row["handler_func"],
        row["handler_file"],
        row["handler_line"],
        row["depth"],
        row["sink_label"],
        row["sink_file"],
        row["sink_line"],
        row["call_chain"],
    )


def sink_key(row: dict[str, str]) -> tuple[str, str, str]:
    return (row["sink_label"], row["sink_file"], row["sink_line"])


def gate_identity(row: dict[str, str]) -> tuple[str, str, str, str, str]:
    return (
        row.get("gate_kind", ""),
        row["gate_in_func"],
        row["gate_file"],
        row["gate_line"],
        row["guard_kind"],
    )


def write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def parse_call_chain(call_chain: str) -> list[tuple[str, str, str]]:
    _, _, chain = call_chain.partition("#")
    parts = chain.split("->")
    hops: list[tuple[str, str, str]] = []
    for part in parts[:-1]:
        func, sep, file_name = part.rpartition("@")
        if not sep:
            continue
        hops.append((func, file_name, f"{func}@{file_name}"))
    return hops


def chain_func_positions(call_chain: str) -> dict[str, int]:
    positions: dict[str, int] = {}
    for index, (func, _file_name, _chain_func) in enumerate(
        parse_call_chain(call_chain)
    ):
        positions.setdefault(func, index)
    return positions


def build_chain_gates(
    handler_rows: list[dict[str, str]],
    gate_rows: list[dict[str, str]],
    transform_rows: list[dict[str, str]],
    source_index: SourceIndex,
) -> list[dict[str, str]]:
    gates_by_sink: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for gate in gate_rows:
        gates_by_sink[(gate["sink_file"], gate["sink_line"])].append(gate)

    transforms_by_handler_sink: dict[tuple[str, str, str], list[dict[str, str]]] = (
        defaultdict(list)
    )
    for transform in transform_rows:
        transforms_by_handler_sink[
            (
                transform["handler_func"],
                transform["sink_file"],
                transform["sink_line"],
            )
        ].append(transform)

    out_rows: list[dict[str, str]] = []
    for chain in handler_rows:
        positions = chain_func_positions(chain["call_chain"])
        matching_gates: list[dict[str, str]] = []
        for gate in gates_by_sink.get((chain["sink_file"], chain["sink_line"]), []):
            if gate["in_func"] not in positions:
                continue
            matching_gates.append(
                {
                    "gate_kind": "dominance",
                    "gate_fn": gate["gate_fn"],
                    "gate_file": gate["gate_file"],
                    "gate_line": gate["gate_line"],
                    "in_func": gate["in_func"],
                    "guard_kind": gate["guard_kind"],
                    "taint_verdict": gate["taint_verdict"],
                }
            )

        transform_key = (
            chain["handler_func"],
            chain["sink_file"],
            chain["sink_line"],
        )
        hops = parse_call_chain(chain["call_chain"])
        for transform in transforms_by_handler_sink.get(transform_key, []):
            call_file = transform.get("transform_call_file", "")
            call_line = transform.get("transform_call_line", "")
            attached = False
            for source_file, source_fn in source_index.functions_at_line(
                call_file, int_or_zero(call_line)
            ):
                for chain_func, chain_file, _chain_label in hops:
                    if not source_index.same_source_file(source_file, chain_file):
                        continue
                    if not (
                        chain_func == source_fn.qualname
                        or simple_func_name(chain_func) == source_fn.simple_name
                    ):
                        continue
                    matching_gates.append(
                        {
                            "gate_kind": "transform",
                            "gate_fn": transform["transform_fn"],
                            "gate_file": call_file,
                            "gate_line": call_line,
                            "in_func": chain_func,
                            "guard_kind": transform["transform_role"],
                            "taint_verdict": transform["taint_verdict"],
                        }
                    )
                    attached = True

            # The fallback returns from _markdown_to_html() to on-chain MatrixAdapter.send().
            # Its helper callsite is therefore not itself a forward call-chain hop.
            if (
                not attached
                and transform.get("transform_fn")
                in {"_sanitize_link_url", "_markdown_to_html_fallback"}
                and source_index.same_source_file(
                    call_file, "gateway/platforms/matrix.py"
                )
            ):
                for chain_func, chain_file, _chain_label in hops:
                    if (
                        not source_index.same_source_file(
                            chain_file, "gateway/platforms/matrix.py"
                        )
                        or simple_func_name(chain_func) != "send"
                    ):
                        continue
                    matching_gates.append(
                        {
                            "gate_kind": "transform",
                            "gate_fn": transform["transform_fn"],
                            "gate_file": call_file,
                            "gate_line": call_line,
                            "in_func": chain_func,
                            "guard_kind": transform["transform_role"]
                            + " [parent-owner:_markdown_to_html]",
                            "taint_verdict": transform["taint_verdict"],
                        }
                    )

        deduped_gates: dict[tuple[str, ...], dict[str, str]] = {}
        for gate in matching_gates:
            identity = (
                gate["gate_kind"],
                gate["gate_fn"],
                gate["gate_file"],
                gate["gate_line"],
                gate["in_func"],
                gate["guard_kind"],
                gate["taint_verdict"],
            )
            deduped_gates.setdefault(identity, gate)
        matching_gates = list(deduped_gates.values())
        matching_gates.sort(
            key=lambda gate: (
                positions[gate["in_func"]],
                int_or_zero(gate["gate_line"]),
                gate["gate_kind"],
                gate["gate_fn"],
                gate["guard_kind"],
                gate["taint_verdict"],
            )
        )

        if not matching_gates:
            out_rows.append(
                {
                    **{field: chain.get(field, "") for field in CHAIN_GATES_FIELDS},
                    "gate_seq": "",
                    "gate_kind": "",
                    "gate_fn": "",
                    "gate_file": "",
                    "gate_line": "",
                    "gate_in_func": "",
                    "guard_kind": "",
                    "taint_verdict": "",
                }
            )
            continue

        for seq, gate in enumerate(matching_gates, start=1):
            out_rows.append(
                {
                    "handler_func": chain["handler_func"],
                    "handler_file": chain["handler_file"],
                    "handler_line": chain["handler_line"],
                    "depth": chain["depth"],
                    "sink_label": chain["sink_label"],
                    "sink_file": chain["sink_file"],
                    "sink_line": chain["sink_line"],
                    "gate_seq": str(seq),
                    "gate_kind": gate["gate_kind"],
                    "gate_fn": gate["gate_fn"],
                    "gate_file": gate["gate_file"],
                    "gate_line": gate["gate_line"],
                    "gate_in_func": gate["in_func"],
                    "guard_kind": gate["guard_kind"],
                    "taint_verdict": gate["taint_verdict"],
                    "call_chain": chain["call_chain"],
                }
            )
    return out_rows


@dataclass
class FunctionInfo:
    qualname: str
    simple_name: str
    start_line: int
    end_line: int
    calls_by_name: dict[str, list[int]]


class _CallCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.calls_by_name: dict[str, set[int]] = defaultdict(set)

    def visit_Call(self, node: ast.Call) -> None:
        callee = call_name(node.func)
        if callee:
            self.calls_by_name[callee].add(node.lineno)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return


def call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


class _FunctionCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.class_stack: list[str] = []
        self.func_stack: list[str] = []
        self.functions: list[FunctionInfo] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_stack.append(node.name)
        for child in node.body:
            self.visit(child)
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        collector = _CallCollector()
        for child in node.body:
            collector.visit(child)

        qual_parts = [*self.class_stack, *self.func_stack, node.name]
        self.functions.append(
            FunctionInfo(
                qualname=".".join(qual_parts),
                simple_name=node.name,
                start_line=node.lineno,
                end_line=getattr(node, "end_lineno", node.lineno),
                calls_by_name={
                    name: sorted(lines)
                    for name, lines in collector.calls_by_name.items()
                },
            )
        )

        self.func_stack.append(node.name)
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.visit(child)
        self.func_stack.pop()


class SourceIndex:
    def __init__(self, root: Path | None) -> None:
        self.root = root
        self._functions_by_path: dict[str, list[FunctionInfo]] = {}
        self._paths_by_basename: dict[str, list[str]] = defaultdict(list)
        if root:
            self._build()

    @classmethod
    def from_first_existing(cls, roots: list[Path]) -> "SourceIndex":
        for root in roots:
            if root.exists():
                return cls(root.resolve())
        return cls(None)

    def _build(self) -> None:
        assert self.root is not None
        for path in self.root.rglob("*.py"):
            if ".venv" in path.parts or "__pycache__" in path.parts:
                continue
            rel = str(path.relative_to(self.root))
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", SyntaxWarning)
                    tree = ast.parse(
                        path.read_text(encoding="utf-8"), filename=str(path)
                    )
            except (OSError, SyntaxError, UnicodeDecodeError):
                continue
            collector = _FunctionCollector()
            collector.visit(tree)
            self._functions_by_path[rel] = collector.functions
            self._paths_by_basename[path.name].append(rel)

    def _candidate_paths(self, file_hint: str, func_hint: str) -> list[str]:
        normalized = file_hint.lstrip("/")
        if normalized in self._functions_by_path:
            return [normalized]
        paths = self._paths_by_basename.get(Path(file_hint).name, [])
        if not paths:
            return []

        matching_func_paths = [
            rel for rel in paths if self._select_function(rel, func_hint) is not None
        ]
        return matching_func_paths or paths

    def _select_function(self, rel_path: str, func_hint: str) -> FunctionInfo | None:
        functions = self._functions_by_path.get(rel_path, [])
        exact = [fn for fn in functions if fn.qualname == func_hint]
        if exact:
            return exact[0]
        simple = simple_func_name(func_hint)
        simple_matches = [fn for fn in functions if fn.simple_name == simple]
        if simple_matches:
            return simple_matches[0]
        return None

    @staticmethod
    def same_source_file(left: str, right: str) -> bool:
        left_normalized = left.lstrip("/")
        right_normalized = right.lstrip("/")
        return (
            left_normalized == right_normalized
            or Path(left_normalized).name == Path(right_normalized).name
        )

    def functions_at_line(
        self, file_hint: str, line: int
    ) -> list[tuple[str, FunctionInfo]]:
        if self.root is None or not file_hint or line <= 0:
            return []

        matches: list[tuple[str, FunctionInfo]] = []
        for rel_path in self._candidate_paths(file_hint, ""):
            containing = [
                fn
                for fn in self._functions_by_path.get(rel_path, [])
                if fn.start_line <= line <= fn.end_line
            ]
            if containing:
                containing.sort(
                    key=lambda fn: (fn.end_line - fn.start_line, -fn.start_line)
                )
                matches.append((rel_path, containing[0]))
        return matches

    def call_site(self, caller_file: str, caller_func: str, callee_func: str) -> str:
        if self.root is None:
            return ""
        callee_simple = simple_func_name(callee_func)
        for rel_path in self._candidate_paths(caller_file, caller_func):
            fn = self._select_function(rel_path, caller_func)
            if fn is None:
                continue
            lines = fn.calls_by_name.get(callee_simple, [])
            if lines:
                return f"{rel_path}:{','.join(str(line) for line in lines)}"
        return ""


def format_call_chain(row: dict[str, str]) -> str:
    hops = [
        chain_func
        for _func, _file_name, chain_func in parse_call_chain(row["call_chain"])
    ]
    hops.append(f"{row['sink_label']}@{row['sink_file']}:{row['sink_line']}")
    return " -> ".join(hops)


def previous_sink_order(path: Path) -> dict[str, list[tuple[str, str, str]]]:
    if not path.exists():
        return {}

    order: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    current_handler: str | None = None
    handler_re = re.compile(r"^### `([^`]+)`")
    sink_re = re.compile(r"^\*\*sink `([^`]+)` @ `([^:]+):(\d+)`")

    for line in path.read_text(encoding="utf-8").splitlines():
        handler_match = handler_re.match(line)
        if handler_match:
            current_handler = handler_match.group(1)
            continue
        sink_match = sink_re.match(line)
        if current_handler and sink_match:
            order[current_handler].append(
                (sink_match.group(1), sink_match.group(2), sink_match.group(3))
            )
    return order


def verdict(value: str) -> str:
    if not value:
        return ""
    if value == "confirmed":
        return "✅ confirmed"
    if value == "branch-confirmed":
        return "🔷 branch-confirmed"
    return "⚠️ needs-review"


def is_rendered_gate(row: dict[str, str], exclude_needs_review: bool) -> bool:
    if not row["gate_fn"]:
        return False
    return not (exclude_needs_review and row["taint_verdict"] == "needs-review")


def first_seen_chains(
    rows: list[dict[str, str]],
) -> dict[tuple[str, ...], list[dict[str, str]]]:
    grouped: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[chain_key(row)].append(row)
    return grouped


def ordered_chain_groups(rows: list[dict[str, str]]) -> list[list[dict[str, str]]]:
    groups = first_seen_chains(rows)
    first_index = {key: idx for idx, key in enumerate(groups)}
    return [
        groups[key]
        for key in sorted(
            groups,
            key=lambda key: (
                int_or_zero(groups[key][0]["depth"]),
                first_index[key],
                groups[key][0]["call_chain"],
            ),
        )
    ]


def handler_entry(rows: list[dict[str, str]], handler: str) -> tuple[str, str]:
    for row in rows:
        if row["handler_func"] == handler:
            return row["handler_file"], row["handler_line"]
    return "", ""


def ordered_sinks(
    handler_rows: list[dict[str, str]],
    preferred: list[tuple[str, str, str]],
) -> list[tuple[str, str, str]]:
    present: dict[tuple[str, str, str], None] = {}
    for row in handler_rows:
        present.setdefault(sink_key(row), None)

    ordered = [key for key in preferred if key in present]
    ordered.extend(
        sorted(
            (key for key in present if key not in set(ordered)),
            key=lambda key: (key[1], int_or_zero(key[2]), key[0]),
        )
    )
    return ordered


def render_chain_table(
    chain_rows: list[dict[str, str]],
    source_index: SourceIndex,
    exclude_needs_review: bool = False,
) -> list[str]:
    sample = chain_rows[0]
    hops = parse_call_chain(sample["call_chain"])
    gates_by_func: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in chain_rows:
        if is_rendered_gate(row, exclude_needs_review):
            gates_by_func[row["gate_in_func"]].append(row)
    for rows in gates_by_func.values():
        rows.sort(
            key=lambda row: (
                int_or_zero(row["gate_seq"]),
                int_or_zero(row["gate_line"]),
            )
        )

    seen_func: set[str] = set()
    lines = [
        "| # | chain_func | call_site | gate_kind | gate_fn | @ | in_func | guard_kind | verdict |",
        "|---:|---|---|---|---|---|---|---|---|",
    ]
    row_no = 1
    for index, (func, _file_name, chain_func) in enumerate(hops):
        call_site = ""
        if index > 0:
            caller_func, caller_file, _caller_chain_func = hops[index - 1]
            call_site = source_index.call_site(caller_file, caller_func, func)
        gate_rows = gates_by_func.get(func, []) if func not in seen_func else []
        seen_func.add(func)
        if gate_rows:
            for gate in gate_rows:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            str(row_no),
                            md_escape(chain_func),
                            md_escape(call_site),
                            md_escape(gate.get("gate_kind", "dominance")),
                            md_escape(f"`{gate['gate_fn']}`"),
                            md_escape(f"{gate['gate_file']}:{gate['gate_line']}"),
                            md_escape(gate["gate_in_func"]),
                            md_escape(gate["guard_kind"]),
                            verdict(gate["taint_verdict"]),
                        ]
                    )
                    + " |"
                )
                row_no += 1
        else:
            lines.append(
                f"| {row_no} | {md_escape(chain_func)} | {md_escape(call_site)} |  |  |  |  |  |  |"
            )
            row_no += 1

    unmatched = [
        row
        for func_rows in gates_by_func.values()
        for row in func_rows
        if row["gate_in_func"] not in {func for func, _, _ in hops}
    ]
    for gate in unmatched:
        lines.append(
            "| "
            + " | ".join(
                [
                    str(row_no),
                    md_escape(f"{gate['gate_in_func']}@?"),
                    "",
                    md_escape(gate.get("gate_kind", "dominance")),
                    md_escape(f"`{gate['gate_fn']}`"),
                    md_escape(f"{gate['gate_file']}:{gate['gate_line']}"),
                    md_escape(gate["gate_in_func"]),
                    md_escape(gate["guard_kind"]),
                    verdict(gate["taint_verdict"]),
                ]
            )
            + " |"
        )
        row_no += 1
    return lines


def render_summary(
    rows: list[dict[str, str]],
    exclude_needs_review: bool = False,
) -> list[str]:
    chains_by_handler: dict[str, set[tuple[str, ...]]] = defaultdict(set)
    sinks_with_gate: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
    gate_ids: dict[str, set[tuple[str, str, str, str, str]]] = defaultdict(set)
    confirmed_gate_ids: dict[str, set[tuple[str, str, str, str, str]]] = defaultdict(
        set
    )
    branch_confirmed_gate_ids: dict[str, set[tuple[str, str, str, str, str]]] = (
        defaultdict(set)
    )
    dominance_gate_ids: dict[str, set[tuple[str, str, str, str, str]]] = defaultdict(
        set
    )
    transform_gate_ids: dict[str, set[tuple[str, str, str, str, str]]] = defaultdict(
        set
    )
    first_entry: dict[str, tuple[str, int]] = {}

    for row in rows:
        handler = row["handler_func"]
        first_entry.setdefault(
            handler, (row["handler_file"], int_or_zero(row["handler_line"]))
        )
        chains_by_handler[handler].add(chain_key(row))
        if is_rendered_gate(row, exclude_needs_review):
            sinks_with_gate[handler].add(sink_key(row))
            identity = gate_identity(row)
            gate_ids[handler].add(identity)
            if row.get("gate_kind", "dominance") == "transform":
                transform_gate_ids[handler].add(identity)
            else:
                dominance_gate_ids[handler].add(identity)
            if row["taint_verdict"] == "confirmed":
                confirmed_gate_ids[handler].add(identity)
            if row["taint_verdict"] == "branch-confirmed":
                branch_confirmed_gate_ids[handler].add(identity)

    handlers = sorted(
        chains_by_handler,
        key=lambda handler: (
            -len(gate_ids[handler]),
            first_entry.get(handler, ("", 0))[1],
            handler,
        ),
    )

    lines = [
        "| handler 入口 | 入口位置 | #链 | #sink(带gate) | #gate(去重) | #dominance | #transform | #confirmed | #branch-confirmed |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for handler in handlers:
        entry_file, entry_line = first_entry.get(handler, ("", 0))
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{handler}`",
                    f"{entry_file}:{entry_line}",
                    str(len(chains_by_handler[handler])),
                    str(len(sinks_with_gate[handler])),
                    str(len(gate_ids[handler])),
                    str(len(dominance_gate_ids[handler])),
                    str(len(transform_gate_ids[handler])),
                    str(len(confirmed_gate_ids[handler])),
                    str(len(branch_confirmed_gate_ids[handler])),
                ]
            )
            + " |"
        )
    return lines


def render(
    rows: list[dict[str, str]],
    out_path: Path,
    source_index: SourceIndex,
    generation_command: str,
    exclude_needs_review: bool = False,
) -> str:
    by_chain = first_seen_chains(rows)
    all_gate_rows = [row for row in rows if is_rendered_gate(row, exclude_needs_review)]
    source_gate_rows = [row for row in rows if row["gate_fn"]]
    no_gate_source_rows = len(rows) - len(source_gate_rows)
    filtered_gate_rows = len(source_gate_rows) - len(all_gate_rows)
    chains_with_gate = {
        key
        for key, chain_rows in by_chain.items()
        if any(is_rendered_gate(row, exclude_needs_review) for row in chain_rows)
    }
    unique_handlers = {row["handler_func"] for row in rows}
    handlers_with_gate = {
        row["handler_func"]
        for row in rows
        if is_rendered_gate(row, exclude_needs_review)
    }
    triples = {
        (
            row.get("gate_kind", "dominance"),
            row["gate_in_func"],
            row["sink_file"],
            row["sink_line"],
            row["gate_fn"],
            row["gate_file"],
            row["gate_line"],
            row["guard_kind"],
        )
        for row in all_gate_rows
    }
    confirmed_triples = {
        (
            row.get("gate_kind", "dominance"),
            row["gate_in_func"],
            row["sink_file"],
            row["sink_line"],
            row["gate_fn"],
            row["gate_file"],
            row["gate_line"],
            row["guard_kind"],
        )
        for row in all_gate_rows
        if row["taint_verdict"] == "confirmed"
    }
    branch_confirmed_triples = {
        (
            row.get("gate_kind", "dominance"),
            row["gate_in_func"],
            row["sink_file"],
            row["sink_line"],
            row["gate_fn"],
            row["gate_file"],
            row["gate_line"],
            row["guard_kind"],
        )
        for row in all_gate_rows
        if row["taint_verdict"] == "branch-confirmed"
    }
    gate_kind_counts = Counter(identity[0] for identity in triples)
    transparent_counts = {
        label: len(
            {
                (
                    row.get("gate_kind", "dominance"),
                    row["gate_in_func"],
                    row["sink_file"],
                    row["sink_line"],
                    row["gate_fn"],
                    row["gate_file"],
                    row["gate_line"],
                    row["guard_kind"],
                )
                for row in all_gate_rows
                if label in row["guard_kind"]
            }
        )
        for label in ["[loop:", "[opt-guard:", "[bypass:"]
    }

    sink_order = previous_sink_order(out_path)
    handler_rows: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        handler_rows[row["handler_func"]].append(row)

    lines: list[str] = [
        "# Hermes-Agent — 每条 handler→sink call chain 及其检查点 gate（chain × gate 标注"
        + ("，排除 needs-review" if exclude_needs_review else "")
        + "）",
        "",
        "> **本文件为生成物**（`*coverage*.md`），勿手改；改上游后按下方「复现」重跑。",
        ">",
        f"> **生成命令**：`{generation_command}`",
        ">",
        f"> 把**步骤 3 的 handler→sink taint-valid call chain**（[`handler-sink-chains.csv`](handler-sink-chains.csv)，`get_handler_to_sink.ql`，{len(by_chain)} 条见证边）与**步骤 4 的 gate 检测**（dominance: `get_gates.ql`；transform: `fte_transform.ql`）**按链标注**。dominance 按 `in_func` 挂链；transform 按候选的实际 `transform_call_file/line` 反查其所在函数后挂链；两类都要求 sink 位置(file+line)一致，transform 还要求 handler 一致。逐 (链,gate) 明细见 [`chain-gates.csv`](chain-gates.csv)（含 `gate_seq` / `gate_kind` 列）。",
        "",
        "> **表格顺序 = 调用序（call sequence）**：表内 `chain_func` 自上而下按 call-chain hop 展开；`call_site` 是上一跳 caller 内调用当前 `chain_func` 的源码位置（best-effort AST 反查）；`gate_kind` 区分 `dominance` / `transform`；同一函数内多个 gate 再按 `gate_seq` / 源码行号排列，同名函数沿用既有口径挂到首次出现的 hop。没有 gate 的链上函数仍保留一行，gate 列留空。",
        *(
            [
                ">",
                "> **过滤口径**：本版本仅移除 `taint_verdict=needs-review` 的 gate 行；`confirmed` 与 `branch-confirmed` 均保留。handler 输入未污点到达 sinkArg/receiver 的纯调用链已在 `handler-sink-chains.csv` 阶段移除。",
            ]
            if exclude_needs_review
            else []
        ),
        "",
        "## 结论 / 统计",
        "",
        f"- **call chain**：{len(by_chain)} 条 source→sink taint-valid 见证边（深度 1–8），覆盖 **{len(unique_handlers)}** 个去重 handler 入口；**{len(chains_with_gate)}** 条至少挂 1 gate、{len(by_chain) - len(chains_with_gate)} 条无 gate。",
        (
            f"- **[`chain-gates.csv`](chain-gates.csv)**：渲染 {len(all_gate_rows)} 条 confirmed/branch-confirmed (见证链 × gate) 行；过滤 {filtered_gate_rows} 条 `needs-review` gate 行；保留 {no_gate_source_rows} 条原始无 gate 链行；去重 **(gate_kind,in_func,sink,gate) 身份 {len(triples)}**（**{len(confirmed_triples)} confirmed**，**{len(branch_confirmed_triples)} branch-confirmed**）。"
            if exclude_needs_review
            else f"- **[`chain-gates.csv`](chain-gates.csv)**：{len(all_gate_rows)} 条 (见证链 × gate) 行（每链内 `gate_seq` 按调用序）+ {no_gate_source_rows} 条无 gate 链行；去重 **(gate_kind,in_func,sink,gate) 身份 {len(triples)}**（**{len(confirmed_triples)} confirmed**，**{len(branch_confirmed_triples)} branch-confirmed**）。"
        ),
        f"- **gate kind（去重身份）**：`dominance` **{gate_kind_counts['dominance']}**，`transform` **{gate_kind_counts['transform']}**。",
        f"- **dominance 透明化标签**（去重身份计）：`[loop:x]` **{transparent_counts['[loop:']}**、`[opt-guard:x]` **{transparent_counts['[opt-guard:']}**、`[bypass:force]` **{transparent_counts['[bypass:']}**。",
        f"- **{len(handlers_with_gate)}/{len(unique_handlers)}** handler 至少 1 gate；GT dominance + transform 覆盖见 [`../../gate/debug/recall-result.md`](../../gate/debug/recall-result.md)。",
        "",
        "### gate_kind / guard_kind 图例",
        "",
        "| 标签 | 含义 |",
        "|---|---|",
        "| `gate_kind=dominance` / `gate_kind=transform` | 控制支配检查 gate / 同源污点穿过的值变换 gate |",
        "| `in-condition` / `assign-then-branch` | (B1) 校验调用在守卫测试子树 / (B2) 结果赋值后再判 |",
        "| `sink-transform` / `guard-normalizer` | transform 输出继续到 sink / transform 输出进入检查且同源原值继续到 sink |",
        "| `[bypass:force]` / `[opt-guard:x]` / `[loop:x]` / `[branch-local]` | (A′) `if not force:` / (A′) `if x: vc(x)` / (A″) `for x in xs: if bad(x): return` 透明化，或同源但非全局支配的分支局部 gate |",
        (
            "| `confirmed` / `branch-confirmed` | (C) 同源污点双腿连通；后者只确认 gate 所在分支到 sink-ward 调用的路径 |"
            if exclude_needs_review
            else "| `confirmed` / `branch-confirmed` / `needs-review` | (C) 同源污点双腿连通 / 分支局部同源确认 / 定位到但污点未连通 |"
        ),
        "",
        "## GT 工具链 —— 每条链上的检查点（按调用序）",
        "",
        "> 8 个 GT handler 入口到各 sink 的链上识别的 dominance / transform gate，**表内自上而下 = call-chain 函数顺序**；没有 gate 的函数保留空 gate 行。",
        "",
    ]

    for handler, title in GT_HANDLERS:
        h_rows = handler_rows.get(handler, [])
        if not h_rows:
            continue
        entry_file, entry_line = handler_entry(rows, handler)
        sinks = ordered_sinks(h_rows, sink_order.get(handler, []))
        chains = {chain_key(row) for row in h_rows}
        lines.extend(
            [
                f"### `{handler}`  —  {title}",
                f"入口：`{entry_file}:{entry_line}` · 链数 {len(chains)} · sink 数 {len(sinks)}",
                "",
            ]
        )
        for skey in sinks:
            chain_rows = [row for row in h_rows if sink_key(row) == skey]
            lines.extend(
                [
                    f"**sink `{skey[0]}` @ `{skey[1]}:{skey[2]}`**  （↓ 调用序）",
                    "",
                ]
            )
            chain_groups = ordered_chain_groups(chain_rows)
            for index, group_rows in enumerate(chain_groups, start=1):
                lines.extend(
                    [
                        f"_chain {index}/{len(chain_groups)} · depth {group_rows[0]['depth']}_: `{format_call_chain(group_rows[0])}`",
                        "",
                        *render_chain_table(
                            group_rows, source_index, exclude_needs_review
                        ),
                        "",
                    ]
                )

    lines.extend(
        [
            "## 全部 handler 汇总",
            "",
            "> `#gate(去重)` = 该 handler 名下**去重的 gate 身份** `(gate_kind, in_func, gate_file, gate_line, guard_kind)`（跨 sink 合并，同一 gate 守多个 sink 只计一次）；`#dominance` / `#transform` 按类型拆分；`#confirmed` 包含两类 confirmed，`#branch-confirmed` 仅用于 dominance 分支局部同源确认。按 `#gate` 降序、同数按入口行号。",
            "",
            *render_summary(rows, exclude_needs_review),
            "",
            "## 复现",
            "",
            "```bash",
            "bin/codeql query run --database=codeql-db/hermes-agent-db \\",
            "  --additional-packs=src/ql -o /tmp/h2s_taint_valid.bqrs src/ql/get_handler_to_sink.ql",
            "bin/codeql bqrs decode --format=csv /tmp/h2s_taint_valid.bqrs \\",
            "  > design/hermes-agent/call-chain/debug/handler-sink-chains.csv",
            "bin/codeql query run --database=codeql-db/hermes-agent-db \\",
            "  --additional-packs=src/ql -o /tmp/gates_v10.bqrs src/ql/get_gates.ql",
            "bin/codeql bqrs decode --format=csv /tmp/gates_v10.bqrs \\",
            "  > design/hermes-agent/gate/debug/gate-candidates.csv",
            "bin/codeql query run --database=codeql-db/hermes-agent-db \\",
            "  --additional-packs=src/ql -o /tmp/transform_gates.bqrs src/ql/fte_transform.ql",
            "bin/codeql bqrs decode --format=csv /tmp/transform_gates.bqrs \\",
            "  > design/hermes-agent/gate/debug/transform-candidates.csv",
            "# dominance: gate.in_func ∈ chain.hops ∧ 同 sink；transform: 同 handler/sink 且 callsite 所在函数 ∈ chain.hops",
            "python design/hermes-agent/call-chain/debug/script/render_chain_gates_coverage.py \\",
            "  --rebuild-chain-gates \\",
            "  --handler-sink-chains design/hermes-agent/call-chain/debug/handler-sink-chains.csv \\",
            "  --gate-candidates design/hermes-agent/gate/debug/gate-candidates.csv \\",
            "  --transform-candidates design/hermes-agent/gate/debug/transform-candidates.csv \\",
            "  --chain-gates design/hermes-agent/call-chain/debug/chain-gates.csv \\",
            "  --out design/hermes-agent/call-chain/debug/chain-gates-coverage.md",
            "# 同时默认输出 design/hermes-agent/call-chain/debug/chain-gates-coverage-exclude-needs-review.md",
            "```",
            "",
            "## 口径与注意",
            "",
            "- **调用序**：`chain_func` 按链 hop 顺序展开；`call_site` 由源码 AST 从「上一跳函数体内调用当前 hop 的 call 表达式」反查，若同一 caller 里有多个同名调用则列出多行号。没有可解析源码或无法唯一反查时留空。同一 `chain_func` 内的多个 gate 再按 `gate_seq` / 源码行号排序；同名函数取首次出现的 hop。没有 gate 的 hop 仍显示一行，gate 列为空。`chain-gates.csv` 中的 `gate_seq` 仍只编号 gate 行，`gate_kind` 标明 dominance / transform。",
            "- **有效链判据**：`get_handler_to_sink.ql` 不再只看 call graph；还要求当前 handler 的非 `self`/`cls` 形参能污点到达 sink 实参或 receiver。`active_path.read_text()` 这类配置路径读取若不从 handler 输入派生，会在链源头被过滤。",
            "- **归属判据**：gate 挂链 ⟺ `gate.in_func` 是该链某 hop 且 sink(file+line) 一致（gate 是兄弟分支 early-return 守卫，`in_func` 在链上即归属）。**透明化 gate（`[opt-guard:]`/`[loop:]`）另要求 gate 块能前向到达该 sink-ward 调用**——否则 gate 在 sink 之后执行、并不管辖它（`get_gates.ql` 的 `gateBlockReachesSink`）。",
            "- **transform 归属判据**：候选 handler 与链 handler 相同、sink(file+line) 相同，且 `transform_call_file/line` 的源码所在函数是该链 hop。报告中的 `@` 对 transform 显示实际调用位置，不是 transform 函数定义位置；只在 off-chain sibling helper 内发生、无法落到链 hop 的 transform 不强行挂链。Matrix fallback 的两个已审计 transform 是例外：它们在 `_markdown_to_html` 内执行并返回 on-chain `MatrixAdapter.send`，以 `[parent-owner:_markdown_to_html]` 显式挂到该父 hop。",
            (
                "- **共享上游函数**的 gate 挂到所有经它到同 sink 的链——真覆盖。此版本仅过滤 `needs-review` gate 行，保留 `confirmed` 与 `branch-confirmed`。"
                if exclude_needs_review
                else "- **共享上游函数**的 gate 挂到所有经它到同 sink 的链——真覆盖。同一 gate 在不同 sink 上可有不同 verdict（严格同源者 confirmed、分支局部同源者 branch-confirmed、无关者 needs-review），已如实保留。"
            ),
            "- **sink_label 口径**：链含接收者(`provider.extract`)，gate 侧 `calleeName` 只取 `extract`——join 按 sink file+line、不按 label。",
        ]
    )
    return "\n".join(lines) + "\n"


def handler_sink_generation_summary(
    rows: list[dict[str, str]],
    generation_command: str,
    source_root: Path | None,
) -> str:
    unique_chains = {chain_key(row): row for row in rows}
    unique_sink_calls = {
        (row["handler_func"], row["sink_file"], row["sink_line"])
        for row in rows
    }
    unique_handlers = {row["handler_func"] for row in rows}
    by_handler: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in unique_chains.values():
        by_handler[row["handler_func"]].append(row)

    lines = [
        "# Hermes-Agent — handler 入口 → sink 的 taint-valid call chain 验证（步骤 3）",
        "",
        "> **本文件为生成物**，勿手改；改上游后重跑下列命令。",
        ">",
        f"> **生成命令**：`{generation_command}`",
        ">",
        "> 查询：[`../../../../src/ql/get_handler_to_sink.ql`](../../../../src/ql/get_handler_to_sink.ql)；",
        "> 原始结果：[`handler-sink-chains.csv`](handler-sink-chains.csv)。",
        *(
            [
                ">",
                f"> 源码树：`{source_root}`。CodeQL DB：`codeql-db/hermes-agent-db`。",
            ]
            if source_root is not None
            else []
        ),
        "",
        "## 结论 / 统计",
        "",
        f"- **{len(unique_chains)}** 条 source→sink taint-valid 见证链，覆盖 **{len(unique_handlers)}** 个去重 handler。",
        f"- **{len(unique_sink_calls)}** 个去重 `(handler, sink file, sink line)` 调用点，深度范围 **{min(int_or_zero(row['depth']) for row in rows) if rows else 0}–{max(int_or_zero(row['depth']) for row in rows) if rows else 0}**。",
        "- 下表是 13 份 D5 JSON 涉及的 handler 家族在当前数据库中的查询结果；一份 JSON 可能有多个 sink，同一 handler 也可能对应多份 JSON。逐 JSON 的精确 GT 映射见 [`d5-chain-coverage.md`](d5-chain-coverage.md)。",
        "",
        "## D5 handler 家族摘要",
        "",
        "| handler | 关联问题 | 见证链 | sink 调用点 | 深度 | 最短见证链 |",
        "|---|---|---:|---:|---|---|",
    ]

    for handler, title in GT_HANDLERS:
        handler_rows = by_handler.get(handler, [])
        sink_count = len(
            {
                (row["sink_file"], row["sink_line"])
                for row in handler_rows
            }
        )
        depths = sorted({int_or_zero(row["depth"]) for row in handler_rows})
        representative = min(
            handler_rows,
            key=lambda row: (
                int_or_zero(row["depth"]),
                row["sink_file"],
                int_or_zero(row["sink_line"]),
                row["call_chain"],
            ),
            default=None,
        )
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{handler}`",
                    md_escape(title),
                    str(len(handler_rows)),
                    str(sink_count),
                    (
                        f"{depths[0]}–{depths[-1]}"
                        if len(depths) > 1
                        else str(depths[0])
                        if depths
                        else "—"
                    ),
                    (
                        f"`{md_escape(format_call_chain(representative))}`"
                        if representative is not None
                        else "—"
                    ),
                ]
            )
            + " |"
        )

    send_message_rows = by_handler.get("send_message_tool", [])
    lines.extend(
        [
            "",
            "## 当前源码版本说明",
            "",
            (
                f"- 当前数据库直接识别 `send_message_tool` 为 handler，并产出 **{len(send_message_rows)}** 条 taint-valid 见证链；旧 xclaw 数据库中“send_message 未注册、主查询不锚定”的说明不再适用。"
                if send_message_rows
                else "- 当前数据库没有产出 `send_message_tool` 见证链；需要结合工具注册查询检查 root 锚定。"
            ),
            "- 本报告只陈述当前 `get_handler_to_sink.ql` 的 detector 输出，不把旧 commit 的行号或辅助桥查询混入当前主结果。JSON sink 的 exact / semantic-representative 判定由 `d5-chain-coverage.md` 单独记录。",
            "",
            "## 复现上游 CSV",
            "",
            "```bash",
            "bin/codeql query run --database=codeql-db/hermes-agent-db \\",
            "  --additional-packs=src/ql -o /tmp/h2s_taint_valid.bqrs src/ql/get_handler_to_sink.ql",
            "bin/codeql bqrs decode --format=csv /tmp/h2s_taint_valid.bqrs \\",
            "  > design/hermes-agent/call-chain/debug/handler-sink-chains.csv",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def explicit_generation_command(args: argparse.Namespace) -> str:
    parts = [
        "python",
        "design/hermes-agent/call-chain/debug/script/render_chain_gates_coverage.py",
    ]
    if args.rebuild_chain_gates:
        parts.append("--rebuild-chain-gates")
    parts.extend(
        [
            "--handler-sink-chains",
            str(args.handler_sink_chains),
            "--gate-candidates",
            str(args.gate_candidates),
            "--transform-candidates",
            str(args.transform_candidates),
            "--chain-gates",
            str(args.chain_gates),
            "--out",
            str(args.out),
        ]
    )
    if args.handler_sink_out is not None:
        parts.extend(["--handler-sink-out", str(args.handler_sink_out)])
    if args.exclude_needs_review_out is not None:
        parts.extend(
            ["--exclude-needs-review-out", str(args.exclude_needs_review_out)]
        )
    if args.source_root is not None:
        parts.extend(["--source-root", str(args.source_root)])
    return " ".join(shlex.quote(part) for part in parts)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--chain-gates",
        type=Path,
        default=Path("design/hermes-agent/call-chain/debug/chain-gates.csv"),
    )
    parser.add_argument(
        "--handler-sink-chains",
        type=Path,
        default=Path("design/hermes-agent/call-chain/debug/handler-sink-chains.csv"),
        help="Taint-valid handler→sink chain CSV used when --rebuild-chain-gates is set.",
    )
    parser.add_argument(
        "--gate-candidates",
        type=Path,
        default=Path("design/hermes-agent/gate/debug/gate-candidates.csv"),
        help="Dominance gate candidate CSV used when --rebuild-chain-gates is set.",
    )
    parser.add_argument(
        "--transform-candidates",
        type=Path,
        default=Path("design/hermes-agent/gate/debug/transform-candidates.csv"),
        help="Transform gate candidate CSV used when --rebuild-chain-gates is set.",
    )
    parser.add_argument(
        "--rebuild-chain-gates",
        action="store_true",
        help=(
            "Rebuild --chain-gates from handler/sink chains plus dominance and "
            "transform candidates before rendering."
        ),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("design/hermes-agent/call-chain/debug/chain-gates-coverage.md"),
    )
    parser.add_argument(
        "--handler-sink-out",
        type=Path,
        help=(
            "Optional legacy summary of the supplied handler→sink query results. "
            "The canonical report is owned by count_detected_call_chains.py."
        ),
    )
    parser.add_argument(
        "--exclude-needs-review-out",
        type=Path,
        help="Additional markdown output with taint_verdict=needs-review gate rows removed.",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        help=(
            "Source tree used to derive adjacent-hop call_site line numbers. "
            "Defaults to the CodeQL DB source checkout when present."
        ),
    )
    args = parser.parse_args()
    generation_command = explicit_generation_command(args)

    source_roots = [args.source_root] if args.source_root else DEFAULT_SOURCE_ROOTS
    source_index = SourceIndex.from_first_existing(source_roots)

    if args.rebuild_chain_gates:
        rows = build_chain_gates(
            read_csv(args.handler_sink_chains),
            read_csv(args.gate_candidates),
            read_csv(args.transform_candidates),
            source_index,
        )
        write_csv(args.chain_gates, rows, CHAIN_GATES_FIELDS)
    else:
        rows = read_csv(args.chain_gates)
        for row in rows:
            row.setdefault("gate_kind", "dominance" if row.get("gate_fn", "") else "")

    exclude_out = args.exclude_needs_review_out
    if exclude_out is None:
        exclude_out = args.out.with_name(
            f"{args.out.stem}-exclude-needs-review{args.out.suffix}"
        )

    args.out.write_text(
        render(rows, args.out, source_index, generation_command), encoding="utf-8"
    )
    exclude_out.write_text(
        render(
            rows,
            args.out,
            source_index,
            generation_command,
            exclude_needs_review=True,
        ),
        encoding="utf-8",
    )
    if args.handler_sink_out is not None:
        args.handler_sink_out.write_text(
            handler_sink_generation_summary(
                read_csv(args.handler_sink_chains),
                generation_command,
                args.source_root,
            ),
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()

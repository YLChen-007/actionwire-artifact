"""Deterministically assemble an ordered handler-to-sink gate sequence."""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


INCLUDED_VERDICTS = {"confirmed", "branch-confirmed"}


class ChainAssemblyError(ValueError):
    """Raised when endpoint or gate identity cannot be resolved uniquely."""


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _chain_id(call_chain: str) -> str:
    return "C-" + hashlib.sha1(call_chain.encode("utf-8")).hexdigest()[:10]


def _split_chain_ids(value: str) -> set[str]:
    return {item for item in value.split(";") if item}


def _parse_location(value: str) -> tuple[str, int]:
    raw_file, separator, raw_line = value.rpartition(":")
    if not separator or not raw_line.isdigit():
        raise ChainAssemblyError(f"invalid source location: {value!r}")
    return raw_file.replace("\\", "/"), int(raw_line)


def _same_file(left: str, right: str) -> bool:
    left_path = PurePosixPath(left.replace("\\", "/"))
    right_path = PurePosixPath(right.replace("\\", "/"))
    return left_path == right_path or left_path.name == right_path.name


def _parse_hops(call_chain: str) -> list[dict[str, str]]:
    _depth, separator, body = call_chain.partition("#")
    if not separator:
        raise ChainAssemblyError(f"invalid call-chain encoding: {call_chain!r}")
    hops: list[dict[str, str]] = []
    for raw_hop in body.split("->"):
        symbol, at, location = raw_hop.partition("@")
        if not at:
            raise ChainAssemblyError(f"invalid call-chain hop: {raw_hop!r}")
        file_value = location.split("$$", 1)[0]
        hops.append({"function": symbol, "file": file_value})
    return hops


def _gate_input_id(ir: dict[str, Any]) -> str:
    if ir.get("schema_version") == "gate-semantic-ir/v3":
        inputs = ir.get("inputs", [])
        if isinstance(inputs, list) and inputs and isinstance(inputs[0], dict):
            return str(inputs[0].get("id", ""))
    value = ir.get("input", "")
    return value.split(":", 1)[0] if isinstance(value, str) else ""


def _unresolved_union(records: Iterable[dict[str, Any]]) -> list[str]:
    unresolved: set[str] = set()
    for ir in records:
        gate_id = str(ir["gate_id"])
        explicit = ir.get("unresolved", [])
        if isinstance(explicit, list):
            unresolved.update(str(value) for value in explicit if str(value).strip())
        if ir.get("schema_version") != "gate-semantic-ir/v2":
            for step in ir.get("steps", []):
                if step.get("op") == "unknown":
                    unresolved.add(
                        f"{gate_id}:{step.get('id', 'unknown')}:{step.get('rule', 'unknown behavior')}"
                    )
    return sorted(unresolved)


@dataclass(frozen=True)
class ResolvedChain:
    chain_id: str
    call_chain: str
    hops: tuple[dict[str, str], ...]
    handler: dict[str, str]
    sink: dict[str, str]
    raw_row: dict[str, str]
    excluded_ground_truth_fields: tuple[str, ...]


@dataclass(frozen=True)
class GateSelection:
    gate_number: int
    gate_uid: str
    gate_id: str
    gate_name: str
    qualified_function: str
    enclosing_function: str
    callsite_file: str
    callsite_line: int
    static_verdict: str
    content_digest: str

    def to_dict(self) -> dict[str, object]:
        return {
            "gate_number": self.gate_number,
            "gate_uid": self.gate_uid,
            "gate_id": self.gate_id,
            "gate_name": self.gate_name,
            "qualified_function": self.qualified_function,
            "enclosing_function": self.enclosing_function,
            "callsite": f"{self.callsite_file}:{self.callsite_line}",
            "static_verdict": self.static_verdict,
            "content_digest": self.content_digest,
        }


@dataclass(frozen=True)
class CallChainSliceV2:
    project_revision: str
    chain_id: str
    call_chain: str
    calls: tuple[dict[str, str], ...]
    handler: dict[str, str]
    sink: dict[str, str]
    values: tuple[dict[str, Any], ...]
    selected_gates: tuple[dict[str, object], ...]
    gate_semantics: tuple[dict[str, Any], ...]
    unresolved: tuple[str, ...]
    status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "call-chain-slice/v2",
            "project_revision": self.project_revision,
            "chain_id": self.chain_id,
            "call_chain": self.call_chain,
            "calls": list(self.calls),
            "handler": self.handler,
            "sink": self.sink,
            "values": list(self.values),
            "selected_gates": list(self.selected_gates),
            "gate_semantics": list(self.gate_semantics),
            "unresolved": list(self.unresolved),
            "status": self.status,
        }


def resolve_chain(
    *,
    ground_truth_json: Path,
    coverage_items_csv: Path,
    handler_sink_chains_csv: Path,
) -> ResolvedChain:
    data = json.loads(ground_truth_json.read_text(encoding="utf-8"))
    handlers = data.get("d5_tool_handler_entry", [])
    sinks = data.get("d5_sink_points", [])
    if not isinstance(handlers, list) or len(handlers) != 1:
        raise ChainAssemblyError(
            "the first call-chain semantic prototype requires one handler"
        )
    if not isinstance(sinks, list) or len(sinks) != 1:
        raise ChainAssemblyError(
            "the first call-chain semantic prototype requires one sink"
        )
    handler_gt = handlers[0]
    sink_gt = sinks[0]

    item_rows = [
        row
        for row in _read_csv(coverage_items_csv)
        if Path(row.get("json_file", "")).name == ground_truth_json.name
    ]
    handler_rows = [row for row in item_rows if row.get("item_kind") == "handler"]
    sink_rows = [row for row in item_rows if row.get("item_kind") == "sink"]
    if len(handler_rows) != 1 or len(sink_rows) != 1:
        raise ChainAssemblyError(
            "ground-truth endpoint coverage must contain exactly one handler and one sink row"
        )
    intersection = _split_chain_ids(handler_rows[0]["chain_ids"]) & _split_chain_ids(
        sink_rows[0]["chain_ids"]
    )
    if len(intersection) != 1:
        raise ChainAssemblyError(
            "handler and sink must resolve to exactly one common call chain; got "
            + ", ".join(sorted(intersection))
        )
    selected_chain_id = next(iter(intersection))

    chain_rows = _read_csv(handler_sink_chains_csv)
    matching = [
        row for row in chain_rows if _chain_id(row["call_chain"]) == selected_chain_id
    ]
    if len(matching) != 1:
        raise ChainAssemblyError(
            f"expected one structural row for {selected_chain_id}, got {len(matching)}"
        )
    row = matching[0]
    sink_file, sink_line = _parse_location(str(sink_gt.get("location", "")))
    if (
        row.get("sink_label") != sink_gt.get("name")
        or not _same_file(row.get("sink_file", ""), sink_file)
        or int(row.get("sink_line", "0") or 0) != sink_line
    ):
        raise ChainAssemblyError(
            "the structural chain does not match the selected sink"
        )

    entry_file, entry_line = _parse_location(str(handler_gt.get("location", "")))
    handler = {
        "tool_name": str(handler_gt.get("name", "")),
        "tool_entry_location": f"{entry_file}:{entry_line}",
        "call_graph_root": row["handler_func"],
        "root_location": f"{row['handler_file']}:{row['handler_line']}",
    }
    sink = {
        "name": str(sink_gt.get("name", "")),
        "kind": str(sink_gt.get("kind", "")),
        "location": f"{sink_file}:{sink_line}",
        "checked_parameter": str(sink_gt.get("problematic_parameter", "")),
        "boundary": "invocation",
    }
    excluded = tuple(
        sorted(set(data) - {"report_name", "d5_tool_handler_entry", "d5_sink_points"})
    )
    return ResolvedChain(
        chain_id=selected_chain_id,
        call_chain=row["call_chain"],
        hops=tuple(_parse_hops(row["call_chain"])),
        handler=handler,
        sink=sink,
        raw_row=row,
        excluded_ground_truth_fields=excluded,
    )


def _catalog_match(
    candidate: dict[str, str], catalog: list[dict[str, str]]
) -> dict[str, str]:
    matches = [
        row
        for row in catalog
        if row.get("gate_name") == candidate.get("gate_fn")
        and row.get("callsite_file") == candidate.get("gate_file")
        and int(row.get("callsite_line", "0") or 0)
        == int(candidate.get("gate_line", "0") or 0)
        and row.get("enclosing_function") == candidate.get("gate_in_func")
    ]
    if len(matches) != 1:
        raise ChainAssemblyError(
            "candidate does not map to one semantic gate: "
            f"{candidate.get('gate_fn')}@{candidate.get('gate_file')}:{candidate.get('gate_line')}"
        )
    return matches[0]


def select_chain_gates(
    *,
    resolved: ResolvedChain,
    chain_gates_csv: Path,
    gate_index_csv: Path,
) -> list[GateSelection]:
    catalog = _read_csv(gate_index_csv)
    candidate_rows = [
        row
        for row in _read_csv(chain_gates_csv)
        if row.get("call_chain") == resolved.call_chain
        and row.get("taint_verdict") in INCLUDED_VERDICTS
    ]
    matched: dict[str, dict[str, str]] = {}
    for candidate in candidate_rows:
        row = _catalog_match(candidate, catalog)
        gate_uid = row.get("gate_uid", "")
        if not gate_uid:
            raise ChainAssemblyError(
                f"catalog gate #{row.get('gate_number')} has no gate_uid"
            )
        matched[gate_uid] = row

    hop_positions = {hop["function"]: index for index, hop in enumerate(resolved.hops)}

    def order(row: dict[str, str]) -> tuple[int, int, str]:
        return (
            hop_positions.get(row.get("enclosing_function", ""), 10_000),
            int(row.get("callsite_line", "0") or 0),
            row["gate_uid"],
        )

    selected: list[GateSelection] = []
    for row in sorted(matched.values(), key=order):
        selected.append(
            GateSelection(
                gate_number=int(row["gate_number"]),
                gate_uid=row["gate_uid"],
                gate_id=row["gate_id"],
                gate_name=row["gate_name"],
                qualified_function=row["qualified_function"],
                enclosing_function=row["enclosing_function"],
                callsite_file=row["callsite_file"],
                callsite_line=int(row["callsite_line"]),
                static_verdict=row["static_verdict"],
                content_digest=row.get("content_digest", ""),
            )
        )
    if any(item.static_verdict not in INCLUDED_VERDICTS for item in selected):
        raise ChainAssemblyError("needs-review gates cannot enter chain assembly")
    return selected


def gate_semantic_path(store_dir: Path, selection: GateSelection) -> Path:
    """Return the canonical reusable semantic artifact for one catalog gate."""

    return (
        store_dir / "repository" / selection.gate_uid / "semantic.json"
    )


def load_gate_semantics(
    store_dir: Path, selections: list[GateSelection]
) -> list[dict[str, Any]]:
    """Load exact per-gate results; aggregate JSONL files are not chain inputs."""

    records: list[dict[str, Any]] = []
    missing: list[str] = []
    for selection in selections:
        path = gate_semantic_path(store_dir, selection)
        if not path.is_file():
            missing.append(f"{selection.gate_id} ({path})")
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ChainAssemblyError(
                f"cannot read gate semantic {selection.gate_id} at {path}: {exc}"
            ) from exc
        actual_id = str(record.get("gate_id", ""))
        if actual_id != selection.gate_id:
            raise ChainAssemblyError(
                f"gate semantic identity mismatch at {path}: expected "
                f"{selection.gate_id}, got {actual_id or '<missing>'}"
            )
        records.append(record)
    if missing:
        raise ChainAssemblyError("missing gate semantics: " + ", ".join(missing))
    return records


def build_chain_slice(
    *,
    resolved: ResolvedChain,
    selections: list[GateSelection],
    gate_semantics: list[dict[str, Any]],
    project_revision: str,
) -> CallChainSliceV2:
    if [item.gate_id for item in selections] != [
        str(ir["gate_id"]) for ir in gate_semantics
    ]:
        raise ChainAssemblyError("gate semantics are not in execution order")
    values = (
        {
            "id": "CV1",
            "meaning": "the model-provided terminal command carried through the selected chain",
            "gate_bindings": [
                {"gate_id": str(ir["gate_id"]), "input_value_id": _gate_input_id(ir)}
                for ir in gate_semantics
            ],
            "sink_binding": {
                "parameter": resolved.sink["checked_parameter"],
                "relation": "same command value at the selected sink invocation",
            },
        },
    )
    status = (
        "partial"
        if any(ir.get("status") == "partial" for ir in gate_semantics)
        else "complete"
    )
    return CallChainSliceV2(
        project_revision=project_revision,
        chain_id=resolved.chain_id,
        call_chain=resolved.call_chain,
        calls=resolved.hops,
        handler=resolved.handler,
        sink=resolved.sink,
        values=values,
        selected_gates=tuple(item.to_dict() for item in selections),
        gate_semantics=tuple(gate_semantics),
        unresolved=tuple(_unresolved_union(gate_semantics)),
        status=status,
    )

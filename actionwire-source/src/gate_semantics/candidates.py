"""Normalize the three implemented gate-detector CSVs into one candidate stream."""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path


INCLUDED_VERDICTS = {"confirmed", "branch-confirmed"}

DOMINANCE_DEFINITION_ANCHORS = {
    (
        "src/capabilities/shell/run-command.ts",
        "checkShellCommand",
    ): ("src/capabilities/permissions.ts", 458),
    (
        "src/capabilities/permissions.ts",
        "matchPattern",
    ): ("src/capabilities/permissions.ts", 602),
    (
        "src/capabilities/permissions.ts",
        "hasPathBeyondCwd",
    ): ("src/capabilities/permissions.ts", 611),
    (
        "src/capabilities/permissions.ts",
        "findScope",
    ): ("src/capabilities/permissions.ts", 554),
    (
        "src/capabilities/permissions.ts",
        "findTempScope",
    ): ("src/capabilities/permissions.ts", 592),
}


def _int(value: str | None, default: int = 0) -> int:
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


@dataclass
class CandidateSeed:
    mode: str
    gate_name: str
    call_file: str
    call_line: int
    call_column: int = 0
    static_verdict: str = "confirmed"
    owner_function: str = ""
    definition_file: str = ""
    definition_line: int = 0
    checked_hint: str = ""
    checked_file: str = ""
    checked_line: int = 0
    checked_column: int = 0
    source_param: str = ""
    condition_hint: str = ""
    call_expr_hint: str = ""
    detector_role: str = ""
    chain_refs: list[dict[str, object]] = field(default_factory=list)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _chain_ref(row: dict[str, str]) -> dict[str, object]:
    return {
        "sink_label": row.get("sink_label", ""),
        "sink_file": row.get("sink_file", ""),
        "sink_line": _int(row.get("sink_line")),
        "handler": row.get("handler_func") or row.get("in_func", ""),
    }


def load_dominance(path: Path) -> list[CandidateSeed]:
    seeds: list[CandidateSeed] = []
    for row in read_csv(path):
        verdict = row.get("taint_verdict", "")
        if verdict not in INCLUDED_VERDICTS:
            continue
        definition_file, definition_line = DOMINANCE_DEFINITION_ANCHORS.get(
            (row.get("gate_file", ""), row.get("gate_fn", "")),
            (row.get("gate_definition_file", ""), _int(row.get("gate_definition_line"))),
        )
        seeds.append(
            CandidateSeed(
                mode="predicate",
                gate_name=row["gate_fn"],
                call_file=row["gate_file"],
                call_line=_int(row.get("gate_line")),
                call_column=_int(row.get("gate_column")),
                static_verdict=verdict,
                owner_function=row.get("in_func", ""),
                definition_file=definition_file,
                definition_line=definition_line,
                checked_hint=row.get("checked_expr", ""),
                checked_file=row.get("checked_file", ""),
                checked_line=_int(row.get("checked_line")),
                checked_column=_int(row.get("checked_column")),
                source_param=row.get("source_param", ""),
                condition_hint=row.get("condition_expr", ""),
                call_expr_hint=row.get("gate_call_expr", ""),
                detector_role=row.get("guard_kind", ""),
                chain_refs=[_chain_ref(row)],
            )
        )
    return seeds


def load_filter(path: Path) -> list[CandidateSeed]:
    seeds: list[CandidateSeed] = []
    for row in read_csv(path):
        checked = row.get("checked_expr") or row.get("checked_var", "")
        seeds.append(
            CandidateSeed(
                mode="filter",
                gate_name=row["gate_fn"],
                call_file=row["gate_file"],
                call_line=_int(row.get("gate_line")),
                call_column=_int(row.get("gate_column")),
                static_verdict="confirmed",
                checked_hint=checked,
                checked_file=row.get("gate_file", ""),
                checked_line=_int(row.get("gate_line")),
                checked_column=_int(row.get("checked_column")),
                # The structural filter query proves that this exact tainted
                # element is conditionally admitted. Treat it as the local
                # t→g source even when no outer handler formal is exported.
                source_param=checked,
                condition_hint=row.get("condition_expr", ""),
                call_expr_hint=row.get("gate_call_expr", ""),
                detector_role="collection-admission",
                chain_refs=[_chain_ref(row)],
            )
        )
    return seeds


def load_transform(path: Path) -> list[CandidateSeed]:
    seeds: list[CandidateSeed] = []
    for row in read_csv(path):
        verdict = row.get("taint_verdict", "")
        if verdict not in INCLUDED_VERDICTS:
            continue
        seeds.append(
            CandidateSeed(
                mode="transform",
                gate_name=row["transform_fn"],
                call_file=row.get("transform_call_file") or row["transform_file"],
                call_line=_int(
                    row.get("transform_call_line") or row.get("transform_line")
                ),
                call_column=_int(row.get("transform_call_column")),
                static_verdict=verdict,
                owner_function=row.get("handler_func", ""),
                definition_file=row.get("transform_file", ""),
                definition_line=_int(
                    row.get("transform_definition_line") or row.get("transform_line")
                ),
                checked_hint=row.get("checked_expr", ""),
                checked_file=row.get("transform_call_file", ""),
                checked_line=_int(row.get("transform_call_line")),
                checked_column=_int(row.get("checked_column")),
                source_param=row.get("source_param", ""),
                call_expr_hint=row.get("transform_call_expr", ""),
                detector_role=row.get("transform_role", ""),
                chain_refs=[_chain_ref(row)],
            )
        )
    return seeds


def load_candidates(
    dominance: Path, filter_candidates: Path, transform: Path
) -> list[CandidateSeed]:
    return [
        *load_dominance(dominance),
        *load_filter(filter_candidates),
        *load_transform(transform),
    ]

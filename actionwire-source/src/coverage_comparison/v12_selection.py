"""Risk-prioritized deferred-candidate batching for precision v12."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class ValidationBatch:
    project: str
    chain_id: str
    index: int
    candidates: tuple[dict[str, Any], ...]


def select_wrong_check_batches(
    *,
    candidates: Sequence[Mapping[str, Any]],
    dispositions: Sequence[Mapping[str, Any]],
    max_batch_size: int = 4,
) -> tuple[ValidationBatch, ...]:
    """Select unresolved wrong-checks and losslessly batch them by chain."""

    if max_batch_size < 1:
        raise ValueError("max_batch_size must be positive")
    deferred = {
        str(row["candidate_id"])
        for row in dispositions
        if row["disposition"] == "needs-source-validation"
    }
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for raw in candidates:
        candidate = dict(raw)
        if candidate["candidate_id"] not in deferred:
            continue
        if candidate["failure_mode"] != "wrong-check":
            continue
        key = (str(candidate["project"]), str(candidate["chain_id"]))
        grouped.setdefault(key, []).append(candidate)
    output: list[ValidationBatch] = []
    for (project, chain_id), rows in sorted(grouped.items()):
        ordered = sorted(rows, key=lambda row: row["candidate_id"])
        for offset in range(0, len(ordered), max_batch_size):
            output.append(
                ValidationBatch(
                    project=project,
                    chain_id=chain_id,
                    index=offset // max_batch_size + 1,
                    candidates=tuple(ordered[offset : offset + max_batch_size]),
                )
            )
    return tuple(output)

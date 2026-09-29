"""Upstream-completeness partition and dense-chain validation selection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence


UPSTREAM_FILTER_VERSION = "coverage-upstream-completeness-filter/v13"


@dataclass(frozen=True)
class DeferredBatch:
    project: str
    chain_id: str
    index: int
    candidates: tuple[dict[str, Any], ...]


def partition_upstream_incomplete(
    *,
    candidates: Sequence[Mapping[str, Any]],
    dispositions: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    candidate_by_id = {str(row["candidate_id"]): row for row in candidates}
    output: list[dict[str, Any]] = []
    for raw in dispositions:
        row = dict(raw)
        if row["disposition"] != "needs-source-validation":
            output.append(row)
            continue
        candidate = candidate_by_id[str(row["candidate_id"])]
        if candidate["group_oracle_status"] != "partial":
            output.append(row)
            continue
        row.update(
            {
                "schema_version": UPSTREAM_FILTER_VERSION,
                "prior_disposition": "needs-source-validation",
                "disposition": "upstream-incomplete",
                "reason": (
                    "Group Oracle is partial; requirement applicability is not complete "
                    "enough for candidate validation"
                ),
            }
        )
        output.append(row)
    return tuple(output)


def select_dense_chain_batches(
    *,
    candidates: Sequence[Mapping[str, Any]],
    dispositions: Sequence[Mapping[str, Any]],
    target_remaining: int = 149,
    max_batch_size: int = 4,
) -> tuple[DeferredBatch, ...]:
    if target_remaining < 0 or max_batch_size < 1:
        raise ValueError("invalid deferred validation target or batch size")
    deferred = {
        str(row["candidate_id"])
        for row in dispositions
        if row["disposition"] == "needs-source-validation"
    }
    if len(deferred) <= target_remaining:
        return ()
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for raw in candidates:
        candidate = dict(raw)
        if candidate["candidate_id"] not in deferred:
            continue
        key = (str(candidate["project"]), str(candidate["chain_id"]))
        grouped.setdefault(key, []).append(candidate)
    selected: list[tuple[tuple[str, str], list[dict[str, Any]]]] = []
    selected_count = 0
    required = len(deferred) - target_remaining
    for key, rows in sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0])):
        if selected_count >= required:
            break
        ordered = sorted(rows, key=lambda row: row["candidate_id"])
        selected.append((key, ordered))
        selected_count += len(ordered)
    output: list[DeferredBatch] = []
    for (project, chain_id), rows in selected:
        for offset in range(0, len(rows), max_batch_size):
            output.append(
                DeferredBatch(
                    project=project,
                    chain_id=chain_id,
                    index=offset // max_batch_size + 1,
                    candidates=tuple(rows[offset : offset + max_batch_size]),
                )
            )
    return tuple(output)

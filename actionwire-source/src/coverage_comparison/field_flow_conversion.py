"""Convert CodeQL field-flow CSV rows into revision-bound JSONL ledgers."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from .field_flow_contract import (
    EXCLUSION_REASONS,
    FieldFlowContractError,
    canonical_payload,
    parse_path_nodes,
    parse_transforms,
    source_hashes,
    stable_identifier,
    validate_common,
)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _integer(row: Mapping[str, str], key: str) -> int:
    try:
        return int(row[key])
    except (KeyError, ValueError) as exc:
        raise FieldFlowContractError(f"invalid integer column {key!r}") from exc


def _binding_key(row: Mapping[str, str]) -> tuple[Any, ...]:
    return (
        row["project"],
        row["handler_name"],
        row["handler_file"],
        _integer(row, "handler_line"),
        row["sink_file"],
        _integer(row, "sink_line"),
        _integer(row, "sink_column"),
        row["sink_role"],
    )


def _index_bindings(rows: Iterable[Mapping[str, Any]]) -> dict[tuple[Any, ...], Mapping[str, Any]]:
    index: dict[tuple[Any, ...], Mapping[str, Any]] = {}
    for row in rows:
        if row.get("schema_version") != "field-flow-chain-binding/v1":
            raise FieldFlowContractError("invalid field-flow chain binding schema")
        key = (
            row["project"],
            row["handler"]["name"],
            row["handler"]["file"],
            row["handler"]["line"],
            row["sink"]["file"],
            row["sink"]["line"],
            row["sink"]["column"],
            row["sink"]["role"],
        )
        if key in index:
            raise FieldFlowContractError(f"ambiguous field-flow chain binding: {key!r}")
        index[key] = row
    return index


def _base_record(
    row: Mapping[str, str], binding: Mapping[str, Any], source_root: Path
) -> dict[str, Any]:
    path_nodes = parse_path_nodes(row["path_nodes"])
    record = {
        "project": binding["project"],
        "revision": binding["revision"],
        "chain_id": binding["chain_id"],
        "handler_id": binding["handler_id"],
        "sink_id": binding["sink_id"],
        "source_parameter": row["source_parameter"],
        "field": row["field"],
        "property_read": row["property_read"],
        "sink_role": row["sink_role"],
        "value_authority": row["value_authority"],
        "transforms": parse_transforms(row.get("transforms", "")),
        "path_nodes": path_nodes,
        "source_hashes": source_hashes(source_root, path_nodes),
    }
    return record


def convert_rows(
    witness_rows: Iterable[Mapping[str, str]],
    exclusion_rows: Iterable[Mapping[str, str]],
    bindings: Iterable[Mapping[str, Any]],
    source_root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    index = _index_bindings(bindings)
    witnesses: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    for row in witness_rows:
        binding = index.get(_binding_key(row))
        if binding is None:
            raise FieldFlowContractError(f"unbound witness row: {_binding_key(row)!r}")
        record = _base_record(row, binding, source_root)
        record.update({"schema_version": "field-flow-witness/v1", "proof_kind": row["proof"]})
        validate_common(record)
        record["origin_witness_id"] = stable_identifier(
            "FFW", canonical_payload(record, identifier_key="origin_witness_id")
        )
        witnesses.append(record)
    for row in exclusion_rows:
        binding = index.get(_binding_key(row))
        if binding is None:
            raise FieldFlowContractError(f"unbound exclusion row: {_binding_key(row)!r}")
        reason = row["exclusion_reason"]
        if reason not in EXCLUSION_REASONS:
            raise FieldFlowContractError(f"invalid exclusion reason: {reason!r}")
        record = _base_record(row, binding, source_root)
        record.update(
            {
                "schema_version": "field-flow-exclusion/v1",
                "proof_kind": "none",
                "exclusion_reason": reason,
            }
        )
        validate_common(record)
        record["origin_exclusion_id"] = stable_identifier(
            "FFE", canonical_payload(record, identifier_key="origin_exclusion_id")
        )
        exclusions.append(record)
    return (
        sorted(witnesses, key=lambda row: row["origin_witness_id"]),
        sorted(exclusions, key=lambda row: row["origin_exclusion_id"]),
    )


def _write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    text = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--witness-csv", type=Path, required=True)
    parser.add_argument("--exclusion-csv", type=Path, required=True)
    parser.add_argument("--chain-index", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--witness-out", type=Path, required=True)
    parser.add_argument("--exclusion-out", type=Path, required=True)
    args = parser.parse_args()
    witnesses, exclusions = convert_rows(
        _read_csv(args.witness_csv),
        _read_csv(args.exclusion_csv),
        _read_jsonl(args.chain_index),
        args.source_root,
    )
    _write_jsonl(args.witness_out, witnesses)
    _write_jsonl(args.exclusion_out, exclusions)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

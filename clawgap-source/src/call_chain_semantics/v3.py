"""Project-neutral all-chain semantic assembly with terminal sink constraints."""

from __future__ import annotations

import copy
import csv
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from jsonschema import validate as validate_schema

from src.gate_semantics.contracts import estimate_tokens

from .contracts import HARD_TOKEN_LIMIT


SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
SEMANTIC_SCHEMA_PATH = SCHEMA_DIR / "call-chain-semantic-ir-v3.schema.json"
SCHEMA_VERSION = "call-chain-semantic-ir/v3"
ASSEMBLY_VERSION = "call-chain-semantic-assembly-v3.1"
ELIGIBLE_VERDICTS = {"confirmed", "branch-confirmed"}


class ChainV3Error(ValueError):
    pass


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _json_line(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, values: Iterable[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(_json_line(value) + "\n" for value in values), encoding="utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(_json_line(value).encode("utf-8")).hexdigest()


def _unresolved(records: Iterable[dict[str, Any]]) -> list[str]:
    values: set[str] = set()
    for record in records:
        explicit = record.get("unresolved", [])
        if isinstance(explicit, list):
            values.update(str(item) for item in explicit if str(item).strip())
        if record.get("schema_version") != "gate-semantic-ir/v2":
            for step in record.get("steps", []):
                if isinstance(step, dict) and step.get("op") == "unknown":
                    values.add(
                        f"{record.get('gate_id')}:{step.get('id')}:{step.get('rule')}"
                    )
    return sorted(values)


def _parse_calls(call_chain: str) -> list[dict[str, str]]:
    _depth, separator, body = call_chain.partition("#")
    if not separator:
        raise ChainV3Error(f"invalid call chain: {call_chain!r}")
    calls: list[dict[str, str]] = []
    for hop in body.split("->"):
        symbol, at, location = hop.partition("@")
        if not at:
            raise ChainV3Error(f"invalid call-chain hop: {hop!r}")
        calls.append({"symbol": symbol, "location": location})
    return calls


@dataclass(frozen=True)
class CallChainSliceV3:
    project: dict[str, str]
    chain_id: str
    call_chain: str
    calls: tuple[dict[str, str], ...]
    handler: dict[str, str]
    sink: dict[str, object]
    sink_constraint: dict[str, object]
    selected_gates: tuple[dict[str, object], ...]
    gate_semantics: tuple[dict[str, Any], ...]
    values: tuple[dict[str, Any], ...]
    unresolved: tuple[str, ...]
    status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "call-chain-slice/v3",
            "project": copy.deepcopy(self.project),
            "chain_id": self.chain_id,
            "call_chain": self.call_chain,
            "calls": copy.deepcopy(list(self.calls)),
            "handler": copy.deepcopy(self.handler),
            "sink": copy.deepcopy(self.sink),
            "sink_constraint": copy.deepcopy(self.sink_constraint),
            "selected_gates": copy.deepcopy(list(self.selected_gates)),
            "gate_semantics": copy.deepcopy(list(self.gate_semantics)),
            "values": copy.deepcopy(list(self.values)),
            "unresolved": list(self.unresolved),
            "status": self.status,
        }


def build_semantic_ir(chain_slice: CallChainSliceV3) -> dict[str, Any]:
    gates = [
        {
            "gate_number": selection["gate_number"],
            "gate_uid": selection["gate_uid"],
            "gate_name": selection["gate_name"],
            "callsite": selection["callsite"],
            "static_verdict": selection["static_verdict"],
            "semantic": copy.deepcopy(semantic),
        }
        for selection, semantic in zip(
            chain_slice.selected_gates, chain_slice.gate_semantics, strict=True
        )
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "project": copy.deepcopy(chain_slice.project),
        "chain_id": chain_slice.chain_id,
        "handler": copy.deepcopy(chain_slice.handler),
        "sink": copy.deepcopy(chain_slice.sink),
        "sink_constraint": copy.deepcopy(chain_slice.sink_constraint),
        "values": copy.deepcopy(list(chain_slice.values)),
        "summary": (
            f"Collects {len(gates)} detected gate semantics in call-chain order before "
            f"{chain_slice.sink['label']}; the terminal sink point is the capability constraint."
        ),
        "gates": gates,
        "unresolved": list(chain_slice.unresolved),
        "status": chain_slice.status,
    }


def validate_semantic_ir(ir: dict[str, Any], chain_slice: CallChainSliceV3) -> list[str]:
    errors: list[str] = []
    if ir != build_semantic_ir(chain_slice):
        errors.append("semantic IR differs from deterministic V3 assembly")
    try:
        schema = json.loads(SEMANTIC_SCHEMA_PATH.read_text(encoding="utf-8"))
        validate_schema(instance=ir, schema=schema)
    except Exception as exc:
        errors.append(f"schema validation failed: {exc}")
    tokens = estimate_tokens(ir)
    if tokens > HARD_TOKEN_LIMIT:
        errors.append(
            f"semantic IR is approximately {tokens} tokens; "
            f"hard limit is {HARD_TOKEN_LIMIT}"
        )
    return errors


def _constraint(row: dict[str, str]) -> dict[str, object]:
    return {
        "constraint_id": row["constraint_id"],
        "sink_id": row["sink_id"],
        "sink_api": row["sink_api"],
        "capability_class": row["capability_class"],
        "location": f"{row['sink_file']}:{row['sink_line']}:{row['sink_column']}",
        "controlled_argument": row["controlled_argument"],
        "call_shape": row["call_shape"],
        "capability_card": {
            "path": row["capability_card"],
            "sha256": row["capability_card_sha256"],
        },
    }


def _load_semantic(store: Path, gate_uid: str, gate_id: str) -> dict[str, Any]:
    path = store / "repository" / gate_uid / "semantic.json"
    if not path.is_file():
        raise ChainV3Error(f"missing gate semantic {gate_id}: {path}")
    record = json.loads(path.read_text(encoding="utf-8"))
    if record.get("gate_id") != gate_id:
        raise ChainV3Error(
            f"gate semantic identity mismatch at {path}: {record.get('gate_id')} != {gate_id}"
        )
    return record


def assemble_all_chains(
    *,
    project_id: str,
    project_revision: str,
    handler_sink_chains_csv: Path,
    chain_gates_csv: Path,
    sink_constraints_csv: Path,
    gate_index_csv: Path,
    gate_semantics_dir: Path,
    out_dir: Path,
    generation_command: str,
    excluded_chains: Iterable[dict[str, str]] = (),
    handler_impact_path: Path | None = None,
) -> dict[str, Any]:
    structural_chains = _read_csv(handler_sink_chains_csv)
    chain_ids = [row["chain_id"] for row in structural_chains]
    if len(chain_ids) != len(set(chain_ids)):
        raise ChainV3Error("handler/sink input contains duplicate chain IDs")
    exclusion_rows = sorted(
        (dict(row) for row in excluded_chains), key=lambda row: row["chain_id"]
    )
    excluded_ids = [row.get("chain_id", "") for row in exclusion_rows]
    if (
        any(not chain_id for chain_id in excluded_ids)
        or len(excluded_ids) != len(set(excluded_ids))
        or not set(excluded_ids) <= set(chain_ids)
    ):
        raise ChainV3Error("excluded chains must uniquely reference structural chain IDs")
    chains = [row for row in structural_chains if row["chain_id"] not in set(excluded_ids)]
    constraint_rows = _read_csv(sink_constraints_csv)
    constraint_ids = [row["sink_id"] for row in constraint_rows]
    if len(constraint_ids) != len(set(constraint_ids)):
        raise ChainV3Error("sink-constraint input contains duplicate sink IDs")
    constraints = {row["sink_id"]: row for row in constraint_rows}
    chain_sink_ids = {row["sink_id"] for row in structural_chains}
    extra_constraints = sorted(set(constraints) - chain_sink_ids)
    if extra_constraints:
        raise ChainV3Error(
            "sink constraints are not referenced by structural chains: "
            + ", ".join(extra_constraints)
        )
    catalog = {row["gate_uid"]: row for row in _read_csv(gate_index_csv)}
    gate_rows: dict[str, list[dict[str, str]]] = {}
    for row in _read_csv(chain_gates_csv):
        if row["chain_id"] not in set(chain_ids):
            raise ChainV3Error(
                f"chain-gate row references unknown chain {row['chain_id']}"
            )
        if row.get("gate_uid") and row.get("static_verdict") in ELIGIBLE_VERDICTS:
            gate_rows.setdefault(row["chain_id"], []).append(row)

    slices: list[dict[str, Any]] = []
    semantics: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for chain in chains:
        chain_id = chain["chain_id"]
        try:
            constraint_row = constraints.get(chain["sink_id"])
            if constraint_row is None:
                raise ChainV3Error(f"chain {chain_id} has no sink constraint")
            ordered_rows = sorted(
                gate_rows.get(chain_id, []), key=lambda row: int(row["gate_seq"])
            )
            sequences = [int(row["gate_seq"]) for row in ordered_rows]
            if sequences != list(range(1, len(sequences) + 1)):
                raise ChainV3Error(
                    f"chain {chain_id} has non-contiguous or duplicate gate sequence"
                )
            selected: list[dict[str, object]] = []
            gate_semantics: list[dict[str, Any]] = []
            for row in ordered_rows:
                catalog_row = catalog.get(row["gate_uid"])
                if catalog_row is None:
                    raise ChainV3Error(f"unknown gate UID {row['gate_uid']} on {chain_id}")
                selected.append(
                    {
                        "gate_number": int(catalog_row["gate_number"]),
                        "gate_uid": catalog_row["gate_uid"],
                        "gate_id": catalog_row["gate_id"],
                        "gate_name": catalog_row["gate_name"],
                        "callsite": (
                            f"{catalog_row['callsite_file']}:"
                            f"{catalog_row['callsite_line']}:"
                            f"{catalog_row['callsite_column']}"
                        ),
                        "static_verdict": catalog_row["static_verdict"],
                    }
                )
                gate_semantics.append(
                    _load_semantic(
                        gate_semantics_dir,
                        catalog_row["gate_uid"],
                        catalog_row["gate_id"],
                    )
                )
            sink_constraint = _constraint(constraint_row)
            unresolved = _unresolved(gate_semantics)
            status = (
                "partial"
                if unresolved or any(row.get("status") == "partial" for row in gate_semantics)
                else "complete"
            )
            value_id = "CV-" + hashlib.sha1(chain_id.encode("utf-8")).hexdigest()[:12]
            chain_slice = CallChainSliceV3(
                project={"id": project_id, "revision": project_revision},
                chain_id=chain_id,
                call_chain=chain["call_chain"],
                calls=tuple(_parse_calls(chain["call_chain"])),
                handler={
                    "tool_name": chain["tool_name"],
                    "qualified_name": chain["handler_qualified_name"],
                    "location": f"{chain['handler_file']}:{chain['handler_line']}",
                    "source_parameter": chain["source_parameter"],
                },
                sink={
                    "sink_id": chain["sink_id"],
                    "label": chain["sink_label"],
                    "location": f"{chain['sink_file']}:{chain['sink_line']}:{chain['sink_column']}",
                    "boundary": "invocation",
                },
                sink_constraint=sink_constraint,
                selected_gates=tuple(selected),
                gate_semantics=tuple(gate_semantics),
                values=(
                    {
                        "id": value_id,
                        "source_parameter": chain["source_parameter"],
                        "gate_bindings": [
                            {"gate_id": row["gate_id"]} for row in selected
                        ],
                        "sink_binding": sink_constraint["controlled_argument"],
                    },
                ),
                unresolved=tuple(unresolved),
                status=status,
            )
            slice_record = chain_slice.to_dict()
            semantic = build_semantic_ir(chain_slice)
            errors = validate_semantic_ir(semantic, chain_slice)
            if errors:
                raise ChainV3Error("; ".join(errors))
            slices.append(slice_record)
            semantics.append(semantic)
            audit = {
                "chain_id": chain_id,
                "assembly_version": ASSEMBLY_VERSION,
                "input_digest": digest(slice_record),
                "semantic_digest": digest(semantic),
                "selected_gate_uids": [row["gate_uid"] for row in selected],
                "sink_constraint_id": sink_constraint["constraint_id"],
                "estimated_semantic_tokens": estimate_tokens(semantic),
                "status": "complete",
            }
            audits.append(audit)
            selected_dir = out_dir / "selected" / chain_id
            _write_json(selected_dir / "slice.json", slice_record)
            _write_json(selected_dir / "semantic.json", semantic)
            _write_json(selected_dir / "audit.json", audit)
        except Exception as exc:
            failures.append(
                {"chain_id": chain_id, "error": f"{type(exc).__name__}: {exc}"}
            )

    _write_jsonl(out_dir / "chain-slices.jsonl", slices)
    _write_jsonl(out_dir / "call-chain-semantics.jsonl", semantics)
    _write_jsonl(out_dir / "call-chain-semantics-audit.jsonl", audits)
    _write_jsonl(out_dir / "excluded-chains.jsonl", exclusion_rows)
    index = [
        "# Call-Chain Semantics",
        "",
        f"> Generation command: `{generation_command}`",
        "",
        f"Semantic records: **{len(semantics)}** / **{len(chains)}** chains.",
        "",
        "| Chain | Tool | Sink constraint | Gates | Status |",
        "|---|---|---|---:|---|",
    ]
    for semantic in semantics:
        index.append(
            f"| `{semantic['chain_id']}` | `{semantic['handler']['tool_name']}` | "
            f"`{semantic['sink_constraint']['constraint_id']}` | {len(semantic['gates'])} | "
            f"{semantic['status']} |"
        )
    (out_dir / "chain-index.md").parent.mkdir(parents=True, exist_ok=True)
    (out_dir / "chain-index.md").write_text("\n".join(index) + "\n", encoding="utf-8")
    manifest = {
        "schema_version": "call-chain-semantics-manifest/v4",
        "generation_command": generation_command,
        "assembly_version": ASSEMBLY_VERSION,
        "project": {"id": project_id, "revision": project_revision},
        "inputs": {
            "handler_sink_chains": str(handler_sink_chains_csv),
            "chain_gates": str(chain_gates_csv),
            "sink_constraints": str(sink_constraints_csv),
            "gate_index": str(gate_index_csv),
            "gate_semantics_dir": str(gate_semantics_dir),
            **(
                {"handler_impact": str(handler_impact_path)}
                if handler_impact_path is not None
                else {}
            ),
        },
        "counts": {
            "structural_chains": len(structural_chains),
            "eligible_chains": len(chains),
            "excluded_chains": len(exclusion_rows),
            "semantic_records": len(semantics),
            "zero_gate_chains": sum(not row["gates"] for row in semantics),
            "assembly_failures": len(failures),
        },
        "excluded_chains": exclusion_rows,
        "assembly_failures": failures,
    }
    _write_json(out_dir / "manifest.json", manifest)
    return manifest

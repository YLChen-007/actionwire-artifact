"""Contracts for deterministic ordered call-chain gate semantics."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from src.gate_semantics.contracts import estimate_tokens

from .assembler import CallChainSliceV2


SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
SLICE_SCHEMA_PATH = SCHEMA_DIR / "call-chain-slice-v2.schema.json"
SEMANTIC_SCHEMA_PATH = SCHEMA_DIR / "call-chain-semantic-ir-v2.schema.json"
SCHEMA_VERSION = "call-chain-semantic-ir/v2"
ASSEMBLY_VERSION = "call-chain-semantic-assembly-v2.1"
HARD_TOKEN_LIMIT = 64_000
FINAL_FIELDS = {
    "schema_version",
    "chain_id",
    "handler",
    "sink",
    "values",
    "summary",
    "gates",
    "unresolved",
    "status",
}
ORDERED_GATE_FIELDS = {
    "gate_number",
    "gate_uid",
    "gate_name",
    "callsite",
    "static_verdict",
    "semantic",
}


class ChainContractError(ValueError):
    """Raised when deterministic chain assembly violates its contract."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


def chain_summary(chain_slice: CallChainSliceV2) -> str:
    """Return a stable summary without invoking an LLM."""

    count = len(chain_slice.selected_gates)
    return (
        f"Collects {count} detected gate semantics in call-chain order before "
        f"{chain_slice.sink['name']}."
    )


def ordered_gates(chain_slice: CallChainSliceV2) -> list[dict[str, Any]]:
    """Wrap each verbatim gate IR with its chain-local ordering metadata."""

    return [
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


def build_call_chain_semantic_ir(chain_slice: CallChainSliceV2) -> dict[str, Any]:
    """Build the final semantic IR by ordered aggregation only."""

    return {
        "schema_version": SCHEMA_VERSION,
        "chain_id": chain_slice.chain_id,
        "handler": copy.deepcopy(chain_slice.handler),
        "sink": copy.deepcopy(chain_slice.sink),
        "values": copy.deepcopy(list(chain_slice.values)),
        "summary": chain_summary(chain_slice),
        "gates": ordered_gates(chain_slice),
        "unresolved": list(chain_slice.unresolved),
        "status": chain_slice.status,
    }


def validate_call_chain_semantic_ir(
    ir: dict[str, Any],
    *,
    chain_slice: CallChainSliceV2,
    hard_token_limit: int = HARD_TOKEN_LIMIT,
) -> list[str]:
    """Validate exact order, metadata, verbatim gate IRs, and aggregate status."""

    if not isinstance(ir, dict):
        return ["call-chain semantic IR must be an object"]

    errors: list[str] = []
    extras = sorted(set(ir) - FINAL_FIELDS)
    missing = sorted(FINAL_FIELDS - set(ir))
    if extras:
        errors.append("semantic IR contains unsupported fields: " + ", ".join(extras))
    if missing:
        errors.append("semantic IR is missing fields: " + ", ".join(missing))

    expected = build_call_chain_semantic_ir(chain_slice)
    for key, value in expected.items():
        if ir.get(key) != value:
            errors.append(f"semantic IR must preserve deterministic field {key}")

    gates = ir.get("gates")
    if not isinstance(gates, list) or not gates:
        errors.append("gates must be a non-empty ordered list")
        gates = []
    gate_ids: list[str] = []
    for index, gate in enumerate(gates):
        label = f"gates[{index}]"
        if not isinstance(gate, dict):
            errors.append(f"{label} must be an object")
            continue
        extra_gate = sorted(set(gate) - ORDERED_GATE_FIELDS)
        missing_gate = sorted(ORDERED_GATE_FIELDS - set(gate))
        if extra_gate:
            errors.append(
                f"{label} contains unsupported fields: {', '.join(extra_gate)}"
            )
        if missing_gate:
            errors.append(f"{label} is missing fields: {', '.join(missing_gate)}")
        if gate.get("static_verdict") not in {"confirmed", "branch-confirmed"}:
            errors.append(f"{label}.static_verdict is not eligible")
        semantic = gate.get("semantic")
        if not isinstance(semantic, dict) or not semantic.get("gate_id"):
            errors.append(f"{label}.semantic must contain a gate_id")
        else:
            gate_ids.append(str(semantic["gate_id"]))
    if len(gate_ids) != len(set(gate_ids)):
        errors.append("gates must not contain duplicate gate IDs")

    tokens = estimate_tokens(ir)
    if tokens > hard_token_limit:
        errors.append(
            f"semantic IR is approximately {tokens} tokens; hard limit is {hard_token_limit}"
        )
    return errors


def digest(value: object) -> str:
    serialized = json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


__all__ = [
    "ASSEMBLY_VERSION",
    "ChainContractError",
    "HARD_TOKEN_LIMIT",
    "SEMANTIC_SCHEMA_PATH",
    "SLICE_SCHEMA_PATH",
    "build_call_chain_semantic_ir",
    "chain_summary",
    "digest",
    "estimate_tokens",
    "ordered_gates",
    "validate_call_chain_semantic_ir",
]

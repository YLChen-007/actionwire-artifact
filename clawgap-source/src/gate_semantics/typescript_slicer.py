"""TypeScript compiler-API backend for deterministic GateSlice V1 records."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Iterable

from .candidates import CandidateSeed
from .slicer import GateSlice, SourceChunk


BRIDGE = Path(__file__).with_name("typescript_bridge.mjs")


def _digest(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


def typescript_call_context(
    source_root: Path, relative_path: str, line: int, column: int = 0
) -> tuple[str, tuple[str, ...]]:
    """Return the normalized TypeScript call and its lexical function owners."""

    payload = {
        "operation": "call_context",
        "source_root": str(source_root.resolve()),
        "file": relative_path,
        "line": line,
        "column": column,
    }
    completed = subprocess.run(
        ["node", str(BRIDGE)],
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        detail = (completed.stderr or completed.stdout).strip()
        raise ValueError(f"TypeScript call-context bridge failed: {detail}")
    value = json.loads(completed.stdout)
    return str(value["call_shape"]), tuple(
        str(item) for item in value.get("enclosing_functions", [])
    )


class TypeScriptGateSlicer:
    """Turn JavaScript CodeQL detector rows into TypeScript GateSlice records."""

    def __init__(
        self,
        source_root: Path,
        *,
        project_name: str = "openclaw",
        revision: str | None = None,
    ) -> None:
        self.source_root = source_root.resolve()
        self.project_name = project_name
        self.revision = revision or "unknown-revision"

    def _bridge(self, seed: CandidateSeed) -> dict[str, Any]:
        payload = {
            "source_root": str(self.source_root),
            "file": seed.call_file,
            "line": seed.call_line,
            "column": seed.call_column,
            "gate_name": seed.gate_name,
            "checked_hint": seed.checked_hint,
            "checked_line": seed.checked_line,
            "checked_column": seed.checked_column,
            "condition_hint": seed.condition_hint,
            "owner_function": seed.owner_function,
            "definition_file": seed.definition_file,
            "definition_line": seed.definition_line,
            "mode": seed.mode,
        }
        completed = subprocess.run(
            ["node", str(BRIDGE)],
            input=json.dumps(payload, ensure_ascii=False),
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode:
            detail = (completed.stderr or completed.stdout).strip()
            raise ValueError(f"TypeScript AST bridge failed: {detail}")
        value = json.loads(completed.stdout)
        if not isinstance(value, dict):
            raise ValueError("TypeScript AST bridge returned a non-object")
        return value

    @staticmethod
    def _source_chunks(payload: dict[str, Any]) -> list[SourceChunk]:
        chunks: list[SourceChunk] = []
        for raw in payload.get("chunks", []):
            span = raw["span"]
            source = str(raw["source"])
            chunks.append(
                SourceChunk(
                    role=str(raw["role"]),
                    symbol=str(raw["symbol"]),
                    file=str(span["file"]),
                    line_start=int(span["start_line"]),
                    line_end=int(span["end_line"]),
                    sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
                    source=source,
                )
            )
        return chunks

    def build_slice(self, seed: CandidateSeed) -> GateSlice:
        parsed = self._bridge(seed)
        checked_expr = str(parsed["checked_expression"])
        call_span = dict(parsed["callsite_span"])
        identity = "|".join(
            [
                self.project_name,
                self.revision,
                seed.mode,
                seed.call_file,
                str(call_span["start_line"]),
                str(call_span["start_column"]),
                seed.gate_name,
                checked_expr,
            ]
        )
        gate_id = "G" + _digest(identity, 16)
        input_value_id = "V" + _digest(gate_id + ":" + checked_expr, 12)
        output_value_id = "V" + _digest(gate_id + ":output", 12)
        uid_parts = {
            "project": self.project_name,
            "module": seed.call_file,
            "enclosing_function": parsed["enclosing_function"],
            "mode": seed.mode,
            "qualified_function": parsed["qualified_function"],
            "normalized_gate_ast": parsed["normalized_gate_ast"],
            "normalized_checked_ast": parsed["normalized_checked_ast"],
            "normalized_callsite_context": parsed["normalized_context_ast"],
            "lexical_activation": parsed["activation"],
        }
        lexical_owners = list(parsed.get("lexical_owners") or [])
        if len(lexical_owners) > 1:
            # Nested execute callbacks have intentionally generic names. The
            # outer factory/wrapper stack distinguishes independent tool
            # callsites without introducing source coordinates.
            uid_parts["lexical_owners"] = lexical_owners
        uid_identity = json.dumps(
            uid_parts,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        gate_uid = "GU" + _digest(uid_identity, 20)
        unresolved: list[str] = []
        if seed.mode == "predicate" and not seed.source_param:
            unresolved.append(
                "source-witness:not-exported; regenerate enriched dominance candidates"
            )
        if parsed["binding_status"] != "resolved":
            unresolved.append(f"actual-to-formal:{seed.gate_name}")

        return GateSlice(
            gate_id=gate_id,
            gate_uid=gate_uid,
            project={
                "name": self.project_name,
                "revision": self.revision,
                "language": "typescript",
                "source_root": str(self.source_root),
            },
            gate={
                "mode": seed.mode,
                "static_verdict": seed.static_verdict,
                "name": seed.gate_name,
                "qualified_function": parsed["qualified_function"],
                "callee_kind": parsed["callee_kind"],
                "detector_role": seed.detector_role,
                "call_expression": parsed["call_expression"],
                "definition_span": parsed["definition_span"],
                "output_value_id": output_value_id,
                "output_meaning": (
                    "transformed return value"
                    if seed.mode == "transform"
                    else "boolean or decision value controlling continuation"
                ),
            },
            callsite={
                "span": call_span,
                "enclosing_function": parsed["enclosing_function"],
                "condition": parsed["condition"],
                "source": parsed["context_source"],
                "branch_effects": parsed["branch_effects"],
                "activation": parsed["activation"],
                "lexical_owners": lexical_owners,
            },
            checked_value={
                "value_id": input_value_id,
                "expression": checked_expr,
                "span": parsed["checked_span"],
                "actual_to_formal_binding": parsed["binding"],
                "binding_status": parsed["binding_status"],
                "semantic_role_hint": checked_expr,
                "type": "unknown",
            },
            dataflow={
                "source_symbol": seed.source_param or "unknown",
                "t_to_g_path": list(
                    dict.fromkeys(
                        [seed.source_param or "unknown source parameter", checked_expr]
                    )
                ),
            },
            source_bundle=self._source_chunks(parsed),
            unresolved_symbols=sorted(set(unresolved)),
            chain_refs=list(seed.chain_refs),
        )

    def build_slices(self, seeds: Iterable[CandidateSeed]) -> list[GateSlice]:
        result: dict[str, GateSlice] = {}
        for seed in seeds:
            gate_slice = self.build_slice(seed)
            result.setdefault(gate_slice.gate_uid, gate_slice)
        return sorted(result.values(), key=lambda item: item.gate_id)


__all__ = ["TypeScriptGateSlicer", "typescript_call_context"]

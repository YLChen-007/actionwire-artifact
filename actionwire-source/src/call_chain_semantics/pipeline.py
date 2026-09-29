"""Orchestrate endpoint selection and deterministic ordered gate assembly."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Iterable

from .assembler import (
    ChainAssemblyError,
    build_chain_slice,
    gate_semantic_path,
    load_gate_semantics,
    resolve_chain,
    select_chain_gates,
)
from .contracts import (
    ASSEMBLY_VERSION,
    ChainContractError,
    build_call_chain_semantic_ir,
    digest,
    estimate_tokens,
    validate_call_chain_semantic_ir,
)
from .render import write_chain_index


def _json_line(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _write_jsonl(path: Path, values: Iterable[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(_json_line(value) + "\n" for value in values), encoding="utf-8"
    )


def _source_revision(source_root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return "unknown"
    return result.stdout.strip()


def _paths_overlap(left: Path, right: Path) -> bool:
    left_resolved = left.resolve()
    right_resolved = right.resolve()
    return (
        left_resolved == right_resolved
        or left_resolved in right_resolved.parents
        or right_resolved in left_resolved.parents
    )


def run_pipeline(
    *,
    source_root: Path,
    ground_truth_json: Path,
    coverage_items_csv: Path,
    handler_sink_chains_csv: Path,
    chain_gates_csv: Path,
    gate_index_csv: Path,
    gate_semantics_dir: Path,
    out_dir: Path,
    generation_command: str,
) -> dict[str, Any]:
    if _paths_overlap(gate_semantics_dir, out_dir):
        raise ChainAssemblyError(
            "gate-semantics input and call-chain output directories must not overlap"
        )
    resolved = resolve_chain(
        ground_truth_json=ground_truth_json,
        coverage_items_csv=coverage_items_csv,
        handler_sink_chains_csv=handler_sink_chains_csv,
    )
    selections = select_chain_gates(
        resolved=resolved,
        chain_gates_csv=chain_gates_csv,
        gate_index_csv=gate_index_csv,
    )
    expected_ids = [item.gate_id for item in selections]
    expected_uids = [item.gate_uid for item in selections]
    gate_semantics = load_gate_semantics(gate_semantics_dir, selections)
    gate_semantic_paths = [
        str(gate_semantic_path(gate_semantics_dir, item)) for item in selections
    ]
    project_revision = _source_revision(source_root)
    chain_slice = build_chain_slice(
        resolved=resolved,
        selections=selections,
        gate_semantics=gate_semantics,
        project_revision=project_revision,
    )
    slice_record = chain_slice.to_dict()

    out_dir.mkdir(parents=True, exist_ok=True)
    slices_path = out_dir / "chain-slices.jsonl"
    semantics_path = out_dir / "call-chain-semantics.jsonl"
    audit_path = out_dir / "call-chain-semantics-audit.jsonl"
    manifest_path = out_dir / "manifest.json"
    index_path = out_dir / "chain-index.md"
    selected_dir = out_dir / "selected" / chain_slice.chain_id
    _write_jsonl(slices_path, [slice_record])
    _write_json(selected_dir / "slice.json", slice_record)

    semantic_ir: dict[str, Any] | None = None
    assembly_failures: list[dict[str, str]] = []
    try:
        semantic_ir = build_call_chain_semantic_ir(chain_slice)
        errors = validate_call_chain_semantic_ir(semantic_ir, chain_slice=chain_slice)
        if errors:
            raise ChainContractError(errors)
        _write_jsonl(semantics_path, [semantic_ir])
        _write_json(selected_dir / "semantic.json", semantic_ir)
        audit_record = {
            "chain_id": chain_slice.chain_id,
            "assembly_version": ASSEMBLY_VERSION,
            "project_revision": project_revision,
            "input_digest": digest(slice_record),
            "semantic_digest": digest(semantic_ir),
            "selected_gate_ids": expected_ids,
            "selected_gate_uids": expected_uids,
            "excluded_ground_truth_fields": list(resolved.excluded_ground_truth_fields),
            "estimated_semantic_tokens": estimate_tokens(semantic_ir),
            "status": "complete",
        }
    except Exception as exc:
        assembly_failures.append(
            {
                "chain_id": chain_slice.chain_id,
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
        _write_jsonl(semantics_path, [])
        audit_record = {
            "chain_id": chain_slice.chain_id,
            "assembly_version": ASSEMBLY_VERSION,
            "project_revision": project_revision,
            "input_digest": digest(slice_record),
            "selected_gate_ids": expected_ids,
            "selected_gate_uids": expected_uids,
            "excluded_ground_truth_fields": list(resolved.excluded_ground_truth_fields),
            "error": f"{type(exc).__name__}: {exc}",
            "status": "failed",
        }
    _write_jsonl(audit_path, [audit_record])
    _write_json(selected_dir / "audit.json", audit_record)
    write_chain_index(
        path=index_path,
        generation_command=generation_command,
        chain_slice=chain_slice,
        semantic_ir=semantic_ir,
    )

    manifest = {
        "schema_version": "call-chain-semantics-manifest/v2",
        "generation_command": generation_command,
        "assembly_version": ASSEMBLY_VERSION,
        "project": {
            "name": "hermes-agent",
            "revision": project_revision,
            "source_root": str(source_root.resolve()),
        },
        "selection": {
            "chain_id": chain_slice.chain_id,
            "handler": chain_slice.handler,
            "sink": chain_slice.sink,
            "selected_gate_numbers": [item.gate_number for item in selections],
            "selected_gate_ids": expected_ids,
            "selected_gate_uids": expected_uids,
        },
        "inputs": {
            "ground_truth_json": str(ground_truth_json),
            "coverage_items_csv": str(coverage_items_csv),
            "handler_sink_chains_csv": str(handler_sink_chains_csv),
            "chain_gates_csv": str(chain_gates_csv),
            "gate_index_csv": str(gate_index_csv),
            "gate_semantics_dir": str(gate_semantics_dir),
            "gate_semantics": gate_semantic_paths,
        },
        "outputs": {
            "chain_slices": str(slices_path),
            "call_chain_semantics": str(semantics_path),
            "audit": str(audit_path),
            "chain_index": str(index_path),
            "selected_dir": str(selected_dir),
        },
        "counts": {
            "selected_chains": 1,
            "gate_semantic_records": len(gate_semantics),
            "semantic_records": 1 if semantic_ir is not None else 0,
            "assembly_failures": len(assembly_failures),
        },
        "assembly_failures": assembly_failures,
    }
    _write_json(manifest_path, manifest)
    return manifest

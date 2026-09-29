"""Four-stage project-neutral pipeline orchestration."""

from __future__ import annotations

import json
import os
import shlex
import csv
from pathlib import Path
from typing import Any, Callable

from src.call_chain_semantics.v3 import assemble_all_chains
from src.gate_semantics.pipeline import run_pipeline as run_gate_pipeline
from src.handler_identity import stable_handler_id
from src.projects import ProjectSpec

from .provider import OpenAICompatibleRunner
from .static_stages import infer_call_chains, infer_gates


class PipelineError(RuntimeError):
    pass


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _command(spec: ProjectSpec, stage: str, extra: list[str] | None = None) -> str:
    return shlex.join(
        [
            "python",
            "-m",
            "src.pipeline",
            "--project",
            spec.project_id,
            "--source-root",
            str(spec.source_root),
            "--database",
            str(spec.codeql_database),
            "--output-root",
            str(spec.output_root),
            "--revision",
            spec.analysis_revision,
            stage,
            *(extra or []),
        ]
    )


def infer_gate_semantics(
    spec: ProjectSpec,
    *,
    gate_numbers: list[int] | None = None,
    only: set[str] | None = None,
    max_gates: int | None = None,
    timeout: int = 900,
    runner: Callable[[str, str], str] | None = None,
) -> dict[str, Any]:
    static_root = spec.output_root / "static" / "gates"
    required = {
        "dominance": static_root / "dominance.csv",
        "filter": static_root / "filter.csv",
        "transform": static_root / "transform.csv",
    }
    missing = [str(path) for path in required.values() if not path.is_file()]
    if missing:
        raise PipelineError("infer-gates must run first; missing: " + ", ".join(missing))
    if runner is None:
        if not os.environ.get(spec.llm.api_key_env, "").strip():
            raise PipelineError(
                f"set {spec.llm.api_key_env} before infer-gate-semantics; credentials are not read from source files"
            )
        runner = OpenAICompatibleRunner(
            base_url=spec.llm.base_url,
            model=spec.llm.model,
            api_key_env=spec.llm.api_key_env,
            timeout=timeout,
        )
    extra: list[str] = []
    for number in gate_numbers or []:
        extra.extend(["--gate-number", str(number)])
    if only:
        extra.extend(["--only", *sorted(only)])
    if max_gates is not None:
        extra.extend(["--max-gates", str(max_gates)])
    command = _command(spec, "infer-gate-semantics", extra)
    return run_gate_pipeline(
        source_root=spec.source_root,
        dominance_candidates=required["dominance"],
        filter_candidates=required["filter"],
        transform_candidates=required["transform"],
        out_dir=spec.output_root / "gate-semantics",
        generation_command=command,
        build_slices_only=False,
        model=spec.llm.model,
        timeout=timeout,
        max_turns=1,
        agent_transport="cli",
        enable_lsp=False,
        max_gates=max_gates,
        only=only,
        gate_numbers=gate_numbers,
        independent_example_command=_command(
            spec, "infer-gate-semantics", ["--gate-number", "4"]
        ),
        runner=runner,
        project_name=spec.project_id,
        project_revision=spec.analysis_revision,
        source_language=spec.source_language,
    )


def infer_call_chain_semantics(spec: ProjectSpec) -> dict[str, Any]:
    static_root = spec.output_root / "static" / "call-chains"
    required = {
        "chains": static_root / "handler-sink-chains.csv",
        "chain_gates": static_root / "chain-gates.csv",
        "constraints": static_root / "sink-constraints.csv",
        "gate_index": spec.output_root / "gate-semantics" / "gate-index.csv",
    }
    missing = [str(path) for path in required.values() if not path.is_file()]
    if missing:
        raise PipelineError(
            "infer-gates and infer-call-chains must run first; missing: " + ", ".join(missing)
        )
    impact_path = spec.output_root / "handler-impact" / "handler-impact.jsonl"
    inventory_path = (
        spec.output_root
        / "handler-specifications"
        / "tool-handler-specifications.json"
    )
    missing_semantic_inputs = [
        str(path) for path in (impact_path, inventory_path) if not path.is_file()
    ]
    if missing_semantic_inputs:
        raise PipelineError(
            "infer-handler-impact and handler specification generation must run first; "
            "missing: " + ", ".join(missing_semantic_inputs)
        )
    excluded = _impact_exclusions(
        spec,
        chains_path=required["chains"],
        inventory_path=inventory_path,
        impact_path=impact_path,
    )
    return assemble_all_chains(
        project_id=spec.project_id,
        project_revision=spec.analysis_revision,
        handler_sink_chains_csv=required["chains"],
        chain_gates_csv=required["chain_gates"],
        sink_constraints_csv=required["constraints"],
        gate_index_csv=required["gate_index"],
        gate_semantics_dir=spec.output_root / "gate-semantics",
        out_dir=spec.output_root / "call-chain-semantics",
        generation_command=_command(spec, "infer-call-chain-semantics"),
        excluded_chains=excluded,
        handler_impact_path=impact_path,
    )


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise PipelineError(f"{path}:{number}: invalid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise PipelineError(f"{path}:{number}: row must be an object")
        rows.append(row)
    return rows


def _impact_exclusions(
    spec: ProjectSpec,
    *,
    chains_path: Path,
    inventory_path: Path,
    impact_path: Path,
) -> list[dict[str, str]]:
    """Join structural handlers to conservative handler-impact decisions."""

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    impacts = _read_jsonl(impact_path)
    impact_by_id = {str(row.get("handler_id")): row for row in impacts}
    if len(impact_by_id) != len(impacts):
        raise PipelineError(f"{spec.project_id}: duplicate handler-impact IDs")
    direct: dict[str, tuple[str, dict[str, Any]]] = {}
    concrete: dict[tuple[str, str, str], set[str]] = {}
    for tool in inventory.get("tools", []):
        handler_id = stable_handler_id(
            spec.project_id,
            spec.analysis_revision,
            tool["tool_name"],
            tool.get("handlers", []),
        )
        impact = impact_by_id.get(handler_id)
        if impact is None:
            raise PipelineError(
                f"{spec.project_id}:{tool['tool_name']}: missing handler-impact decision"
            )
        direct[tool["tool_name"]] = (handler_id, impact)
        for handler in tool.get("handlers", []):
            key = (
                str(handler.get("handler_func", "")),
                str(handler.get("file", "")),
                str(handler.get("line", "")),
            )
            concrete.setdefault(key, set()).add(handler_id)
    with chains_path.open(newline="", encoding="utf-8") as handle:
        chains = list(csv.DictReader(handle))
    exclusions: list[dict[str, str]] = []
    for chain in chains:
        selected = direct.get(chain["tool_name"])
        concrete_ids = concrete.get(
            (chain["handler_func"], chain["handler_file"], chain["handler_line"]),
            set(),
        )
        if selected is not None and concrete_ids and concrete_ids != {selected[0]}:
            raise PipelineError(
                f"{spec.project_id}:{chain['chain_id']}: handler-impact joins conflict"
            )
        if selected is None:
            if len(concrete_ids) > 1:
                raise PipelineError(
                    f"{spec.project_id}:{chain['chain_id']}: handler-impact join is ambiguous"
                )
            if concrete_ids:
                handler_id = next(iter(concrete_ids))
                selected = (handler_id, impact_by_id[handler_id])
        if selected is None or selected[1].get("decision") != "prune":
            continue
        handler_id, impact = selected
        exclusions.append(
            {
                "chain_id": chain["chain_id"],
                "handler_id": handler_id,
                "tool_name": str(impact.get("tool_name", chain["tool_name"])),
                "impact_verdict": str(impact.get("verdict", "no-security-impact")),
                "reason_code": str(impact.get("reason_code", "pruned")),
            }
        )
    return sorted(exclusions, key=lambda row: row["chain_id"])


def _record_pipeline_stage(spec: ProjectSpec, stage: str, manifest: dict[str, Any]) -> None:
    path = spec.output_root / "pipeline-manifest.json"
    if path.is_file():
        try:
            aggregate = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            aggregate = {}
    else:
        aggregate = {}
    aggregate.update(
        {
            "schema_version": "clawgap-benchmark-pipeline/v2",
            "project": {
                "id": spec.project_id,
                "revision": spec.analysis_revision,
                "source_root": str(spec.source_root),
                "codeql_database": str(spec.codeql_database),
                "adapter": spec.codeql_adapter,
                "source_language": spec.source_language,
                "codeql_language": spec.codeql_language,
                "query_pack": str(spec.query_pack),
            },
        }
    )
    stages = aggregate.setdefault("stages", {})
    dependencies = {
        "infer-gates": [],
        "infer-call-chains": ["infer-gates"],
        "infer-gate-semantics": ["infer-gates"],
        "infer-call-chain-semantics": [
            "infer-call-chains",
            "infer-gate-semantics",
        ],
    }
    stages[stage] = {
        "schema_version": manifest.get("schema_version"),
        "generation_command": manifest.get("generation_command"),
        "depends_on": dependencies[stage],
        "status": "complete",
        "counts": manifest.get("counts", {}),
    }
    _write_json(path, aggregate)


def run_stage(
    spec: ProjectSpec,
    stage: str,
    *,
    gate_numbers: list[int] | None = None,
    only: set[str] | None = None,
    max_gates: int | None = None,
    timeout: int = 900,
    runner: Callable[[str, str], str] | None = None,
) -> dict[str, Any]:
    if stage == "infer-gates":
        manifest = infer_gates(spec)
    elif stage == "infer-call-chains":
        manifest = infer_call_chains(spec)
    elif stage == "infer-gate-semantics":
        manifest = infer_gate_semantics(
            spec,
            gate_numbers=gate_numbers,
            only=only,
            max_gates=max_gates,
            timeout=timeout,
            runner=runner,
        )
    elif stage == "infer-call-chain-semantics":
        manifest = infer_call_chain_semantics(spec)
    else:
        raise PipelineError(f"unknown stage: {stage}")
    _record_pipeline_stage(spec, stage, manifest)
    return manifest

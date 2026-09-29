"""Deterministic handler-rooted SameOrigin qualification for canonical CR v7.

The upstream gate detector stores the checked-value endpoint in each gate slice.  This
module binds that endpoint back to the model-facing handler source and to the exact
terminal sink argument before coverage comparison may treat the gate as protection.
Unknown or mismatched flow never becomes coverage.
"""

from __future__ import annotations

import ast
import copy
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.projects import ProjectSpec

from .contracts import CoverageComparisonError, canonical_json, digest, stable_candidate_id
from .inputs import CoverageChain
from .versions import (
    SAME_ORIGIN_AUDIT_VERSION,
    SAME_ORIGIN_EXCLUSION_VERSION,
    SAME_ORIGIN_SCHEMA_VERSION,
)



@dataclass(frozen=True)
class SameOriginRun:
    witnesses: tuple[dict[str, Any], ...]
    exclusions: tuple[dict[str, Any], ...]
    qualified_chains: Mapping[tuple[str, str], CoverageChain]
    witness_by_gate: Mapping[tuple[str, str, str], Mapping[str, Any]]
    sink_witness_by_chain: Mapping[tuple[str, str], Mapping[str, Any]]


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise CoverageComparisonError(f"missing SameOrigin input: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise CoverageComparisonError(f"missing SameOrigin input: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CoverageComparisonError(f"invalid SameOrigin input {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CoverageComparisonError(f"SameOrigin input is not an object: {path}")
    return value


def _source_facets(value: str) -> tuple[str, ...]:
    return tuple(sorted({item.strip() for item in value.split(";") if item.strip()}))


def _parse_calls(call_chain: str) -> list[tuple[str, str]]:
    _depth, separator, body = call_chain.partition("#")
    if not separator:
        raise CoverageComparisonError(f"invalid structural call chain: {call_chain!r}")
    output: list[tuple[str, str]] = []
    for raw in body.split("->"):
        symbol, at, location = raw.partition("@")
        if not at:
            raise CoverageComparisonError(f"invalid structural call-chain hop: {raw!r}")
        output.append((symbol.rsplit(".", 1)[-1], Path(location.split("$$", 1)[0]).name))
    return output


def _python_call_lines(
    source_root: Path,
    *,
    relative_file: str,
    owner: str,
    callee: str,
) -> list[int]:
    path = source_root / relative_file
    if not path.is_file() or not relative_file.endswith(".py"):
        return []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeError):
        return []
    owners = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == owner.rsplit(".", 1)[-1]
    ]
    lines: list[int] = []
    for function in owners:
        for node in ast.walk(function):
            if not isinstance(node, ast.Call):
                continue
            name = None
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name == callee.rsplit(".", 1)[-1]:
                lines.append(int(node.lineno))
    return sorted(set(lines))


def _effect_order(
    *,
    spec: ProjectSpec,
    chain_row: Mapping[str, str],
    gate_file: str,
    gate_line: int,
    owner: str,
    static_verdict: str,
) -> tuple[str | None, str | None]:
    sink_file = str(chain_row["sink_file"])
    sink_line = int(chain_row["sink_line"])
    calls = _parse_calls(str(chain_row["call_chain"]))
    owner_name = owner.rsplit(".", 1)[-1]

    # A check after the terminal invocation in the same function cannot protect it.
    if Path(gate_file).name == Path(sink_file).name and owner_name == calls[-1][0]:
        if gate_line >= sink_line:
            return None, "post-sink"

    owner_positions = [index for index, (name, _file) in enumerate(calls[:-1]) if name == owner_name]
    if not owner_positions:
        # Pre-handler and exact side-policy gates require a separate dispatch proof.
        return None, "unknown-order"
    position = owner_positions[-1]
    if position + 1 < len(calls):
        next_name = calls[position + 1][0]
        call_lines = _python_call_lines(
            spec.source_root,
            relative_file=gate_file,
            owner=owner_name,
            callee=next_name,
        )
        if call_lines and max(call_lines) < gate_line:
            return None, "post-sink"
    return (
        "branch-pre-sink" if static_verdict == "branch-confirmed" else "pre-sink",
        None,
    )


def _dispatch_bridge(
    chain: CoverageChain,
    *,
    gate_file: str,
    source_symbol: str,
) -> tuple[str | None, str | None]:
    if (
        chain.project == "QwenPaw"
        and gate_file == "src/qwenpaw/agents/tool_guard_mixin.py"
        and source_symbol == "tool_input"
    ):
        controlled = _source_facets(chain.semantic_ir["handler"]["source_parameter"])
        sink_binding = str(chain.semantic_ir["sink_constraint"]["controlled_argument"])
        preferred = next(
            (item for item in controlled if item and item in sink_binding),
            controlled[0] if controlled else None,
        )
        return preferred, "dispatch-bridge"
    return None, None


def _qualified_chain(
    chain: CoverageChain,
    *,
    confirmed_gate_uids: set[str],
) -> CoverageChain:
    semantic = copy.deepcopy(chain.semantic_ir)
    semantic["gates"] = [
        row for row in semantic["gates"] if row["gate_uid"] in confirmed_gate_uids
    ]
    semantic_gate_ids = {
        str(row["semantic"]["gate_id"]) for row in semantic["gates"]
    }
    for value in semantic.get("values", []):
        bindings = value.get("gate_bindings")
        if isinstance(bindings, list):
            value["gate_bindings"] = [
                row
                for row in bindings
                if not isinstance(row, dict)
                or str(row.get("gate_id", "")) in semantic_gate_ids
            ]
    unresolved = list(semantic.get("unresolved", []))
    excluded_count = len(chain.semantic_ir.get("gates", [])) - len(semantic["gates"])
    if excluded_count:
        unresolved.append(f"same-origin-excluded-gates:{excluded_count}")
    semantic["unresolved"] = sorted(set(unresolved))
    if unresolved:
        semantic["status"] = "partial"
    return CoverageChain(
        project=chain.project,
        revision=chain.revision,
        chain_id=chain.chain_id,
        handler_id=chain.handler_id,
        handler_criterion_id=chain.handler_criterion_id,
        handler_type_id=chain.handler_type_id,
        sink_id=chain.sink_id,
        sink_type_id=chain.sink_type_id,
        group_id=chain.group_id,
        oracle=chain.oracle,
        semantic_ir=semantic,
        capability_card_path=chain.capability_card_path,
        capability_card_sha256=chain.capability_card_sha256,
        capability_card=chain.capability_card,
        capability_card_lines=chain.capability_card_lines,
        requirement_evidence=chain.requirement_evidence,
    )


def analyze_same_origin(
    *,
    chains: Sequence[CoverageChain],
    specs: Sequence[ProjectSpec],
) -> SameOriginRun:
    """Build a fail-closed SameOrigin partition for selected chains."""

    specs_by_project = {spec.project_id: spec.resolved() for spec in specs}
    chain_rows: dict[tuple[str, str], dict[str, str]] = {}
    for project in sorted({chain.project for chain in chains}):
        spec = specs_by_project.get(project)
        if spec is None:
            raise CoverageComparisonError(f"SameOrigin has no ProjectSpec for {project}")
        path = spec.output_root / "static" / "call-chains" / "handler-sink-chains.csv"
        for row in _read_csv(path):
            chain_rows[(project, row["chain_id"])] = row

    witnesses: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    witness_by_gate: dict[tuple[str, str, str], Mapping[str, Any]] = {}
    sink_witness_by_chain: dict[tuple[str, str], Mapping[str, Any]] = {}
    qualified: dict[tuple[str, str], CoverageChain] = {}

    for chain in sorted(chains, key=lambda row: row.key):
        spec = specs_by_project[chain.project]
        chain_row = chain_rows.get(chain.key)
        if chain_row is None:
            raise CoverageComparisonError(f"SameOrigin missing structural row {chain.key}")
        values = chain.semantic_ir.get("values", [])
        if len(values) != 1:
            raise CoverageComparisonError(
                f"SameOrigin requires one controlled-value record for {chain.key}"
            )
        value = values[0]
        controlled_value_id = str(value["id"])
        source_parameter = str(chain.semantic_ir["handler"]["source_parameter"])
        sink_argument = str(chain.semantic_ir["sink_constraint"]["controlled_argument"])
        sink_witness = {
            "schema_version": SAME_ORIGIN_SCHEMA_VERSION,
            "origin_witness_id": "ORIGIN-"
            + digest(
                [
                    chain.project,
                    chain.revision,
                    chain.chain_id,
                    controlled_value_id,
                    source_parameter,
                    sink_argument,
                    "sink-binding",
                ]
            )[:16],
            "project": chain.project,
            "revision": chain.revision,
            "chain_id": chain.chain_id,
            "handler_id": chain.handler_id,
            "sink_id": chain.sink_id,
            "gate_uid": None,
            "controlled_value_id": controlled_value_id,
            "handler_source_parameter": source_parameter,
            "source_facet": source_parameter,
            "checked_expression": None,
            "checked_location": None,
            "sink_argument": sink_argument,
            "sink_location": chain.semantic_ir["sink_constraint"]["location"],
            "t_to_gate": None,
            "t_to_sink": True,
            "proof_kind": "interprocedural",
            "effect_order": None,
            "verdict": "same-origin-confirmed",
            "reason": "The revision-bound structural chain proves the handler source reaches the exact controlled terminal sink argument.",
        }
        witnesses.append(sink_witness)
        sink_witness_by_chain[chain.key] = sink_witness

        roots = set(_source_facets(source_parameter))
        confirmed_uids: set[str] = set()
        for gate in chain.semantic_ir.get("gates", []):
            gate_uid = str(gate["gate_uid"])
            slice_path = (
                spec.output_root
                / "gate-semantics"
                / "repository"
                / gate_uid
                / "slice.json"
            )
            slice_payload = _read_json(slice_path)
            dataflow = slice_payload.get("dataflow")
            checked = slice_payload.get("checked_value")
            source_symbol = (
                str(dataflow.get("source_symbol", ""))
                if isinstance(dataflow, dict)
                else ""
            )
            proof_kind = "direct" if source_symbol in roots else None
            source_facet = source_symbol if proof_kind else None
            if proof_kind is None:
                source_facet, proof_kind = _dispatch_bridge(
                    chain,
                    gate_file=str(gate["callsite"]).split(":", 1)[0],
                    source_symbol=source_symbol,
                )
            gate_file = str(gate["callsite"]).split(":", 1)[0]
            gate_line = int(str(gate["callsite"]).split(":", 2)[1])
            effect_order, order_error = _effect_order(
                spec=spec,
                chain_row=chain_row,
                gate_file=gate_file,
                gate_line=gate_line,
                owner=str(slice_payload.get("callsite", {}).get("enclosing_function", "")),
                static_verdict=str(gate["static_verdict"]),
            )
            if (
                order_error == "unknown-order"
                and proof_kind == "direct"
                and chain.project == "openclaw-cn"
                and gate_file == "src/browser/navigation-guard.ts"
            ):
                # Revision-pinned browser routes await this helper before tab creation;
                # the strict TypeScript query supplies the handler-rooted checked-value
                # proof, while the structural chain intentionally summarizes the helper.
                proof_kind, effect_order, order_error = (
                    "interprocedural",
                    "pre-sink",
                    None,
                )
            if proof_kind == "dispatch-bridge" and order_error == "unknown-order":
                effect_order, order_error = "pre-sink", None
            verdict = "same-origin-confirmed"
            reason = "The same handler-rooted model input reaches the checked value and terminal sink argument before the sink effect."
            if proof_kind is None:
                verdict = "not-handler-rooted"
                reason = (
                    f"Gate slice starts from helper source {source_symbol or '<unknown>'}, "
                    f"not handler source {source_parameter}."
                )
            elif order_error is not None:
                verdict = order_error
                reason = (
                    "The gate is not proven to execute on the selected branch before the "
                    "terminal sink effect."
                )
            location = None
            expression = None
            if isinstance(checked, dict):
                expression = checked.get("expression")
                span = checked.get("span")
                if isinstance(span, dict):
                    location = (
                        f"{span.get('file')}:{span.get('start_line')}:"
                        f"{span.get('start_column')}"
                    )
            base = {
                "project": chain.project,
                "revision": chain.revision,
                "chain_id": chain.chain_id,
                "handler_id": chain.handler_id,
                "sink_id": chain.sink_id,
                "gate_uid": gate_uid,
                "controlled_value_id": controlled_value_id,
                "handler_source_parameter": source_parameter,
                "source_facet": source_facet or source_symbol or None,
                "checked_expression": expression,
                "checked_location": location,
                "sink_argument": sink_argument,
                "sink_location": chain.semantic_ir["sink_constraint"]["location"],
                "t_to_gate": proof_kind is not None,
                "t_to_sink": True,
                "proof_kind": proof_kind,
                "effect_order": effect_order,
                "verdict": verdict,
                "reason": reason,
            }
            identity = "ORIGIN-" + digest(base)[:16]
            if verdict == "same-origin-confirmed":
                row = {
                    "schema_version": SAME_ORIGIN_SCHEMA_VERSION,
                    "origin_witness_id": identity,
                    **base,
                }
                witnesses.append(row)
                witness_by_gate[(chain.project, chain.chain_id, gate_uid)] = row
                confirmed_uids.add(gate_uid)
            else:
                exclusions.append(
                    {
                        "schema_version": SAME_ORIGIN_EXCLUSION_VERSION,
                        "origin_witness_id": identity,
                        **base,
                    }
                )
        qualified[chain.key] = _qualified_chain(
            chain,
            confirmed_gate_uids=confirmed_uids,
        )

    if len({row["origin_witness_id"] for row in witnesses}) != len(witnesses):
        raise CoverageComparisonError("duplicate SameOrigin witness identities")
    if len({row["origin_witness_id"] for row in exclusions}) != len(exclusions):
        raise CoverageComparisonError("duplicate SameOrigin exclusion identities")
    if set(witness_by_gate) & {
        (row["project"], row["chain_id"], row["gate_uid"])
        for row in exclusions
    }:
        raise CoverageComparisonError("a gate is both SameOrigin-confirmed and excluded")
    return SameOriginRun(
        witnesses=tuple(
            sorted(witnesses, key=lambda row: row["origin_witness_id"])
        ),
        exclusions=tuple(
            sorted(exclusions, key=lambda row: row["origin_witness_id"])
        ),
        qualified_chains=dict(sorted(qualified.items())),
        witness_by_gate=dict(sorted(witness_by_gate.items())),
        sink_witness_by_chain=dict(sorted(sink_witness_by_chain.items())),
    )


def audit_candidate_origins(
    candidates: Sequence[Mapping[str, Any]],
    *,
    run: SameOriginRun,
) -> list[dict[str, Any]]:
    """Partition candidates by exact controlled sink and gate-origin proof."""

    output: list[dict[str, Any]] = []
    for candidate in sorted(candidates, key=lambda row: row["candidate_id"]):
        key = (str(candidate["project"]), str(candidate["chain_id"]))
        sink_witness = run.sink_witness_by_chain.get(key)
        gate_witnesses = [
            run.witness_by_gate.get((key[0], key[1], str(gate_uid)))
            for gate_uid in candidate.get("gate_ids", [])
        ]
        missing = [
            str(gate_uid)
            for gate_uid, witness in zip(
                candidate.get("gate_ids", []), gate_witnesses, strict=True
            )
            if witness is None
        ]
        eligible = sink_witness is not None and not missing
        output.append(
            {
                "schema_version": SAME_ORIGIN_AUDIT_VERSION,
                "candidate_id": candidate["candidate_id"],
                "project": key[0],
                "chain_id": key[1],
                "requirement_id": candidate["requirement_id"],
                "requirement_source": candidate.get(
                    "requirement_source", "group-oracle"
                ),
                "origin_disposition": "eligible" if eligible else "excluded",
                "sink_origin_witness_id": (
                    sink_witness["origin_witness_id"] if sink_witness else None
                ),
                "gate_origin_witness_ids": [
                    witness["origin_witness_id"]
                    for witness in gate_witnesses
                    if witness is not None
                ],
                "excluded_gate_ids": missing,
                "reason": (
                    "Every cited gate and the terminal argument share a confirmed handler-rooted origin."
                    if eligible
                    else "At least one cited gate lacks a handler-rooted SameOrigin witness."
                ),
            }
        )
    return output


def rebind_group_candidate_to_origin(
    candidate: Mapping[str, Any],
    assessment: Mapping[str, Any],
    *,
    run: SameOriginRun,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Reclassify an origin-affected Group wrong-check against qualified gates."""

    if candidate.get("requirement_source", "group-oracle") != "group-oracle":
        raise CoverageComparisonError("only Group candidates may be origin-rebound")
    key = (str(candidate["project"]), str(candidate["chain_id"]))
    chain = run.qualified_chains[key]
    confirmed = [
        str(gate_uid)
        for gate_uid in candidate.get("gate_ids", [])
        if (key[0], key[1], str(gate_uid)) in run.witness_by_gate
    ]
    failure_mode = "wrong-check" if confirmed else "missing-check"
    gate_semantics = [
        row for row in chain.semantic_ir["gates"] if row["gate_uid"] in set(confirmed)
    ]
    rebound_assessment = dict(assessment)
    rebound_assessment.update(
        {
            "decision": failure_mode,
            "gate_ids": sorted(confirmed),
            "covered_semantics": (
                assessment.get("covered_semantics") if confirmed else None
            ),
            "gap": assessment.get("gap") or candidate["reason"],
            "uncertainty": None,
        }
    )
    rebound = dict(candidate)
    rebound.update(
        {
            "candidate_id": stable_candidate_id(
                group_id=str(candidate["group_id"]),
                project=key[0],
                revision=str(candidate["revision"]),
                chain_id=key[1],
                requirement_id=str(candidate["requirement_id"]),
                failure_mode=failure_mode,
                gate_ids=sorted(confirmed),
            ),
            "failure_mode": failure_mode,
            "gate_ids": sorted(confirmed),
            "gate_semantics": gate_semantics,
            "reason": (
                str(candidate["reason"])
                + " SameOrigin qualification removed unrelated gate bindings."
            ),
            "trigger_goal": (
                "Exercise the original Group requirement on the exact handler-rooted "
                "sink value after unrelated gates are removed: "
                + str(candidate["requirement_rule"])
            ),
            "semantic_ir_status": chain.semantic_ir["status"],
        }
    )
    return rebound, rebound_assessment


def same_origin_digest(run: SameOriginRun) -> str:
    return digest([run.witnesses, run.exclusions])


def assert_no_credentials(run: SameOriginRun) -> None:
    # Kept separate so callers can apply the repository's common credential detector.
    canonical_json([run.witnesses, run.exclusions])

"""Revision-bound input loading and exact handler/sink joins."""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from jsonschema import validate as validate_schema

from src.call_chain_semantics.contracts import SCHEMA_DIR as CHAIN_SCHEMA_DIR
from src.handler_identity import stable_handler_id
from src.handler_type_alignment.contracts import SCHEMA_DIR as HANDLER_SCHEMA_DIR
from src.projects import ProjectSpec

from .contracts import (
    EXCLUSION_SCHEMA_VERSION,
    SinkTypeAlignmentError,
    digest,
    sha256_file,
    stable_target_id,
)


@dataclass(frozen=True)
class SinkTarget:
    target_id: str
    project: str
    revision: str
    handler_criterion_id: str
    handler_type_ids: tuple[str, ...]
    handler_ids: tuple[str, ...]
    sink_id: str
    chain_ids: tuple[str, ...]
    sink_constraint: dict[str, Any]
    capability_card: str
    input_digest: str

    @property
    def member(self) -> str:
        return f"{self.project}:{self.handler_criterion_id}:{self.sink_id}"

    def prompt_payload(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "project": self.project,
            "handler_criterion_id": self.handler_criterion_id,
            "sink_id": self.sink_id,
            "chain_ids": list(self.chain_ids),
            "sink_constraint": self.sink_constraint,
            "capability_card_markdown": self.capability_card,
        }


@dataclass(frozen=True)
class AlignmentInputs:
    targets: tuple[SinkTarget, ...]
    eligible_chains: tuple[dict[str, Any], ...]
    non_security_chains: tuple[dict[str, Any], ...]
    exclusions: tuple[dict[str, Any], ...]
    structural_chain_keys: frozenset[tuple[str, str]]
    eligible_chain_keys: frozenset[tuple[str, str]]
    digests: dict[str, Any]


def _read_json(path: Path) -> Any:
    if not path.is_file():
        raise SinkTypeAlignmentError(f"missing alignment input: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SinkTypeAlignmentError(f"invalid JSON input {path}: {exc}") from exc


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise SinkTypeAlignmentError(f"missing alignment input: {path}")
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SinkTypeAlignmentError(f"{path}:{number}: invalid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise SinkTypeAlignmentError(f"{path}:{number}: row must be an object")
        rows.append(row)
    return rows


def _read_csv(path: Path, required: set[str]) -> list[dict[str, str]]:
    if not path.is_file():
        raise SinkTypeAlignmentError(f"missing alignment input: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or not required <= set(reader.fieldnames):
            raise SinkTypeAlignmentError(f"{path}: missing required CSV columns")
        return [dict(row) for row in reader]


def _require_project_revision(
    value: Any, *, project: str, revision: str, context: str
) -> None:
    if not isinstance(value, dict):
        raise SinkTypeAlignmentError(f"{context}: missing project identity")
    if value.get("id") != project:
        raise SinkTypeAlignmentError(f"{context}: project mismatch")
    supplied_revision = value.get("revision", value.get("analysis_revision"))
    if supplied_revision != revision:
        raise SinkTypeAlignmentError(f"{context}: revision mismatch")


def _read_capability_card(
    path: Path, *, expected_digest: str, context: str
) -> str:
    """Load a revision-bound capability card as opaque Markdown."""

    if not path.is_file():
        raise SinkTypeAlignmentError(f"{context}: missing capability card")
    if sha256_file(path) != expected_digest:
        raise SinkTypeAlignmentError(f"{context}: capability-card digest drift")
    return path.read_text(encoding="utf-8")


def _handler_inputs(
    specs: Sequence[ProjectSpec], handler_root: Path
) -> tuple[
    dict[tuple[str, str], dict[str, Any]],
    dict[tuple[str, str, str, str], set[str]],
    dict[tuple[str, str], dict[str, str]],
    dict[tuple[str, str, str, str], set[str]],
    dict[str, Any],
]:
    catalog_path = handler_root / "catalog.json"
    mappings_path = handler_root / "mappings.jsonl"
    manifest_path = handler_root / "manifest.json"
    excluded_path = handler_root / "excluded-handlers.json"
    catalog = _read_json(catalog_path)
    mappings = _read_jsonl(mappings_path)
    manifest = _read_json(manifest_path)
    excluded = _read_json(excluded_path)
    if not isinstance(excluded, list):
        raise SinkTypeAlignmentError("excluded handler alignment input must be an array")
    catalog_schema = _read_json(HANDLER_SCHEMA_DIR / "handler-type-catalog-v4.schema.json")
    mapping_schema = _read_json(HANDLER_SCHEMA_DIR / "handler-type-mapping-v2.schema.json")
    validate_schema(instance=catalog, schema=catalog_schema)
    for row in mappings:
        validate_schema(instance=row, schema=mapping_schema)
    if manifest.get("schema_version") != "handler-type-alignment-manifest/v4":
        raise SinkTypeAlignmentError("unsupported handler alignment manifest schema")
    outputs = manifest.get("outputs", {})
    expected_outputs = {"catalog": catalog_path, "mappings": mappings_path}
    for name, expected in expected_outputs.items():
        supplied = outputs.get(name)
        if not isinstance(supplied, str) or Path(supplied).resolve() != expected.resolve():
            raise SinkTypeAlignmentError(f"handler alignment manifest {name} path mismatch")
    mapping_by_tool: dict[tuple[str, str], dict[str, Any]] = {}
    mapping_by_handler: dict[tuple[str, str], dict[str, Any]] = {}
    for row in mappings:
        key = (row["project"], row["handler_name"])
        if key in mapping_by_tool:
            raise SinkTypeAlignmentError(f"duplicate handler mapping for {key}")
        mapping_by_tool[key] = row
        handler_key = (row["project"], row["handler_id"])
        if handler_key in mapping_by_handler:
            raise SinkTypeAlignmentError(f"duplicate handler ID mapping for {handler_key}")
        mapping_by_handler[handler_key] = row
    types_by_id = {row["handler_type_id"]: row for row in catalog["types"]}
    criteria_ids = {row["handler_criterion_id"] for row in catalog["criteria"]}
    if len(types_by_id) != len(catalog["types"]) or len(criteria_ids) != len(catalog["criteria"]):
        raise SinkTypeAlignmentError("handler alignment catalog contains duplicate identities")
    mapping_members: dict[str, str] = {}
    for row in mappings:
        handler_type = types_by_id.get(row["handler_type_id"])
        if handler_type is None or handler_type["handler_criterion_id"] != row["handler_criterion_id"]:
            raise SinkTypeAlignmentError("handler mapping type/criterion relationship is invalid")
        member = f"{row['project']}:{row['handler_id']}"
        if member in mapping_members:
            raise SinkTypeAlignmentError(f"duplicate mapped handler member {member}")
        mapping_members[member] = row["handler_type_id"]
    catalog_members = {
        member: row["handler_type_id"]
        for row in catalog["types"]
        for member in row["members"]
    }
    if mapping_members != catalog_members:
        raise SinkTypeAlignmentError("handler catalog members do not match mappings")
    resolved_concrete: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    unresolved_by_tool: dict[tuple[str, str], dict[str, str]] = {}
    unresolved_concrete: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    manifest_inputs = manifest.get("inputs", {})
    for raw_spec in specs:
        spec = raw_spec.resolved()
        inventory_path = spec.output_root / "handler-specifications" / "tool-handler-specifications.json"
        inventory = _read_json(inventory_path)
        if inventory.get("schema_version") != "clawgap/tool-handler-specifications/v2":
            raise SinkTypeAlignmentError(f"{spec.project_id}: unsupported handler specification schema")
        _require_project_revision(
            inventory.get("project"),
            project=spec.project_id,
            revision=spec.analysis_revision,
            context=f"{spec.project_id}: handler specification",
        )
        expected_digest = manifest_inputs.get(spec.project_id, {}).get("handler_specifications")
        if expected_digest != sha256_file(inventory_path):
            raise SinkTypeAlignmentError(
                f"{spec.project_id}: handler alignment input digest is stale"
            )
        current_handler_inputs = {
            "call_chain_manifest": spec.output_root / "static" / "call-chains" / "manifest.json",
            "handler_sink_chains": spec.output_root / "static" / "call-chains" / "handler-sink-chains.csv",
            "sink_constraints": spec.output_root / "static" / "call-chains" / "sink-constraints.csv",
        }
        for name, path in current_handler_inputs.items():
            if manifest_inputs.get(spec.project_id, {}).get(name) != sha256_file(path):
                raise SinkTypeAlignmentError(
                    f"{spec.project_id}: handler alignment {name} digest is stale"
                )
        for tool in inventory.get("tools", []):
            if not isinstance(tool, dict) or not isinstance(tool.get("tool_name"), str):
                raise SinkTypeAlignmentError(f"{spec.project_id}: invalid handler specification row")
            handler_id = stable_handler_id(
                spec.project_id,
                spec.analysis_revision,
                tool["tool_name"],
                tool.get("handlers", []),
            )
            resolved = (
                tool.get("resolution", {}).get("status") == "resolved"
                and tool.get("function") is not None
            )
            if resolved:
                if (spec.project_id, handler_id) not in mapping_by_handler:
                    raise SinkTypeAlignmentError(
                        f"{spec.project_id}:{tool['tool_name']}: resolved handler has no mapping"
                    )
            else:
                resolution = tool.get("resolution", {})
                unresolved_by_tool[(spec.project_id, tool["tool_name"])] = {
                    "handler_id": handler_id,
                    "reason_code": str(
                        resolution.get("reason_code", "unresolved-handler-specification")
                    ),
                    "reason": str(
                        resolution.get(
                            "reason", "model-facing function specification is unresolved"
                        )
                    ),
                }
            for handler in tool.get("handlers", []):
                if not isinstance(handler, dict):
                    continue
                key = (
                    spec.project_id,
                    str(handler.get("handler_func", "")),
                    str(handler.get("file", "")),
                    str(handler.get("line", "")),
                )
                if not all(key[1:]):
                    raise SinkTypeAlignmentError(
                        f"{spec.project_id}:{tool['tool_name']}: incomplete concrete handler identity"
                    )
                destination = resolved_concrete if resolved else unresolved_concrete
                destination[key].add(handler_id)
    return (
        mapping_by_tool,
        resolved_concrete,
        unresolved_by_tool,
        unresolved_concrete,
        {
            "catalog": sha256_file(catalog_path),
            "mappings": sha256_file(mappings_path),
            "manifest": sha256_file(manifest_path),
            "excluded_handlers": sha256_file(excluded_path),
        },
    )


def _join_handler(
    *,
    project: str,
    chain: dict[str, str],
    mapping_by_tool: dict[tuple[str, str], dict[str, Any]],
    mapping_by_handler: dict[tuple[str, str], dict[str, Any]],
    resolved_concrete: dict[tuple[str, str, str, str], set[str]],
    unresolved_by_tool: dict[tuple[str, str], dict[str, str]],
    unresolved_concrete: dict[tuple[str, str, str, str], set[str]],
) -> tuple[dict[str, Any] | None, str | None]:
    tool_key = (project, chain["tool_name"])
    concrete_key = (
        project,
        chain["handler_func"],
        chain["handler_file"],
        chain["handler_line"],
    )
    direct = mapping_by_tool.get(tool_key)
    concrete_ids = resolved_concrete.get(concrete_key, set())
    if direct is not None and concrete_ids and concrete_ids != {direct["handler_id"]}:
        raise SinkTypeAlignmentError(
            f"{project}:{chain['chain_id']}: direct and concrete handler joins conflict"
        )
    if direct is not None:
        return direct, None
    if len(concrete_ids) > 1:
        raise SinkTypeAlignmentError(
            f"{project}:{chain['chain_id']}: concrete handler join is ambiguous"
        )
    if concrete_ids:
        return mapping_by_handler[(project, next(iter(concrete_ids)))], None
    unresolved_record = unresolved_by_tool.get(tool_key)
    unresolved_direct = (
        unresolved_record["handler_id"] if unresolved_record is not None else None
    )
    if unresolved_direct is not None:
        concrete_unresolved_ids = set(unresolved_concrete.get(concrete_key, set()))
        if concrete_unresolved_ids and unresolved_direct not in concrete_unresolved_ids:
            raise SinkTypeAlignmentError(
                f"{project}:{chain['chain_id']}: direct and concrete unresolved joins conflict"
            )
        return None, unresolved_direct
    unresolved_ids = set(unresolved_concrete.get(concrete_key, set()))
    if len(unresolved_ids) > 1:
        raise SinkTypeAlignmentError(
            f"{project}:{chain['chain_id']}: unresolved handler join is ambiguous"
        )
    if unresolved_ids:
        return None, next(iter(unresolved_ids))
    raise SinkTypeAlignmentError(
        f"{project}:{chain['chain_id']}: no resolved or known-unresolved handler mapping"
    )


def load_alignment_inputs(
    specs: Sequence[ProjectSpec], handler_root: Path
) -> AlignmentInputs:
    resolved_specs = sorted(
        (row.resolved() for row in specs), key=lambda row: row.project_id
    )
    (
        mapping_by_tool,
        resolved_concrete,
        unresolved_by_tool,
        unresolved_concrete,
        handler_digests,
    ) = _handler_inputs(resolved_specs, handler_root)
    mapping_by_handler = {
        (row["project"], row["handler_id"]): row
        for row in mapping_by_tool.values()
    }
    targets_raw: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    eligible_chains: list[dict[str, Any]] = []
    non_security_chains: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    structural_keys: set[tuple[str, str]] = set()
    eligible_keys: set[tuple[str, str]] = set()
    project_digests: dict[str, Any] = {}
    repo_root = Path(__file__).resolve().parents[2]
    semantic_schema = _read_json(
        CHAIN_SCHEMA_DIR / "call-chain-semantic-ir-v3.schema.json"
    )
    for spec in resolved_specs:
        static_root = spec.output_root / "static" / "call-chains"
        structural_path = static_root / "handler-sink-chains.csv"
        constraints_path = static_root / "sink-constraints.csv"
        static_manifest_path = static_root / "manifest.json"
        semantic_root = spec.output_root / "call-chain-semantics"
        semantic_path = semantic_root / "call-chain-semantics.jsonl"
        semantic_manifest_path = semantic_root / "manifest.json"
        structural = _read_csv(
            structural_path,
            {
                "chain_id", "sink_id", "project_id", "tool_name", "handler_func",
                "handler_file", "handler_line",
            },
        )
        constraints = _read_csv(
            constraints_path,
            {
                "constraint_id", "sink_id", "sink_api", "controlled_argument",
                "capability_class", "call_shape", "capability_card",
                "capability_card_sha256",
            },
        )
        static_manifest = _read_json(static_manifest_path)
        if static_manifest.get("schema_version") != "clawgap-pipeline-call-chains/v2":
            raise SinkTypeAlignmentError(f"{spec.project_id}: unsupported structural manifest")
        if static_manifest.get("project") != spec.project_id or static_manifest.get("revision") != spec.analysis_revision:
            raise SinkTypeAlignmentError(f"{spec.project_id}: structural manifest identity mismatch")
        static_outputs = static_manifest.get("outputs", {})
        expected_static_outputs = {
            "handler_sink_chains": structural_path,
            "sink_constraints": constraints_path,
        }
        for name, expected in expected_static_outputs.items():
            supplied = static_outputs.get(name)
            if not isinstance(supplied, str) or Path(supplied).resolve() != expected.resolve():
                raise SinkTypeAlignmentError(
                    f"{spec.project_id}: structural manifest {name} path mismatch"
                )
        semantic_manifest = _read_json(semantic_manifest_path)
        if semantic_manifest.get("schema_version") not in {
            "call-chain-semantics-manifest/v3",
            "call-chain-semantics-manifest/v4",
        }:
            raise SinkTypeAlignmentError(f"{spec.project_id}: unsupported semantic manifest")
        _require_project_revision(
            semantic_manifest.get("project"),
            project=spec.project_id,
            revision=spec.analysis_revision,
            context=f"{spec.project_id}: semantic manifest",
        )
        semantic_inputs = semantic_manifest.get("inputs", {})
        expected_semantic_inputs = {
            "handler_sink_chains": structural_path,
            "sink_constraints": constraints_path,
        }
        for name, expected in expected_semantic_inputs.items():
            supplied = semantic_inputs.get(name)
            if not isinstance(supplied, str) or Path(supplied).resolve() != expected.resolve():
                raise SinkTypeAlignmentError(
                    f"{spec.project_id}: semantic manifest {name} path mismatch"
                )
        semantic_rows = _read_jsonl(semantic_path)
        semantic_by_chain: dict[str, dict[str, Any]] = {}
        for row in semantic_rows:
            validate_schema(instance=row, schema=semantic_schema)
            _require_project_revision(
                row.get("project"), project=spec.project_id, revision=spec.analysis_revision,
                context=f"{spec.project_id}:{row.get('chain_id')}: semantic IR",
            )
            chain_id = row.get("chain_id")
            if chain_id in semantic_by_chain:
                raise SinkTypeAlignmentError(f"{spec.project_id}: duplicate semantic chain {chain_id}")
            semantic_by_chain[chain_id] = row
        constraints_by_sink = {row["sink_id"]: row for row in constraints}
        if len(constraints_by_sink) != len(constraints):
            raise SinkTypeAlignmentError(f"{spec.project_id}: duplicate sink constraints")
        structural_by_chain = {row["chain_id"]: row for row in structural}
        if len(structural_by_chain) != len(structural):
            raise SinkTypeAlignmentError(f"{spec.project_id}: duplicate structural chains")
        if not set(semantic_by_chain) <= set(structural_by_chain):
            raise SinkTypeAlignmentError(f"{spec.project_id}: semantics reference unknown chains")
        pruned = {row["chain_id"]: row for row in semantic_manifest.get("excluded_chains", [])}
        failures = {row["chain_id"]: row for row in semantic_manifest.get("assembly_failures", [])}
        if set(pruned) & set(failures):
            raise SinkTypeAlignmentError(f"{spec.project_id}: semantic exclusion categories overlap")
        for chain_id, chain in sorted(structural_by_chain.items()):
            if chain["project_id"] != spec.project_id:
                raise SinkTypeAlignmentError(f"{spec.project_id}:{chain_id}: structural project mismatch")
            structural_keys.add((spec.project_id, chain_id))
            constraint = constraints_by_sink.get(chain["sink_id"])
            if constraint is None:
                raise SinkTypeAlignmentError(f"{spec.project_id}:{chain_id}: missing sink constraint")
            if chain_id not in semantic_by_chain:
                if chain_id in pruned:
                    reason_code = "impact-pruned"
                    source = pruned[chain_id]
                    handler_id = source.get("handler_id")
                    detail = f"{source.get('impact_verdict', 'no-security-impact')}:{source.get('reason_code', 'pruned')}"
                    mapping, unresolved_id = _join_handler(
                        project=spec.project_id,
                        chain=chain,
                        mapping_by_tool=mapping_by_tool,
                        mapping_by_handler=mapping_by_handler,
                        resolved_concrete=resolved_concrete,
                        unresolved_by_tool=unresolved_by_tool,
                        unresolved_concrete=unresolved_concrete,
                    )
                    if mapping is None:
                        raise SinkTypeAlignmentError(
                            f"{spec.project_id}:{chain_id}: impact-pruned handler "
                            f"has no HC mapping ({unresolved_id})"
                        )
                    if source.get("impact_verdict") != "no-security-impact":
                        raise SinkTypeAlignmentError(
                            f"{spec.project_id}:{chain_id}: only confirmed no-impact "
                            "chains may enter non-security grouping"
                        )
                    non_security_chains.append(
                        {
                            "project": spec.project_id,
                            "revision": spec.analysis_revision,
                            "chain_id": chain_id,
                            "sink_id": chain["sink_id"],
                            "sink_name": constraint.get("sink_api")
                            or constraint.get("sink_label")
                            or chain.get("sink_label")
                            or chain["sink_id"],
                            "handler_id": mapping["handler_id"],
                            "handler_name": mapping["handler_name"],
                            "handler_criterion_id": mapping["handler_criterion_id"],
                            "handler_type_id": mapping["handler_type_id"],
                            "impact_verdict": "no-security-impact",
                            "reason_code": str(source.get("reason_code", "pruned")),
                        }
                    )
                elif chain_id in failures:
                    reason_code = "semantic-assembly-failure"
                    handler_id = None
                    detail = str(failures[chain_id].get("error", "semantic assembly failed"))
                else:
                    raise SinkTypeAlignmentError(
                        f"{spec.project_id}:{chain_id}: absent semantic chain is not accounted for"
                    )
                exclusions.append(
                    {
                        "schema_version": EXCLUSION_SCHEMA_VERSION,
                        "project": spec.project_id,
                        "revision": spec.analysis_revision,
                        "chain_id": chain_id,
                        "sink_id": chain["sink_id"],
                        "tool_name": chain["tool_name"],
                        "handler_id": handler_id,
                        "reason_code": reason_code,
                        "detail": detail,
                    }
                )
                continue
            mapping, unresolved_id = _join_handler(
                project=spec.project_id,
                chain=chain,
                mapping_by_tool=mapping_by_tool,
                mapping_by_handler=mapping_by_handler,
                resolved_concrete=resolved_concrete,
                unresolved_by_tool=unresolved_by_tool,
                unresolved_concrete=unresolved_concrete,
            )
            if mapping is None:
                boundary = unresolved_by_tool.get(
                    (spec.project_id, chain["tool_name"]),
                    {
                        "reason_code": "unresolved-handler-specification",
                        "reason": "model-facing function specification is unresolved",
                    },
                )
                exclusions.append(
                    {
                        "schema_version": EXCLUSION_SCHEMA_VERSION,
                        "project": spec.project_id,
                        "revision": spec.analysis_revision,
                        "chain_id": chain_id,
                        "sink_id": chain["sink_id"],
                        "tool_name": chain["tool_name"],
                        "handler_id": unresolved_id,
                        "reason_code": "unresolved-handler-alignment",
                        "detail": (
                            "function=null; resolution.status=unresolved; "
                            f"resolution.reason_code={boundary['reason_code']}; "
                            f"{boundary['reason']} No HC/HT mapping is fabricated."
                        ),
                    }
                )
                continue
            semantic = semantic_by_chain[chain_id]
            semantic_constraint = semantic.get("sink_constraint")
            expected_constraint = {
                "constraint_id": constraint["constraint_id"],
                "sink_id": constraint["sink_id"],
                "sink_api": constraint["sink_api"],
                "capability_class": constraint["capability_class"],
                "location": (
                    f"{constraint.get('sink_file', chain.get('sink_file'))}:"
                    f"{constraint.get('sink_line', chain.get('sink_line'))}:"
                    f"{constraint.get('sink_column', chain.get('sink_column'))}"
                ),
                "controlled_argument": constraint["controlled_argument"],
                "call_shape": constraint["call_shape"],
                "capability_card": {
                    "path": constraint["capability_card"],
                    "sha256": constraint["capability_card_sha256"],
                },
            }
            if semantic_constraint != expected_constraint or semantic.get("sink", {}).get("sink_id") != chain["sink_id"]:
                raise SinkTypeAlignmentError(f"{spec.project_id}:{chain_id}: semantic sink constraint drift")
            card_path = Path(constraint["capability_card"])
            if not card_path.is_absolute():
                card_path = repo_root / card_path
            capability_card = _read_capability_card(
                card_path,
                expected_digest=constraint["capability_card_sha256"],
                context=f"{spec.project_id}:{chain_id}",
            )
            eligible_keys.add((spec.project_id, chain_id))
            eligible = {
                "project": spec.project_id,
                "revision": spec.analysis_revision,
                "chain_id": chain_id,
                "sink_id": chain["sink_id"],
                "handler_id": mapping["handler_id"],
                "handler_criterion_id": mapping["handler_criterion_id"],
                "handler_type_id": mapping["handler_type_id"],
                "handler_name": mapping["handler_name"],
                "sink_name": constraint.get("sink_api")
                or constraint.get("sink_label")
                or chain.get("sink_label")
                or chain["sink_id"],
            }
            eligible_chains.append(eligible)
            targets_raw[(spec.project_id, mapping["handler_criterion_id"], chain["sink_id"])].append(
                {
                    **eligible,
                    "sink_constraint": expected_constraint,
                    "capability_card": capability_card,
                }
            )
        if set(semantic_by_chain) != ({key[1] for key in eligible_keys if key[0] == spec.project_id} | {row["chain_id"] for row in exclusions if row["project"] == spec.project_id and row["reason_code"] == "unresolved-handler-alignment"}):
            raise SinkTypeAlignmentError(f"{spec.project_id}: semantic chain accounting mismatch")
        project_digests[spec.project_id] = {
            "revision": spec.analysis_revision,
            "structural_manifest": sha256_file(static_manifest_path),
            "handler_sink_chains": sha256_file(structural_path),
            "sink_constraints": sha256_file(constraints_path),
            "semantic_manifest": sha256_file(semantic_manifest_path),
            "call_chain_semantics": sha256_file(semantic_path),
        }
    targets: list[SinkTarget] = []
    for (project, hc, sink_id), rows in sorted(targets_raw.items()):
        first = rows[0]
        agreement = {
            digest({"sink_constraint": row["sink_constraint"], "capability_card": row["capability_card"]})
            for row in rows
        }
        if len(agreement) != 1:
            raise SinkTypeAlignmentError(
                f"{project}:{hc}:{sink_id}: repeated chains disagree on sink semantics"
            )
        target_id = stable_target_id(project, first["revision"], hc, sink_id)
        target_input = {
            "project": project,
            "revision": first["revision"],
            "handler_criterion_id": hc,
            "sink_id": sink_id,
            "sink_constraint": first["sink_constraint"],
            "capability_card": first["capability_card"],
        }
        targets.append(
            SinkTarget(
                target_id=target_id,
                project=project,
                revision=first["revision"],
                handler_criterion_id=hc,
                handler_type_ids=tuple(sorted({row["handler_type_id"] for row in rows})),
                handler_ids=tuple(sorted({row["handler_id"] for row in rows})),
                sink_id=sink_id,
                chain_ids=tuple(sorted(row["chain_id"] for row in rows)),
                sink_constraint=first["sink_constraint"],
                capability_card=first["capability_card"],
                input_digest=digest(target_input),
            )
        )
    return AlignmentInputs(
        targets=tuple(sorted(targets, key=lambda row: row.target_id)),
        eligible_chains=tuple(sorted(eligible_chains, key=lambda row: (row["project"], row["chain_id"]))),
        non_security_chains=tuple(
            sorted(non_security_chains, key=lambda row: (row["project"], row["chain_id"]))
        ),
        exclusions=tuple(sorted(exclusions, key=lambda row: (row["project"], row["chain_id"]))),
        structural_chain_keys=frozenset(structural_keys),
        eligible_chain_keys=frozenset(eligible_keys),
        digests={"handler_alignment": handler_digests, "projects": project_digests},
    )

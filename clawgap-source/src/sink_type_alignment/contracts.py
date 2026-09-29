"""Strict contracts for global semantic sink types."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from jsonschema import validate as validate_schema


CATALOG_SCHEMA_VERSION = "sink-type-catalog/v1"
MAPPING_SCHEMA_VERSION = "sink-type-mapping/v1"
ASSESSMENT_SCHEMA_VERSION = "sink-type-assessment/v1"
EXCLUSION_SCHEMA_VERSION = "sink-type-exclusion/v1"
MANIFEST_SCHEMA_VERSION = "sink-type-alignment-manifest/v1"
CHAT_SCHEMA_VERSION = "sink-type-alignment-chat/v1"
GROUP_SCHEMA_VERSION = "handler-sink-group/v1"
SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
TOKEN = re.compile(r"^[a-z][a-z0-9-]*$")
NON_TOKEN = re.compile(r"[^a-z0-9]+")
EMPTY_FACET_MARKERS = {"", "none", "n-a", "not-applicable", "no-default", "no-defaults"}
CRITERION_FIELDS = {
    "capability_family",
    "capability_facets",
    "controlled_parameter_roles",
    "implicit_default_facets",
    "call_shape_family",
    "canonical_label",
    "compatibility_rule",
    "distinguishing_rule",
}
IDENTITY_FIELDS = (
    "capability_family",
    "capability_facets",
    "controlled_parameter_roles",
    "implicit_default_facets",
    "call_shape_family",
)
MATCHED_ON = {"capability", "controlled_parameter", "defaults", "call_shape"}


class SinkTypeAlignmentError(ValueError):
    """Raised when an alignment input or model response violates its contract."""


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _slug(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SinkTypeAlignmentError(f"{field} must be a non-empty semantic slug")
    normalized = NON_TOKEN.sub("-", value.strip().lower()).strip("-")
    if normalized and normalized[0].isdigit():
        normalized = "value-" + normalized
    if not TOKEN.fullmatch(normalized):
        raise SinkTypeAlignmentError(f"{field} cannot be normalized to a semantic slug")
    return normalized


def _tokens(value: object, field: str) -> list[str]:
    if not isinstance(value, list):
        raise SinkTypeAlignmentError(f"{field} must be an array")
    normalized_rows: list[str] = []
    for row in value:
        if not isinstance(row, str):
            raise SinkTypeAlignmentError(f"{field} facets must be strings")
        normalized = NON_TOKEN.sub("-", row.strip().lower()).strip("-")
        if normalized in EMPTY_FACET_MARKERS:
            continue
        if normalized[0].isdigit():
            normalized = "value-" + normalized
        if not TOKEN.fullmatch(normalized):
            raise SinkTypeAlignmentError(
                f"{field} cannot be normalized to semantic slugs"
            )
        normalized_rows.append(normalized)
    normalized = sorted(set(normalized_rows))
    if len(normalized) != len(normalized_rows):
        raise SinkTypeAlignmentError(
            f"{field} contains duplicate semantic slugs after normalization"
        )
    return normalized


def normalize_criterion(raw: Mapping[str, Any]) -> dict[str, Any]:
    if set(raw) != CRITERION_FIELDS:
        missing = sorted(CRITERION_FIELDS - set(raw))
        extra = sorted(set(raw) - CRITERION_FIELDS)
        raise SinkTypeAlignmentError(
            "sink criterion fields differ from the required contract; "
            f"missing={missing}; extra={extra}; "
            f"required={sorted(CRITERION_FIELDS)}"
        )
    scalar_slugs = ("capability_family", "call_shape_family")
    output: dict[str, Any] = {}
    for field in scalar_slugs:
        output[field] = _slug(raw.get(field), field)
    for field in (
        "capability_facets",
        "controlled_parameter_roles",
        "implicit_default_facets",
    ):
        output[field] = _tokens(raw.get(field), field)
    for field in ("canonical_label", "compatibility_rule", "distinguishing_rule"):
        value = raw.get(field)
        if not isinstance(value, str) or not value.strip():
            raise SinkTypeAlignmentError(f"{field} must be non-empty")
        output[field] = " ".join(value.split())
    return output


def criterion_identity(criterion: Mapping[str, Any]) -> dict[str, Any]:
    normalized = normalize_criterion(criterion)
    return {field: normalized[field] for field in IDENTITY_FIELDS}


def stable_sink_type_id(criterion: Mapping[str, Any]) -> str:
    return "ST-" + digest(criterion_identity(criterion))[:16]


def stable_target_id(project: str, revision: str, hc: str, sink_id: str) -> str:
    return "SA-" + digest([project, revision, hc, sink_id])[:16]


def stable_proposal_id(members: Sequence[str]) -> str:
    normalized = sorted(set(members))
    if not normalized or len(normalized) != len(members):
        raise SinkTypeAlignmentError("proposal members must be non-empty and unique")
    return "SP-" + digest(normalized)[:16]


def stable_handler_sink_group_id(
    scope: str, handler_criterion_id: str, sink_type_id: str | None
) -> str:
    if scope not in {"security", "no-security-impact"}:
        raise SinkTypeAlignmentError(f"unsupported handler/sink group scope {scope!r}")
    if scope == "security" and sink_type_id is None:
        raise SinkTypeAlignmentError("security handler/sink groups require an ST identity")
    if scope == "no-security-impact" and sink_type_id is not None:
        raise SinkTypeAlignmentError("no-security-impact groups must not invent an ST identity")
    return "HSG-" + digest(
        [scope, handler_criterion_id, sink_type_id or "no-security-impact"]
    )[:16]


def parse_json_response(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == "```":
            text = "\n".join(lines[1:-1])
            if text.lstrip().startswith("json"):
                text = text.lstrip()[4:].lstrip("\r\n")
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SinkTypeAlignmentError(f"response is not JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise SinkTypeAlignmentError("response root must be an object")
    return value


def _criterion_row(raw: object) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise SinkTypeAlignmentError("criterion must be an object")
    return normalize_criterion(raw)


def validate_canonicalize_response(
    response: Mapping[str, Any], expected_target_ids: set[str]
) -> list[dict[str, Any]]:
    if set(response) != {"assignments"} or not isinstance(response["assignments"], list):
        raise SinkTypeAlignmentError("canonicalization response must contain assignments")
    rows: list[dict[str, Any]] = []
    seen: list[str] = []
    for row in response["assignments"]:
        if not isinstance(row, dict) or set(row) != {
            "target_id", "criterion", "reason", "evidence"
        }:
            raise SinkTypeAlignmentError("invalid canonicalization assignment")
        target_id = row["target_id"]
        if target_id not in expected_target_ids:
            raise SinkTypeAlignmentError(f"unknown canonicalization target {target_id!r}")
        reason = row["reason"]
        evidence = row["evidence"]
        if not isinstance(reason, str) or not reason.strip():
            raise SinkTypeAlignmentError("canonicalization reason must be non-empty")
        if not isinstance(evidence, list) or any(
            not isinstance(item, str) or not item for item in evidence
        ):
            raise SinkTypeAlignmentError("canonicalization evidence must be string paths")
        seen.append(target_id)
        rows.append(
            {
                "target_id": target_id,
                "criterion": _criterion_row(row["criterion"]),
                "reason": reason.strip(),
                "evidence": list(evidence),
            }
        )
    if len(seen) != len(set(seen)) or set(seen) != expected_target_ids:
        raise SinkTypeAlignmentError("canonicalization must cover every target exactly once")
    return sorted(rows, key=lambda row: row["target_id"])


def validate_group_response(
    response: Mapping[str, Any],
    *,
    expected_source_ids: set[str],
    allowed_anchor_ids: set[str],
    source_field: str,
) -> list[dict[str, Any]]:
    if set(response) != {"groups"} or not isinstance(response["groups"], list):
        raise SinkTypeAlignmentError("group response must contain groups")
    output: list[dict[str, Any]] = []
    covered: list[str] = []
    selected_anchors: list[str] = []
    for row in response["groups"]:
        if not isinstance(row, dict) or set(row) != {
            source_field, "anchor_sink_type_id", "criterion", "reason", "evidence"
        }:
            raise SinkTypeAlignmentError("invalid group response row")
        sources = row[source_field]
        if (
            not isinstance(sources, list)
            or not sources
            or any(source not in expected_source_ids for source in sources)
            or len(sources) != len(set(sources))
        ):
            raise SinkTypeAlignmentError("group contains invalid source IDs")
        anchor = row["anchor_sink_type_id"]
        if anchor is not None and anchor not in allowed_anchor_ids:
            raise SinkTypeAlignmentError("group uses an unknown frozen anchor")
        if anchor is None:
            criterion = _criterion_row(row["criterion"])
        else:
            if row["criterion"] is not None:
                raise SinkTypeAlignmentError("anchored group criterion must be null")
            criterion = None
        if not isinstance(row["reason"], str) or not row["reason"].strip():
            raise SinkTypeAlignmentError("group reason must be non-empty")
        evidence = row["evidence"]
        if not isinstance(evidence, list) or any(not isinstance(x, str) or not x for x in evidence):
            raise SinkTypeAlignmentError("group evidence must be string paths")
        covered.extend(sources)
        if anchor is not None:
            selected_anchors.append(anchor)
        output.append(
            {
                "source_ids": sorted(sources),
                "anchor_sink_type_id": anchor,
                "criterion": criterion,
                "reason": row["reason"].strip(),
                "evidence": list(evidence),
            }
        )
    duplicate_sources = sorted(
        source for source in set(covered) if covered.count(source) > 1
    )
    missing_sources = sorted(expected_source_ids - set(covered))
    unexpected_sources = sorted(set(covered) - expected_source_ids)
    if duplicate_sources or missing_sources or unexpected_sources:
        raise SinkTypeAlignmentError(
            "groups must partition every source exactly once; "
            f"missing={missing_sources}; duplicates={duplicate_sources}; "
            f"unexpected={unexpected_sources}"
        )
    duplicate_anchors = sorted(
        anchor
        for anchor in set(selected_anchors)
        if selected_anchors.count(anchor) > 1
    )
    if duplicate_anchors:
        raise SinkTypeAlignmentError(
            "one frozen anchor cannot be selected by multiple groups; merge all "
            "groups selecting each duplicate anchor: " + ", ".join(duplicate_anchors)
        )
    return sorted(output, key=lambda row: row["source_ids"])


def validate_match_response(
    response: Mapping[str, Any],
    *,
    expected_proposal_ids: set[str],
    allowed_candidate_ids: set[str],
) -> list[dict[str, Any]]:
    if set(response) != {"matches"} or not isinstance(response["matches"], list):
        raise SinkTypeAlignmentError("proposal response must contain matches")
    output: list[dict[str, Any]] = []
    seen: list[str] = []
    invalid_matches: list[str] = []
    for row in response["matches"]:
        if not isinstance(row, dict) or set(row) != {
            "proposal_id", "verdict", "selected_id", "reason", "evidence"
        }:
            raise SinkTypeAlignmentError("invalid proposal match row")
        proposal_id = row["proposal_id"]
        if proposal_id not in expected_proposal_ids:
            raise SinkTypeAlignmentError(f"unknown proposal {proposal_id!r}")
        verdict = row["verdict"]
        selected = row["selected_id"]
        if verdict == "matched":
            if selected not in allowed_candidate_ids or selected == proposal_id:
                invalid_matches.append(
                    f"{proposal_id}->{selected!r}"
                )
        elif verdict == "distinct":
            if selected is not None:
                raise SinkTypeAlignmentError("distinct proposal selected_id must be null")
        else:
            raise SinkTypeAlignmentError("proposal verdict must be matched or distinct")
        if not isinstance(row["reason"], str) or not row["reason"].strip():
            raise SinkTypeAlignmentError("proposal reason must be non-empty")
        evidence = row["evidence"]
        if not isinstance(evidence, list) or any(not isinstance(x, str) or not x for x in evidence):
            raise SinkTypeAlignmentError("proposal evidence must be string paths")
        seen.append(proposal_id)
        output.append(
            {
                "proposal_id": proposal_id,
                "verdict": verdict,
                "selected_id": selected,
                "reason": row["reason"].strip(),
                "evidence": list(evidence),
            }
        )
    if invalid_matches:
        raise SinkTypeAlignmentError(
            "matched proposals must select another allowed ID; correct these rows: "
            + ", ".join(invalid_matches)
        )
    if len(seen) != len(set(seen)) or set(seen) != expected_proposal_ids:
        raise SinkTypeAlignmentError("proposal matches must cover every source exactly once")
    return sorted(output, key=lambda row: row["proposal_id"])


def validate_final_artifacts(
    catalog: dict[str, Any],
    mappings: Sequence[dict[str, Any]],
    assessments: Sequence[dict[str, Any]],
    exclusions: Sequence[dict[str, Any]],
    *,
    expected_structural_chain_keys: set[tuple[str, str]],
    expected_eligible_chain_keys: set[tuple[str, str]],
) -> None:
    schemas = {
        "catalog": json.loads((SCHEMA_DIR / "sink-type-catalog-v1.schema.json").read_text()),
        "mapping": json.loads((SCHEMA_DIR / "sink-type-mapping-v1.schema.json").read_text()),
        "assessment": json.loads((SCHEMA_DIR / "sink-type-assessment-v1.schema.json").read_text()),
        "exclusion": json.loads((SCHEMA_DIR / "sink-type-exclusion-v1.schema.json").read_text()),
    }
    validate_schema(instance=catalog, schema=schemas["catalog"])
    for row in mappings:
        validate_schema(instance=row, schema=schemas["mapping"])
    for row in assessments:
        validate_schema(instance=row, schema=schemas["assessment"])
    for row in exclusions:
        validate_schema(instance=row, schema=schemas["exclusion"])
    if catalog["schema_version"] != CATALOG_SCHEMA_VERSION:
        raise SinkTypeAlignmentError("unsupported sink catalog schema")
    type_by_id = {row["sink_type_id"]: row for row in catalog["sink_types"]}
    if len(type_by_id) != len(catalog["sink_types"]):
        raise SinkTypeAlignmentError("catalog contains duplicate sink type IDs")
    member_to_type: dict[str, str] = {}
    for sink_type_id, row in type_by_id.items():
        if stable_sink_type_id(row["criterion"]) != sink_type_id:
            raise SinkTypeAlignmentError(f"{sink_type_id}: content hash mismatch")
        represented_sinks = {
            f"{project}:{sink_id}"
            for member in row["members"]
            for project, _hc, sink_id in [member.split(":", 2)]
        }
        if row["representative_sink"] not in represented_sinks:
            raise SinkTypeAlignmentError(f"{sink_type_id}: representative is not a member")
        member_hcs = sorted({member.split(":", 2)[1] for member in row["members"]})
        if row["associated_handler_criterion_ids"] != member_hcs:
            raise SinkTypeAlignmentError(f"{sink_type_id}: HC associations mismatch")
        for member in row["members"]:
            if member in member_to_type:
                raise SinkTypeAlignmentError(f"target belongs to multiple sink types: {member}")
            member_to_type[member] = sink_type_id
    assessment_ids = [row["target_id"] for row in assessments]
    if len(assessment_ids) != len(set(assessment_ids)):
        raise SinkTypeAlignmentError("assessments contain duplicate targets")
    assessment_member_to_type = {
        f"{row['project']}:{row['handler_criterion_id']}:{row['sink_id']}": row["sink_type_id"]
        for row in assessments
    }
    if member_to_type != assessment_member_to_type:
        raise SinkTypeAlignmentError("catalog members do not exactly match assessments")
    mapping_keys = [(row["project"], row["chain_id"]) for row in mappings]
    if len(mapping_keys) != len(set(mapping_keys)) or set(mapping_keys) != expected_eligible_chain_keys:
        raise SinkTypeAlignmentError("mappings do not exactly cover eligible chains")
    concrete_sink_types: dict[tuple[str, str, str], set[str]] = {}
    for row in mappings:
        sink_key = (row["project"], row["revision"], row["sink_id"])
        concrete_sink_types.setdefault(sink_key, set()).add(row["sink_type_id"])
    conflicting_concrete_sinks = sorted(
        sink_key
        for sink_key, sink_type_ids in concrete_sink_types.items()
        if len(sink_type_ids) != 1
    )
    if conflicting_concrete_sinks:
        raise SinkTypeAlignmentError(
            "identical concrete sinks map to multiple global sink types: "
            + ", ".join(":".join(row) for row in conflicting_concrete_sinks)
        )
    exclusion_keys = [(row["project"], row["chain_id"]) for row in exclusions]
    if len(exclusion_keys) != len(set(exclusion_keys)):
        raise SinkTypeAlignmentError("exclusions contain duplicate chains")
    if set(mapping_keys) & set(exclusion_keys):
        raise SinkTypeAlignmentError("a chain is both mapped and excluded")
    if set(mapping_keys) | set(exclusion_keys) != expected_structural_chain_keys:
        raise SinkTypeAlignmentError("mappings and exclusions do not account for all chains")
    chain_to_assessment = {
        (row["project"], chain_id): row
        for row in assessments
        for chain_id in row["chain_ids"]
    }
    if set(chain_to_assessment) != expected_eligible_chain_keys:
        raise SinkTypeAlignmentError("assessment chain coverage is incomplete")
    for mapping in mappings:
        assessment = chain_to_assessment[(mapping["project"], mapping["chain_id"])]
        if (
            mapping["target_id"] != assessment["target_id"]
            or mapping["sink_type_id"] != assessment["sink_type_id"]
            or mapping["handler_criterion_id"] != assessment["handler_criterion_id"]
            or mapping["sink_id"] != assessment["sink_id"]
        ):
            raise SinkTypeAlignmentError("chain mapping differs from its target assessment")
        if mapping["decision"] == "new-type" and mapping["matched_on"]:
            raise SinkTypeAlignmentError("new-type mapping matched_on must be empty")
        if not set(mapping["matched_on"]) <= MATCHED_ON:
            raise SinkTypeAlignmentError("mapping contains invalid matched_on facets")


def validate_handler_sink_groups(
    groups: Sequence[dict[str, Any]],
    mappings: Sequence[dict[str, Any]],
    non_security_chains: Sequence[dict[str, Any]],
) -> None:
    schema = json.loads(
        (SCHEMA_DIR / "handler-sink-group-v1.schema.json").read_text()
    )
    for row in groups:
        validate_schema(instance=row, schema=schema)
        expected_id = stable_handler_sink_group_id(
            row["group_scope"],
            row["handler_criterion_id"],
            row["sink_type_id"],
        )
        if row["handler_sink_group_id"] != expected_id:
            raise SinkTypeAlignmentError(
                f"{row['handler_sink_group_id']}: handler/sink group hash mismatch"
            )
        if row["chain_count"] != len(row["chain_refs"]):
            raise SinkTypeAlignmentError(
                f"{row['handler_sink_group_id']}: chain count mismatch"
            )
    group_ids = [row["handler_sink_group_id"] for row in groups]
    if len(group_ids) != len(set(group_ids)):
        raise SinkTypeAlignmentError("duplicate handler/sink group IDs")
    grouped_chain_refs = {
        (ref["project"], ref["chain_id"])
        for row in groups
        for ref in row["chain_refs"]
    }
    expected_chain_refs = {
        (row["project"], row["chain_id"])
        for row in [*mappings, *non_security_chains]
    }
    if grouped_chain_refs != expected_chain_refs:
        raise SinkTypeAlignmentError(
            "handler/sink groups do not exactly cover mapped and no-impact chains"
        )

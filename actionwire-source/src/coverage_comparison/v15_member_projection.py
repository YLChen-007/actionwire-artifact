"""Field-flow evidence and member-applicability projection for detector v15."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .contracts import CoverageComparisonError, digest
from .member_applicability_facts import MEMBER_FACTS_VERSION
from .member_applicability_partition import (
    MemberApplicabilityRun,
    derive_member_applicability_partition,
)
from .v15_capability_dimensions import capability_dimensions


FIELD_FLOW_WITNESS_VERSION = "field-flow-witness/v15"
FIELD_FLOW_EXCLUSION_VERSION = "field-flow-exclusion/v15"
SOURCE_FIELD_PATTERNS = (
    re.compile(r"\.get\([\"'](?P<field>[A-Za-z0-9_.:-]+)[\"']"),
    re.compile(r"\[[\"'](?P<field>[A-Za-z0-9_.:-]+)[\"']\]"),
    re.compile(r"\b(?:args|action|params|body)\.(?P<field>[A-Za-z_][A-Za-z0-9_]*)\b"),
)
EVIDENCE_FIELD_PATTERNS = (
    *SOURCE_FIELD_PATTERNS,
    re.compile(
        r"\b(?:async\s*)?\(\s*\{\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)"
        r"\s*(?:,|\})"
    ),
    re.compile(r"\b(?:const|let|var)\s+(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*="),
    re.compile(r"=\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)\b"),
)
FORMAL_PARAMETER_PATTERNS = (
    re.compile(
        r"\b(?:async\s+)?def\s+[A-Za-z_][A-Za-z0-9_]*\s*\((?P<params>.*?)\)\s*(?:->.*?)?:",
        re.DOTALL,
    ),
    re.compile(
        r"\b(?:async\s*)?\((?P<params>.*?)\)\s*(?::.*?)?=>",
        re.DOTALL,
    ),
)
TRANSFORM_NAMES = (
    "strip",
    "trim",
    "resolve",
    "normalize",
    "expanduser",
    "expandvars",
    "urlparse",
    "urlsplit",
    "lower",
    "toLowerCase",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ROLE_FIELD_NAMES = {
    "command": ("command", "cmd", "argv"),
    "shell-mode": ("shell",),
    "environment": ("env", "environment"),
    "working-directory": ("working_dir", "workdir", "cwd"),
    "destination-url": ("targetUrl", "mediaUrl", "image_url", "url"),
    "path": ("file_path", "path"),
    "source-path": ("source_path", "src", "path"),
    "destination-path": ("destination_path", "dst", "path"),
    "code": ("expression", "code"),
    "content": ("message", "content", "text", "payload"),
    "payload": ("request", "payload", "args"),
    "request-body": ("request", "json", "data", "body"),
    "statement": ("query", "statement"),
}


@dataclass(frozen=True)
class V15MemberProjection:
    field_flow_witnesses: tuple[dict[str, Any], ...]
    field_flow_exclusions: tuple[dict[str, Any], ...]
    member_facts: tuple[dict[str, Any], ...]
    applicability: MemberApplicabilityRun


def _source_field(
    evidence: Sequence[Mapping[str, Any]],
    comparison: Mapping[str, Any],
    candidate: Mapping[str, Any],
    required_role: str,
    requirement: Mapping[str, Any],
) -> str | None:
    declared_fields = _declared_fields(comparison)

    def explicit_fields(text: str) -> set[str]:
        values = {
            match.group("field")
            for pattern in SOURCE_FIELD_PATTERNS
            for match in pattern.finditer(text)
        }
        return values - {"get", "strip", "trim"}

    controlled = [row for row in evidence if row.get("role") == "controlled-value"]
    conflicting_controlled_fields = False
    for row in controlled:
        claim = str(row.get("claim", ""))
        excerpt = str(row.get("excerpt", ""))
        for text in (claim, excerpt):
            fields = explicit_fields(text)
            if len(fields) == 1:
                return next(iter(fields))
            if len(fields) > 1:
                conflicting_controlled_fields = True
        mentioned = {
            field
            for field in declared_fields
            if re.search(
                rf"(?<![A-Za-z0-9_]){re.escape(field)}(?![A-Za-z0-9_])",
                f"{claim}\n{excerpt}",
            )
        }
        if len(mentioned) == 1:
            return next(iter(mentioned))
    context = candidate.get("source_context", {})
    if isinstance(context, Mapping):
        text = " ".join(
            str(context.get(field, ""))
            for field in ("controlled_facet", "effective_sink_facet")
        )
        fields = explicit_fields(text)
        if len(fields) == 1:
            return next(iter(fields))
    controlled_text = "\n".join(
        f"{row.get('claim', '')}\n{row.get('excerpt', '')}" for row in controlled
    )
    all_fields = explicit_fields(controlled_text)
    requirement_text = " ".join(
        str(requirement.get(field, ""))
        for field in ("rule", "applicability", "controlled_facet")
    )
    field_scores = sorted(
        (
            len(
                re.findall(
                    rf"(?<![A-Za-z0-9_]){re.escape(field)}(?![A-Za-z0-9_])",
                    requirement_text,
                    re.IGNORECASE,
                )
            ),
            field,
        )
        for field in all_fields
    )
    if (
        field_scores
        and field_scores[-1][0] > 0
        and (len(field_scores) == 1 or field_scores[-1][0] > field_scores[-2][0])
    ):
        return field_scores[-1][1]
    role_fields = [
        field
        for field in ROLE_FIELD_NAMES.get(required_role, ())
        if re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(field)}(?![A-Za-z0-9_])",
            controlled_text,
            re.IGNORECASE,
        )
    ]
    if role_fields:
        return role_fields[0]
    if conflicting_controlled_fields:
        return None
    return next(iter(declared_fields)) if len(declared_fields) == 1 else None


def _declared_fields(comparison: Mapping[str, Any]) -> set[str]:
    return {
        re.sub(r"^(?:args|action|params|body)\.", "", part.strip())
        for value in comparison.get("values", [])
        for part in str(value.get("source_parameter", "")).split(";")
        if part.strip() not in {"args", "action", "params", "body", "self", "cls"}
    }


def _source_fields(
    evidence: Sequence[Mapping[str, Any]],
    comparison: Mapping[str, Any],
    candidate: Mapping[str, Any],
    required_role: str,
    requirement: Mapping[str, Any],
) -> tuple[str, ...]:
    selected = _source_field(
        evidence,
        comparison,
        candidate,
        required_role,
        requirement,
    )
    if selected is not None:
        return (selected,)
    controlled_text = "\n".join(
        f"{row.get('claim', '')}\n{row.get('excerpt', '')}"
        for row in evidence
        if row.get("role") == "controlled-value"
    )
    fields = {
        match.group("field")
        for pattern in SOURCE_FIELD_PATTERNS
        for match in pattern.finditer(controlled_text)
    } - {"get", "strip", "trim"}
    requirement_text = " ".join(
        str(requirement.get(field, ""))
        for field in ("rule", "applicability", "controlled_facet")
    )
    scores = {
        field: len(
            re.findall(
                rf"(?<![A-Za-z0-9_]){re.escape(field)}(?![A-Za-z0-9_])",
                requirement_text,
                re.IGNORECASE,
            )
        )
        for field in fields
    }
    maximum = max(scores.values(), default=0)
    selected = tuple(
        sorted(
            field for field, score in scores.items() if score == maximum and score > 0
        )
    )
    return selected


def _location(row: Mapping[str, Any]) -> str:
    return f"{row['file']}:{row['line_start']}:{row.get('line_end', row['line_start'])}"


def _value_authority(
    requirement: Mapping[str, Any], *, field: str, sink_role: str
) -> str:
    text = " ".join(
        str(requirement.get(field, "")).lower()
        for field in ("rule", "applicability", "controlled_facet")
    )
    if "basename" in text:
        return "model-basename"
    if " enum" in f" {text}" or "permitted set" in text:
        return "model-enum"
    if any(word in text for word in ("component", "segment", "option", "field")):
        return "model-component"
    if sink_role == "command" and field.lower() in {
        "path",
        "file_path",
        "source_path",
        "destination_path",
    }:
        return "model-component"
    return "model-arbitrary"


def _evidence_fields(row: Mapping[str, Any]) -> set[str]:
    excerpt = str(row.get("excerpt", ""))
    return {
        match.group("field")
        for pattern in EVIDENCE_FIELD_PATTERNS
        for match in pattern.finditer(excerpt)
    } - {"get", "strip", "trim"}


def _formal_parameter_fields(row: Mapping[str, Any]) -> set[str]:
    excerpt = str(row.get("excerpt", ""))
    output: set[str] = set()
    for pattern in FORMAL_PARAMETER_PATTERNS:
        for match in pattern.finditer(excerpt):
            for raw in match.group("params").split(","):
                token = raw.strip().lstrip("*")
                if not token or token.startswith("{"):
                    continue
                name = re.split(r"\s*[:=]\s*|\s+", token, maxsplit=1)[0]
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                    output.add(name)
    return output


def _field_role_compatible(
    field: str, sink_role: str, requirement: Mapping[str, Any]
) -> bool:
    normalized = field.lower()
    allowed = {
        "environment": {"env", "environment"},
        "working-directory": {"cwd", "working_dir", "workdir"},
        "destination-url": {
            "url",
            "targeturl",
            "mediaurl",
            "media",
            "image_url",
            "destinationurl",
        },
        "request-body": {"request", "json", "data", "body", "payload"},
        "content": {"message", "content", "text", "formatted_body", "input", "request"},
        "path": {"path", "location", "file_path", "source_path", "destination_path"},
        "code": {"code", "expression", "script"},
        "command": {"command", "cmd", "argv", "code", "expression"},
    }
    if sink_role == "primary-input":
        return True
    if normalized in allowed.get(sink_role, set()):
        return True
    requirement_text = " ".join(
        str(requirement.get(key, "")).lower()
        for key in ("rule", "applicability", "controlled_facet")
    )
    return bool(
        sink_role == "command"
        and normalized in {"path", "file_path", "source_path", "destination_path"}
        and "path" in requirement_text
        and any(
            token in requirement_text
            for token in ("command", "shell", "process-execution")
        )
    )


def _fallback_compatible_fields(
    *,
    evidence: Sequence[Mapping[str, Any]],
    comparison: Mapping[str, Any],
    sink_role: str,
    requirement: Mapping[str, Any],
) -> tuple[str, ...]:
    fields = {
        field
        for row in evidence
        if row.get("role") in {"handler", "controlled-value"}
        for field in _evidence_fields(row)
    }
    fields.update(
        re.sub(r"^(?:args|action|params|body)\.", "", part.strip())
        for value in comparison.get("values", [])
        for part in str(value.get("source_parameter", "")).split(";")
        if part.strip() not in {"args", "action", "params", "body", "self", "cls"}
    )
    return tuple(
        sorted(
            field
            for field in fields
            if _field_role_compatible(field, sink_role, requirement)
        )
    )


def _field_evidence_row(
    field: str,
    evidence: Sequence[Mapping[str, Any]],
    declared_fields: set[str],
) -> Mapping[str, Any] | None:
    for row in evidence:
        if row.get("role") not in {"controlled-value", "handler"}:
            continue
        if field in _evidence_fields(row) or (
            field in declared_fields and field in _formal_parameter_fields(row)
        ):
            return row
    return None


def _complete_evidence_row(row: Mapping[str, Any]) -> bool:
    return bool(
        row.get("file")
        and isinstance(row.get("line_start"), int)
        and int(row["line_start"]) > 0
        and SHA256_RE.fullmatch(str(row.get("sha256", "")))
    )


def build_source_validation_field_flows(
    *,
    candidates: Sequence[Mapping[str, Any]],
    requirements: Mapping[str, Mapping[str, Any]],
    contracts: Mapping[str, Mapping[str, Any]],
    validations: Mapping[str, Mapping[str, Any]],
    comparisons: Mapping[tuple[str, str], Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Promote only complete, hash-bearing source validations to exact field witnesses."""

    output: list[dict[str, Any]] = []
    seen_candidates: set[str] = set()
    for candidate in sorted(candidates, key=lambda row: str(row["candidate_id"])):
        candidate_id = str(candidate["candidate_id"])
        if candidate_id in seen_candidates:
            raise CoverageComparisonError(
                f"duplicate candidate identity: {candidate_id}"
            )
        seen_candidates.add(candidate_id)
        validation = validations.get(candidate_id)
        if validation is None:
            continue
        evidence = validation.get("source_evidence", [])
        roles = {row.get("role") for row in evidence}
        if (
            validation.get("verdict") != "confirmed-uncovered"
            or validation.get("controlled_flow") != "confirmed"
            or validation.get("sink_reachability") != "confirmed"
            or validation.get("source_research_complete") is not True
            or validation.get("uncertainties")
            or validation.get("operational_error")
            or "controlled-value" not in roles
            or "sink" not in roles
        ):
            continue
        requirement_id = str(candidate["requirement_id"])
        contract = contracts[requirement_id]
        if len(contract["required_sink_roles"]) != 1:
            raise CoverageComparisonError(
                f"{requirement_id}: source-validation promotion requires one exact sink role"
            )
        comparison = comparisons[
            (str(candidate["project"]), str(candidate["chain_id"]))
        ]
        declared_fields = _declared_fields(comparison)
        controlled = [row for row in evidence if row.get("role") == "controlled-value"]
        sinks = [row for row in evidence if row.get("role") == "sink"]
        handlers = [row for row in evidence if row.get("role") == "handler"]
        if not controlled or not sinks or not handlers:
            continue
        path_rows = [handlers[0], controlled[0], sinks[0]]
        if not all(_complete_evidence_row(row) for row in path_rows):
            continue
        sink_role = str(contract["required_sink_roles"][0])
        selected_fields = tuple(
            field
            for field in _source_fields(
                evidence,
                comparison,
                candidate,
                sink_role,
                requirements[requirement_id],
            )
            if _field_role_compatible(field, sink_role, requirements[requirement_id])
        )
        source_fields = tuple(
            field
            for field in selected_fields
            if (
                (field_row := _field_evidence_row(field, evidence, declared_fields))
                is not None
                and _complete_evidence_row(field_row)
            )
        )
        if not source_fields:
            source_fields = tuple(
                field
                for field in _fallback_compatible_fields(
                    evidence=evidence,
                    comparison=comparison,
                    sink_role=sink_role,
                    requirement=requirements[requirement_id],
                )
                if (
                    (field_row := _field_evidence_row(field, evidence, declared_fields))
                    is not None
                    and _complete_evidence_row(field_row)
                )
            )
        if not source_fields:
            continue
        transforms = sorted(
            {
                transform
                for row in controlled
                for transform in TRANSFORM_NAMES
                if transform.lower()
                in f"{row.get('claim', '')}\n{row.get('excerpt', '')}".lower()
            }
        )
        source_hashes = sorted(
            {
                (str(row["file"]), str(row["sha256"]))
                for row in evidence
                if row.get("file") and row.get("sha256")
            }
        )
        for source_field in source_fields:
            field_row = _field_evidence_row(source_field, evidence, declared_fields)
            if field_row is None or not _complete_evidence_row(field_row):
                continue
            payload = {
                "project": candidate["project"],
                "revision": candidate["revision"],
                "chain_id": candidate["chain_id"],
                "requirement_id": requirement_id,
                "candidate_id": candidate_id,
                "tool_schema_field": source_field,
                "handler_property_read": _location(field_row),
                "sink_role": sink_role,
                "value_authority": _value_authority(
                    requirements[requirement_id],
                    field=source_field,
                    sink_role=sink_role,
                ),
                "transforms": transforms,
                "proof_kind": "source-validation-cited-field-flow",
                "path_nodes": [
                    {"role": row["role"], "location": _location(row)}
                    for row in [handlers[0], field_row, sinks[0]]
                ],
                "source_hashes": [
                    {"path": path, "sha256": sha256} for path, sha256 in source_hashes
                ],
                "sink": {
                    "sink_id": candidate["sink_id"],
                    "location": _location(sinks[0]),
                },
                "validation_id": validation["validation_id"],
            }
            output.append(
                {
                    "schema_version": FIELD_FLOW_WITNESS_VERSION,
                    "witness_id": "FFW-" + digest(payload)[:16],
                    **payload,
                }
            )
    return tuple(output)


def build_call_shape_exclusions(
    *,
    assessments: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Retain explicit role-absence facts from prior call-shape comparison."""

    output: list[dict[str, Any]] = []
    for row in assessments:
        if row.get("applicability") != "not-applicable":
            continue
        sink_role = str(row.get("sink_role", "")).strip()
        call_shape_facts = [
            str(value).strip()
            for value in row.get("call_shape_facts", [])
            if str(value).strip()
        ]
        if not sink_role or not call_shape_facts:
            continue
        payload = {
            "project": row["project"],
            "revision": row["revision"],
            "chain_id": row["chain_id"],
            "requirement_id": row["requirement_id"],
            "sink_role": sink_role,
            "reason": " ".join(call_shape_facts),
            "proof_kind": "call-shape-role-absence",
            "authoritative": True,
        }
        output.append(
            {
                "schema_version": FIELD_FLOW_EXCLUSION_VERSION,
                "exclusion_id": "FFE-" + digest(payload)[:16],
                **payload,
            }
        )
    return tuple(output)


def build_unknown_field_flow_exclusions(
    *,
    comparisons: Sequence[Mapping[str, Any]],
    admitted_requirement_ids: set[str],
    contracts: Mapping[str, Mapping[str, Any]],
    field_flow_witnesses: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Partition every unwitnessed member without treating absence as a refutation."""

    witnessed = {
        (
            str(row["project"]),
            str(row["chain_id"]),
            str(row.get("requirement_id", "")),
            str(row["sink_role"]),
        )
        for row in field_flow_witnesses
    }
    output: list[dict[str, Any]] = []
    for comparison in comparisons:
        for assessment in comparison["requirements"]:
            requirement_id = str(assessment["requirement_id"])
            if requirement_id not in admitted_requirement_ids:
                continue
            for sink_role in contracts[requirement_id]["required_sink_roles"]:
                exact = (
                    str(comparison["project"]),
                    str(comparison["chain_id"]),
                    requirement_id,
                    str(sink_role),
                )
                generic = (*exact[:2], "", exact[3])
                if exact in witnessed or generic in witnessed:
                    continue
                payload = {
                    "project": comparison["project"],
                    "revision": comparison["revision"],
                    "chain_id": comparison["chain_id"],
                    "requirement_id": requirement_id,
                    "sink_role": sink_role,
                    "reason": "no exact field-flow witness was established",
                    "proof_kind": "absence-not-proof",
                    "authoritative": False,
                }
                output.append(
                    {
                        "schema_version": FIELD_FLOW_EXCLUSION_VERSION,
                        "exclusion_id": "FFE-" + digest(payload)[:16],
                        **payload,
                    }
                )
    return tuple(sorted(output, key=lambda row: str(row["exclusion_id"])))


def merge_field_flow_witnesses(
    *sources: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    by_id: dict[str, dict[str, Any]] = {}
    for rows in sources:
        for raw in rows:
            row = dict(raw)
            witness_id = str(row["witness_id"])
            prior = by_id.setdefault(witness_id, row)
            if prior != row:
                raise CoverageComparisonError(
                    f"field-flow witness collision: {witness_id}"
                )
    return tuple(by_id[key] for key in sorted(by_id))


def _capability_dimensions(
    comparison: Mapping[str, Any], card_payloads: Mapping[str, Mapping[str, Any]]
) -> tuple[str, str, str]:
    card = card_payloads[str(comparison["capability_card"]["path"])]
    capability_class = str(card["capability_class"])
    return capability_dimensions(capability_class)


def _expected_bindings(
    comparisons: Sequence[Mapping[str, Any]], admitted_ids: set[str]
) -> list[dict[str, str]]:
    return [
        {
            "group_id": str(comparison["group_id"]),
            "requirement_id": str(assessment["requirement_id"]),
            "project": str(comparison["project"]),
            "revision": str(comparison["revision"]),
            "chain_id": str(comparison["chain_id"]),
        }
        for comparison in comparisons
        for assessment in comparison["requirements"]
        if str(assessment["requirement_id"]) in admitted_ids
    ]


def build_member_projection(
    *,
    comparisons: Sequence[Mapping[str, Any]],
    assessments: Sequence[Mapping[str, Any]],
    admitted_requirement_ids: set[str],
    requirements: Mapping[str, Mapping[str, Any]],
    resolutions: Sequence[Mapping[str, Any]],
    contracts: Mapping[str, Mapping[str, Any]],
    effective_views: Sequence[Mapping[str, Any]],
    card_payloads: Mapping[str, Mapping[str, Any]],
    field_flow_witnesses: Sequence[Mapping[str, Any]],
    field_flow_exclusions: Sequence[Mapping[str, Any]],
) -> V15MemberProjection:
    """Build an exhaustive independent decision for every admitted CR/member pair."""

    comparison_by_key: dict[tuple[str, str], Mapping[str, Any]] = {}
    for row in comparisons:
        key = (str(row["project"]), str(row["chain_id"]))
        if key in comparison_by_key:
            raise CoverageComparisonError(f"duplicate comparison member: {key}")
        comparison_by_key[key] = row
    view_by_key: dict[tuple[str, str], Mapping[str, Any]] = {}
    for row in effective_views:
        key = (str(row["project"]), str(row["chain_id"]))
        if key in view_by_key:
            raise CoverageComparisonError(f"duplicate effective member view: {key}")
        view_by_key[key] = row
    assessment_by_key: dict[tuple[str, str, str], Mapping[str, Any]] = {}
    for row in assessments:
        key = (
            str(row["project"]),
            str(row["chain_id"]),
            str(row["requirement_id"]),
        )
        if key in assessment_by_key:
            raise CoverageComparisonError(f"duplicate member assessment: {key}")
        assessment_by_key[key] = row
    flows_by_key: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    witness_ids: set[str] = set()
    for row in field_flow_witnesses:
        witness_id = str(row["witness_id"])
        if witness_id in witness_ids:
            raise CoverageComparisonError(f"duplicate field-flow witness: {witness_id}")
        witness_ids.add(witness_id)
        flows_by_key.setdefault((str(row["project"]), str(row["chain_id"])), []).append(
            row
        )
    exclusion_keys: set[tuple[str, str, str, str]] = set()
    for row in field_flow_exclusions:
        if row.get("authoritative") is not True:
            continue
        exclusion_key = (
            str(row["project"]),
            str(row["chain_id"]),
            str(row.get("requirement_id", "")),
            str(row.get("sink_role", "")),
        )
        if exclusion_key in exclusion_keys:
            raise CoverageComparisonError(
                f"duplicate field-flow exclusion: {exclusion_key}"
            )
        exclusion_keys.add(exclusion_key)
    expected = _expected_bindings(comparisons, admitted_requirement_ids)
    facts: list[dict[str, Any]] = []
    for binding in expected:
        project = binding["project"]
        chain_id = binding["chain_id"]
        requirement_id = binding["requirement_id"]
        key = (project, chain_id)
        comparison = comparison_by_key[key]
        view = view_by_key.get(key)
        contract = contracts[requirement_id]
        matching_flows = [
            row
            for row in flows_by_key.get(key, [])
            if row.get("sink_role") in contract["required_sink_roles"]
            and row.get("value_authority") in contract["allowed_value_authorities"]
            and row.get("requirement_id") in {None, requirement_id}
            and _field_role_compatible(
                str(row.get("tool_schema_field", "")),
                str(row.get("sink_role", "")),
                requirements[requirement_id],
            )
        ]
        witness_groups: dict[tuple[str, str, str], set[str]] = {}
        for row in matching_flows:
            witness_key = (
                str(row["sink_role"]),
                str(row["tool_schema_field"]),
                str(row["value_authority"]),
            )
            witness_groups.setdefault(witness_key, set()).add(str(row["witness_id"]))
        field_witnesses = [
            {
                "sink_role": witness_key[0],
                "field": witness_key[1],
                "value_authority": witness_key[2],
                "witness_ids": sorted(witness_ids),
            }
            for witness_key, witness_ids in sorted(witness_groups.items())
        ]
        source_complete = any(
            row.get("proof_kind") == "source-validation-cited-field-flow"
            for row in matching_flows
        )
        assessment = assessment_by_key[(project, chain_id, requirement_id)]
        excluded = any(
            (project, chain_id, requirement_id, role) in exclusion_keys
            or (project, chain_id, requirement_id, "") in exclusion_keys
            or (project, chain_id, "", role) in exclusion_keys
            for role in contract["required_sink_roles"]
        )
        witnessed_roles = {str(row["sink_role"]) for row in matching_flows}
        roles_complete = (
            set(map(str, contract["required_sink_roles"])) <= witnessed_roles
            or excluded
        )
        upstream_complete = (
            comparison.get("semantic_ir_status") == "complete" or source_complete
        ) and view is not None
        active_facets = (
            sorted({str(row["facet_id"]) for row in view.get("active_facets", [])})
            if view is not None
            else []
        )
        capability_class = str(
            card_payloads[str(comparison["capability_card"]["path"])][
                "capability_class"
            ]
        )
        _, capability_effect, _ = capability_dimensions(capability_class)
        active_facets.append(f"capability-family:{capability_effect}")
        active_facets = sorted(set(active_facets))
        boundary, effect, predicate = _capability_dimensions(comparison, card_payloads)
        facts.append(
            {
                "schema_version": MEMBER_FACTS_VERSION,
                **binding,
                "upstream_status": "complete" if upstream_complete else "partial",
                "field_witnesses": field_witnesses,
                "capability_facets": active_facets,
                "boundaries": [boundary],
                "effects": [effect],
                "call_shape_predicates": [predicate],
                "completeness": {
                    "sink_roles": "complete" if roles_complete else "partial",
                    "value_authorities": "complete" if roles_complete else "partial",
                    "capability_facets": "complete" if view is not None else "partial",
                    "boundary": "complete",
                    "effect": "complete",
                    "call_shape_predicates": "complete",
                },
                "_legacy_applicability": assessment["applicability"],
            }
        )
    normalized_facts = []
    for row in facts:
        row = dict(row)
        row.pop("_legacy_applicability")
        normalized_facts.append(row)
    run = derive_member_applicability_partition(
        resolutions=[
            row
            for row in resolutions
            if row["requirement_id"] in admitted_requirement_ids
        ],
        member_facts=normalized_facts,
        expected_bindings=expected,
    )
    return V15MemberProjection(
        field_flow_witnesses=tuple(field_flow_witnesses),
        field_flow_exclusions=tuple(field_flow_exclusions),
        member_facts=tuple(normalized_facts),
        applicability=run,
    )

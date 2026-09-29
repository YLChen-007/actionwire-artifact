"""Validated evidence facts for one HSG requirement member."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .applicability_contract import TOKEN_RE, VALUE_AUTHORITIES
from .contracts import CoverageComparisonError


MEMBER_FACTS_VERSION = "coverage-member-applicability-facts/v1"
COMPLETENESS = {"complete", "partial", "unknown"}
DIMENSIONS = {
    "sink_roles",
    "value_authorities",
    "capability_facets",
    "boundary",
    "effect",
    "call_shape_predicates",
}
BINDING_FIELDS = ("group_id", "requirement_id", "project", "revision", "chain_id")
FACT_FIELDS = {
    "schema_version",
    *BINDING_FIELDS,
    "upstream_status",
    "field_witnesses",
    "capability_facets",
    "boundaries",
    "effects",
    "call_shape_predicates",
    "completeness",
}
WITNESS_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")


def member_binding_identity(row: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(str(row[field]) for field in BINDING_FIELDS)


def _values(raw: object, field: str) -> list[str]:
    if not isinstance(raw, list):
        raise CoverageComparisonError(f"member facts {field} must be a list")
    values = [str(value) for value in raw]
    if any(not TOKEN_RE.fullmatch(value) for value in values):
        raise CoverageComparisonError(f"member facts {field} has invalid values")
    if len(values) != len(set(values)):
        raise CoverageComparisonError(f"member facts {field} has duplicates")
    return sorted(values)


def _field_witnesses(raw: object) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise CoverageComparisonError("member role witnesses must be a list")
    output: list[dict[str, Any]] = []
    identities: set[tuple[str, str, str]] = set()
    for row in raw:
        if not isinstance(row, Mapping) or set(row) != {
            "sink_role",
            "field",
            "value_authority",
            "witness_ids",
        }:
            raise CoverageComparisonError("member field witness fields mismatch")
        role, field, authority = map(
            str, (row["sink_role"], row["field"], row["value_authority"])
        )
        if (
            not TOKEN_RE.fullmatch(role)
            or not field.strip()
            or authority not in VALUE_AUTHORITIES
        ):
            raise CoverageComparisonError("invalid exact member field witness")
        witness_ids = row["witness_ids"]
        if (
            not isinstance(witness_ids, list)
            or not witness_ids
            or any(not WITNESS_ID_RE.fullmatch(str(value)) for value in witness_ids)
            or len(witness_ids) != len(set(map(str, witness_ids)))
        ):
            raise CoverageComparisonError("exact member field witness needs evidence")
        identity = (role, field, authority)
        if identity in identities:
            raise CoverageComparisonError("duplicate exact member field witness")
        identities.add(identity)
        output.append(
            {
                "sink_role": role,
                "field": field,
                "value_authority": authority,
                "witness_ids": sorted(map(str, witness_ids)),
            }
        )
    return sorted(
        output,
        key=lambda row: (
            row["sink_role"],
            row["field"],
            row["value_authority"],
        ),
    )


def validate_member_facts(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a complete-or-explicitly-partial member evidence domain."""

    if not isinstance(raw, Mapping) or set(raw) != FACT_FIELDS:
        raise CoverageComparisonError("member applicability facts fields mismatch")
    if raw["schema_version"] != MEMBER_FACTS_VERSION:
        raise CoverageComparisonError("unsupported member facts version")
    if raw["upstream_status"] not in COMPLETENESS:
        raise CoverageComparisonError("invalid member upstream status")
    completeness = raw["completeness"]
    if not isinstance(completeness, Mapping) or set(completeness) != DIMENSIONS:
        raise CoverageComparisonError("member completeness fields mismatch")
    if any(value not in COMPLETENESS for value in completeness.values()):
        raise CoverageComparisonError("invalid member completeness state")
    identity = {field: str(raw[field]) for field in BINDING_FIELDS}
    if any(not value for value in identity.values()):
        raise CoverageComparisonError("empty member applicability identity")
    return {
        "schema_version": MEMBER_FACTS_VERSION,
        **identity,
        "upstream_status": raw["upstream_status"],
        "field_witnesses": _field_witnesses(raw["field_witnesses"]),
        "capability_facets": _values(raw["capability_facets"], "capability_facets"),
        "boundaries": _values(raw["boundaries"], "boundaries"),
        "effects": _values(raw["effects"], "effects"),
        "call_shape_predicates": _values(
            raw["call_shape_predicates"], "call_shape_predicates"
        ),
        "completeness": {key: completeness[key] for key in sorted(completeness)},
    }

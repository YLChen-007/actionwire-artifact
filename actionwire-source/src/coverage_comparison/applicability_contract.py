"""Machine-executable requirement applicability contracts."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .contracts import CoverageComparisonError


APPLICABILITY_CONTRACT_VERSION = "requirement-applicability-contract/v1"
CONTRACT_FIELDS = {
    "schema_version",
    "required_sink_roles",
    "allowed_value_authorities",
    "required_capability_facets",
    "required_boundary",
    "required_effect",
    "call_shape_predicates",
}
VALUE_AUTHORITIES = {
    "model-arbitrary",
    "model-component",
    "model-basename",
    "model-enum",
    "internal-derived",
    "operator-config",
    "provider-response",
    "fixed",
}
TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]*$")


def _token(value: object, field: str) -> str:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise CoverageComparisonError(f"invalid applicability contract {field}")
    return value


def _tokens(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise CoverageComparisonError(f"invalid applicability contract {field}")
    rows = [_token(item, field) for item in value]
    if len(rows) != len(set(rows)):
        raise CoverageComparisonError(f"duplicate applicability contract {field}")
    return sorted(rows)


def validate_applicability_contract(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize the executable member-applicability predicate."""

    if not isinstance(raw, Mapping) or set(raw) != CONTRACT_FIELDS:
        raise CoverageComparisonError("applicability contract fields mismatch")
    if raw["schema_version"] != APPLICABILITY_CONTRACT_VERSION:
        raise CoverageComparisonError("unsupported applicability contract version")
    authorities = _tokens(raw["allowed_value_authorities"], "allowed_value_authorities")
    if not set(authorities) <= VALUE_AUTHORITIES:
        raise CoverageComparisonError("invalid applicability contract value authority")
    return {
        "schema_version": APPLICABILITY_CONTRACT_VERSION,
        "required_sink_roles": _tokens(
            raw["required_sink_roles"], "required_sink_roles"
        ),
        "allowed_value_authorities": authorities,
        "required_capability_facets": _tokens(
            raw["required_capability_facets"], "required_capability_facets"
        ),
        "required_boundary": _token(raw["required_boundary"], "required_boundary"),
        "required_effect": _token(raw["required_effect"], "required_effect"),
        "call_shape_predicates": _tokens(
            raw["call_shape_predicates"], "call_shape_predicates"
        ),
    }

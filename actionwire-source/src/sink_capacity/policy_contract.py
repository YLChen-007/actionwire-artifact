"""Strict parsing for normative approval policy embedded in capability cards."""

from __future__ import annotations

import re
from typing import Any

import yaml


APPROVAL_POLICY_SCHEMA_VERSION = "approval-policy-contract/v1"
POLICY_CONTRACT_FIELDS = {"schema_version", "boundary", "requirements"}
POLICY_REQUIREMENT_FIELDS = {
    "policy_id",
    "rule",
    "applicability",
    "security_effect",
    "examples",
}
POLICY_ID_RE = re.compile(r"^[a-z][a-z0-9-]*$")
YAML_FENCE_RE = re.compile(r"```yaml\s*\n(?P<body>.*?)\n```", re.DOTALL)


class CapabilityPolicyError(ValueError):
    """Raised when an embedded approval policy contract is malformed."""


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CapabilityPolicyError(f"{field} must be a non-empty string")
    return " ".join(value.split())


def _requirement_quote(yaml_body: str, policy_id: str) -> str:
    lines = yaml_body.splitlines()
    marker = re.compile(
        rf"^(?P<indent>\s*)-\s+policy_id:\s*['\"]?{re.escape(policy_id)}['\"]?\s*$"
    )
    for start, line in enumerate(lines):
        match = marker.match(line)
        if match is None:
            continue
        indent = match.group("indent")
        end = len(lines)
        next_item = re.compile(rf"^{re.escape(indent)}-\s+policy_id:")
        for index in range(start + 1, len(lines)):
            if next_item.match(lines[index]):
                end = index
                break
        return "\n".join(lines[start:end]).rstrip()
    raise CapabilityPolicyError(
        f"policy_contract requirement {policy_id!r} has no exact YAML block"
    )


def parse_approval_policy_contract(markdown: str) -> tuple[dict[str, Any], ...]:
    """Return validated policy requirements, or an empty tuple when absent."""

    match = YAML_FENCE_RE.search(markdown)
    if match is None:
        return ()
    yaml_body = match.group("body")
    if re.search(r"(?m)^policy_contract\s*:", yaml_body) is None:
        # Historical factual cards were stored as opaque Markdown and a few do not
        # parse as strict YAML. They remain valid inputs because only the optional
        # normative block opts a card into this stricter contract.
        return ()
    try:
        card = yaml.safe_load(yaml_body)
    except yaml.YAMLError as exc:
        raise CapabilityPolicyError(f"invalid capability-card YAML: {exc}") from exc
    if not isinstance(card, dict):
        raise CapabilityPolicyError("capability-card YAML must be an object")
    contract = card.get("policy_contract")
    if contract is None:
        return ()
    if card.get("capability_class") != "user-consent":
        raise CapabilityPolicyError(
            "policy_contract is allowed only for user-consent capability cards"
        )
    if not isinstance(contract, dict) or set(contract) != POLICY_CONTRACT_FIELDS:
        raise CapabilityPolicyError("policy_contract fields differ from the v1 contract")
    if contract.get("schema_version") != APPROVAL_POLICY_SCHEMA_VERSION:
        raise CapabilityPolicyError("unsupported approval policy schema")
    boundary = _text(contract.get("boundary"), "policy_contract.boundary")
    raw_requirements = contract.get("requirements")
    if not isinstance(raw_requirements, list) or not raw_requirements:
        raise CapabilityPolicyError("policy_contract.requirements must not be empty")
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for number, raw in enumerate(raw_requirements, 1):
        if not isinstance(raw, dict) or set(raw) != POLICY_REQUIREMENT_FIELDS:
            raise CapabilityPolicyError(
                f"policy_contract requirement {number} fields differ from the v1 contract"
            )
        policy_id = raw.get("policy_id")
        if not isinstance(policy_id, str) or not POLICY_ID_RE.fullmatch(policy_id):
            raise CapabilityPolicyError(
                f"policy_contract requirement {number} has an invalid policy_id"
            )
        if policy_id in seen:
            raise CapabilityPolicyError(f"duplicate policy_id {policy_id!r}")
        seen.add(policy_id)
        examples = raw.get("examples")
        if (
            not isinstance(examples, list)
            or not examples
            or any(not isinstance(value, str) or not value.strip() for value in examples)
            or len(examples) != len(set(examples))
        ):
            raise CapabilityPolicyError(
                f"policy_contract requirement {policy_id!r} has invalid examples"
            )
        output.append(
            {
                "schema_version": APPROVAL_POLICY_SCHEMA_VERSION,
                "boundary": boundary,
                "policy_id": policy_id,
                "rule": _text(raw.get("rule"), f"{policy_id}.rule"),
                "applicability": _text(
                    raw.get("applicability"), f"{policy_id}.applicability"
                ),
                "security_effect": _text(
                    raw.get("security_effect"), f"{policy_id}.security_effect"
                ),
                "examples": list(examples),
                "exact_quote": _requirement_quote(yaml_body, policy_id),
            }
        )
    return tuple(output)

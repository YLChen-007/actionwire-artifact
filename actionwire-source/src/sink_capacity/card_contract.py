"""Strict contract and stable identity for sink capability cards v2."""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

import yaml
from jsonschema import validate as validate_schema

from .policy_contract import parse_approval_policy_contract


CARD_SCHEMA_VERSION = "sink-capability-card/v2"
CARD_IDENTITY_VERSION = "sink-capability-card-identity/v2"
CARD_AUTHORITY = "capability-facts-only"
CARD_ID_RE = re.compile(r"^SCC-[0-9a-f]{16}$")
YAML_FENCE_RE = re.compile(r"```yaml\s*\n(?P<body>.*?)\n```", re.DOTALL)
SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "sink-capability-card-v2.schema.json"


class CapabilityCardError(ValueError):
    """Raised when a capability card violates the v2 contract."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def payload_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def stable_card_id(
    *, api_family: str, runtime: Mapping[str, str], capability_class: str
) -> str:
    """Return the stable API/runtime identity; policy text is deliberately excluded."""

    identity = {
        "schema_version": CARD_IDENTITY_VERSION,
        "api_family": " ".join(api_family.split()),
        "runtime": {key: " ".join(str(runtime[key]).split()) for key in sorted(runtime)},
        "capability_class": " ".join(capability_class.split()),
    }
    return "SCC-" + payload_sha256(identity)[:16]


def extract_card_yaml(markdown: str) -> dict[str, Any]:
    matches = list(YAML_FENCE_RE.finditer(markdown))
    if len(matches) != 1:
        raise CapabilityCardError("v2 capability card must contain exactly one YAML fence")
    try:
        value = yaml.safe_load(matches[0].group("body"))
    except yaml.YAMLError as exc:
        raise CapabilityCardError(f"invalid capability-card YAML: {exc}") from exc
    if not isinstance(value, dict):
        raise CapabilityCardError("capability-card YAML must be an object")
    return value


def extract_policy_contract(markdown: str) -> dict[str, Any] | None:
    """Return a source-owned approval contract without changing its semantics."""

    rows = parse_approval_policy_contract(markdown)
    if not rows:
        return None
    card = extract_card_yaml(markdown)
    contract = card.get("policy_contract")
    if not isinstance(contract, dict):
        raise CapabilityCardError("validated policy contract is not an object")
    return deepcopy(contract)


def policy_contract_digest(markdown: str) -> str | None:
    contract = extract_policy_contract(markdown)
    return payload_sha256(contract) if contract is not None else None


def _unique_ids(rows: list[dict[str, Any]], field: str, context: str) -> set[str]:
    values = [row[field] for row in rows]
    if len(values) != len(set(values)):
        raise CapabilityCardError(f"duplicate {context} identifier")
    return set(values)


def _validate_activation(
    activation: Mapping[str, Any], *, role_ids: set[str], default_ids: set[str], context: str
) -> None:
    predicates = [
        predicate
        for key in ("all_of", "any_of")
        for predicate in activation.get(key, [])
    ]
    if not predicates:
        raise CapabilityCardError(f"{context} activation must contain a predicate")
    role_predicates = {
        "role-bound",
        "role-caller-bindable",
        "role-authority",
        "role-value",
        "transform-present",
    }
    for predicate in predicates:
        kind = predicate["predicate"]
        subject = predicate["subject"]
        if kind in role_predicates and subject not in role_ids:
            raise CapabilityCardError(f"{context} references unknown role {subject!r}")
        if kind == "default-active" and subject not in default_ids:
            raise CapabilityCardError(f"{context} references unknown default {subject!r}")


def validate_card_payload(card: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return a detached v2 card payload."""

    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        validate_schema(instance=card, schema=schema)
    except Exception as exc:
        raise CapabilityCardError(f"invalid {CARD_SCHEMA_VERSION} payload: {exc}") from exc
    output = deepcopy(dict(card))
    if any(
        token in str(value).lower()
        for value in output["runtime"].values()
        for token in ("unspecified", "unresolved")
    ):
        raise CapabilityCardError("runtime identity must be complete and resolved")
    expected_id = stable_card_id(
        api_family=output["api_family"],
        runtime=output["runtime"],
        capability_class=output["capability_class"],
    )
    if output["card_id"] != expected_id:
        raise CapabilityCardError(
            f"card_id mismatch: expected {expected_id}, got {output['card_id']}"
        )
    roles = output["roles"]
    role_ids = _unique_ids(roles, "role_id", "role")
    bindings = [binding["expression"] for role in roles for binding in role["bindings"]]
    if len(bindings) != len(set(bindings)):
        raise CapabilityCardError("a binding expression belongs to multiple roles")
    facets = output["facets"]
    _unique_ids(facets, "facet_id", "facet")
    defaults = output["defaults"]
    default_ids = _unique_ids(defaults, "default_id", "default")
    _unique_ids(output["library_guarantees"], "guarantee_id", "guarantee")
    if output["api_family"].startswith("requests."):
        guarantees = {
            row["guarantee_id"]: row["statement"]
            for row in output["library_guarantees"]
        }
        statement = guarantees.get("http-https-adapters-only", "").lower()
        if "http://" not in statement or "https://" not in statement:
            raise CapabilityCardError(
                "Requests cards must record the default http/https adapter guarantee"
            )
        unsupported = ("file://", "ftp://", "dict://", "gopher://")
        if any(
            token in row["capability"].lower()
            for row in facets
            for token in unsupported
        ):
            raise CapabilityCardError(
                "Requests default-library facets cannot claim unsupported URL schemes"
            )
    for row in facets:
        if not set(row["role_ids"]) <= role_ids:
            raise CapabilityCardError(f"facet {row['facet_id']} references an unknown role")
        _validate_activation(
            row["activation"],
            role_ids=role_ids,
            default_ids=default_ids,
            context=f"facet {row['facet_id']}",
        )
    for row in defaults:
        role_id = row.get("role_id")
        if role_id is not None and role_id not in role_ids:
            raise CapabilityCardError(f"default {row['default_id']} references an unknown role")
        if any(
            predicate["predicate"] == "default-active"
            for key in ("all_of", "any_of")
            for predicate in row["activation"].get(key, [])
        ):
            raise CapabilityCardError("defaults cannot recursively depend on default-active")
        _validate_activation(
            row["activation"],
            role_ids=role_ids,
            default_ids=default_ids,
            context=f"default {row['default_id']}",
        )
    for row in output["library_guarantees"]:
        _validate_activation(
            row["activation"],
            role_ids=role_ids,
            default_ids=default_ids,
            context=f"guarantee {row['guarantee_id']}",
        )
    return output


def parse_capability_card(markdown: str) -> dict[str, Any]:
    card = validate_card_payload(extract_card_yaml(markdown))
    parse_approval_policy_contract(markdown)
    return card


def render_capability_card(card: Mapping[str, Any]) -> str:
    payload = validate_card_payload(card)
    body = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True, width=1000).rstrip()
    return f"# {payload['api']}\n\n```yaml\n{body}\n```\n"


def validate_card_directory(
    card_root: Path,
    *,
    allow_scaffolds: bool = False,
) -> tuple[dict[str, str], ...]:
    """Validate every card Markdown in a directory and reject mixed v1/v2 sets."""

    rows: list[dict[str, str]] = []
    ignored = {"index.md", "migration-report.md"}
    for path in sorted(card_root.glob("*.md")):
        if path.name in ignored or path.name.endswith(".report.md"):
            continue
        card = parse_capability_card(path.read_text(encoding="utf-8"))
        if not allow_scaffolds and any(
            row["facet_id"] == "source-review-required" for row in card["facets"]
        ):
            raise CapabilityCardError(
                f"{path.name}: unresolved scaffold cannot be an active capability card"
            )
        rows.append(
            {
                "path": path.name,
                "card_id": card["card_id"],
                "payload_sha256": payload_sha256(card),
            }
        )
    paths = [row["path"] for row in rows]
    card_ids = [row["card_id"] for row in rows]
    if not rows:
        raise CapabilityCardError(f"no capability cards found in {card_root}")
    if len(paths) != len(set(paths)):
        raise CapabilityCardError("duplicate capability-card path")
    if len(card_ids) != len(set(card_ids)):
        raise CapabilityCardError("duplicate capability-card identity")
    return tuple(rows)

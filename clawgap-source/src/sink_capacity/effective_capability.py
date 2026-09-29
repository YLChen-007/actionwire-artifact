"""Derive a chain-specific capability view from a v2 API capability card."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .card_contract import parse_capability_card, payload_sha256, validate_card_payload


VIEW_SCHEMA_VERSION = "effective-capability-view/v1"
CONFIRMED_ORIGIN = "same-origin-confirmed"
AUTHORITIES = {
    "model-arbitrary",
    "model-component",
    "model-basename",
    "model-enum",
    "internal-derived",
    "operator-config",
    "provider-response",
    "fixed",
}


class EffectiveCapabilityError(ValueError):
    """Raised when a chain-specific capability view cannot be derived safely."""


def _tokens(value: object) -> set[str]:
    if not isinstance(value, str):
        return set()
    return {item.strip() for item in value.split(";") if item.strip()}


def _operator(actual: object, operator: str, expected: object) -> bool:
    if operator == "exists":
        return (
            actual is not None and actual is not False and actual != [] and actual != ""
        )
    if operator == "equals":
        if isinstance(actual, (set, frozenset, list, tuple)):
            return expected in actual
        return actual == expected
    if operator == "not-equals":
        return not _operator(actual, "equals", expected)
    if operator == "contains":
        if isinstance(actual, (str, list, tuple, set, frozenset)):
            return expected in actual
        return False
    if operator == "in":
        return (
            isinstance(expected, (list, tuple, set, frozenset)) and actual in expected
        )
    raise EffectiveCapabilityError(f"unsupported activation operator {operator!r}")


def _predicate_actual(
    predicate: Mapping[str, Any],
    *,
    roles: Mapping[str, Mapping[str, Any]],
    runtime_features: set[str],
    call_shape: str,
    active_defaults: set[str],
) -> object:
    kind = predicate["predicate"]
    subject = predicate["subject"]
    role = roles.get(subject, {})
    if kind == "always":
        return True
    if kind == "role-bound":
        return bool(role.get("matched_bindings"))
    if kind == "role-caller-bindable":
        return bool(role.get("caller_bindable"))
    if kind == "role-authority":
        return set(role.get("authorities", []))
    if kind == "role-value":
        values = role.get("values", [])
        return values[0] if len(values) == 1 else values
    if kind == "runtime-feature":
        return subject in runtime_features
    if kind == "transform-present":
        return set(role.get("transforms", []))
    if kind == "call-shape":
        return call_shape
    if kind == "default-active":
        return subject in active_defaults
    raise EffectiveCapabilityError(f"unsupported activation predicate {kind!r}")


def _evaluate_activation(
    activation: Mapping[str, Any],
    *,
    roles: Mapping[str, Mapping[str, Any]],
    runtime_features: set[str],
    call_shape: str,
    active_defaults: set[str],
) -> tuple[bool, list[dict[str, Any]], list[dict[str, Any]]]:
    passed: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    results: dict[str, list[bool]] = {"all_of": [], "any_of": []}
    for group in results:
        for predicate in activation.get(group, []):
            actual = _predicate_actual(
                predicate,
                roles=roles,
                runtime_features=runtime_features,
                call_shape=call_shape,
                active_defaults=active_defaults,
            )
            matched = _operator(actual, predicate["operator"], predicate["value"])
            record = {
                **predicate,
                "actual": sorted(actual) if isinstance(actual, set) else actual,
            }
            (passed if matched else failed).append(record)
            results[group].append(matched)
    all_ok = all(results["all_of"]) if "all_of" in activation else True
    any_ok = any(results["any_of"]) if "any_of" in activation else True
    return all_ok and any_ok, passed, failed


def _role_views(
    card: Mapping[str, Any],
    *,
    structural_bindings: set[str],
    confirmed_bindings: Mapping[str, set[str]],
    authority_by_binding: Mapping[str, str],
    transforms_by_binding: Mapping[str, Sequence[str]],
    argument_values: Mapping[str, object],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, str]]]:
    roles: dict[str, dict[str, Any]] = {}
    conflicts: list[dict[str, str]] = []
    for role in card["roles"]:
        matched = [
            binding
            for binding in role["bindings"]
            if binding["expression"] in structural_bindings
            or binding["expression"] in argument_values
            or binding["expression"] in confirmed_bindings
            or binding["expression"] in authority_by_binding
            or binding["expression"] in transforms_by_binding
        ]
        authorities: set[str] = set()
        source_facets: set[str] = set()
        transforms: set[str] = set()
        values: list[object] = []
        for binding in matched:
            expression = binding["expression"]
            authority = authority_by_binding.get(expression)
            if authority is None and expression in confirmed_bindings:
                authority = (
                    "model-arbitrary"
                    if binding["caller_bindable"]
                    else "internal-derived"
                )
            authority = authority or "internal-derived"
            if authority not in AUTHORITIES:
                raise EffectiveCapabilityError(
                    f"unsupported authority {authority!r} for {expression!r}"
                )
            if expression in confirmed_bindings and not binding["caller_bindable"]:
                conflicts.append(
                    {
                        "role_id": role["role_id"],
                        "binding": expression,
                        "reason": "origin witness targets a non-caller-bindable API binding",
                    }
                )
            authorities.add(authority)
            source_facets.update(confirmed_bindings.get(expression, set()))
            transforms.update(transforms_by_binding.get(expression, ()))
            if expression in argument_values:
                values.append(argument_values[expression])
        roles[role["role_id"]] = {
            "role_id": role["role_id"],
            "description": role["description"],
            "matched_bindings": sorted(binding["expression"] for binding in matched),
            "caller_bindable": any(binding["caller_bindable"] for binding in matched),
            "authorities": sorted(authorities),
            "source_facets": sorted(source_facets),
            "transforms": sorted(transforms),
            "values": values,
        }
    return roles, conflicts


def derive_effective_capability_view(
    *,
    card: Mapping[str, Any] | str,
    project: str,
    revision: str,
    chain_id: str,
    sink_constraint: Mapping[str, Any],
    origin_witnesses: Sequence[Mapping[str, Any]] = (),
    authority_by_binding: Mapping[str, str] | None = None,
    transforms_by_binding: Mapping[str, Sequence[str]] | None = None,
    argument_values: Mapping[str, object] | None = None,
    runtime_features: Sequence[str] = (),
) -> dict[str, Any]:
    """Build a fail-closed effective view using exact role/binding identities."""

    parsed = (
        parse_capability_card(card)
        if isinstance(card, str)
        else validate_card_payload(card)
    )
    structural = _tokens(sink_constraint.get("controlled_argument"))
    confirmed: dict[str, set[str]] = {}
    for witness in origin_witnesses:
        if (
            witness.get("chain_id") != chain_id
            or witness.get("verdict") != CONFIRMED_ORIGIN
        ):
            continue
        source_facet = str(witness.get("source_facet") or "")
        for binding in _tokens(witness.get("sink_argument")):
            confirmed.setdefault(binding, set()).add(source_facet)
    authorities = dict(authority_by_binding or {})
    transforms = dict(transforms_by_binding or {})
    values = dict(argument_values or {})
    role_views, conflicts = _role_views(
        parsed,
        structural_bindings=structural,
        confirmed_bindings=confirmed,
        authority_by_binding=authorities,
        transforms_by_binding=transforms,
        argument_values=values,
    )
    features = set(runtime_features)
    call_shape = str(sink_constraint.get("call_shape") or "")
    active_defaults: set[str] = set()
    default_rows: list[dict[str, Any]] = []
    for row in parsed["defaults"]:
        active, passed, failed = _evaluate_activation(
            row["activation"],
            roles=role_views,
            runtime_features=features,
            call_shape=call_shape,
            active_defaults=set(),
        )
        role = role_views.get(row.get("role_id"))
        if role and role["matched_bindings"]:
            active = False
            failed.append({"predicate": "role-omitted", "actual": False})
        if active:
            active_defaults.add(row["default_id"])
        default_rows.append(
            {**row, "active": active, "passed": passed, "failed": failed}
        )
    capability_rows: list[dict[str, Any]] = []
    for row in parsed["facets"]:
        active, passed, failed = _evaluate_activation(
            row["activation"],
            roles=role_views,
            runtime_features=features,
            call_shape=call_shape,
            active_defaults=active_defaults,
        )
        if not any(
            role_views[role_id]["matched_bindings"] for role_id in row["role_ids"]
        ):
            active = False
            failed.append({"predicate": "required-role-bound", "actual": False})
        capability_rows.append(
            {**row, "active": active, "passed": passed, "failed": failed}
        )
    guarantee_rows: list[dict[str, Any]] = []
    for row in parsed["library_guarantees"]:
        active, passed, failed = _evaluate_activation(
            row["activation"],
            roles=role_views,
            runtime_features=features,
            call_shape=call_shape,
            active_defaults=active_defaults,
        )
        guarantee_rows.append(
            {**row, "active": active, "passed": passed, "failed": failed}
        )
    view_input = {
        "project": project,
        "revision": revision,
        "chain_id": chain_id,
        "card_id": parsed["card_id"],
        "sink_constraint": dict(sink_constraint),
        "roles": role_views,
        "runtime_features": sorted(features),
        "argument_values": values,
    }
    return {
        "schema_version": VIEW_SCHEMA_VERSION,
        "view_id": "ECV-" + payload_sha256(view_input)[:16],
        "project": project,
        "revision": revision,
        "chain_id": chain_id,
        "card_id": parsed["card_id"],
        "capability_class": parsed["capability_class"],
        "constraint_id": sink_constraint.get("constraint_id"),
        "ordinary_card_normative": False,
        "policy_contract_ids": sorted(
            requirement["policy_id"]
            for requirement in parsed.get("policy_contract", {}).get("requirements", [])
        ),
        "roles": [role_views[role_id] for role_id in sorted(role_views)],
        "boundaries": [
            {
                "boundary_id": f"{role_id}-authority",
                "role_id": role_id,
                "sink_bindings": role_views[role_id]["matched_bindings"],
                "authorities": role_views[role_id]["authorities"],
                "caller_bindable": role_views[role_id]["caller_bindable"],
                "source_facets": role_views[role_id]["source_facets"],
            }
            for role_id in sorted(role_views)
            if role_views[role_id]["matched_bindings"]
        ],
        "origin_conflicts": sorted(
            conflicts, key=lambda row: (row["role_id"], row["binding"])
        ),
        "active_facets": [row for row in capability_rows if row["active"]],
        "inactive_facets": [row for row in capability_rows if not row["active"]],
        "active_library_guarantees": [row for row in guarantee_rows if row["active"]],
        "inactive_library_guarantees": [
            row for row in guarantee_rows if not row["active"]
        ],
        "active_defaults": [row for row in default_rows if row["active"]],
        "inactive_defaults": [row for row in default_rows if not row["active"]],
        "actual_effects": [
            {
                "facet_id": row["facet_id"],
                "capability": row["capability"],
                "role_ids": row["role_ids"],
                "activation_witnesses": row["passed"],
            }
            for row in capability_rows
            if row["active"]
        ],
        "call_shape_predicates": {
            "exact_call_shape": call_shape,
            "controlled_arguments": sorted(structural),
            "confirmed_origin_arguments": sorted(confirmed),
            "argument_values": values,
            "runtime_features": sorted(features),
            "active_default_ids": sorted(active_defaults),
        },
        "input_sha256": payload_sha256(view_input),
    }


def derive_effective_capability_views(
    *,
    semantic_chains: Sequence[Mapping[str, Any]],
    cards_by_path: Mapping[str, Mapping[str, Any] | str],
    field_flow_rows: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Derive exactly one view per semantic chain from field-sensitive flow rows."""

    flows_by_chain: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    for row in field_flow_rows:
        chain_id = row.get("chain_id")
        project = row.get("project")
        revision = row.get("revision")
        if not all(
            isinstance(value, str) and value for value in (project, revision, chain_id)
        ):
            raise EffectiveCapabilityError(
                "field-flow row lacks project/revision/chain_id"
            )
        flows_by_chain.setdefault((project, revision, chain_id), []).append(row)
    output: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for semantic in semantic_chains:
        chain_id = semantic.get("chain_id")
        if not isinstance(chain_id, str) or not chain_id:
            raise EffectiveCapabilityError("semantic chain has no chain_id")
        project_row = semantic.get("project")
        if not isinstance(project_row, Mapping):
            raise EffectiveCapabilityError(f"{chain_id}: missing project identity")
        project = project_row.get("id")
        revision = project_row.get("revision")
        if not all(isinstance(value, str) and value for value in (project, revision)):
            raise EffectiveCapabilityError(f"{chain_id}: invalid project identity")
        chain_key = (project, revision, chain_id)
        if chain_key in seen:
            raise EffectiveCapabilityError(f"duplicate semantic chain {chain_key}")
        seen.add(chain_key)
        constraint = semantic.get("sink_constraint")
        if not isinstance(constraint, Mapping):
            raise EffectiveCapabilityError(f"{chain_id}: missing sink constraint")
        card_ref = constraint.get("capability_card")
        card_path = card_ref.get("path") if isinstance(card_ref, Mapping) else None
        if not isinstance(card_path, str) or card_path not in cards_by_path:
            raise EffectiveCapabilityError(f"{chain_id}: missing v2 card {card_path!r}")
        flows = flows_by_chain.get(chain_key, [])
        authority_by_binding: dict[str, str] = {}
        transforms_by_binding: dict[str, set[str]] = {}
        for flow in flows:
            authority = flow.get("authority")
            raw_transforms = flow.get("transforms", [])
            if isinstance(raw_transforms, str):
                raw_transforms = [raw_transforms]
            if not isinstance(raw_transforms, Sequence):
                raise EffectiveCapabilityError(f"{chain_id}: invalid flow transforms")
            for binding in _tokens(flow.get("sink_argument")):
                if authority is not None:
                    authority_value = str(authority)
                    prior = authority_by_binding.setdefault(binding, authority_value)
                    if prior != authority_value:
                        raise EffectiveCapabilityError(
                            f"{chain_id}:{binding}: conflicting field-flow authority"
                        )
                transforms_by_binding.setdefault(binding, set()).update(
                    str(value) for value in raw_transforms
                )
        view = derive_effective_capability_view(
            card=cards_by_path[card_path],
            project=project,
            revision=revision,
            chain_id=chain_id,
            sink_constraint=constraint,
            origin_witnesses=flows,
            authority_by_binding=authority_by_binding,
            transforms_by_binding={
                key: sorted(values) for key, values in transforms_by_binding.items()
            },
            argument_values=(
                constraint.get("argument_values")
                if isinstance(constraint.get("argument_values"), Mapping)
                else {}
            ),
            runtime_features=(
                constraint.get("runtime_features")
                if isinstance(constraint.get("runtime_features"), list)
                else []
            ),
        )
        view["capability_card_path"] = card_path
        output.append(view)
    extra_flow_keys = set(flows_by_chain) - seen
    if extra_flow_keys:
        raise EffectiveCapabilityError(
            f"field-flow rows reference unknown semantic chains: {sorted(extra_flow_keys)}"
        )
    return tuple(
        sorted(
            output, key=lambda row: (row["project"], row["revision"], row["chain_id"])
        )
    )


def load_v2_cards(card_root: Path) -> dict[str, str]:
    """Load a migration/regeneration staging directory using repository-relative keys."""

    output: dict[str, str] = {}
    for path in sorted(card_root.glob("*.md")):
        if path.name == "index.md":
            continue
        markdown = path.read_text(encoding="utf-8")
        parse_capability_card(markdown)
        output[f"src/sink_capacity/sink-capability-cards/{path.name}"] = markdown
    return output

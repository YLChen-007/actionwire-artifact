"""Strict contracts for intent-centered handler-family alignment."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from jsonschema import validate as validate_schema


MAPPING_SCHEMA_VERSION = "handler-type-mapping/v2"
CATALOG_SCHEMA_VERSION = "handler-type-catalog/v4"
CAPABILITY_OBSERVATION_SCHEMA_VERSION = "handler-type-capability-observation/v1"
SINGLETON_AUDIT_SCHEMA_VERSION = "handler-type-singleton-audit/v2"
CRITERION_SUPPORT_SCHEMA_VERSION = "handler-criterion-support/v1"
ORACLE_INHERITANCE_SCHEMA_VERSION = "handler-oracle-inheritance/v1"
SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"

OPERATION_FAMILIES = (
    "analyze",
    "authorize",
    "control",
    "create",
    "delegate",
    "delete",
    "execute",
    "generate",
    "list",
    "manage",
    "read",
    "search",
    "send",
    "transfer",
    "update",
    "write",
    "other",
)
RESOURCE_FAMILIES = (
    "agent",
    "browser",
    "code",
    "configuration",
    "credential",
    "database",
    "device",
    "external-service",
    "file",
    "filesystem",
    "image",
    "media",
    "memory",
    "message",
    "model",
    "process",
    "repository",
    "schedule",
    "session",
    "skill",
    "task",
    "ui",
    "web",
    "other",
)
EFFECT_FAMILIES = (
    "authorize",
    "communicate",
    "delegate",
    "execute",
    "mixed",
    "mutate",
    "none",
    "observe",
)
INTENT_PROFILE_FIELDS = {
    "intent_family",
    "canonical_label",
    "operation_family",
    "resource_family",
    "effect",
    "core_roles",
    "optional_roles",
    "compatibility_rule",
    "distinguishing_rule",
}
FAMILY_CRITERION_FIELDS = {
    "intent_family",
    "canonical_label",
    "operation_family",
    "resource_family",
    "effect",
    "compatibility_rule",
    "distinguishing_rule",
}
FINAL_CRITERION_FIELDS = FAMILY_CRITERION_FIELDS | {"role_signatures"}
PARENT_CRITERION_FIELDS = {"operation_family", "resource_family", "effect"}
TOKEN_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$")
OPERATION_ALIASES = {
    "approve": "authorize",
    "automate": "control",
    "call": "execute",
    "cancel": "manage",
    "communicate": "send",
    "convert": "generate",
    "download": "transfer",
    "edit": "update",
    "fetch": "read",
    "find": "search",
    "get": "read",
    "grant": "authorize",
    "inspect": "read",
    "invoke": "execute",
    "modify": "update",
    "navigate": "control",
    "query": "search",
    "react": "send",
    "remove": "delete",
    "render": "generate",
    "retrieve": "read",
    "run": "execute",
    "schedule": "manage",
    "set": "update",
    "spawn": "delegate",
    "synthesize": "generate",
    "upload": "transfer",
    "view": "read",
}
EFFECT_ALIASES = {
    "analyze": "observe",
    "control": "mutate",
    "create": "mutate",
    "delete": "mutate",
    "generate": "mutate",
    "inspect": "observe",
    "list": "observe",
    "manage": "mixed",
    "modify": "mutate",
    "read": "observe",
    "search": "observe",
    "send": "communicate",
    "spawn": "delegate",
    "update": "mutate",
    "write": "mutate",
}
RESOURCE_ALIASES = {
    "agent-memory": "memory",
    "artifact": "file",
    "audio": "media",
    "browser-page": "browser",
    "channel": "message",
    "database-record": "database",
    "directory": "filesystem",
    "file-content": "file",
    "file-path": "file",
    "file-system": "filesystem",
    "filesystem-path": "file",
    "image-content": "image",
    "media-content": "media",
    "memory-content": "memory",
    "operating-system-process": "process",
    "scheduled-task": "schedule",
    "speech": "media",
    "user-memory": "memory",
    "video": "media",
    "web-content": "web",
}
INTENT_NORMALIZATION_RULES = {
    ("comment-document", "file"): ("comment-document", "create", "mutate"),
    ("reply-comment", "file"): ("comment-document", "create", "mutate"),
    ("control-playback", "media"): ("control-playback", "control", "mutate"),
    ("create-skill", "skill"): ("create-skill", "create", "mutate"),
    ("create-skill-candidate", "skill"): ("create-skill", "create", "mutate"),
    ("create-skill-payload", "skill"): ("create-skill", "create", "mutate"),
    ("evaluate-skill-candidate", "skill"): ("manage-skill", "manage", "mutate"),
    ("execute-browser", "browser"): (
        "execute-browser-command",
        "execute",
        "execute",
    ),
    ("execute-browser-batch", "browser"): (
        "execute-browser-command",
        "execute",
        "execute",
    ),
    ("git-diff", "repository"): ("inspect-repository", "read", "observe"),
    ("git-log", "repository"): ("inspect-repository", "read", "observe"),
    ("git-status", "repository"): ("inspect-repository", "read", "observe"),
    ("launch-app", "device"): ("launch-device-app", "execute", "execute"),
    ("list-devices", "device"): ("list-device-resources", "list", "observe"),
    ("list-entities", "device"): ("list-device-resources", "list", "observe"),
    ("list-services", "device"): ("list-device-resources", "list", "observe"),
    ("list-skill-candidates", "skill"): ("list-skills", "list", "observe"),
    ("list-skill-releases", "skill"): ("list-skills", "list", "observe"),
    ("manage-skill", "skill"): ("manage-skill", "manage", "mutate"),
    ("pause-task", "schedule"): ("manage-schedule", "manage", "mutate"),
    ("promote-skill-candidate", "skill"): ("manage-skill", "manage", "mutate"),
    ("read-artifact", "file"): ("read-file", "read", "observe"),
    ("read-document", "file"): ("read-file", "read", "observe"),
    ("resume-task", "schedule"): ("manage-schedule", "manage", "mutate"),
    ("rollback-skill-release", "skill"): ("manage-skill", "manage", "mutate"),
    ("run-browser-skill", "browser"): (
        "execute-browser-command",
        "execute",
        "execute",
    ),
    ("send-card", "message"): ("send-message", "send", "communicate"),
    ("send-cdp-command", "browser"): (
        "execute-browser-command",
        "execute",
        "execute",
    ),
    ("send-dm", "message"): ("send-message", "send", "communicate"),
    ("send-message", "message"): ("send-message", "send", "communicate"),
    ("send-sticker", "message"): ("send-message", "send", "communicate"),
    ("switch-app", "device"): ("launch-device-app", "execute", "execute"),
    ("sync-skill-release", "skill"): ("manage-skill", "manage", "mutate"),
    ("update-task", "schedule"): ("manage-schedule", "manage", "mutate"),
}


class AlignmentContractError(ValueError):
    """Raised when an alignment input or LLM response violates its contract."""


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def parse_json_response(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == "```":
            text = "\n".join(lines[1:-1])
            if text.lstrip().startswith("json"):
                text = text.lstrip()[4:].lstrip("\r\n")
    try:
        result = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AlignmentContractError(f"response is not JSON: {exc}") from exc
    if not isinstance(result, dict):
        raise AlignmentContractError("response must be a JSON object")
    return result


def _normalized_text(raw: object, field: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise AlignmentContractError(f"criterion {field} must be non-empty")
    return " ".join(raw.strip().split())


def _token(raw: object, field: str) -> str:
    value = _normalized_text(raw, field).lower()
    token = re.sub(r"[^a-z0-9]+", "-", value).strip("-")
    if not token or TOKEN_PATTERN.fullmatch(token) is None:
        raise AlignmentContractError(f"criterion {field} must be a canonical slug")
    return token


def _normalized_family(
    raw: object,
    field: str,
    allowed: Sequence[str],
    aliases: Mapping[str, str],
) -> str:
    token = _token(raw, field)
    if token in allowed:
        return token
    if token in aliases:
        return aliases[token]
    resource_markers = (
        ("memory", "memory"),
        ("file", "file"),
        ("directory", "filesystem"),
        ("browser", "browser"),
        ("device", "device"),
        ("message", "message"),
        ("session", "session"),
        ("process", "process"),
        ("repository", "repository"),
        ("schedule", "schedule"),
        ("task", "task"),
        ("image", "image"),
        ("media", "media"),
        ("web", "web"),
    )
    if field == "resource_family":
        for marker, family in resource_markers:
            if marker in token:
                return family
    raise AlignmentContractError(f"unknown {field.replace('_', ' ')}: {token}")


def _normalized_roles(raw: object, field: str) -> list[str]:
    if not isinstance(raw, list) or any(not isinstance(role, str) for role in raw):
        raise AlignmentContractError(f"criterion {field} must be a string array")
    roles = sorted({_token(role, field) for role in raw})
    return roles


def _normalize_family_fields(raw: Mapping[str, Any]) -> dict[str, Any]:
    intent_family = _token(raw.get("intent_family"), "intent_family")
    operation_family = _normalized_family(
        raw.get("operation_family"),
        "operation_family",
        OPERATION_FAMILIES,
        OPERATION_ALIASES,
    )
    resource_family = _normalized_family(
        raw.get("resource_family"),
        "resource_family",
        RESOURCE_FAMILIES,
        RESOURCE_ALIASES,
    )
    effect = _normalized_family(
        raw.get("effect"), "effect", EFFECT_FAMILIES, EFFECT_ALIASES
    )
    normalized_intent = INTENT_NORMALIZATION_RULES.get(
        (intent_family, resource_family)
    )
    if normalized_intent is not None:
        intent_family, operation_family, effect = normalized_intent
    return {
        "intent_family": intent_family,
        "canonical_label": _normalized_text(
            raw.get("canonical_label"), "canonical_label"
        ),
        "operation_family": operation_family,
        "resource_family": resource_family,
        "effect": effect,
        "compatibility_rule": _normalized_text(
            raw.get("compatibility_rule"), "compatibility_rule"
        ),
        "distinguishing_rule": _normalized_text(
            raw.get("distinguishing_rule"), "distinguishing_rule"
        ),
    }


def normalize_intent_profile(raw: object) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != INTENT_PROFILE_FIELDS:
        raise AlignmentContractError(
            "intent profile must contain intent_family, canonical_label, operation_family, "
            "resource_family, effect, core_roles, optional_roles, compatibility_rule, "
            "and distinguishing_rule"
        )
    normalized = _normalize_family_fields(raw)
    core_roles = _normalized_roles(raw.get("core_roles"), "core_roles")
    optional_roles = _normalized_roles(raw.get("optional_roles"), "optional_roles")
    if set(core_roles) & set(optional_roles):
        raise AlignmentContractError("core and optional roles must be disjoint")
    return {
        **normalized,
        "core_roles": core_roles,
        "optional_roles": optional_roles,
    }


def normalize_family_criterion(raw: object) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != FAMILY_CRITERION_FIELDS:
        raise AlignmentContractError(
            "family criterion must contain intent_family, canonical_label, "
            "operation_family, resource_family, effect, compatibility_rule, and "
            "distinguishing_rule"
        )
    return _normalize_family_fields(raw)


def _normalize_role_signatures(raw: object) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        raise AlignmentContractError("criterion role_signatures must be non-empty")
    normalized: list[dict[str, Any]] = []
    seen_members: set[str] = set()
    for signature in raw:
        if not isinstance(signature, dict) or set(signature) != {
            "core_roles",
            "optional_roles",
            "members",
        }:
            raise AlignmentContractError("invalid role signature")
        core_roles = _normalized_roles(signature["core_roles"], "core_roles")
        optional_roles = _normalized_roles(
            signature["optional_roles"], "optional_roles"
        )
        if set(core_roles) & set(optional_roles):
            raise AlignmentContractError("role signature core and optional roles overlap")
        members = signature["members"]
        if (
            not isinstance(members, list)
            or not members
            or any(not isinstance(member, str) or not member for member in members)
        ):
            raise AlignmentContractError("role signature members must be non-empty")
        sorted_members = sorted(set(members))
        if len(sorted_members) != len(members) or seen_members & set(sorted_members):
            raise AlignmentContractError("role signature members must be unique")
        seen_members.update(sorted_members)
        normalized.append(
            {
                "core_roles": core_roles,
                "optional_roles": optional_roles,
                "members": sorted_members,
            }
        )
    return sorted(
        normalized,
        key=lambda row: (
            row["core_roles"],
            row["optional_roles"],
            row["members"],
        ),
    )


def normalize_criterion(raw: object) -> dict[str, Any]:
    """Normalize a final catalog criterion."""

    if not isinstance(raw, dict) or set(raw) != FINAL_CRITERION_FIELDS:
        raise AlignmentContractError(
            "final criterion must contain family fields and role_signatures"
        )
    return {
        **_normalize_family_fields(raw),
        "role_signatures": _normalize_role_signatures(raw["role_signatures"]),
    }


def normalize_parent_criterion(raw: object) -> dict[str, str]:
    """Normalize the closed operation/resource/effect parent vocabulary."""

    if not isinstance(raw, dict) or set(raw) != PARENT_CRITERION_FIELDS:
        raise AlignmentContractError(
            "parent criterion must contain operation_family, resource_family, and effect"
        )
    return {
        "operation_family": _normalized_family(
            raw.get("operation_family"),
            "operation_family",
            OPERATION_FAMILIES,
            OPERATION_ALIASES,
        ),
        "resource_family": _normalized_family(
            raw.get("resource_family"),
            "resource_family",
            RESOURCE_FAMILIES,
            RESOURCE_ALIASES,
        ),
        "effect": _normalized_family(
            raw.get("effect"), "effect", EFFECT_FAMILIES, EFFECT_ALIASES
        ),
    }


def criterion_type_key(criterion: Mapping[str, Any]) -> dict[str, Any]:
    if "role_signatures" in criterion:
        normalized = normalize_criterion(dict(criterion))
    elif "core_roles" in criterion or "optional_roles" in criterion:
        normalized = normalize_intent_profile(dict(criterion))
    else:
        normalized = normalize_family_criterion(dict(criterion))
    return {
        "intent_family": normalized["intent_family"],
        "operation_family": normalized["operation_family"],
        "resource_family": normalized["resource_family"],
        "effect": normalized["effect"],
    }


def criterion_parent_key(criterion: Mapping[str, Any]) -> dict[str, str]:
    """Return the normalized deterministic parent key for any criterion shape."""

    return normalize_parent_criterion(
        {
            "operation_family": criterion.get("operation_family"),
            "resource_family": criterion.get("resource_family"),
            "effect": criterion.get("effect"),
        }
    )


def stable_criterion_id(criterion: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(
        canonical_json(criterion_parent_key(criterion)).encode("utf-8")
    ).hexdigest()
    return "HC-" + digest[:16]


def stable_type_id(criterion: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(
        canonical_json(criterion_type_key(criterion)).encode("utf-8")
    ).hexdigest()
    return "HT-" + digest[:16]


def stable_proposal_id(members: Sequence[str]) -> str:
    normalized = sorted(set(members))
    if not normalized or len(normalized) != len(members):
        raise AlignmentContractError("proposal members must be non-empty and unique")
    digest = hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()
    return "HP-" + digest[:16]


def merge_equivalent_criteria(
    criteria: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if not criteria:
        raise AlignmentContractError("cannot merge an empty criterion set")
    normalized = [normalize_family_criterion(dict(row)) for row in criteria]
    keys = {canonical_json(criterion_type_key(row)) for row in normalized}
    if len(keys) != 1:
        raise AlignmentContractError("cannot merge criteria with different intent keys")
    labels = sorted(
        {row["canonical_label"] for row in normalized}, key=lambda value: (len(value), value)
    )
    compatibility = sorted(
        {row["compatibility_rule"] for row in normalized},
        key=lambda value: (len(value), value),
    )
    distinguishing = sorted(
        {row["distinguishing_rule"] for row in normalized},
        key=lambda value: (len(value), value),
    )
    return {
        **criterion_type_key(normalized[0]),
        "canonical_label": labels[0],
        "compatibility_rule": compatibility[0],
        "distinguishing_rule": distinguishing[0],
    }


def _validate_reason_and_evidence(row: Mapping[str, Any]) -> None:
    if not isinstance(row.get("reason"), str) or not str(row["reason"]).strip():
        raise AlignmentContractError("alignment reason must be non-empty")
    evidence = row.get("evidence")
    if not isinstance(evidence, list) or any(
        not isinstance(item, str) or not item.strip() for item in evidence
    ):
        raise AlignmentContractError("alignment evidence must be a string array")


def validate_profile_batch_response(
    response: dict[str, Any], expected_handler_ids: set[str]
) -> list[dict[str, Any]]:
    if set(response) != {"assignments"} or not isinstance(
        response.get("assignments"), list
    ):
        raise AlignmentContractError("profile response must contain assignments")
    rows = response["assignments"]
    ids = [row.get("handler_id") for row in rows if isinstance(row, dict)]
    if len(ids) != len(rows) or len(ids) != len(set(ids)) or set(ids) != expected_handler_ids:
        raise AlignmentContractError(
            "profile assignments must cover every handler exactly once"
        )
    output: list[dict[str, Any]] = []
    for row in rows:
        if set(row) != {"handler_id", "profile", "reason", "evidence"}:
            raise AlignmentContractError("profile assignment has unexpected fields")
        _validate_reason_and_evidence(row)
        output.append(
            {
                "handler_id": row["handler_id"],
                "profile": normalize_intent_profile(row["profile"]),
                "reason": row["reason"].strip(),
                "evidence": list(row["evidence"]),
            }
        )
    return sorted(output, key=lambda row: row["handler_id"])


def validate_seed_response(
    response: dict[str, Any], expected_handler_ids: set[str]
) -> list[dict[str, Any]]:
    return validate_profile_batch_response(response, expected_handler_ids)


def validate_axis_conflict_response(
    response: dict[str, Any],
    *,
    allowed_parent_keys: Mapping[str, Sequence[Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    """Validate one order-independent resolution for every conflicting intent slug."""

    if set(response) != {"resolutions"} or not isinstance(
        response.get("resolutions"), list
    ):
        raise AlignmentContractError("axis-conflict response must contain resolutions")
    fields = {
        "intent_family",
        "operation_family",
        "resource_family",
        "effect",
        "reason",
        "evidence",
    }
    expected = set(allowed_parent_keys)
    seen: list[str] = []
    output: list[dict[str, Any]] = []
    for row in response["resolutions"]:
        if not isinstance(row, dict) or set(row) != fields:
            raise AlignmentContractError("axis-conflict resolution has unexpected fields")
        intent_family = _token(row.get("intent_family"), "intent_family")
        if intent_family not in expected:
            raise AlignmentContractError(
                f"axis-conflict resolution references unknown intent {intent_family!r}"
            )
        _validate_reason_and_evidence(row)
        parent_key = normalize_parent_criterion(
            {field: row[field] for field in PARENT_CRITERION_FIELDS}
        )
        allowed = {
            canonical_json(criterion_parent_key(candidate))
            for candidate in allowed_parent_keys[intent_family]
        }
        if canonical_json(parent_key) not in allowed:
            raise AlignmentContractError(
                f"{intent_family}: resolved parent must copy one observed parent tuple"
            )
        seen.append(intent_family)
        output.append(
            {
                "intent_family": intent_family,
                **parent_key,
                "reason": row["reason"].strip(),
                "evidence": list(row["evidence"]),
            }
        )
    if len(seen) != len(set(seen)) or set(seen) != expected:
        raise AlignmentContractError(
            "axis-conflict resolutions must cover every conflicting intent exactly once"
        )
    return sorted(output, key=lambda row: row["intent_family"])


def validate_reconciliation_response(
    response: dict[str, Any],
    *,
    expected_handler_ids: set[str],
    seed_type_ids: set[str],
    expected_parent_key: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if set(response) != {"groups"} or not isinstance(response.get("groups"), list):
        raise AlignmentContractError("reconciliation response must contain groups")
    fields = {
        "handler_ids",
        "decision",
        "handler_type_id",
        "criterion",
        "reason",
        "evidence",
    }
    identifier_errors: list[str] = []
    for index, group in enumerate(response["groups"]):
        if not isinstance(group, dict) or set(group) != fields:
            continue
        if group.get("decision") != "matched":
            continue
        handler_type_id = group.get("handler_type_id")
        if handler_type_id not in seed_type_ids:
            identifier_errors.append(
                f"groups[{index}] uses unknown seed type {handler_type_id!r}"
            )
    if identifier_errors:
        raise AlignmentContractError(
            "reconciliation ID errors; correct every listed row in one response: "
            + "; ".join(identifier_errors)
            + f"; exact allowed seed type IDs are {sorted(seed_type_ids)!r}"
        )
    seen: list[str] = []
    output: list[dict[str, Any]] = []
    for group in response["groups"]:
        if not isinstance(group, dict) or set(group) != fields:
            raise AlignmentContractError("reconciliation group has unexpected fields")
        ids = group["handler_ids"]
        if (
            not isinstance(ids, list)
            or not ids
            or any(not isinstance(item, str) or not item for item in ids)
        ):
            raise AlignmentContractError("handler_ids must be non-empty")
        _validate_reason_and_evidence(group)
        seen.extend(ids)
        decision = group["decision"]
        if decision == "matched":
            handler_type_id = group.get("handler_type_id")
            if group.get("criterion") is not None:
                raise AlignmentContractError("matched group must not include a criterion")
            criterion = None
        elif decision == "new-type":
            if group.get("handler_type_id") is not None:
                raise AlignmentContractError("new-type group cannot preassign a type ID")
            criterion = normalize_family_criterion(group.get("criterion"))
            if expected_parent_key is not None and criterion_parent_key(
                criterion
            ) != criterion_parent_key(expected_parent_key):
                raise AlignmentContractError(
                    "reconciliation cannot move a leaf to a different parent criterion"
                )
            normalized_type_id = stable_type_id(criterion)
            if normalized_type_id in seed_type_ids:
                decision = "matched"
                handler_type_id = normalized_type_id
                criterion = None
            else:
                handler_type_id = None
        else:
            raise AlignmentContractError(f"invalid reconciliation decision: {decision!r}")
        output.append(
            {
                "handler_ids": sorted(ids),
                "decision": decision,
                "handler_type_id": handler_type_id,
                "criterion": criterion,
                "reason": group["reason"].strip(),
                "evidence": list(group["evidence"]),
            }
        )
    if len(seen) != len(set(seen)) or set(seen) != expected_handler_ids:
        raise AlignmentContractError(
            "reconciliation groups must cover every subject exactly once"
        )
    return sorted(output, key=lambda row: row["handler_ids"])


def validate_proposal_match_response(
    response: dict[str, Any],
    *,
    expected_proposal_ids: set[str],
    allowed_candidate_ids: set[str],
) -> list[dict[str, Any]]:
    if set(response) != {"matches"} or not isinstance(response.get("matches"), list):
        raise AlignmentContractError("proposal response must contain matches")
    fields = {"proposal_id", "verdict", "selected_id", "reason", "evidence"}
    selection_errors: list[str] = []
    for row in response["matches"]:
        if not isinstance(row, dict) or set(row) != fields:
            continue
        proposal_id = row.get("proposal_id")
        if proposal_id not in expected_proposal_ids:
            continue
        verdict = row.get("verdict")
        selected_id = row.get("selected_id")
        if verdict == "matched" and selected_id == proposal_id:
            selection_errors.append(f"{proposal_id} selects itself")
        elif verdict == "matched" and selected_id not in allowed_candidate_ids:
            selection_errors.append(
                f"{proposal_id} selects unknown candidate {selected_id!r}"
            )
        elif verdict == "distinct" and selected_id is not None:
            selection_errors.append(
                f"{proposal_id} is distinct but selects {selected_id!r}"
            )
    if selection_errors:
        raise AlignmentContractError(
            "proposal selection errors; correct every listed row in one response: "
            + "; ".join(selection_errors)
            + "; use only the request's candidate_ids_by_source entries"
        )
    output: list[dict[str, Any]] = []
    seen: list[str] = []
    for row in response["matches"]:
        if not isinstance(row, dict) or set(row) != fields:
            raise AlignmentContractError("proposal match has unexpected fields")
        proposal_id = row.get("proposal_id")
        if proposal_id not in expected_proposal_ids:
            raise AlignmentContractError("proposal match references unknown source")
        _validate_reason_and_evidence(row)
        verdict = row.get("verdict")
        selected_id = row.get("selected_id")
        if verdict == "matched":
            # Selection validity is reported for all rows together above so the one
            # permitted repair can correct the complete response in a single pass.
            pass
        elif verdict == "distinct":
            if selected_id is not None:
                raise AlignmentContractError("distinct proposal cannot select a candidate")
        else:
            raise AlignmentContractError(f"invalid proposal verdict: {verdict!r}")
        seen.append(proposal_id)
        output.append(
            {
                "proposal_id": proposal_id,
                "verdict": verdict,
                "selected_id": selected_id,
                "reason": row["reason"].strip(),
                "evidence": list(row["evidence"]),
            }
        )
    if len(seen) != len(set(seen)) or set(seen) != expected_proposal_ids:
        raise AlignmentContractError("proposal matches must cover every source exactly once")
    return sorted(output, key=lambda row: row["proposal_id"])


def validate_component_response(
    response: dict[str, Any],
    *,
    expected_source_ids: set[str],
    seed_type_ids: set[str],
    expected_parent_key: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if set(response) != {"groups"} or not isinstance(response.get("groups"), list):
        raise AlignmentContractError("component response must contain groups")
    fields = {
        "source_ids",
        "anchor_type_id",
        "criterion",
        "reason",
        "evidence",
    }
    source_errors: list[str] = []
    structurally_valid_sources: list[str] = []
    for index, row in enumerate(response["groups"]):
        if not isinstance(row, dict) or set(row) != fields:
            continue
        source_ids = row.get("source_ids")
        if not isinstance(source_ids, list) or not source_ids:
            source_errors.append(f"groups[{index}].source_ids is not a non-empty array")
            continue
        unknown = [source for source in source_ids if source not in expected_source_ids]
        if unknown:
            source_errors.append(
                f"groups[{index}].source_ids contains unknown IDs {unknown!r}"
            )
        structurally_valid_sources.extend(
            source for source in source_ids if source in expected_source_ids
        )
    duplicates = sorted(
        source
        for source in set(structurally_valid_sources)
        if structurally_valid_sources.count(source) > 1
    )
    missing = sorted(expected_source_ids - set(structurally_valid_sources))
    if duplicates:
        source_errors.append(f"duplicate source IDs {duplicates!r}")
    if missing:
        source_errors.append(f"missing source IDs {missing!r}")
    if source_errors:
        raise AlignmentContractError(
            "component source ID errors; use each source_family_ids entry exactly once: "
            + "; ".join(source_errors)
            + f"; exact source IDs are {sorted(expected_source_ids)!r}"
        )
    output: list[dict[str, Any]] = []
    seen: list[str] = []
    for row in response["groups"]:
        if not isinstance(row, dict) or set(row) != fields:
            raise AlignmentContractError("component group has unexpected fields")
        source_ids = row.get("source_ids")
        if not isinstance(source_ids, list) or not source_ids:
            raise AlignmentContractError("component source_ids are invalid")
        _validate_reason_and_evidence(row)
        anchors = set(source_ids) & seed_type_ids
        anchor_type_id = row.get("anchor_type_id")
        if anchors:
            if len(anchors) != 1 or anchor_type_id not in anchors:
                raise AlignmentContractError(
                    "component group must preserve exactly one frozen anchor"
                )
            if row.get("criterion") is not None:
                raise AlignmentContractError("anchored component cannot replace criterion")
            criterion = None
        else:
            if anchor_type_id is not None:
                raise AlignmentContractError("external component cannot name an anchor")
            criterion = normalize_family_criterion(row.get("criterion"))
            if expected_parent_key is not None and criterion_parent_key(
                criterion
            ) != criterion_parent_key(expected_parent_key):
                raise AlignmentContractError(
                    "component cannot move a leaf to a different parent criterion"
                )
        seen.extend(source_ids)
        output.append(
            {
                "source_ids": sorted(source_ids),
                "anchor_type_id": anchor_type_id,
                "criterion": criterion,
                "reason": row["reason"].strip(),
                "evidence": list(row["evidence"]),
            }
        )
    if len(seen) != len(set(seen)) or set(seen) != expected_source_ids:
        raise AlignmentContractError("component groups must cover every source exactly once")
    return sorted(output, key=lambda row: row["source_ids"])


def validate_singleton_response(
    response: dict[str, Any],
    *,
    expected_family_ids: set[str],
    allowed_candidate_ids: set[str],
    seed_type_ids: set[str],
    preferred_candidate_ids: Mapping[str, Sequence[str]] | None = None,
) -> list[dict[str, Any]]:
    if set(response) != {"assessments"} or not isinstance(
        response.get("assessments"), list
    ):
        raise AlignmentContractError("singleton response must contain assessments")
    fields = {
        "family_id",
        "verdict",
        "selected_id",
        "closest_candidate_ids",
        "distinguishing_reason",
        "evidence",
    }
    selection_errors: list[str] = []
    candidate_errors: list[str] = []
    for row in response["assessments"]:
        if not isinstance(row, dict) or set(row) != fields:
            continue
        family_id = row.get("family_id")
        if family_id not in expected_family_ids:
            continue
        verdict = row.get("verdict")
        selected_id = row.get("selected_id")
        if verdict == "matched" and selected_id == family_id:
            selection_errors.append(f"{family_id} selects itself")
        elif verdict == "matched" and selected_id not in allowed_candidate_ids:
            selection_errors.append(
                f"{family_id} selects unknown candidate {selected_id!r}"
            )
        elif verdict == "distinct" and selected_id is not None:
            selection_errors.append(
                f"{family_id} is distinct but selects {selected_id!r}"
            )
        closest = row.get("closest_candidate_ids")
        if not isinstance(closest, list):
            candidate_errors.append(
                f"{family_id} closest_candidate_ids is not an array"
            )
            continue
        invalid_closest = [
            candidate
            for candidate in closest
            if candidate not in allowed_candidate_ids or candidate == family_id
        ]
        if len(closest) != len(set(closest)) or invalid_closest:
            candidate_errors.append(
                f"{family_id} has invalid closest candidate IDs {invalid_closest!r}"
            )
        elif (
            verdict == "distinct"
            and allowed_candidate_ids - {family_id}
            and not closest
        ):
            candidate_errors.append(
                f"{family_id} is distinct but has no closest candidate ID"
            )
        elif verdict == "distinct" and preferred_candidate_ids:
            preferred = list(preferred_candidate_ids.get(family_id, []))
            if preferred and preferred[0] not in closest:
                candidate_errors.append(
                    f"{family_id} omits top-ranked candidate {preferred[0]}"
                )
    if selection_errors:
        raise AlignmentContractError(
            "singleton selection errors; correct every listed row in one response: "
            + "; ".join(selection_errors)
            + "; use only exact allowed_candidate_ids other than the source"
        )
    if candidate_errors:
        raise AlignmentContractError(
            "singleton candidate errors; correct every listed row in one response: "
            + "; ".join(candidate_errors)
            + "; choose one to three exact allowed_candidate_ids other than the source"
        )
    seen: list[str] = []
    output: list[dict[str, Any]] = []
    for row in response["assessments"]:
        if not isinstance(row, dict) or set(row) != fields:
            raise AlignmentContractError("singleton assessment has unexpected fields")
        family_id = row.get("family_id")
        if family_id not in expected_family_ids:
            raise AlignmentContractError("singleton assessment references unknown family")
        evidence = row.get("evidence")
        if not isinstance(evidence, list) or any(
            not isinstance(item, str) or not item.strip() for item in evidence
        ):
            raise AlignmentContractError("singleton evidence must be a string array")
        reason = row.get("distinguishing_reason")
        if not isinstance(reason, str) or not reason.strip():
            raise AlignmentContractError("singleton distinguishing reason must be non-empty")
        closest = row.get("closest_candidate_ids")
        if (
            not isinstance(closest, list)
            or len(closest) != len(set(closest))
            or any(
                candidate not in allowed_candidate_ids or candidate == family_id
                for candidate in closest
            )
        ):
            raise AlignmentContractError("singleton closest candidates are invalid")
        verdict = row.get("verdict")
        selected_id = row.get("selected_id")
        if verdict == "matched":
            if family_id in seed_type_ids and selected_id in seed_type_ids:
                raise AlignmentContractError("frozen NanoBot anchors cannot merge")
        elif verdict == "distinct":
            if selected_id is not None:
                raise AlignmentContractError("distinct singleton cannot select a candidate")
            if allowed_candidate_ids - {family_id} and not closest:
                raise AlignmentContractError(
                    "distinct singleton must identify its closest candidate"
                )
        else:
            raise AlignmentContractError(f"invalid singleton verdict: {verdict!r}")
        seen.append(family_id)
        output.append(
            {
                "family_id": family_id,
                "verdict": verdict,
                "selected_id": selected_id,
                "closest_candidate_ids": sorted(closest),
                "distinguishing_reason": reason.strip(),
                "evidence": list(evidence),
            }
        )
    if len(seen) != len(set(seen)) or set(seen) != expected_family_ids:
        raise AlignmentContractError(
            "singleton assessments must cover every source exactly once"
        )
    return sorted(output, key=lambda row: row["family_id"])


def validate_final_artifacts(
    catalog: dict[str, Any],
    mappings: Sequence[dict[str, Any]],
    capability_observations: Sequence[dict[str, Any]],
    singleton_audits: Sequence[dict[str, Any]],
    criterion_support: Sequence[dict[str, Any]],
    oracle_inheritance: Sequence[dict[str, Any]],
    *,
    expected_handler_ids: set[str] | None = None,
) -> None:
    catalog_schema = json.loads(
        (SCHEMA_DIR / "handler-type-catalog-v4.schema.json").read_text(encoding="utf-8")
    )
    mapping_schema = json.loads(
        (SCHEMA_DIR / "handler-type-mapping-v2.schema.json").read_text(encoding="utf-8")
    )
    observation_schema = json.loads(
        (SCHEMA_DIR / "handler-type-capability-observation-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    singleton_schema = json.loads(
        (SCHEMA_DIR / "handler-type-singleton-audit-v2.schema.json").read_text(
            encoding="utf-8"
        )
    )
    support_schema = json.loads(
        (SCHEMA_DIR / "handler-criterion-support-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    inheritance_schema = json.loads(
        (SCHEMA_DIR / "handler-oracle-inheritance-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validate_schema(instance=catalog, schema=catalog_schema)
    for mapping in mappings:
        validate_schema(instance=mapping, schema=mapping_schema)
    for observation in capability_observations:
        validate_schema(instance=observation, schema=observation_schema)
    for audit in singleton_audits:
        validate_schema(instance=audit, schema=singleton_schema)
    for support in criterion_support:
        validate_schema(instance=support, schema=support_schema)
    for inheritance in oracle_inheritance:
        validate_schema(instance=inheritance, schema=inheritance_schema)
    ids = [row["handler_id"] for row in mappings]
    if len(ids) != len(set(ids)):
        raise AlignmentContractError("final mappings contain duplicate handlers")
    if expected_handler_ids is not None and set(ids) != expected_handler_ids:
        raise AlignmentContractError("final mappings do not exactly cover eligible handlers")
    type_ids = {row["handler_type_id"] for row in catalog["types"]}
    if len(type_ids) != len(catalog["types"]):
        raise AlignmentContractError("catalog contains duplicate handler type IDs")
    criteria_by_id = {
        row["handler_criterion_id"]: row for row in catalog["criteria"]
    }
    if len(criteria_by_id) != len(catalog["criteria"]):
        raise AlignmentContractError("catalog contains duplicate handler criterion IDs")
    if any(row["handler_type_id"] not in type_ids for row in mappings):
        raise AlignmentContractError("final mapping references unknown catalog type")
    observation_ids = [row["handler_type_id"] for row in capability_observations]
    if len(observation_ids) != len(set(observation_ids)) or set(observation_ids) != type_ids:
        raise AlignmentContractError(
            "capability observations must cover every handler type exactly once"
        )
    member_to_type: dict[str, str] = {}
    member_to_criterion: dict[str, str] = {}
    types_by_criterion: dict[str, set[str]] = {
        criterion_id: set() for criterion_id in criteria_by_id
    }
    singleton_ids: set[str] = set()
    for handler_type in catalog["types"]:
        handler_type_id = handler_type["handler_type_id"]
        criterion_id = handler_type["handler_criterion_id"]
        if criterion_id not in criteria_by_id:
            raise AlignmentContractError(
                f"{handler_type_id}: references unknown parent criterion"
            )
        normalized = normalize_criterion(handler_type["criterion"])
        if stable_type_id(normalized) != handler_type_id:
            raise AlignmentContractError(
                f"{handler_type_id}: ID does not match canonical intent key"
            )
        if stable_criterion_id(normalized) != criterion_id:
            raise AlignmentContractError(
                f"{handler_type_id}: parent ID does not match canonical axes"
            )
        types_by_criterion[criterion_id].add(handler_type_id)
        if handler_type["representative_handler"] not in handler_type["members"]:
            raise AlignmentContractError(
                f"{handler_type_id}: representative must be a type member"
            )
        signature_members = {
            member
            for signature in normalized["role_signatures"]
            for member in signature["members"]
        }
        if signature_members != set(handler_type["members"]):
            raise AlignmentContractError(
                f"{handler_type_id}: role signatures do not cover type members"
            )
        if len(handler_type["members"]) == 1:
            singleton_ids.add(handler_type_id)
        for member in handler_type["members"]:
            if member in member_to_type:
                raise AlignmentContractError(
                    f"catalog member belongs to multiple types: {member}"
                )
            member_to_type[member] = handler_type_id
            member_to_criterion[member] = criterion_id
    for criterion_id, criterion in criteria_by_id.items():
        parent_key = criterion_parent_key(criterion)
        if stable_criterion_id(parent_key) != criterion_id:
            raise AlignmentContractError(
                f"{criterion_id}: ID does not match canonical parent axes"
            )
        if set(criterion["child_type_ids"]) != types_by_criterion[criterion_id]:
            raise AlignmentContractError(
                f"{criterion_id}: child type IDs do not exactly cover its leaves"
            )
        child_members = {
            member
            for handler_type in catalog["types"]
            if handler_type["handler_criterion_id"] == criterion_id
            for member in handler_type["members"]
        }
        if child_members != set(criterion["members"]):
            raise AlignmentContractError(
                f"{criterion_id}: members do not exactly cover child leaves"
            )
        if criterion["representative_handler"] not in child_members:
            raise AlignmentContractError(
                f"{criterion_id}: representative must be a criterion member"
            )
    mapping_members = {
        f"{row['project']}:{row['handler_id']}": row["handler_type_id"]
        for row in mappings
    }
    if member_to_type != mapping_members:
        raise AlignmentContractError(
            "catalog members do not exactly match final handler mappings"
        )
    mapping_criteria = {
        f"{row['project']}:{row['handler_id']}": row["handler_criterion_id"]
        for row in mappings
    }
    if member_to_criterion != mapping_criteria:
        raise AlignmentContractError(
            "mapping parent criteria do not exactly match catalog membership"
        )
    audited_final_ids = [row["final_handler_type_id"] for row in singleton_audits]
    if len(audited_final_ids) != len(set(audited_final_ids)):
        raise AlignmentContractError("singleton audit contains duplicate final types")
    if set(audited_final_ids) != singleton_ids:
        raise AlignmentContractError(
            "singleton audit must cover every final singleton type exactly once"
        )
    if any(row["verdict"] != "distinct" for row in singleton_audits):
        raise AlignmentContractError("final singleton audits must be distinct verdicts")
    type_by_id = {row["handler_type_id"]: row for row in catalog["types"]}
    for audit in singleton_audits:
        handler_type = type_by_id[audit["final_handler_type_id"]]
        criterion_id = handler_type["handler_criterion_id"]
        if audit["handler_criterion_id"] != criterion_id:
            raise AlignmentContractError("singleton audit parent criterion mismatch")
        expected_siblings = set(criteria_by_id[criterion_id]["child_type_ids"]) - {
            audit["final_handler_type_id"]
        }
        has_sibling = bool(expected_siblings)
        candidate_ids = set(audit["candidate_family_ids"])
        if not set(audit["closest_candidate_ids"]) <= candidate_ids:
            raise AlignmentContractError(
                "singleton closest candidates must be covered sibling leaves"
            )
        if audit["coverage_kind"] == "no-sibling-candidate":
            if has_sibling or audit["candidate_family_ids"] or audit[
                "closest_candidate_ids"
            ]:
                raise AlignmentContractError(
                    "no-sibling singleton audit must have an empty sibling boundary"
                )
        elif audit["coverage_kind"] == "complete-sibling-catalog":
            if not has_sibling or candidate_ids != expected_siblings:
                raise AlignmentContractError(
                    "complete sibling audit must enumerate every final sibling leaf"
                )

    support_by_id = {
        row["handler_criterion_id"]: row for row in criterion_support
    }
    if len(support_by_id) != len(criterion_support) or set(support_by_id) != set(
        criteria_by_id
    ):
        raise AlignmentContractError(
            "criterion support must cover every criterion exactly once"
        )
    for criterion_id, support in support_by_id.items():
        criterion = criteria_by_id[criterion_id]
        members = sorted(criterion["members"])
        projects = sorted({member.split(":", 1)[0] for member in members})
        expected_support = "singleton" if len(members) == 1 else "multi"
        if (
            support["handler_count"] != len(members)
            or support["leaf_type_count"] != len(criterion["child_type_ids"])
            or support["project_count"] != len(projects)
            or support["projects"] != projects
            or support["members"] != members
            or support["support"] != expected_support
        ):
            raise AlignmentContractError(
                f"{criterion_id}: criterion support counts do not match the catalog"
            )

    inheritance_by_type = {
        row["handler_type_id"]: row for row in oracle_inheritance
    }
    if len(inheritance_by_type) != len(oracle_inheritance) or set(
        inheritance_by_type
    ) != type_ids:
        raise AlignmentContractError(
            "oracle inheritance must cover every leaf type exactly once"
        )
    for handler_type_id, inheritance in inheritance_by_type.items():
        criterion_id = type_by_id[handler_type_id]["handler_criterion_id"]
        if (
            inheritance["handler_criterion_id"] != criterion_id
            or inheritance["inheritance_order"]
            != [criterion_id, handler_type_id]
        ):
            raise AlignmentContractError(
                f"{handler_type_id}: invalid parent-to-leaf inheritance order"
            )

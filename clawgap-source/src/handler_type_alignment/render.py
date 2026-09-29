"""Markdown rendering for the cross-project handler-family catalog."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Sequence

from .contracts import AlignmentContractError
from .inputs import HandlerProfile


def _member_key(profile: HandlerProfile) -> str:
    return f"{profile.project_id}:{profile.handler_id}"


def render_alignment_index(
    generation_command: str,
    catalog: dict[str, Any],
    mappings: Sequence[dict[str, Any]],
    excluded: Sequence[dict[str, str]],
    profiles: Sequence[HandlerProfile],
    capability_observations: Sequence[dict[str, Any]],
    singleton_audits: Sequence[dict[str, Any]],
    criterion_support: Sequence[dict[str, Any]],
) -> str:
    functions_by_member: dict[str, list[str]] = {}
    for profile in profiles:
        member = _member_key(profile)
        functions = sorted(
            {
                f"{profile.project_id}:{profile.tool['tool_name']}::"
                f"{handler['handler_func']}"
                for handler in profile.tool.get("handlers", [])
                if isinstance(handler, dict)
                and isinstance(handler.get("handler_func"), str)
                and handler["handler_func"]
            }
        )
        if not functions:
            raise AlignmentContractError(
                f"{member}: no concrete handler function to render"
            )
        if member in functions_by_member:
            raise AlignmentContractError(f"duplicate handler profile: {member}")
        functions_by_member[member] = functions

    mappings_by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
    members_by_type: dict[str, list[str]] = defaultdict(list)
    for mapping in mappings:
        mappings_by_project[mapping["project"]].append(mapping)
        members_by_type[mapping["handler_type_id"]].append(
            f"{mapping['project']}:{mapping['handler_id']}"
        )
    unresolved_by_project: dict[str, int] = defaultdict(int)
    for row in excluded:
        unresolved_by_project[row["project"]] += 1
    project_ids = sorted(set(mappings_by_project) | set(unresolved_by_project))
    observation_by_type = {
        row["handler_type_id"]: row for row in capability_observations
    }
    singleton_by_type = {
        row["final_handler_type_id"]: row for row in singleton_audits
    }
    singleton_types = sum(len(row["members"]) == 1 for row in catalog["types"])
    singleton_criteria = sum(len(row["members"]) == 1 for row in catalog["criteria"])
    support_by_criterion = {
        row["handler_criterion_id"]: row for row in criterion_support
    }

    lines = [
        "# Cross-Project Handler-Type Alignment",
        "",
        f"> Generation command: `{generation_command}`",
        "",
        f"Criteria: **{len(catalog['criteria'])}**; leaf variants: "
        f"**{len(catalog['types'])}**; resolved handler mappings: "
        f"**{len(mappings)}**; unresolved handler specifications: "
        f"**{len(excluded)}**; singleton criteria: **{singleton_criteria}**; "
        f"singleton leaves: **{singleton_types}**.",
        "",
        "Each deterministic `HC-*` criterion hashes operation/resource/effect. Precise "
        "user-visible actions remain `HT-*` leaves and retain intent/operation/resource/"
        "effect identity. Reconciliation and singleton challenges use only the complete "
        "sibling catalog under one parent; role signatures remain metadata.",
        "",
        "Reachable sink capability classes are attached afterward as deterministic "
        "observations. They never enter handler-family prompts or type identities, and "
        "`no-reachable-sink` is not a no-security-impact verdict.",
        "",
        "## Project Summary",
        "",
        "| Project | Resolved handlers | Distinct criteria | Distinct leaf variants | Unresolved |",
        "|---|---:|---:|---:|---:|",
    ]
    for project_id in project_ids:
        project_mappings = mappings_by_project.get(project_id, [])
        lines.append(
            f"| `{project_id}` | {len(project_mappings)} | "
            f"{len({row['handler_criterion_id'] for row in project_mappings})} | "
            f"{len({row['handler_type_id'] for row in project_mappings})} | "
            f"{unresolved_by_project.get(project_id, 0)} |"
        )
    lines.extend(
        [
            "",
            "## Handler Criteria",
            "",
            "| Criterion | Label | Axes | Child leaves | Handlers | Projects | Support |",
            "|---|---|---|---:|---:|---:|---|",
        ]
    )
    for row in catalog["criteria"]:
        support = support_by_criterion[row["handler_criterion_id"]]
        axes = (
            f"{row['operation_family']}/{row['resource_family']}/{row['effect']}"
        )
        lines.append(
            f"| `{row['handler_criterion_id']}` | `{row['canonical_label']}` | "
            f"`{axes}` | {len(row['child_type_ids'])} | {len(row['members'])} | "
            f"{support['project_count']} | `{support['support']}` |"
        )
    lines.extend(
        [
            "",
            "## Handler Intent Leaves",
            "",
            "| Type | Parent criterion | Family | Intent key | Role variants | Origin | Representative | "
            "Members | Capability observation | Singleton justification | "
            "Concrete handler functions |",
            "|---|---|---|---|---|---|---|---:|---|---|---|",
        ]
    )
    for row in catalog["types"]:
        handler_type_id = row["handler_type_id"]
        mapped_members = members_by_type.get(handler_type_id, [])
        if set(row["members"]) != set(mapped_members):
            raise AlignmentContractError(
                f"{handler_type_id}: catalog and mapping members differ"
            )
        functions = sorted(
            {
                function
                for member in mapped_members
                for function in functions_by_member[member]
            }
        )
        criterion = row["criterion"]
        intent_key = (
            f"{criterion['intent_family']}/{criterion['operation_family']}/"
            f"{criterion['resource_family']}/{criterion['effect']}"
        )
        role_variants = "<br>".join(
            (
                f"core=[{','.join(signature['core_roles']) or '-'}]; "
                f"optional=[{','.join(signature['optional_roles']) or '-'}]"
            )
            for signature in criterion["role_signatures"]
        )
        observation = observation_by_type[handler_type_id]
        capabilities = ", ".join(observation["observed_capability_classes"]) or "none"
        capability_text = f"{observation['status']}: {capabilities}"
        lines.append(
            f"| `{handler_type_id}` | `{row['handler_criterion_id']}` | "
            f"`{criterion['canonical_label']}` | "
            f"`{intent_key}` | {role_variants} | `{row['origin']}` | "
            f"`{row['representative_handler']}` | {len(row['members'])} | "
            f"{capability_text} | "
            f"{singleton_by_type.get(handler_type_id, {}).get('distinguishing_reason', '-')} | "
            + "<br>".join(f"`{function}`" for function in functions)
            + " |"
        )
    return "\n".join(lines) + "\n"

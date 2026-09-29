"""Markdown report for the HC-conditioned global sink catalog."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Sequence


def render_alignment_index(
    generation_command: str,
    catalog: dict[str, Any],
    mappings: Sequence[dict[str, Any]],
    assessments: Sequence[dict[str, Any]],
    exclusions: Sequence[dict[str, Any]],
    handler_sink_groups: Sequence[dict[str, Any]],
) -> str:
    mappings_by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
    exclusions_by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in mappings:
        mappings_by_project[row["project"]].append(row)
    for row in exclusions:
        exclusions_by_project[row["project"]].append(row)
    projects = sorted(set(mappings_by_project) | set(exclusions_by_project))
    assessment_by_id = {row["target_id"]: row for row in assessments}
    lines = [
        "# Cross-Project Sink-Type Alignment",
        "",
        f"> Generation command: `{generation_command}`",
        "",
        "## Automatically Generated Results",
        "",
        "The following block is generated from revision-bound handler mappings, structural "
        "chains, semantic IR, sink constraints, and capability cards.",
        "",
        f"<!-- BEGIN GENERATED SINK-TYPE REPORT: {generation_command} -->",
        "",
        f"Global sink types: **{len(catalog['sink_types'])}**; ST-aligned security chains: "
        f"**{len(mappings)}**; terminal no-impact grouped chains: "
        f"**{sum(row['chain_count'] for row in handler_sink_groups if row['group_scope'] == 'no-security-impact')}**; "
        f"unique HC/sink assessments: **{len(assessments)}**; ungrouped structural chains: "
        f"**{sum(row['reason_code'] != 'impact-pruned' for row in exclusions)}**.",
        "",
        "`HC-*` is the public handler axis. `HT-*` is retained in mappings only as trace "
        "metadata. `ST-*` identities are global and may be associated with multiple HCs.",
        "Confirmed no-security-impact chains are grouped under `(HC, no-security-impact)` "
        "for accounting and are explicitly ineligible for the downstream security oracle.",
        "",
        "## Project Summary",
        "",
        "| Project | ST-aligned chains | Assessed HC/sinks | Distinct HCs | Distinct STs | Excluded from ST |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for project in projects:
        rows = mappings_by_project.get(project, [])
        lines.append(
            f"| `{project}` | {len(rows)} | "
            f"{len({row['target_id'] for row in rows})} | "
            f"{len({row['handler_criterion_id'] for row in rows})} | "
            f"{len({row['sink_type_id'] for row in rows})} | "
            f"{len(exclusions_by_project.get(project, []))} |"
        )
    lines.extend(
        [
            "",
            "## Handler-to-Sink Groups",
            "",
            "| Group | Scope | HC | ST | Chains | Projects | Handlers | Sinks | Downstream oracle |",
            "|---|---|---|---|---:|---|---|---|---|",
        ]
    )
    for row in handler_sink_groups:
        sink_type = f"`{row['sink_type_id']}`" if row["sink_type_id"] else "-"
        lines.append(
            f"| `{row['handler_sink_group_id']}` | `{row['group_scope']}` | "
            f"`{row['handler_criterion_id']}` | "
            f"{sink_type} | "
            f"{row['chain_count']} | {', '.join(row['projects'])} | "
            f"{', '.join(f'`{item}`' for item in row['handler_names'])} | "
            f"{', '.join(f'`{item}`' for item in row['sink_names'])} | "
            f"{'yes' if row['downstream_oracle_eligible'] else 'no'} |"
        )
    distribution: dict[tuple[str, int], int] = defaultdict(int)
    for row in handler_sink_groups:
        distribution[(row["group_scope"], row["chain_count"])] += 1
    lines.extend(
        [
            "",
            "## Handler-to-Sink Group-Size Distribution",
            "",
            "| Scope | Chains per group | Groups |",
            "|---|---:|---:|",
        ]
    )
    for (scope, chain_count), group_count in sorted(distribution.items()):
        lines.append(f"| `{scope}` | {chain_count} | {group_count} |")
    lines.extend(
        [
            "",
            "## Global Sink Types",
            "",
            "| Sink type | Label | Capability family | Facets | Controlled roles | Defaults | Call shape | HCs | Targets | Representative |",
            "|---|---|---|---|---|---|---|---:|---:|---|",
        ]
    )
    for row in catalog["sink_types"]:
        criterion = row["criterion"]
        lines.append(
            f"| `{row['sink_type_id']}` | `{criterion['canonical_label']}` | "
            f"`{criterion['capability_family']}` | "
            f"{', '.join(criterion['capability_facets']) or '-'} | "
            f"{', '.join(criterion['controlled_parameter_roles']) or '-'} | "
            f"{', '.join(criterion['implicit_default_facets']) or '-'} | "
            f"`{criterion['call_shape_family']}` | "
            f"{len(row['associated_handler_criterion_ids'])} | {len(row['members'])} | "
            f"`{row['representative_sink']}` |"
        )
    lines.extend(
        [
            "",
            "## HC/Sink Assessments",
            "",
            "| Target | Project | HC | Trace HTs | Sink | Chains | Decision | ST | Representative | Reason |",
            "|---|---|---|---|---|---:|---|---|---|---|",
        ]
    )
    for row in assessments:
        lines.append(
            f"| `{row['target_id']}` | `{row['project']}` | "
            f"`{row['handler_criterion_id']}` | "
            f"{', '.join(f'`{item}`' for item in row['handler_type_ids'])} | "
            f"`{row['sink_id']}` | {len(row['chain_ids'])} | `{row['decision']}` | "
            f"`{row['sink_type_id']}` | `{row['reference_sink']}` | {row['reason']} |"
        )
    lines.extend(
        [
            "",
            "## Chain Mappings",
            "",
            "| Project | Chain | HC | Trace HT | Sink | ST | Decision |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for row in mappings:
        assessment = assessment_by_id[row["target_id"]]
        if assessment["sink_type_id"] != row["sink_type_id"]:
            raise ValueError("mapping/assessment sink type mismatch while rendering")
        lines.append(
            f"| `{row['project']}` | `{row['chain_id']}` | "
            f"`{row['handler_criterion_id']}` | `{row['handler_type_id']}` | "
            f"`{row['sink_id']}` | `{row['sink_type_id']}` | `{row['decision']}` |"
        )
    lines.extend(
        [
            "",
            "## Excluded from ST Inference",
            "",
            "`impact-pruned` rows are still present in terminal no-impact groups above; "
            "they are excluded only from ST inference and the downstream security oracle.",
            "",
            "| Project | Chain | Tool | Sink | Reason | Terminal grouped | Detail |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for row in exclusions:
        lines.append(
            f"| `{row['project']}` | `{row['chain_id']}` | `{row['tool_name']}` | "
            f"`{row['sink_id']}` | `{row['reason_code']}` | "
            f"{'yes' if row['reason_code'] == 'impact-pruned' else 'no'} | "
            f"{row['detail']} |"
        )
    lines.extend(["", "<!-- END GENERATED SINK-TYPE REPORT -->", ""])
    return "\n".join(lines)

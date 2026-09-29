"""Markdown index for generated HC/ST group oracles."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping, Sequence


def render_oracle_index(
    *,
    generation_command: str,
    oracles: Sequence[Mapping[str, Any]],
    exclusions: Sequence[Mapping[str, Any]],
    proposals: Sequence[Mapping[str, Any]],
    evidence_index: Mapping[str, Any],
) -> str:
    groups_by_project: dict[str, set[str]] = defaultdict(set)
    chains_by_project: dict[str, int] = defaultdict(int)
    requirements_by_project: dict[str, set[str]] = defaultdict(set)
    for oracle in oracles:
        projects = {row["project"] for row in oracle["member_chain_refs"]}
        for project in projects:
            groups_by_project[project].add(oracle["group_id"])
            chains_by_project[project] += sum(
                row["project"] == project for row in oracle["member_chain_refs"]
            )
            requirements_by_project[project].update(
                row["requirement_id"] for row in oracle["requirements"]
            )
    lines = [
        "# HC-Conditioned Group Oracles",
        "",
        f"> Generation command: `{generation_command}`",
        "",
        "## Automatically Generated Results",
        "",
        f"Group oracles: **{len(oracles)}**; eligible chains: "
        f"**{sum(len(row['member_chain_refs']) for row in oracles)}**; committed "
        f"requirements: **{sum(len(row['requirements']) for row in oracles)}** "
        f"({len({item['requirement_id'] for row in oracles for item in row['requirements']})} "
        "distinct); no-security-impact groups excluded: "
        f"**{len(exclusions)}**; proposals assessed: **{len(proposals)}**; pinned "
        f"evidence records: **{len(evidence_index['evidence'])}**.",
        "",
        "`HC-*` is the public handler criterion, `ST-*` is the global sink type, and "
        "`HSG-*` is the exact downstream group. `HT-*` is not an oracle axis.",
        "",
        "## Project Projection",
        "",
        "| Project | Eligible groups | Eligible chains | Distinct requirements |",
        "|---|---:|---:|---:|",
    ]
    for project in sorted(groups_by_project):
        lines.append(
            f"| `{project}` | {len(groups_by_project[project])} | "
            f"{chains_by_project[project]} | {len(requirements_by_project[project])} |"
        )
    lines.extend(
        [
            "",
            "## Group Oracles",
            "",
            "| Group | HC | ST | Status | Chains | Seed | Requirements | Rejected proposals |",
            "|---|---|---|---|---:|---|---:|---:|",
        ]
    )
    for row in oracles:
        seed = row["seed"]
        lines.append(
            f"| `{row['group_id']}` | `{row['handler_criterion_id']}` | "
            f"`{row['sink_type_id']}` | `{row['status']}` | "
            f"{len(row['member_chain_refs'])} | "
            f"`{seed['project']}:{seed['chain_id']}` | {len(row['requirements'])} | "
            f"{len(row['rejected_proposal_ids'])} |"
        )
    lines.extend(
        [
            "",
            "## Requirements",
            "",
            "| Group | Requirement | Dimension | Rule | Applicability | Evidence | Origins |",
            "|---|---|---|---|---|---:|---:|",
        ]
    )
    for oracle in oracles:
        for row in oracle["requirements"]:
            lines.append(
                f"| `{oracle['group_id']}` | `{row['requirement_id']}` | "
                f"`{row['dimension']}` | {row['rule']} | {row['applicability']} | "
                f"{len(row['evidence_ids'])} | {len(row['origin_chain_refs'])} |"
            )
    lines.extend(
        [
            "",
            "## Excluded No-Security-Impact Groups",
            "",
            "| Group | HC | Chains | Projects | Reason |",
            "|---|---|---:|---|---|",
        ]
    )
    for row in exclusions:
        projects = sorted({ref["project"] for ref in row["chain_refs"]})
        lines.append(
            f"| `{row['group_id']}` | `{row['handler_criterion_id']}` | "
            f"{row['chain_count']} | {', '.join(projects)} | `{row['reason_code']}` |"
        )
    lines.extend(
        [
            "",
            "No excluded group is sent to seed profiling, peer extension, evidence "
            "validation, or any later coverage-comparison stage.",
            "",
        ]
    )
    return "\n".join(lines)

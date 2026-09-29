"""Human-readable index for generated chain-to-oracle comparisons."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Mapping, Sequence


def render_coverage_index(
    *,
    generation_command: str,
    comparisons: Sequence[Mapping[str, Any]],
    assessments: Sequence[Mapping[str, Any]],
    candidates: Sequence[Mapping[str, Any]],
    exclusions: Sequence[Mapping[str, Any]],
    challenges: Sequence[Mapping[str, Any]] = (),
    source_validations: Sequence[Mapping[str, Any]] = (),
) -> str:
    by_project: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    groups_by_project: dict[str, set[str]] = defaultdict(set)
    for row in comparisons:
        by_project[row["project"]]["chains"] += 1
        groups_by_project[row["project"]].add(row["group_id"])
    for row in assessments:
        by_project[row["project"]]["assessments"] += 1
        by_project[row["project"]][row["decision"]] += 1
    for row in candidates:
        by_project[row["project"]]["candidates"] += 1
    for row in exclusions:
        by_project[row["project"]]["excluded"] += 1
    decisions = Counter(row["decision"] for row in assessments)
    statuses = Counter(row["status"] for row in comparisons)
    lines = [
        "# Chain-to-Oracle Coverage Comparison",
        "",
        f"> Generation command: `{generation_command}`",
        "",
        "## Automatically Generated Results",
        "",
        f"Eligible comparisons: **{len(comparisons)}**; requirement assessments: "
        f"**{len(assessments)}**; candidates: **{len(candidates)}**; upstream "
        f"exclusions: **{len(exclusions)}**.",
        "",
        "The group oracle supplies normative requirements. The verified existing "
        "sink-capability card supplies concrete execution-capability facts and refines "
        "applicability; it never creates requirements.",
        "",
        "Comparison status: "
        + ", ".join(f"`{key}` **{value}**" for key, value in sorted(statuses.items()))
        + ". Requirement decisions: "
        + ", ".join(f"`{key}` **{value}**" for key, value in sorted(decisions.items()))
        + ".",
        "",
        "## Project Projection",
        "",
        "| Project | HSG groups | Chains | Assessments | Covered | Wrong-Check | Missing-Check | Not applicable | Unknown | Candidates | Excluded |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    if challenges:
        challenge_counts = Counter(row["disposition"] for row in challenges)
        lines[8:8] = [
            "Challenge pass: "
            + ", ".join(
                f"`{key}` **{value}**"
                for key, value in sorted(challenge_counts.items())
            )
            + ".",
            "",
        ]
    if source_validations:
        validation_counts = Counter(row["disposition"] for row in source_validations)
        rank_counts = Counter(
            row["review_priority"]
            for row in source_validations
            if row["review_priority"] is not None
        )
        lines[8:8] = [
            "Blind source validation: "
            + ", ".join(
                f"`{key}` **{value}**"
                for key, value in sorted(validation_counts.items())
            )
            + ". Survivor priority: "
            + (
                ", ".join(
                    f"`{key}` **{value}**" for key, value in sorted(rank_counts.items())
                )
                if rank_counts
                else "none"
            )
            + ".",
            "",
        ]
    projects = sorted(set(by_project) | set(groups_by_project))
    for project in projects:
        row = by_project[project]
        lines.append(
            f"| `{project}` | {len(groups_by_project[project])} | {row['chains']} | "
            f"{row['assessments']} | {row['covered']} | {row['wrong-check']} | "
            f"{row['missing-check']} | {row['not-applicable']} | {row['unknown']} | "
            f"{row['candidates']} | {row['excluded']} |"
        )
    lines.extend(
        [
            "",
            "## Candidates",
            "",
            "| Candidate | Project | Group | Chain | Requirement | Failure mode | Gates | Upstream status |",
            "|---|---|---|---|---|---|---:|---|",
        ]
    )
    for row in candidates:
        upstream = f"{row['group_oracle_status']}/{row['semantic_ir_status']}"
        lines.append(
            f"| `{row['candidate_id']}` | `{row['project']}` | `{row['group_id']}` | "
            f"`{row['chain_id']}` | `{row['requirement_id']}` | "
            f"`{row['failure_mode']}` | {len(row['gate_ids'])} | `{upstream}` |"
        )
    lines.extend(
        [
            "",
            "Partial comparisons assess committed evidence-backed requirements but do "
            "not prove that the upstream oracle or chain is exhaustive. Inconclusive "
            "comparisons have no committed requirement and do not create candidates.",
            "",
        ]
    )
    return "\n".join(lines)


def render_candidate_ranking(
    *,
    generation_command: str,
    source_validations: Sequence[Mapping[str, Any]],
) -> str:
    """Render all source-validation dispositions and ranked survivors."""

    priority_order = {"high": 0, "medium": 1, "low": 2, None: 3}
    ordered = sorted(
        source_validations,
        key=lambda row: (
            priority_order[row["review_priority"]],
            row["project"],
            row["chain_id"],
            row["provisional_candidate_id"],
        ),
    )
    dispositions = Counter(row["disposition"] for row in ordered)
    priorities = Counter(
        row["review_priority"] for row in ordered if row["review_priority"] is not None
    )
    lines = [
        "# Blind Source-Validated Candidate Ranking",
        "",
        f"> Generation command: `{generation_command}`",
        "",
        "## Automatically Generated Results",
        "",
        "Validation dispositions: "
        + ", ".join(
            f"`{key}` **{value}**" for key, value in sorted(dispositions.items())
        )
        + ". Survivor priorities: "
        + (
            ", ".join(
                f"`{key}` **{value}**" for key, value in sorted(priorities.items())
            )
            if priorities
            else "none"
        )
        + ".",
        "",
        "Only `confirmed` rows remain in canonical `candidates.jsonl`. Refuted and "
        "unknown provisional candidates remain here and in `candidate-validations.jsonl` "
        "for auditability.",
        "",
        "| Candidate | Project | Chain | Verdict | Final decision | Priority | Evidence | Reason |",
        "|---|---|---|---|---|---|---:|---|",
    ]
    for row in ordered:
        reason = str(row["reason"]).replace("|", "\\|")
        lines.append(
            f"| `{row['provisional_candidate_id']}` | `{row['project']}` | "
            f"`{row['chain_id']}` | `{row['verdict']}` | "
            f"`{row['final_assessment']['decision']}` | "
            f"`{row['review_priority'] or '--'}` | {len(row['source_evidence'])} | "
            f"{reason} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_precision_audit(
    *,
    generation_command: str,
    sample: Sequence[Mapping[str, Any]],
    source_validations: Sequence[Mapping[str, Any]],
) -> str:
    """Render the state of the independent blind precision sample."""

    labels = Counter(row["blind_adjudication"] or "pending" for row in sample)
    validation_by_id = {
        row["provisional_candidate_id"]: row for row in source_validations
    }
    retained = sum(
        validation_by_id.get(row["candidate_id"], {}).get("disposition") == "confirmed"
        for row in sample
    )
    lines = [
        "# Blind Candidate Precision Audit",
        "",
        f"> Generation command: `{generation_command}`",
        "",
        "## Automatically Generated Sample State",
        "",
        f"Deterministic sample: **{len(sample)}** provisional candidates; "
        f"source-validator survivors in sample: **{retained}**.",
        "",
        "Independent source labels: "
        + ", ".join(f"`{key}` **{value}**" for key, value in sorted(labels.items()))
        + ".",
        "",
    ]
    pending = labels.get("pending", 0)
    if pending:
        lines.extend(
            [
                "Measured precision is intentionally not reported: "
                f"**{pending}** sampled candidates still require independent blind "
                "source adjudication. Populate only `blind_adjudication`, "
                "`adjudication_reason`, and `source_evidence` without consulting curated "
                "ground-truth reports.",
                "",
            ]
        )
    else:
        valid = labels.get("valid", 0)
        false_positive = labels.get("false-positive", 0)
        denominator = valid + false_positive
        precision = valid / denominator if denominator else 0.0
        lines.extend(
            [
                f"Adjudicated provisional precision: **{valid}/{denominator} "
                f"({precision:.1%})**; unknown labels: **{labels.get('unknown', 0)}**.",
                "",
                "This report does not use curated ground truth; strict known-vulnerability "
                "recall is measured separately after blind publication.",
                "",
            ]
        )
    return "\n".join(lines)

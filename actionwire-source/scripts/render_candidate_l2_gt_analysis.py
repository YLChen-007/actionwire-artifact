#!/usr/bin/env python3
"""Render report-level accounting for the canonical 78-candidate L2 campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CANDIDATES = REPO_ROOT / "output/cross-project/coverage-comparison/candidates.jsonl"
DEFAULT_CAMPAIGN = REPO_ROOT / "output/cross-project/runtime-auto-l2"
DEFAULT_OUT = REPO_ROOT / "output/cross-project/runtime-auto-l2-gt-analysis-v1"
ANALYSIS_SCHEMA = "clawgap-auto-l2-gt-analysis/v1"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.runtime_validation.candidate_l2_projection import (  # noqa: E402
    identify_ground_truth,
    project_ground_truth,
)

PROJECT_ADAPTER_STATUS = {
    "mercury-agent": "project-native-candidate-adapter-registered",
    "droidclaw": "targeted-l2-exists-but-candidate-cli-does-not-register-it",
    "lettabot": "targeted-l2-exists-but-candidate-cli-does-not-register-it",
}
SOURCE_REVISED_NATIVE_REPORT_IDS = {
    "GT-0d6ed4cec085773c",
    "GT-c6a9e97a28acf193",
    "GT-f1647abba5c44969",
    "GT-e03e7f2d88091689",
}


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{number}: expected JSON object")
        rows.append(value)
    return rows


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[Mapping[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(args: argparse.Namespace) -> str:
    def display(path: Path) -> str:
        try:
            return str(path.resolve().relative_to(REPO_ROOT))
        except ValueError:
            return str(path.resolve())

    command = (
        "python scripts/render_candidate_l2_gt_analysis.py "
        f"--candidates {display(args.candidates)} "
        f"--campaign {display(args.campaign)} --out-dir {display(args.out_dir)}"
    )
    overlays = getattr(args, "additive_overlay_dirs", None) or []
    for overlay in overlays:
        command += f" --additive-overlay-dir {display(overlay)}"
    source_revised = getattr(args, "source_revised_dir", None)
    if source_revised is not None:
        command += f" --source-revised-dir {display(source_revised)}"
    return command


def report_reason(
    project: str,
    classification: str,
    linked: list[dict[str, Any]],
    missing_ids: list[str],
    boundary_status: str,
) -> tuple[str, str]:
    if classification == "runtime-confirmed":
        confirmed = [row["candidate_id"] for row in linked if row["disposition"] == "runtime-confirmed"]
        return (
            "runtime-confirmed",
            "At least one linked candidate completed three healthy exploit/control pairs and satisfied the deterministic oracle: "
            + ", ".join(confirmed)
            + ".",
        )
    if classification == "candidate-missing":
        return (
            "candidate-missing",
            "The eligible report is bound only to historical candidate IDs absent from the selected canonical input: "
            + ", ".join(missing_ids)
            + ". No current candidate verdict can confirm it without changing the canonical denominator.",
        )
    if classification == "not-reproduced":
        return (
            "not-reproduced",
            "All linked candidates completed healthy runtime pairs, but no exploit trace satisfied the report oracle.",
        )
    if classification == "inconclusive":
        return (
            "inconclusive",
            "At least one linked candidate remained healthy-inconclusive and no linked candidate was runtime-confirmed.",
        )
    if classification == "non-applicable":
        return (
            "non-applicable",
            f"The report boundary is `{boundary_status}`; it is outside the eligible runtime-identification denominator.",
        )

    adapter = PROJECT_ADAPTER_STATUS.get(project, "no-project-native-candidate-adapter")
    if adapter == "targeted-l2-exists-but-candidate-cli-does-not-register-it":
        reason = (
            "All linked current candidates returned `unsupported` because a targeted project runner exists, "
            "but the canonical `validate-candidate-l2` interface does not register that runner. Existing targeted "
            "evidence cannot be promoted to this candidate campaign."
        )
    else:
        reason = (
            "All linked current candidates returned `unsupported` because no project-native candidate execution "
            "adapter is registered in `validate-candidate-l2`. The validator published blocked trace bundles, not "
            "healthy runtime negatives."
        )
    return adapter, reason


def additive_validation_type(row: Mapping[str, Any]) -> str:
    project = str(row.get("project") or "")
    report_name = str(row.get("report_name") or "")
    if project == "nanobot":
        return "Default-off additive MCP tool"
    if project == "openclaw" and "wait-fn-existing-session" in report_name:
        return "Default-off additive Browser plugin tool"
    if project == "openclaw" and report_name.startswith("Media_Root_Bypass"):
        return "Default-off additive message-media plugin tool"
    if project == "chatgpt-on-wechat" and "browser-file-scheme" in report_name:
        return "Default-off additive Browser tool"
    return "Default-off additive tool"


def classify(
    ground_truth: Mapping[str, Any],
    verdicts: list[dict[str, Any]],
    current_ids: set[str],
) -> tuple[str, list[str]]:
    identification = identify_ground_truth(ground_truth, current_ids)
    by_candidate = {str(row["candidate_id"]): row for row in verdicts}
    projection = project_ground_truth(identification, by_candidate)
    return str(projection["disposition"]), list(
        identification["candidate_ids_missing_from_cohort"]
    )


def render(args: argparse.Namespace) -> dict[str, Any]:
    candidate_rows = read_jsonl(args.candidates)
    candidate_ids = {str(row["candidate_id"]) for row in candidate_rows}
    marker_path = args.candidates.parent / "expanded-candidate-l2.json"
    expanded = marker_path.is_file()
    marker = read_json(marker_path) if expanded else {}
    expanded_v3 = marker.get("schema_version") == "clawgap-expanded-candidate-input/v3"
    expected_count = 81 if expanded_v3 else (80 if expanded else 78)
    if len(candidate_rows) != expected_count or len(candidate_ids) != expected_count:
        if expanded:
            raise ValueError(
                "candidate input is not an approved canonical expanded-row/ID artifact"
            )
        raise ValueError("candidate input is not the canonical 78-row/78-ID artifact")
    if expanded:
        added = set(marker.get("added_candidate_ids", []))
        if (len(added) != 1 if expanded_v3 else len(added) != 2) or not added.issubset(
            candidate_ids
        ):
            raise ValueError("expanded candidate identity marker drift")

    ledger = read_jsonl(args.campaign / "batch-ledger.jsonl")
    ledger_ids = [str(row["candidate_id"]) for row in ledger]
    if (
        len(ledger) != expected_count
        or len(set(ledger_ids)) != expected_count
        or set(ledger_ids) != candidate_ids
    ):
        raise ValueError("campaign ledger does not partition the canonical candidate denominator")

    verdict_by_id: dict[str, dict[str, Any]] = {}
    for candidate_id in sorted(candidate_ids):
        result_path = (
            args.campaign / candidate_id / "candidates" / candidate_id / "candidate-result.json"
        )
        result = read_json(result_path)
        if result.get("candidate_id") != candidate_id:
            raise ValueError(f"candidate result identity drift: {candidate_id}")
        verdict_by_id[candidate_id] = result

    ground_truth_rows = read_jsonl(
        args.candidates.parent / "ground-truth-coverage.jsonl"
    )
    if len(ground_truth_rows) != 46:
        raise ValueError("ground-truth artifact does not contain exactly 46 reports")

    additive_overlays: dict[str, dict[str, Any]] = {}
    overlay_dirs = getattr(args, "additive_overlay_dirs", None) or []
    for overlay_dir in overlay_dirs:
        overlay_rows = read_jsonl(overlay_dir / "report-results.jsonl")
        if len(overlay_rows) not in {1, 2}:
            raise ValueError("each additive overlay must contain one or two report results")
        for row in overlay_rows:
            report_id = str(row.get("report_id") or "")
            if not report_id or report_id in additive_overlays:
                raise ValueError("additive overlay report identity drift")
            if (
                row.get("evidence_scope")
                not in {"post-hoc-additive-opt-in-tool", "post-hoc-additive-opt-in-tools"}
                or row.get("canonical_accounting_affected") is not False
                or row.get("canonical_candidate_id") is not None
            ):
                raise ValueError("additive overlay accounting boundary drift")
            additive_overlays[report_id] = row

    source_revised_dir = getattr(args, "source_revised_dir", None)
    source_revised_rows: list[dict[str, Any]] = []
    if source_revised_dir is not None:
        source_revised_rows = read_jsonl(source_revised_dir / "report-results.jsonl")
        actual_source_ids = {str(row.get("report_id")) for row in source_revised_rows}
        if actual_source_ids != SOURCE_REVISED_NATIVE_REPORT_IDS:
            raise ValueError("source-revised native report identity drift")
        if any(
            row.get("evidence_scope") != "source-revised-native-tool"
            or row.get("canonical_accounting_affected") is not False
            or row.get("canonical_candidate_id") is not None
            or row.get("disposition") != "runtime-confirmed"
            for row in source_revised_rows
        ):
            raise ValueError("source-revised native accounting boundary drift")
        trace_rows = [row.get("trace_accounting", {}) for row in source_revised_rows]
        if (
            sum(int(row.get("expected", 0)) for row in trace_rows) != 24
            or sum(int(row.get("valid", 0)) for row in trace_rows) != 24
            or any(
                int(row.get("blocked", 0)) != 0 or int(row.get("not_launched", 0)) != 0
                for row in trace_rows
            )
        ):
            raise ValueError("source-revised native trace accounting drift")

    analysis: list[dict[str, Any]] = []
    for ground_truth in ground_truth_rows:
        historical = [str(item) for item in ground_truth.get("matched_candidate_ids") or []]
        linked_ids = [item for item in historical if item in verdict_by_id]
        linked = [verdict_by_id[item] for item in linked_ids]
        identification = identify_ground_truth(ground_truth, candidate_ids)
        projection = project_ground_truth(identification, verdict_by_id)
        classification = str(projection["disposition"])
        missing = list(identification["candidate_ids_missing_from_cohort"])
        reason_code, reason = report_reason(
            str(ground_truth["project"]),
            classification,
            linked,
            missing,
            str(ground_truth["boundary_status"]),
        )
        overlay_for_report = (
            additive_overlays.get(str(ground_truth["report_id"]))
            if str(ground_truth["report_id"]) in additive_overlays
            else None
        )
        if overlay_for_report is not None:
            reason += (
                " A separately labeled post-hoc additive opt-in-tool overlay runtime-confirmed the "
                "added source shape, but it does not change this canonical classification."
            )
        analysis.append(
            {
                "schema_version": ANALYSIS_SCHEMA,
                "report_id": str(ground_truth["report_id"]),
                "report_name": str(ground_truth.get("report_name") or ""),
                "project": str(ground_truth["project"]),
                "boundary_status": str(ground_truth["boundary_status"]),
                "classification": classification,
                "reason_code": reason_code,
                "reason": reason,
                "historical_candidate_ids": historical,
                "current_candidate_ids": linked_ids,
                "candidate_ids_missing_from_cohort": missing,
                "candidate_verdicts": {
                    item: verdict_by_id[item]["disposition"] for item in linked_ids
                },
                "confirming_candidate_ids": [
                    item
                    for item in linked_ids
                    if verdict_by_id[item]["disposition"] == "runtime-confirmed"
                ],
                "case_ids": {
                    item: verdict_by_id[item].get("case_id") for item in linked_ids
                },
                "runtime_verdict_claimed": classification == "runtime-confirmed",
                "post_hoc_additive_overlay": (
                    {
                        "disposition": overlay_for_report["disposition"],
                        "evidence_scope": overlay_for_report["evidence_scope"],
                        "evidence_tier": overlay_for_report["evidence_tier"],
                        "additive_revision": overlay_for_report["additive_revision"],
                        "canonical_accounting_affected": False,
                    }
                    if overlay_for_report is not None
                    else None
                ),
            }
        )

    classification_counts = Counter(row["classification"] for row in analysis)
    eligible = [row for row in analysis if row["boundary_status"] == "eligible"]
    linked_eligible = [row for row in eligible if row["current_candidate_ids"]]
    expected_linked = 42 if expanded_v3 else (41 if expanded else 38)
    expected_missing = 1 if expanded_v3 else (2 if expanded else 5)
    if (
        len(eligible) != 43
        or len(linked_eligible) != expected_linked
        or classification_counts["candidate-missing"] != expected_missing
        or classification_counts["non-applicable"] != 3
        or sum(classification_counts.values()) != len(ground_truth_rows)
    ):
        raise ValueError("eligible/current-linked report accounting drift")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.out_dir / "ground-truth-analysis.jsonl", analysis)
    write_jsonl(
        args.out_dir / "confirmed-ground-truth.jsonl",
        [row for row in analysis if row["classification"] == "runtime-confirmed"],
    )
    write_jsonl(
        args.out_dir / "not-runtime-confirmed-ground-truth.jsonl",
        [row for row in analysis if row["classification"] != "runtime-confirmed"],
    )

    project_counts = Counter(
        row["project"] for row in analysis if row["classification"] == "linked-unsupported"
    )
    missing_by_project = Counter(
        row["project"] for row in analysis if row["classification"] == "candidate-missing"
    )
    eligible_by_project = Counter(row["project"] for row in eligible)
    confirmed_by_project = Counter(
        row["project"]
        for row in eligible
        if row["classification"] == "runtime-confirmed"
    )
    generation_command = command(args)
    confirmed_count = classification_counts["runtime-confirmed"]
    linked_not_confirmed = len(linked_eligible) - confirmed_count
    nonconfirmed_count = len(analysis) - confirmed_count
    overlay_confirmed_ids = {
        report_id
        for report_id, row in additive_overlays.items()
        if row.get("disposition") == "runtime-confirmed"
    }
    overlay_confirmed_count = len(overlay_confirmed_ids)
    remaining_nonconfirmed_count = nonconfirmed_count - overlay_confirmed_count
    additive_lines = [
        "| Report ID | Project | Post-hoc validation type | Overlay disposition | Evidence scope | Canonical accounting |",
        "|---|---|---|---|---|---|",
    ]
    if additive_overlays:
        # Preserve generation order rather than report-id order in the compact table.
        ordered_overlays = list(additive_overlays.values())
    else:
        ordered_overlays = []
    for row in ordered_overlays:
        additive_lines.append(
            f"| `{row['report_id']}` | {row['project']} | "
            f"{additive_validation_type(row)} | "
            f"`{row['disposition']}` | `{row['evidence_scope']}` | "
            "unchanged |"
        )
    additive_section = (
        "## Post-hoc additive runtime overlay\n\n"
        "This optional-tool/disposable-transform overlay is outside the canonical candidate/report accounting and is not added to the "
        "43-report eligible denominator or the 41 canonical runtime confirmations.\n\n"
        + "\n".join(additive_lines)
        + "\n\n"
        if additive_overlays
        else ""
    )

    source_revised_lines = [
        "| Report ID | Project | Native interface | Source-revised disposition | Trace accounting | Canonical accounting |",
        "|---|---|---|---|---|---|",
    ]
    for row in source_revised_rows:
        traces = row.get("trace_accounting", {})
        source_revised_lines.append(
            f"| `{row['report_id']}` | {row['project']} | "
            f"`{row.get('native_interface', '')}` | `{row['disposition']}` | "
            f"{traces.get('valid', 0)}/{traces.get('expected', 0)} | unchanged |"
        )
    source_revised_section = (
        "## Source-revised native runtime validation\n\n"
        "This separate profile uses only project-native tool interfaces. It is not added to the canonical "
        "candidate/report accounting and does not alter the canonical `41/43` result.\n\n"
        + "\n".join(source_revised_lines)
        + "\n\n"
        if source_revised_rows
        else ""
    )
    if additive_overlays:
        separate_evidence_note = (
            f"Of these canonical non-confirmed reports, **{overlay_confirmed_count}** have separate post-hoc additive "
            f"runtime confirmations and are listed only in the overlay section above; **{remaining_nonconfirmed_count}** "
            f"{'remains' if remaining_nonconfirmed_count == 1 else 'remain'} in the ledger below.\n\n"
        )
    elif source_revised_rows:
        separate_evidence_note = (
            "The separate source-revised native section above is not canonical accounting; all "
            f"**{nonconfirmed_count}** canonical non-confirmed reports remain in the ledger below.\n\n"
        )
    else:
        separate_evidence_note = (
            "No separate overlay or source-revised evidence is counted in this canonical render; all "
            f"**{nonconfirmed_count}** canonical non-confirmed reports remain in the ledger below.\n\n"
        )
    ledger_introduction = (
        "Post-hoc overlay-confirmed rows are excluded here to avoid counting the same report in both evidence layers.\n\n"
        if additive_overlays
        else "Source-revised native rows are shown separately above; this canonical ledger remains unchanged.\n\n"
        if source_revised_rows
        else "No separate evidence layer is excluded from this canonical ledger.\n\n"
    )

    confirmed_lines = [
        "| Report ID | Project | Ground truth | Confirming candidate(s) |",
        "|---|---|---|---|",
    ]
    for row in analysis:
        if row["classification"] != "runtime-confirmed":
            continue
        confirmed_lines.append(
            f"| `{row['report_id']}` | {row['project']} | {row['report_name']} | "
            + ", ".join(f"`{item}`" for item in row["confirming_candidate_ids"])
            + " |"
        )

    nonconfirmed_lines = [
        "| Report ID | Project | Ground truth | Classification | Blocking analysis |",
        "|---|---|---|---|---|",
    ]
    for row in analysis:
        if row["classification"] == "runtime-confirmed":
            continue
        if str(row["report_id"]) in overlay_confirmed_ids:
            continue
        nonconfirmed_lines.append(
            f"| `{row['report_id']}` | {row['project']} | {row['report_name']} | "
            f"`{row['classification']}` | {row['reason']} |"
        )

    project_outcome_lines = [
        "| Project | Runtime-confirmed | Not runtime-confirmed | Eligible total |",
        "|---|---:|---:|---:|",
    ]
    for project in sorted(eligible_by_project):
        confirmed = confirmed_by_project[project]
        total = eligible_by_project[project]
        project_outcome_lines.append(
            f"| {project} | {confirmed} | {total - confirmed} | {total} |"
        )

    summary = (
        f"# Canonical {expected_count}-Candidate L2 Ground-Truth Analysis\n\n"
        f"> Complete reproduction command: `{generation_command}`\n\n"
        "## Candidate denominator\n\n"
        f"- Candidate directories: **{expected_count}/{expected_count}**.\n"
        f"- Unique candidate verdicts: **{expected_count}/{expected_count}**.\n"
        "- Candidate dispositions: **"
        + ", ".join(
            f"{count} {disposition}"
            for disposition, count in sorted(
                Counter(row["disposition"] for row in ledger).items()
            )
        )
        + "**.\n\n"
        "## Ground-truth accounting\n\n"
        "- Total reports: **46**.\n"
        "- Eligible reports: **43**.\n"
        f"- Runtime-confirmed eligible reports: **{confirmed_count}**.\n"
        f"- Current-candidate-linked but not runtime-confirmed: **{linked_not_confirmed}**.\n"
        f"- Eligible `candidate-missing` reports: **{classification_counts['candidate-missing']}**.\n"
        "- Non-applicable boundary reports: **3**.\n\n"
        "No 43/43 ground-truth identification or 46/46 runtime-detection claim is allowed from this "
        + ("explicit expanded input.\n\n" if expanded else "unchanged input.\n\n")
        + "## Per-project eligible report outcomes\n\n"
        "The table below counts only the 43 eligible reports; the 3 non-applicable boundary rows are excluded.\n\n"
        + "\n".join(project_outcome_lines)
        + "\n\n"
        "## Runtime-confirmed ground truths\n\n"
        + "\n".join(confirmed_lines)
        + "\n\n"
        + additive_section
        + source_revised_section
        + "## Why the other reports are not runtime-confirmed\n\n"
        + f"The {nonconfirmed_count} non-confirmed reports are classified from the current candidate receipts, not a "
        "hard-coded snapshot. `linked-unsupported` means no linked candidate completed a healthy L2 run; it is not "
        "negative runtime evidence.\n\n"
        + separate_evidence_note
        + f"Eligible `candidate-missing` reports remain **{classification_counts['candidate-missing']}** because this "
        "renderer is bound to the "
        + (
            "explicit expanded generic 81-row artifact.\n\n"
            if expanded_v3
            else "explicit expanded generic 80-row artifact.\n\n"
            if expanded
            else "unchanged generic 78-row artifact.\n\n"
        )
        + f"Linked-unsupported reports by project: **{dict(sorted(project_counts.items()))}**.\n\n"
        f"Candidate-missing reports by project: **{dict(sorted(missing_by_project.items()))}**.\n\n"
        "## Remaining canonical non-confirmed report ledger\n\n"
        + ledger_introduction
        + "\n".join(nonconfirmed_lines)
        + "\n"
    )
    (args.out_dir / "summary.md").write_text(summary, encoding="utf-8")

    hashes = {
        path.name: digest(path)
        for path in sorted(args.out_dir.iterdir())
        if path.is_file() and path.name not in {"manifest.json"}
    }
    manifest = {
        "schema_version": "clawgap-auto-l2-gt-analysis-manifest/v1",
        "analysis_id": "runtime-auto-l2-gt-analysis-v1",
        "generation_command": generation_command,
        "candidate_count": len(ledger),
        "candidate_status_counts": dict(Counter(row["disposition"] for row in ledger)),
        "ground_truth_count": len(analysis),
        "classification_counts": dict(classification_counts),
        "eligible_count": len(eligible),
        "current_candidate_linked_eligible_count": len(linked_eligible),
        "runtime_confirmed_report_count": classification_counts["runtime-confirmed"],
        "canonical_non_confirmed_report_count": nonconfirmed_count,
        "candidate_missing_report_count": classification_counts["candidate-missing"],
        "non_applicable_report_count": classification_counts["non-applicable"],
        "expanded_input": expanded,
        "green_43_gt_claim_allowed": False,
        "post_hoc_additive_overlay_confirmed_report_count": overlay_confirmed_count,
        "remaining_canonical_non_confirmed_report_count": remaining_nonconfirmed_count,
        "source_revised_native_report_count": len(source_revised_rows),
        "source_revised_native_runtime_confirmed_report_count": sum(
            row.get("disposition") == "runtime-confirmed"
            for row in source_revised_rows
        ),
        "post_hoc_additive_overlays": [
            {
                "path": str(overlay_dir),
                "report_id": row["report_id"],
                "candidate_id": row.get("candidate_id") or row.get("additive_candidate_id"),
                "disposition": row["disposition"],
                "evidence_scope": row["evidence_scope"],
                "canonical_accounting_affected": False,
                "receipt_sha256": digest(overlay_dir / "report-results.jsonl"),
            }
            for overlay_dir in overlay_dirs
            for row in read_jsonl(overlay_dir / "report-results.jsonl")
        ],
        "source_revised_native_runtime": (
            {
                "path": str(source_revised_dir),
                "report_count": len(source_revised_rows),
                "runtime_confirmed_report_count": sum(
                    row.get("disposition") == "runtime-confirmed"
                    for row in source_revised_rows
                ),
                "trace_valid": sum(
                    int(row.get("trace_accounting", {}).get("valid", 0))
                    for row in source_revised_rows
                ),
                "trace_expected": sum(
                    int(row.get("trace_accounting", {}).get("expected", 0))
                    for row in source_revised_rows
                ),
                "receipt_sha256": digest(source_revised_dir / "report-results.jsonl"),
            }
            if source_revised_dir is not None
            else None
        ),
        "artifact_sha256": hashes,
    }
    write_json(args.out_dir / "manifest.json", manifest)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", type=Path, default=DEFAULT_CANDIDATES)
    parser.add_argument("--campaign", type=Path, default=DEFAULT_CAMPAIGN)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument(
        "--additive-overlay-dir",
        type=Path,
        default=None,
        action="append",
        help="explicitly include a post-hoc additive overlay without canonical accounting",
    )
    parser.add_argument(
        "--source-revised-dir",
        type=Path,
        default=None,
        help="include the separate four-report native-tool source-revised campaign",
    )
    args = parser.parse_args(argv)
    manifest = render(
        argparse.Namespace(
            candidates=args.candidates.resolve(),
            campaign=args.campaign.resolve(),
            out_dir=args.out_dir.resolve(),
            additive_overlay_dirs=[
                path.resolve() for path in (args.additive_overlay_dir or [])
            ],
            source_revised_dir=(
                args.source_revised_dir.resolve()
                if args.source_revised_dir is not None
                else None
            ),
        )
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

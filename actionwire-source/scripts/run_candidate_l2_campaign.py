#!/usr/bin/env python3
"""Run an approved canonical candidate L2 CLI sequentially and publish ledgers."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CANDIDATES = REPO_ROOT / "output/cross-project/coverage-comparison/candidates.jsonl"
DEFAULT_OUT = REPO_ROOT / "output/cross-project/runtime-auto-l2"
STOP_DISPOSITIONS = {"environment-blocked", "planning-blocked"}

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.runtime_validation.candidate_l2_projection import (  # noqa: E402
    identify_ground_truth,
    project_ground_truth,
)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{number}: expected object")
        rows.append(value)
    return rows


def write_jsonl(path: Path, rows: list[Mapping[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path.resolve())


def command(
    project: str,
    candidate_id: str,
    candidates_path: Path,
    out_dir: Path,
    source_campaign: Path = REPO_ROOT
    / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1",
) -> list[str]:
    return [
        sys.executable,
        "-m",
        "src.runtime_validation",
        "validate-candidate-l2",
        "--project",
        project,
        "--candidate-id",
        candidate_id,
        "--candidates",
        display_path(candidates_path),
        "--source-campaign",
        display_path(source_campaign),
        "--out-dir",
        display_path(out_dir),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidates", type=Path, default=DEFAULT_CANDIDATES)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    candidates_path = args.candidates.resolve()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    reproduction = (
        "python scripts/run_candidate_l2_campaign.py "
        f"--candidates {candidates_path.relative_to(REPO_ROOT)} "
        f"--out-dir {out_dir.relative_to(REPO_ROOT)}"
    )

    rows = read_jsonl(candidates_path)
    ids = [str(row.get("candidate_id") or "") for row in rows]
    marker_path = candidates_path.parent / "expanded-candidate-l2.json"
    expanded = marker_path.is_file()
    marker = (
        json.loads(marker_path.read_text(encoding="utf-8")) if expanded else {}
    )
    expanded_v3 = marker.get("schema_version") == "clawgap-expanded-candidate-input/v3"
    expected_count = 81 if expanded_v3 else (80 if expanded else 78)
    if len(rows) != expected_count or len(set(ids)) != expected_count:
        raise SystemExit(
            f"candidate denominator is not the frozen {expected_count}-row artifact"
        )
    if expanded_v3:
        source_campaign = (
            REPO_ROOT
            / "output/cross-project/runtime-dynamic-trigger-all-candidates-expanded-v3"
        )
    elif expanded:
        source_campaign = (
            REPO_ROOT
            / "output/cross-project/runtime-dynamic-trigger-all-candidates-expanded-v2"
        )
    else:
        source_campaign = (
            REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
        )
    ordered = sorted(rows, key=lambda row: (str(row["project"]), str(row["candidate_id"])))

    ledger: list[dict[str, Any]] = []
    for row in ordered:
        candidate_id = str(row["candidate_id"])
        project = str(row["project"])
        candidate_out = out_dir / candidate_id
        argv = command(
            project,
            candidate_id,
            candidates_path,
            candidate_out,
            source_campaign,
        )
        completed = subprocess.run(argv, cwd=REPO_ROOT, text=True, capture_output=True)
        result_path = candidate_out / "candidates" / candidate_id / "candidate-result.json"
        if not result_path.is_file():
            raise SystemExit(
                f"candidate result is missing after exit {completed.returncode}: {candidate_id}\n"
                + (completed.stderr or completed.stdout)
            )
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if result.get("candidate_id") != candidate_id or result.get("project") != project:
            raise SystemExit(f"candidate identity drift: {candidate_id}")
        if result.get("attempts") != 3 or result.get("trace_accounting", {}).get("expected") != 6:
            raise SystemExit(f"candidate attempt accounting drift: {candidate_id}")
        artifact_hash = None
        manifest_path = candidate_out / "manifest.json"
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            artifact_hash = manifest.get("artifact_sha256", {}).get(
                f"candidates/{candidate_id}/candidate-result.json"
            )
        ledger.append(
            {
                "schema_version": "clawgap-auto-l2-batch-ledger/v1",
                "candidate_id": candidate_id,
                "project": project,
                "disposition": result["disposition"],
                "exit_code": completed.returncode,
                "case_id": result.get("case_id"),
                "attempt_count": result.get("attempts"),
                "artifact_sha256": artifact_hash,
                "cleanup_status": result.get("cleanup", {}).get("status"),
                "command": " ".join(argv),
            }
        )
        write_jsonl(out_dir / "batch-ledger.jsonl", ledger)
        if result["disposition"] in STOP_DISPOSITIONS:
            raise SystemExit(f"stopping before systemic candidate failure: {candidate_id}")

    if len(ledger) != expected_count:
        raise SystemExit(
            f"campaign denominator drift: {len(ledger)}/{expected_count}"
        )
    by_candidate = {row["candidate_id"]: row for row in ledger}
    gt_rows = read_jsonl(candidates_path.parent / "ground-truth-coverage.jsonl")
    candidate_ids = set(by_candidate)
    projection: list[dict[str, Any]] = []
    for report in gt_rows:
        identification = identify_ground_truth(report, candidate_ids)
        projected = project_ground_truth(identification, by_candidate)
        matched = list(identification["matched_candidate_ids"])
        disposition = str(projected["disposition"])
        projection.append(
            {
                "schema_version": "clawgap-auto-l2-gt-projection/v1",
                "report_id": report["report_id"],
                "project": report["project"],
                "boundary_status": report["boundary_status"],
                "matched_candidate_ids": matched,
                "candidate_dispositions": projected["candidate_dispositions"],
                "disposition": disposition,
            }
        )
    write_jsonl(out_dir / "gt-projection.jsonl", projection)
    status_counts = Counter(row["disposition"] for row in ledger)
    projection_counts = Counter(row["disposition"] for row in projection)
    linked_eligible = sum(
        1
        for row in projection
        if row["boundary_status"] == "eligible" and row["matched_candidate_ids"]
    )
    expected_missing = 1 if expanded_v3 else (2 if expanded else 5)
    expected_linked = 42 if expanded_v3 else (41 if expanded else 38)
    exact = (
        projection_counts["candidate-missing"] == expected_missing
        and projection_counts["non-applicable"] == 3
        and linked_eligible == expected_linked
        and len(ledger) == expected_count
    )
    manifest = {
        "schema_version": "clawgap-auto-l2-batch-manifest/v1",
        "campaign_id": (
            "runtime-auto-l2-canonical-81-expanded-v3"
            if expanded_v3
            else "runtime-auto-l2-canonical-80-expanded-v2"
            if expanded
            else "runtime-auto-l2-canonical-78-v1"
        ),
        "candidate_count": len(ledger),
        "attempt_pairs_per_candidate": 3,
        "status_counts": dict(status_counts),
        "ground_truth_status_counts": dict(projection_counts),
        "current_candidate_linked_eligible_reports": linked_eligible,
        "candidate_missing_eligible_reports": projection_counts["candidate-missing"],
        "non_applicable_reports": sum(
            1 for row in projection if row["boundary_status"] != "eligible"
        ),
        f"exact_{expected_count}_input_accounting": exact,
        "expanded_input": expanded,
        "green_43_gt_claim_allowed": False,
        "reproduction_command": reproduction,
    }
    (out_dir / "batch-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    summary = (
        f"# Canonical {expected_count}-Candidate Runtime L2 Batch\n\n"
        f"> Complete reproduction command: `{reproduction}`\n\n"
        f"Candidate verdicts: **{len(ledger)}/{expected_count}**; dispositions: "
        f"**{json.dumps(dict(status_counts), sort_keys=True)}**.\n\n"
        "Eligible-report accounting from the "
        + ("explicit expanded input" if expanded else "unchanged input")
        + ": "
        + f"**{manifest['current_candidate_linked_eligible_reports']} current-candidate-linked**, "
        f"**{projection_counts['candidate-missing']} candidate-missing**, and "
        f"**{manifest['non_applicable_reports']} non-applicable**. "
        "This ledger must not be reported as 43/43 GT identification.\n"
    )
    (out_dir / "batch-summary.md").write_text(summary, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

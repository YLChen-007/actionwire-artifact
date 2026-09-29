#!/usr/bin/env python3
"""Render revision-pinned AstrBot ground-truth acceptance from pipeline CSVs."""

from __future__ import annotations

import argparse
import csv
import json
import shlex
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[5]
DEFAULT_ORACLE = REPO_ROOT / "design/AstrBot/astrbot-4.25.2-acceptance.json"
DEFAULT_GROUND_TRUTH = REPO_ROOT / "design/AstrBot/groundtruth/new-vuls"
DEFAULT_SOURCE_ROOT = REPO_ROOT / "benchmark/python/AstrBot"
DEFAULT_PIPELINE_OUTPUT = REPO_ROOT / "output/AstrBot"
DEFAULT_OUT = REPO_ROOT / "design/AstrBot/call-chain/debug"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def split_anchor(anchor: str) -> tuple[str, int]:
    file_name, line = anchor.rsplit(":", 1)
    return file_name, int(line)


def command_path(path: Path) -> str:
    return (
        str(path.relative_to(REPO_ROOT))
        if path.is_relative_to(REPO_ROOT)
        else str(path)
    )


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    fields = [
        "row_kind",
        "dimension_id",
        "flow_id",
        "current_status",
        "handler",
        "anchor",
        "expected",
        "detected",
        "status",
        "detail",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--ground-truth", type=Path, default=DEFAULT_GROUND_TRUTH)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--pipeline-output", type=Path, default=DEFAULT_PIPELINE_OUTPUT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    return parser


def load_report_names(root: Path) -> set[str]:
    names: set[str] = set()
    for path in sorted(root.glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        name = value.get("report_name")
        if isinstance(name, str) and name:
            names.add(name)
    return names


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    oracle_path = args.oracle.absolute()
    ground_truth = args.ground_truth.absolute()
    source_root = args.source_root.resolve()
    pipeline_output = args.pipeline_output.resolve()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    report_names = load_report_names(ground_truth)
    static = pipeline_output / "static/call-chains"
    chains = read_csv(static / "handler-sink-chains.csv")
    gates = read_csv(static / "chain-gates.csv")
    constraints = read_csv(static / "sink-constraints.csv")

    chain_by_sink: dict[tuple[str, int], list[dict[str, str]]] = {}
    for chain in chains:
        key = (chain["sink_file"], int(chain["sink_line"]))
        chain_by_sink.setdefault(key, []).append(chain)
    gates_by_chain: dict[str, list[dict[str, str]]] = {}
    for gate in gates:
        if gate.get("gate_uid"):
            gates_by_chain.setdefault(gate["chain_id"], []).append(gate)
    constraints_by_sink: dict[tuple[str, int], list[dict[str, str]]] = {}
    for constraint in constraints:
        key = (constraint["sink_file"], int(constraint["sink_line"]))
        constraints_by_sink.setdefault(key, []).append(constraint)

    expected_capabilities = oracle.get("expected_sink_capabilities", {})
    rows: list[dict[str, object]] = []
    failures = 0
    expected_flows: set[tuple[str, str]] = set()
    found_flows: set[tuple[str, str]] = set()
    expected_gates = 0
    found_gates = 0
    missing_dimensions = 0
    stale = 0
    fixed_dimensions = 0

    oracle_reports = {
        report
        for dimension in oracle["dimensions"]
        for report in dimension.get("source_reports", [])
    }
    for report in sorted(report_names | oracle_reports):
        covered = report in oracle_reports
        present = report in report_names
        passed = covered and present
        failures += int(not passed)
        rows.append(
            {
                "row_kind": "source-report",
                "dimension_id": "",
                "flow_id": "",
                "current_status": "",
                "handler": "",
                "anchor": report,
                "expected": "raw GT report is represented by the pinned oracle",
                "detected": f"raw={present};oracle={covered}",
                "status": "pass" if passed else "fail",
                "detail": "",
            }
        )

    for dimension in oracle["dimensions"]:
        dimension_id = dimension["id"]
        current_status = dimension["current_status"]
        fixed_dimensions += int(current_status.startswith("fixed"))
        for flow_index, flow in enumerate(dimension["flows"], 1):
            handler = flow["handler"]
            flow_id = f"{dimension_id}:{flow_index}:{handler}"
            flow_chains: list[dict[str, str]] = []
            for anchor in flow["sink_points"]:
                key = split_anchor(anchor)
                expected_flows.add((handler, anchor))
                matches = [
                    row
                    for row in chain_by_sink.get(key, [])
                    if row["tool_name"] == handler
                ]
                flow_chains.extend(matches)
                sink_constraints = constraints_by_sink.get(key, [])
                expected_capability = expected_capabilities.get(anchor, "")
                capability_matches = [
                    row
                    for row in sink_constraints
                    if row.get("capability_class") == expected_capability
                ]
                passed = (
                    bool(matches)
                    and len(sink_constraints) == 1
                    and len(capability_matches) == 1
                )
                if matches:
                    found_flows.add((handler, anchor))
                failures += int(not passed)
                rows.append(
                    {
                        "row_kind": "sink-chain",
                        "dimension_id": dimension_id,
                        "flow_id": flow_id,
                        "current_status": current_status,
                        "handler": handler,
                        "anchor": anchor,
                        "expected": (
                            "one or more taint-valid chains; exactly one "
                            f"{expected_capability} constraint"
                        ),
                        "detected": (
                            f"chains={len(matches)};constraints={len(sink_constraints)};"
                            f"capability_matches={len(capability_matches)}"
                        ),
                        "status": "pass" if passed else "fail",
                        "detail": ";".join(sorted(row["chain_id"] for row in matches)),
                    }
                )

            attached = [
                gate
                for chain in flow_chains
                for gate in gates_by_chain.get(chain["chain_id"], [])
            ]
            for anchor in dimension.get("expected_existing_gates", []):
                expected_gates += 1
                file_name, line = split_anchor(anchor)
                matches = [
                    gate
                    for gate in attached
                    if gate["gate_file"] == file_name
                    and int(gate["gate_line"]) == line
                ]
                found_gates += int(bool(matches))
                failures += int(not matches)
                rows.append(
                    {
                        "row_kind": "detected-gate",
                        "dimension_id": dimension_id,
                        "flow_id": flow_id,
                        "current_status": current_status,
                        "handler": handler,
                        "anchor": anchor,
                        "expected": "existing eligible callsite-bound gate",
                        "detected": len(matches),
                        "status": "pass" if matches else "fail",
                        "detail": ";".join(
                            sorted({gate["gate_uid"] for gate in matches})
                        ),
                    }
                )

            for missing in dimension.get("expected_missing", []):
                missing_dimensions += 1
                forbidden = [
                    term.lower()
                    for term in dimension.get("forbidden_fabricated_gate_terms", [])
                ]
                fabricated = [
                    gate
                    for gate in attached
                    if any(term in gate["gate_name"].lower() for term in forbidden)
                ]
                passed = not fabricated
                failures += int(not passed)
                rows.append(
                    {
                        "row_kind": "expected-missing",
                        "dimension_id": dimension_id,
                        "flow_id": flow_id,
                        "current_status": current_status,
                        "handler": handler,
                        "anchor": missing,
                        "expected": "expected missing security check remains explicit",
                        "detected": "no fabricated gate" if passed else len(fabricated),
                        "status": "pass" if passed else "fail",
                        "detail": ";".join(gate["gate_name"] for gate in fabricated),
                    }
                )

        for policy in dimension.get("current_policy_anchors", []):
            file_name, line = split_anchor(policy["location"])
            source_line = (source_root / file_name).read_text(encoding="utf-8").splitlines()[
                line - 1
            ]
            passed = policy["contains"] in source_line
            failures += int(not passed)
            rows.append(
                {
                    "row_kind": "current-policy",
                    "dimension_id": dimension_id,
                    "flow_id": "",
                    "current_status": current_status,
                    "handler": "",
                    "anchor": policy["location"],
                    "expected": policy["contains"],
                    "detected": source_line.strip(),
                    "status": "pass" if passed else "fail",
                    "detail": "revision-pinned current-source check",
                }
            )

        for anchor in dimension.get("stale_report_anchors", []):
            stale += 1
            rows.append(
                {
                    "row_kind": "stale-source-anchor",
                    "dimension_id": dimension_id,
                    "flow_id": "",
                    "current_status": current_status,
                    "handler": "",
                    "anchor": anchor,
                    "expected": "historical report anchor",
                    "detected": "rebased by acceptance oracle",
                    "status": "note",
                    "detail": "",
                }
            )

    zero_gate_chains = [
        chain for chain in chains if not gates_by_chain.get(chain["chain_id"])
    ]
    for chain in zero_gate_chains:
        rows.append(
            {
                "row_kind": "zero-gate-chain",
                "dimension_id": "",
                "flow_id": "",
                "current_status": "",
                "handler": chain["tool_name"],
                "anchor": f"{chain['sink_file']}:{chain['sink_line']}",
                "expected": "preserved structural chain",
                "detected": chain["chain_id"],
                "status": "note",
                "detail": chain["call_chain"],
            }
        )

    csv_path = out_dir / "gt-coverage.csv"
    markdown_path = out_dir / "gt-coverage.md"
    write_csv(csv_path, rows)
    command = shlex.join(
        [
            "python",
            "design/AstrBot/call-chain/debug/script/render_gt_coverage.py",
            "--oracle",
            command_path(oracle_path),
            "--ground-truth",
            command_path(ground_truth),
            "--source-root",
            command_path(source_root),
            "--pipeline-output",
            command_path(pipeline_output),
            "--out-dir",
            command_path(out_dir),
        ]
    )
    flow_recall = len(found_flows) / len(expected_flows) if expected_flows else 1.0
    gate_recall = found_gates / expected_gates if expected_gates else 1.0
    lines = [
        "# AstrBot 4.25.2 Ground-Truth Coverage",
        "",
        f"> Generation command: `{command}`",
        "",
        f"Revision: `{oracle['analysis_revision']}`.",
        "",
        f"- Raw reports represented: **{len(oracle_reports)}/{len(report_names)}**.",
        f"- Expected handler/sink flows: **{len(found_flows)}/{len(expected_flows)}**; recall: **{flow_recall:.1%}**.",
        f"- Expected existing gates: **{found_gates}/{expected_gates}**; recall: **{gate_recall:.1%}**.",
        f"- Expected-missing controls: **{missing_dimensions}**.",
        f"- Fixed-at-revision dimensions: **{fixed_dimensions}**.",
        f"- Zero-gate structural chains: **{len(zero_gate_chains)}**.",
        f"- Stale historical anchors: **{stale}**.",
        f"- Acceptance failures: **{failures}**.",
        "",
        "The CSV distinguishes raw report coverage, current and stale source evidence, "
        "handler/sink chains, gates, expected-missing checks, capability constraints, "
        "and zero-gate chains.",
    ]
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"failures": failures, "rows": len(rows)}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

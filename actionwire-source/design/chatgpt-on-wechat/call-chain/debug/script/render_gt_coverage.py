#!/usr/bin/env python3
"""Render CowAgent current-source acceptance coverage from pipeline CSVs."""

from __future__ import annotations

import argparse
import csv
import json
import shlex
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[5]
DEFAULT_ORACLE = (
    REPO_ROOT
    / "design/chatgpt-on-wechat/groundtruth/cowagent-2.0.8-acceptance.json"
)
DEFAULT_PIPELINE_OUTPUT = REPO_ROOT / "output/chatgpt-on-wechat"
DEFAULT_OUT = REPO_ROOT / "design/chatgpt-on-wechat/call-chain/debug"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def split_anchor(anchor: str) -> tuple[str, int]:
    file_name, line = anchor.rsplit(":", 1)
    return file_name, int(line)


def command_path(path: Path) -> str:
    """Keep repository paths concise without rejecting external symlink targets."""

    return (
        str(path.relative_to(REPO_ROOT))
        if path.is_relative_to(REPO_ROOT)
        else str(path)
    )


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    fields = [
        "row_kind",
        "dimension_id",
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
    parser.add_argument("--pipeline-output", type=Path, default=DEFAULT_PIPELINE_OUTPUT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # Preserve the repository entry path when groundtruth is a symlink. The file
    # can still be read normally, while the generated command stays reproducible
    # from this repository instead of exposing the symlink target checkout.
    oracle_path = args.oracle.absolute()
    pipeline_output = args.pipeline_output.resolve()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
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

    rows: list[dict[str, object]] = []
    failures = 0
    target_sinks: set[tuple[str, int]] = set()
    expected_gates = 0
    found_gates = 0
    duplicates = 0
    stale = 0
    missing_dimensions = 0
    for dimension in oracle["dimensions"]:
        dimension_id = dimension["id"]
        handler = dimension["handler"]
        dimension_chains: list[dict[str, str]] = []
        for anchor in dimension["sink_points"]:
            key = split_anchor(anchor)
            target_sinks.add(key)
            matches = [
                row for row in chain_by_sink.get(key, []) if row["tool_name"] == handler
            ]
            dimension_chains.extend(matches)
            constraint_count = len(constraints_by_sink.get(key, []))
            passed = bool(matches) and constraint_count == 1
            failures += int(not passed)
            rows.append(
                {
                    "row_kind": "sink-chain",
                    "dimension_id": dimension_id,
                    "handler": handler,
                    "anchor": anchor,
                    "expected": "one or more taint-valid chains; exactly one constraint",
                    "detected": f"chains={len(matches)};constraints={constraint_count}",
                    "status": "pass" if passed else "fail",
                    "detail": ";".join(sorted(row["chain_id"] for row in matches)),
                }
            )

        attached = [
            gate
            for chain in dimension_chains
            for gate in gates_by_chain.get(chain["chain_id"], [])
        ]
        for anchor in dimension.get("expected_existing_gates", []):
            expected_gates += 1
            file_name, line = split_anchor(anchor)
            matches = [
                gate
                for gate in attached
                if gate["gate_file"] == file_name and int(gate["gate_line"]) == line
            ]
            found_gates += int(bool(matches))
            failures += int(not matches)
            rows.append(
                {
                    "row_kind": "detected-gate",
                    "dimension_id": dimension_id,
                    "handler": handler,
                    "anchor": anchor,
                    "expected": "existing eligible gate",
                    "detected": len(matches),
                    "status": "pass" if matches else "fail",
                    "detail": ";".join(sorted({gate["gate_uid"] for gate in matches})),
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
                    "handler": handler,
                    "anchor": missing,
                    "expected": "missing check remains explicit",
                    "detected": "no fabricated gate" if passed else len(fabricated),
                    "status": "pass" if passed else "fail",
                    "detail": ";".join(gate["gate_name"] for gate in fabricated),
                }
            )

        for report in dimension.get("duplicate_reports", []):
            duplicates += 1
            rows.append(
                {
                    "row_kind": "duplicate-report",
                    "dimension_id": dimension_id,
                    "handler": handler,
                    "anchor": report,
                    "expected": "deduplicate into this dimension",
                    "detected": "deduplicated",
                    "status": "note",
                    "detail": ",".join(dimension["source_reports"]),
                }
            )
        for anchor in dimension.get("stale_report_anchors", []):
            stale += 1
            rows.append(
                {
                    "row_kind": "stale-source-anchor",
                    "dimension_id": dimension_id,
                    "handler": handler,
                    "anchor": anchor,
                    "expected": "historical report anchor",
                    "detected": "rebased",
                    "status": "note",
                    "detail": "current sinks=" + ",".join(dimension["sink_points"]),
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
            "design/chatgpt-on-wechat/call-chain/debug/script/render_gt_coverage.py",
            "--oracle",
            command_path(oracle_path),
            "--pipeline-output",
            command_path(pipeline_output),
            "--out-dir",
            command_path(out_dir),
        ]
    )
    sink_recall = (
        sum(bool(chain_by_sink.get(key)) for key in target_sinks) / len(target_sinks)
        if target_sinks
        else 1.0
    )
    gate_recall = found_gates / expected_gates if expected_gates else 1.0
    lines = [
        "# CowAgent 2.0.8 Ground-Truth Coverage",
        "",
        f"> Generation command: `{command}`",
        "",
        f"Revision: `{oracle['analysis_revision']}`.",
        "",
        f"- Distinct current sink points: **{len(target_sinks)}**; chain recall: **{sink_recall:.1%}**.",
        f"- Expected existing gates: **{found_gates}/{expected_gates}**; recall: **{gate_recall:.1%}**.",
        f"- Expected-missing dimensions: **{missing_dimensions}**.",
        f"- Zero-gate structural chains: **{len(zero_gate_chains)}**.",
        f"- Stale historical anchors: **{stale}**; duplicate reports: **{duplicates}**.",
        f"- Acceptance failures: **{failures}**.",
        "",
        "The CSV separates `sink-chain`, `detected-gate`, `expected-missing`, "
        "`zero-gate-chain`, `stale-source-anchor`, and `duplicate-report` rows.",
    ]
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"failures": failures, "rows": len(rows)}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

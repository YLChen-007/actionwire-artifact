#!/usr/bin/env python3
"""Render exact-chain Mercury Agent revision-pinned GT coverage."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shlex
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[5]
REVISION = "587fad1bf9449598d1b27833f8c7db55d164741a"
DEFAULT_ORACLE = ROOT / "design/mercury-agent/inventory/mercury-agent-static-oracle.json"
DEFAULT_LOCK = ROOT / "design/mercury-agent/inventory/mercury-agent-groundtruth-lock.json"
DEFAULT_GT = ROOT / "design/mercury-agent/groundtruth"
DEFAULT_INVENTORY = ROOT / "design/mercury-agent/inventory/debug/groundtruth-inventory.json"
DEFAULT_PIPELINE = ROOT / "output/mercury-agent"
DEFAULT_OUT = ROOT / "design/mercury-agent/call-chain/debug"
EXPECTED = {
    "reports": 5,
    "handlers": 5,
    "sinks": 5,
    "gates": 27,
    "cross_component_edges": 5,
    "extraction_records": 10,
}


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _lock_snapshot(gt_root: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(gt_root.rglob("*.json")):
        payload = _json(path)
        rows.append(
            {
                "path": path.relative_to(gt_root).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "handlers": len(payload.get("d5_tool_handler_entry") or []),
                "sinks": len(payload.get("d5_sink_points") or []),
                "gates": len(payload.get("d5_gate_points") or []),
                "cross_component_edges": len(payload.get("d5_cross_component") or []),
                "extraction_records": len(payload.get("d5_param_extraction") or []),
            }
        )
    return rows


def _slice_for_gate(pipeline_output: Path, gate_uid: str) -> dict[str, Any]:
    path = pipeline_output / "gate-semantics/repository" / gate_uid / "slice.json"
    return _json(path) if path.is_file() else {}


def _facet_present(value: str, expected: str) -> bool:
    return expected in {part for part in value.split(";") if part}


def render(
    *,
    oracle_path: Path,
    lock_path: Path,
    inventory_path: Path,
    gt_root: Path,
    pipeline_output: Path,
    out_dir: Path,
    command: str,
) -> dict[str, Any]:
    oracle = _json(oracle_path)
    lock = _json(lock_path)
    inventory = _json(inventory_path)
    if oracle.get("revision") != REVISION or inventory.get("revision") != REVISION:
        raise ValueError("Mercury oracle/inventory revision mismatch")
    if oracle.get("corpus_sha256") != lock.get("corpus_sha256"):
        raise ValueError("Mercury oracle and lock use different corpora")
    if lock.get("reports") != _lock_snapshot(gt_root):
        raise ValueError("Mercury ground-truth hash drift; inventory review required")
    if inventory.get("counts") != EXPECTED:
        raise ValueError("Mercury inventory does not account for 5/5/5/27/5/10 records")

    static = pipeline_output / "static/call-chains"
    chains = _csv(static / "handler-sink-chains.csv")
    constraints = _csv(static / "sink-constraints.csv")
    chain_gates = _csv(static / "chain-gates.csv")
    gate_index = _csv(pipeline_output / "gate-semantics/gate-index.csv")
    gate_manifest = _json(pipeline_output / "static/gates/manifest.json")
    if gate_manifest.get("counts", {}).get("slice_failures") != 0:
        raise ValueError("Mercury gate slicing has failures")

    sink_rows: list[dict[str, Any]] = []
    gate_rows: list[dict[str, Any]] = []
    trace: list[dict[str, Any]] = []
    global_failures: list[str] = []

    for eligible in oracle["eligible_sink_records"]:
        candidates = [
            row
            for row in chains
            if row.get("project_id") == "mercury-agent"
            and row.get("tool_name") == eligible["tool_name"]
            and row.get("handler_file") == eligible["handler_file"]
            and int(row.get("handler_line", "0") or 0) == eligible["handler_line"]
            and row.get("sink_file") == eligible["sink_file"]
            and int(row.get("sink_line", "0") or 0) == eligible["sink_line"]
            and _facet_present(row.get("sink_argument", ""), eligible["controlled_facet"])
        ]
        failures: list[str] = []
        if len(candidates) != 1:
            failures.append(f"expected one exact handler-to-sink chain, got {len(candidates)}")
        chain = candidates[0] if len(candidates) == 1 else None
        chain_constraints = (
            [row for row in constraints if row.get("sink_id") == chain.get("sink_id")]
            if chain
            else []
        )
        if len(chain_constraints) != 1:
            failures.append(f"expected one concrete sink constraint, got {len(chain_constraints)}")
        elif (
            chain_constraints[0].get("capability_class") != eligible["capability_class"]
            or not _facet_present(
                chain_constraints[0].get("controlled_argument", ""),
                eligible["controlled_facet"],
            )
        ):
            failures.append("sink constraint capability/facet mismatch")
        status = "PASS" if not failures else "FAIL"
        sink_rows.append(
            {
                "report_path": eligible["report_path"],
                "sink_record_id": eligible["sink_inventory_record_id"],
                "tool_name": eligible["tool_name"],
                "canonical_sink_id": eligible["canonical_sink_id"],
                "controlled_facet": eligible["controlled_facet"],
                "chain_id": chain.get("chain_id", "") if chain else "",
                "constraint_id": (
                    chain_constraints[0].get("constraint_id", "")
                    if len(chain_constraints) == 1
                    else ""
                ),
                "status": status,
                "failures": "; ".join(failures),
            }
        )
        trace.append(
            {
                "kind": "sink",
                "oracle_record_id": eligible["record_id"],
                "candidate_chain_ids": [row["chain_id"] for row in candidates],
                "constraint_ids": [row["constraint_id"] for row in chain_constraints],
                "status": status,
                "failures": failures,
            }
        )
        global_failures.extend(failures)

    for expected in oracle["eligible_gate_records"]:
        chain_candidates = [
            row
            for row in chains
            if row.get("tool_name") == expected["tool_name"]
            and row.get("sink_file") == expected["sink_file"]
            and int(row.get("sink_line", "0") or 0) == expected["sink_line"]
        ]
        failures = []
        if len(chain_candidates) != 1:
            failures.append(f"expected one gate-bearing chain, got {len(chain_candidates)}")
        chain = chain_candidates[0] if len(chain_candidates) == 1 else None
        matches = (
            [
                row
                for row in chain_gates
                if row.get("chain_id") == chain.get("chain_id")
                and row.get("gate_name") == expected["gate_name"]
                and row.get("gate_file") == expected["gate_file"]
                and int(row.get("gate_line", "0") or 0) == expected["gate_line"]
            ]
            if chain
            else []
        )
        if len(matches) != 1:
            failures.append(f"expected one exact gate row, got {len(matches)}")
        match = matches[0] if len(matches) == 1 else None
        if match:
            catalog = [row for row in gate_index if row.get("gate_uid") == match["gate_uid"]]
            if len(catalog) != 1:
                failures.append("gate lacks one catalog slice")
            if (
                expected["definition_file"] != expected["gate_file"]
                or expected["definition_line"] != expected["gate_line"]
            ):
                sliced = _slice_for_gate(pipeline_output, match["gate_uid"])
                definition = sliced.get("gate", {}).get("definition_span") or {}
                if (
                    definition.get("file") != expected["definition_file"]
                    or int(definition.get("start_line", 0) or 0)
                    != expected["definition_line"]
                ):
                    failures.append("gate helper definition anchor mismatch")
        status = "PASS" if not failures else "FAIL"
        gate_rows.append(
            {
                "report_path": expected["report_path"],
                "gate_record_id": expected["gate_inventory_record_id"],
                "tool_name": expected["tool_name"],
                "expected_gate": f"{expected['gate_name']}@{expected['gate_file']}:{expected['gate_line']}",
                "chain_id": chain.get("chain_id", "") if chain else "",
                "gate_uid": match.get("gate_uid", "") if match else "",
                "status": status,
                "failures": "; ".join(failures),
            }
        )
        trace.append(
            {
                "kind": "gate",
                "oracle_record_id": expected["record_id"],
                "candidate_chain_ids": [row["chain_id"] for row in chain_candidates],
                "gate_uids": [row["gate_uid"] for row in matches],
                "status": status,
                "failures": failures,
            }
        )
        global_failures.extend(failures)

    cross_tool = oracle["cross_tool_state_record_ids"]
    if cross_tool:
        global_failures.append(
            f"expected no cross-tool-state records in the current five-report corpus, got {len(cross_tool)}"
        )
    summary = {
        "schema_version": "mercury-agent-static-coverage/v1",
        "project": "mercury-agent",
        "revision": REVISION,
        "inventory_counts": EXPECTED,
        "raw_sink_references": len(sink_rows),
        "covered_sink_references": sum(row["status"] == "PASS" for row in sink_rows),
        "eligible_gate_records": len(gate_rows),
        "covered_gate_records": sum(row["status"] == "PASS" for row in gate_rows),
        "cross_tool_state_records": len(cross_tool),
        "chains": len(chains),
        "unique_constraints": len({row["constraint_id"] for row in constraints}),
        "eligible_chain_gate_rows": sum(bool(row.get("gate_uid")) for row in chain_gates),
        "zero_gate_chains": sum(not row.get("gate_uid") for row in chain_gates),
        "slice_failures": gate_manifest["counts"]["slice_failures"],
        "global_failures": global_failures,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, rows in (("gt-coverage.csv", sink_rows), ("gt-gate-coverage.csv", gate_rows)):
        with (out_dir / name).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
    (out_dir / "gt-coverage.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (out_dir / "oracle-matcher-trace.json").write_text(
        json.dumps(trace, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# Mercury Agent GT chain coverage",
        "",
        f"生成命令（仓库根目录）：`{command}`",
        "",
        f"固定 revision：`{REVISION}`。",
        "",
        f"结果：sink references **{summary['covered_sink_references']}/{len(sink_rows)}**；exact-chain gate records **{summary['covered_gate_records']}/{summary['eligible_gate_records']}**；cross-tool state **{summary['cross_tool_state_records']}**；chains **{summary['chains']}**；constraints **{summary['unique_constraints']}**；slice failures **{summary['slice_failures']}**。",
        "",
        "| GT sink record | Tool | Canonical sink | Facet | Chain | Constraint | Status |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in sink_rows:
        lines.append(
            f"| `{row['sink_record_id']}` | `{row['tool_name']}` | `{row['canonical_sink_id']}` | "
            f"`{row['controlled_facet']}` | `{row['chain_id']}` | `{row['constraint_id']}` | **{row['status']}** |"
        )
    (out_dir / "gt-coverage.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--gt-root", type=Path, default=DEFAULT_GT)
    parser.add_argument("--pipeline-output", type=Path, default=DEFAULT_PIPELINE)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    pipeline_arg = (
        args.pipeline_output.relative_to(ROOT)
        if args.pipeline_output.is_relative_to(ROOT)
        else args.pipeline_output
    )
    command = shlex.join(
        [
            "python",
            "design/mercury-agent/call-chain/debug/scripts/render_gt_coverage.py",
            "--pipeline-output",
            str(pipeline_arg),
        ]
    )
    summary = render(
        oracle_path=args.oracle,
        lock_path=args.lock,
        inventory_path=args.inventory,
        gt_root=args.gt_root,
        pipeline_output=args.pipeline_output,
        out_dir=args.out_dir,
        command=command,
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 1 if summary["global_failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

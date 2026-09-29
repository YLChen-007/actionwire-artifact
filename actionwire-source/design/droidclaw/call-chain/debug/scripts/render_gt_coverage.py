#!/usr/bin/env python3
"""Render exact-chain DroidClaw revision-pinned ground-truth coverage."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shlex
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[5]
REVISION = "c7c991933e4a0c03cec6044aa7fb9067d391f4d4"
DEFAULT_ORACLE = ROOT / "design/droidclaw/inventory/droidclaw-static-oracle.json"
DEFAULT_LOCK = ROOT / "design/droidclaw/inventory/droidclaw-groundtruth-lock.json"
DEFAULT_GT = ROOT / "design/droidclaw/groundtruth/new-vuls"
DEFAULT_INVENTORY = ROOT / "design/droidclaw/inventory/debug/groundtruth-inventory.json"
DEFAULT_PIPELINE = ROOT / "output/droidclaw"
DEFAULT_OUT = ROOT / "design/droidclaw/call-chain/debug"

EXPECTED_GATE_COUNTS = {
    "dominance_rows": 15,
    "filter_rows": 3,
    "transform_rows": 3,
    "all_candidate_rows": 21,
    "eligible_catalog_gates": 21,
    "slice_failures": 0,
}
EXPECTED_CHAIN_COUNTS = {
    "chains": 19,
    "sink_constraints": 19,
    "eligible_chain_gate_rows": 21,
    "zero_gate_chains": 5,
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
    for path in sorted(gt_root.glob("*.json")):
        payload = _json(path)
        rows.append(
            {
                "path": path.name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "handlers": len(payload.get("d5_tool_handler_entry") or []),
                "sinks": len(payload.get("d5_sink_points") or []),
                "gates": len(payload.get("d5_gate_points") or []),
                "cross_component_edges": len(payload.get("d5_cross_component") or []),
                "extraction_records": len(payload.get("d5_param_extraction") or []),
            }
        )
    return rows


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
        raise ValueError("DroidClaw oracle/inventory revision mismatch")
    if oracle.get("corpus_sha256") != lock.get("corpus_sha256"):
        raise ValueError("DroidClaw oracle and lock use different corpora")
    if lock.get("reports") != _lock_snapshot(gt_root):
        raise ValueError("DroidClaw ground-truth hash drift; inventory review required")
    expected_counts = {
        "reports": 1,
        "handlers": 1,
        "sinks": 1,
        "gates": 2,
        "cross_component_edges": 0,
        "extraction_records": 3,
    }
    if inventory.get("counts") != expected_counts:
        raise ValueError("DroidClaw inventory does not account for 1/1/1/2/0/3 records")

    static = pipeline_output / "static/call-chains"
    chains = _csv(static / "handler-sink-chains.csv")
    constraints = _csv(static / "sink-constraints.csv")
    chain_gates = _csv(static / "chain-gates.csv")
    gate_index = _csv(pipeline_output / "gate-semantics/gate-index.csv")
    gate_manifest = _json(pipeline_output / "static/gates/manifest.json")
    chain_manifest = _json(pipeline_output / "static/call-chains/manifest.json")
    failures: list[str] = []
    gate_counts = gate_manifest.get("counts", {})
    chain_counts = chain_manifest.get("counts", {})
    for name, expected in EXPECTED_GATE_COUNTS.items():
        if gate_counts.get(name) != expected:
            failures.append(
                f"gate count {name} expected {expected}, got {gate_counts.get(name)}"
            )
    for name, expected in EXPECTED_CHAIN_COUNTS.items():
        if chain_counts.get(name) != expected:
            failures.append(
                f"chain count {name} expected {expected}, got {chain_counts.get(name)}"
            )

    expected_sink = oracle["eligible_sink_records"][0]
    candidates = [
        row
        for row in chains
        if row.get("project_id") == "droidclaw"
        and row.get("tool_name") == expected_sink["tool_name"]
        and row.get("handler_file") == expected_sink["handler_file"]
        and int(row.get("handler_line", "0") or 0) == expected_sink["handler_line"]
        and row.get("sink_file") == expected_sink["sink_file"]
        and int(row.get("sink_line", "0") or 0) == expected_sink["sink_line"]
        and expected_sink["controlled_facet"]
        in {part for part in row.get("sink_argument", "").split(";") if part}
        and all(marker in row.get("call_chain", "") for marker in expected_sink["required_chain_markers"])
    ]
    if len(candidates) != 1:
        failures.append(f"expected one exact shell semantic-action chain, got {len(candidates)}")
    chain = candidates[0] if len(candidates) == 1 else None
    matched_constraints = (
        [row for row in constraints if row.get("sink_id") == chain.get("sink_id")]
        if chain
        else []
    )
    if len(matched_constraints) != 1:
        failures.append(f"expected one sink constraint, got {len(matched_constraints)}")
    elif (
        matched_constraints[0].get("capability_class") != expected_sink["capability_class"]
        or expected_sink["controlled_facet"]
        not in {
            part
            for part in matched_constraints[0].get("controlled_argument", "").split(";")
            if part
        }
    ):
        failures.append("sink capability/facet mismatch")

    existing_rows: list[dict[str, Any]] = []
    for expected in oracle["existing_gate_records"]:
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
            failures.append(f"existing gate {expected['record_id']} matched {len(matches)} rows")
        match = matches[0] if len(matches) == 1 else None
        if match and len(
            [row for row in gate_index if row.get("gate_uid") == match.get("gate_uid")]
        ) != 1:
            failures.append("existing gate lacks one catalog record")
        existing_rows.append(
            {
                "record_id": expected["record_id"],
                "expected_gate": f"{expected['gate_name']}@{expected['gate_file']}:{expected['gate_line']}",
                "chain_id": chain.get("chain_id", "") if chain else "",
                "gate_uid": match.get("gate_uid", "") if match else "",
                "status": "COVERED" if match else "MISS",
            }
        )

    missing_rows: list[dict[str, Any]] = []
    for expected in oracle["expected_missing_records"]:
        impostors = (
            [
                row
                for row in chain_gates
                if row.get("chain_id") == chain.get("chain_id")
                and (
                    row.get("gate_name") == expected["gate_name"]
                    or (
                        row.get("gate_file") == expected["gate_file"]
                        and int(row.get("gate_line", "0") or 0) == expected["gate_line"]
                    )
                )
            ]
            if chain
            else []
        )
        if impostors:
            failures.append(
                f"expected-missing approval {expected['record_id']} was claimed by a gate"
            )
        missing_rows.append(
            {
                "record_id": expected["record_id"],
                "expected_control": expected["gate_name"],
                "controlled_facet": expected["controlled_facet"],
                "defect_anchor": f"{expected['gate_file']}:{expected['gate_line']}",
                "status": "EXPECTED_MISSING" if not impostors else "FALSE_COVERAGE",
            }
        )

    summary = {
        "schema_version": "droidclaw-static-coverage/v1",
        "project": "droidclaw",
        "revision": REVISION,
        "inventory_counts": expected_counts,
        "covered_sink_references": 1 if chain and len(matched_constraints) == 1 else 0,
        "covered_existing_gates": sum(row["status"] == "COVERED" for row in existing_rows),
        "expected_missing_controls": len(missing_rows),
        "correctly_missing_controls": sum(
            row["status"] == "EXPECTED_MISSING" for row in missing_rows
        ),
        "chains": len(chains),
        "unique_constraints": len({row["constraint_id"] for row in constraints}),
        "gate_counts": gate_counts,
        "chain_counts": chain_counts,
        "slice_failures": gate_counts.get("slice_failures", 0),
        "global_failures": failures,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    sink_rows = [
        {
            "report_path": expected_sink["report_path"],
            "sink_record_id": expected_sink["sink_inventory_record_id"],
            "chain_id": chain.get("chain_id", "") if chain else "",
            "constraint_id": (
                matched_constraints[0].get("constraint_id", "")
                if len(matched_constraints) == 1
                else ""
            ),
            "status": "PASS" if chain and len(matched_constraints) == 1 else "FAIL",
        }
    ]
    for name, rows in (
        ("gt-coverage.csv", sink_rows),
        ("gt-existing-gate-coverage.csv", existing_rows),
        ("gt-expected-missing-coverage.csv", missing_rows),
    ):
        with (out_dir / name).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
    (out_dir / "gt-coverage.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    trace = {
        "candidate_chain_ids": [row["chain_id"] for row in candidates],
        "constraint_ids": [row["constraint_id"] for row in matched_constraints],
        "existing_gates": existing_rows,
        "expected_missing": missing_rows,
        "failures": failures,
    }
    (out_dir / "oracle-matcher-trace.json").write_text(
        json.dumps(trace, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "# DroidClaw GT chain coverage",
        "",
        f"生成命令（仓库根目录）：`{command}`",
        "",
        f"固定 revision `{REVISION}`。",
        "",
        f"结果：sink **{summary['covered_sink_references']}/1**；existing gate **{summary['covered_existing_gates']}/1**；expected-missing approval **{summary['correctly_missing_controls']}/1**；slice failures **{summary['slice_failures']}**。",
        "",
        "静态 gate：dom **15**；filter **3**；transform **3**；chain attachments **21**；zero-gate chains **5**。",
        "",
        "`if (!cmd)` 只验证非空，不被当作 shell action approval。",
    ]
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
            "design/droidclaw/call-chain/debug/scripts/render_gt_coverage.py",
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
    print(json.dumps(summary, indent=2))
    return 1 if summary["global_failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

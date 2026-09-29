#!/usr/bin/env python3
"""Render revision-pinned OpenClaw inventory/oracle coverage."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shlex
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[5]
DEFAULT_ORACLE = ROOT / "design/openclaw/inventory/openclaw-static-oracle.json"
DEFAULT_LOCK = ROOT / "design/openclaw/inventory/openclaw-groundtruth-lock.json"
DEFAULT_INVENTORY = ROOT / "design/openclaw/inventory/debug/sink-inventory.json"
DEFAULT_GT = ROOT / "design/openclaw/groundtruth"
DEFAULT_PIPELINE = ROOT / "output/openclaw"
DEFAULT_OUT = ROOT / "design/openclaw/call-chain/debug"
EXPECTED_REPORTS = 86
EXPECTED_SINK_REFERENCES = 159
FIELDS = (
    "record_id",
    "report_path",
    "capability_class",
    "tool_names",
    "sink_witness",
    "gate_expectation",
    "matched_chains",
    "matched_gates",
    "status",
    "detail",
)


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise ValueError(f"required pipeline artifact is missing: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _current_lock(gt_root: Path) -> dict[str, Any]:
    reports = []
    for path in sorted(gt_root.rglob("*.json")):
        payload = _load(path)
        reports.append(
            {
                "path": path.relative_to(gt_root).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "sink_count": len(payload.get("d5_sink_points") or []),
            }
        )
    digest = hashlib.sha256(
        json.dumps(reports, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema_version": "openclaw-groundtruth-lock/v1",
        "report_count": len(reports),
        "sink_reference_count": sum(row["sink_count"] for row in reports),
        "corpus_sha256": digest,
        "reports": reports,
    }


def render(
    *, oracle_path: Path, lock_path: Path, inventory_path: Path, gt_root: Path,
    pipeline_output: Path, out_dir: Path, command: str,
) -> dict[str, Any]:
    oracle = _load(oracle_path)
    lock = _load(lock_path)
    inventory = _load(inventory_path)
    if lock != _current_lock(gt_root):
        raise ValueError("OpenClaw ground-truth hash drift; review inventory before acceptance")
    if oracle.get("revision") != "d842b28a1517f95aae2a5bcd97f2f726e42b93d8":
        raise ValueError("OpenClaw oracle revision mismatch")
    if oracle.get("corpus_sha256") != lock.get("corpus_sha256"):
        raise ValueError("OpenClaw oracle and ground-truth lock use different corpora")
    counts = inventory.get("counts", {})
    if (
        counts.get("reports") != EXPECTED_REPORTS
        or counts.get("sink_references") != EXPECTED_SINK_REFERENCES
    ):
        raise ValueError(
            "OpenClaw inventory must account for exactly "
            f"{EXPECTED_REPORTS} reports and {EXPECTED_SINK_REFERENCES} sinks"
        )

    chain_root = pipeline_output / "static/call-chains"
    chains = _read_csv(chain_root / "handler-sink-chains.csv")
    constraints = _read_csv(chain_root / "sink-constraints.csv")
    chain_gates = _read_csv(chain_root / "chain-gates.csv")
    gate_index = _read_csv(pipeline_output / "gate-semantics/gate-index.csv")
    gate_manifest = _load(pipeline_output / "static/gates/manifest.json")

    constraints_by_sink: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in constraints:
        constraints_by_sink[row["sink_id"]].append(row)
    duplicate_constraints = sorted(
        sink_id for sink_id, rows in constraints_by_sink.items() if len(rows) != 1
    )
    if duplicate_constraints:
        raise ValueError("sink constraint cardinality failure: " + ", ".join(duplicate_constraints))

    gates_by_chain: dict[str, set[str]] = defaultdict(set)
    for row in chain_gates:
        if row.get("gate_name"):
            gates_by_chain[row["chain_id"]].add(row["gate_name"])
    all_gate_names = {row.get("gate_name", "") for row in gate_index}

    rows: list[dict[str, str]] = []
    trace: list[dict[str, Any]] = []
    for expected in oracle.get("eligible_records", []):
        tools = set(expected.get("tool_names") or [])
        capability = str(expected["capability_class"])
        candidates = []
        for chain in chains:
            constraint_rows = constraints_by_sink.get(chain["sink_id"], [])
            if len(constraint_rows) != 1:
                continue
            constraint = constraint_rows[0]
            if chain.get("tool_name") in tools and constraint.get("capability_class") == capability:
                candidates.append(chain)
        exact = [
            chain
            for chain in candidates
            if chain.get("sink_file") == expected.get("sink_file")
            and int(chain.get("sink_line", "0")) == int(expected.get("sink_line", 0))
        ]
        matched = exact or candidates
        attached_names = {
            name for chain in matched for name in gates_by_chain.get(chain["chain_id"], set())
        }
        expected_existing = set(expected.get("existing_gate_names") or [])
        expected_missing = set(expected.get("expected_missing_gate_names") or [])
        existing_matches = sorted(expected_existing & (all_gate_names | attached_names))
        false_missing_matches = sorted(expected_missing & (all_gate_names | attached_names))

        failures: list[str] = []
        if not matched:
            failures.append("no taint-valid handler-to-capability chain")
        if expected.get("gate_expectation") == "existing" and not existing_matches:
            failures.append("no expected existing gate was detected")
        if expected.get("gate_expectation") == "expected_missing" and false_missing_matches:
            failures.append("expected-missing control was falsely claimed as present")
        status = "PASS" if not failures else "FAIL"
        sink_witness = f"{expected.get('sink_file')}:{expected.get('sink_line')}"
        rows.append(
            {
                "record_id": str(expected["record_id"]),
                "report_path": str(expected["report_path"]),
                "capability_class": capability,
                "tool_names": ";".join(sorted(tools)),
                "sink_witness": sink_witness,
                "gate_expectation": str(expected.get("gate_expectation", "")),
                "matched_chains": ";".join(sorted(chain["chain_id"] for chain in matched)),
                "matched_gates": ";".join(existing_matches),
                "status": status,
                "detail": "; ".join(failures) or "handler chain, sink constraint, and gate expectation matched",
            }
        )
        trace.append(
            {
                "record_id": expected["record_id"],
                "report_path": expected["report_path"],
                "candidate_chain_ids": [chain["chain_id"] for chain in candidates],
                "exact_witness_chain_ids": [chain["chain_id"] for chain in exact],
                "selected_chain_ids": [chain["chain_id"] for chain in matched],
                "expected_existing_gate_names": sorted(expected_existing),
                "detected_existing_gate_names": existing_matches,
                "expected_missing_gate_names": sorted(expected_missing),
                "unexpected_missing_gate_matches": false_missing_matches,
                "status": status,
            }
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "gt-coverage.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "oracle-matcher-trace.json").write_text(
        json.dumps({"schema_version": "openclaw-oracle-trace/v1", "records": trace}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    statuses = Counter(row["status"] for row in rows)
    summary = {
        "schema_version": "openclaw-static-coverage/v1",
        "project": "openclaw",
        "revision": oracle["revision"],
        "reports": counts["reports"],
        "sink_references": counts["sink_references"],
        "eligible_records": len(rows),
        "statuses": dict(sorted(statuses.items())),
        "slice_failures": gate_manifest.get("counts", {}).get("slice_failures"),
        "unique_constraints": len(constraints),
    }
    if summary["slice_failures"] != 0:
        summary["statuses"]["FAIL"] = summary["statuses"].get("FAIL", 0) + 1
    (out_dir / "gt-coverage.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# OpenClaw revision-pinned D5 coverage",
        "",
        f"生成命令（仓库根目录）：`{command}`",
        "",
        f"固定 revision：`{oracle['revision']}`；语料锁：**{counts['reports']} reports / {counts['sink_references']} sinks**。",
        "",
        f"Eligible oracle records: **{len(rows)}**；PASS: **{statuses.get('PASS', 0)}**；FAIL: **{statuses.get('FAIL', 0)}**。",
        "",
        "| Record | Report | Capability | Tools | Gate expectation | Chains | Status |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| `{row['record_id']}` | `{row['report_path']}` | `{row['capability_class']}` | "
            f"`{row['tool_names']}` | `{row['gate_expectation']}` | `{row['matched_chains']}` | **{row['status']}** |"
        )
    lines.extend(
        [
            "",
            "`expected_missing` 只检查 GT 明确列出的缺失控制名，不把同一链上的参数规范化或其他 gate 冒充为修复控制。",
        ]
    )
    (out_dir / "gt-coverage.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--ground-truth", type=Path, default=DEFAULT_GT)
    parser.add_argument("--pipeline-output", type=Path, default=DEFAULT_PIPELINE)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    command = shlex.join(
        [
            "python",
            "design/openclaw/call-chain/debug/scripts/render_gt_coverage.py",
            "--oracle", str(args.oracle),
            "--lock", str(args.lock),
            "--inventory", str(args.inventory),
            "--ground-truth", str(args.ground_truth),
            "--pipeline-output", str(args.pipeline_output),
            "--out-dir", str(args.out_dir),
        ]
    )
    try:
        summary = render(
            oracle_path=args.oracle.resolve(), lock_path=args.lock.resolve(),
            inventory_path=args.inventory.resolve(), gt_root=args.ground_truth.resolve(),
            pipeline_output=args.pipeline_output.resolve(), out_dir=args.out_dir.resolve(),
            command=command,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc))
        return 1
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 1 if summary["statuses"].get("FAIL") else 0


if __name__ == "__main__":
    raise SystemExit(main())

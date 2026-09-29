#!/usr/bin/env python3
"""Render exact-chain OpenClaw-CN revision-pinned GT coverage."""

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
REVISION = "558f272e6c90e7e0c37644e505e161b91ef738f0"
DEFAULT_ORACLE = ROOT / "design/openclaw-cn/inventory/openclaw-cn-static-oracle.json"
DEFAULT_LOCK = ROOT / "design/openclaw-cn/inventory/openclaw-cn-source-gt-lock.json"
DEFAULT_INVENTORY = ROOT / "design/openclaw-cn/inventory/debug/groundtruth-inventory.json"
DEFAULT_GT = ROOT / "design/openclaw-cn/groundtruth/new-vuls"
DEFAULT_PIPELINE = ROOT / "output/openclaw-cn"
DEFAULT_OUT = ROOT / "design/openclaw-cn/call-chain/debug"


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _report_snapshot(gt_root: Path) -> list[dict[str, Any]]:
    reports = []
    for path in sorted(gt_root.glob("*.json")):
        payload = _json(path)
        reports.append(
            {
                "path": path.name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "handlers": len(payload.get("d5_tool_handler_entry") or []),
                "extraction_records": len(payload.get("d5_param_extraction") or []),
                "gates": len(payload.get("d5_gate_points") or []),
                "sinks": len(payload.get("d5_sink_points") or []),
                "cross_component_edges": len(payload.get("d5_cross_component") or []),
            }
        )
    return reports


def _gate_identity(row: dict[str, Any]) -> tuple[str, str, int]:
    return (
        str(row.get("gate_name", "")),
        str(row.get("gate_file", "")),
        int(row.get("gate_line", 0) or 0),
    )


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
    if {oracle.get("revision"), lock.get("revision"), inventory.get("revision")} != {
        REVISION
    }:
        raise ValueError("OpenClaw-CN revision mismatch")
    if oracle.get("corpus_sha256") != lock.get("corpus_sha256") or inventory.get(
        "corpus_sha256"
    ) != lock.get("corpus_sha256"):
        raise ValueError("OpenClaw-CN lock/inventory/oracle corpus mismatch")
    if lock.get("reports") != _report_snapshot(gt_root):
        raise ValueError("OpenClaw-CN ground-truth hash drift; inventory review required")
    # The oracle has derived fields in addition to the raw inventory totals.
    for key, value in inventory.get("counts", {}).items():
        if oracle.get("expected", {}).get(key) != value:
            raise ValueError(f"OpenClaw-CN raw count mismatch for {key}")

    root = pipeline_output / "static/call-chains"
    chains = _csv(root / "handler-sink-chains.csv")
    constraints = _csv(root / "sink-constraints.csv")
    chain_gates = _csv(root / "chain-gates.csv")
    gate_manifest = _json(pipeline_output / "static/gates/manifest.json")
    chain_manifest = _json(root / "manifest.json")

    constraints_by_sink: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in constraints:
        constraints_by_sink[row["sink_id"]].append(row)
    bad_constraints = sorted(
        sink_id for sink_id, rows in constraints_by_sink.items() if len(rows) != 1
    )
    if bad_constraints:
        raise ValueError("non-unique OpenClaw-CN sink constraints: " + ", ".join(bad_constraints))

    gates_by_chain: dict[str, list[dict[str, str]]] = defaultdict(list)
    all_gate_identities: set[tuple[str, str, int]] = set()
    for row in chain_gates:
        if row.get("gate_uid"):
            gates_by_chain[row["chain_id"]].append(row)
            all_gate_identities.add(_gate_identity(row))

    covered_sink_refs: set[str] = set()
    covered_gate_refs: set[str] = set()
    checked_missing_refs: set[str] = set()
    matched_gt_chain_ids: set[str] = set()
    matched_gt_sink_ids: set[str] = set()
    rows = []
    trace = []
    for expected in oracle["eligible_sink_records"]:
        candidates = [
            chain
            for chain in chains
            if chain.get("tool_name") in set(expected["tool_names"])
            and chain.get("sink_file") == expected["sink_file"]
            and int(chain.get("sink_line", 0) or 0) == expected["sink_line"]
        ]
        matched = []
        for chain in candidates:
            cards = constraints_by_sink.get(chain["sink_id"], [])
            if len(cards) != 1:
                continue
            card = cards[0]
            facets = set(card.get("controlled_argument", "").split(";"))
            if card.get("capability_class") != expected["capability_class"]:
                continue
            if expected["controlled_facet"] not in facets:
                continue
            matched.append(chain)

        attached = [
            row for chain in matched for row in gates_by_chain.get(chain["chain_id"], [])
        ]
        identities = {_gate_identity(row) for row in attached}
        existing_results = []
        for gate in expected["existing_gates"]:
            identity = _gate_identity(gate)
            ok = identity in identities
            if ok:
                covered_gate_refs.add(gate["inventory_record_id"])
            existing_results.append({**gate, "matched": ok})

        missing_results = []
        for missing in expected["expected_missing"]:
            checked_missing_refs.add(missing["inventory_record_id"])
            false_match = any(
                row["gate_name"] == missing["forbidden_gate_name"] for row in attached
            )
            missing_results.append({**missing, "falsely_matched": false_match})

        failures = []
        if len(matched) != 1:
            failures.append(f"expected one exact chain, got {len(matched)}")
        absent = [row["gt_name"] for row in existing_results if not row["matched"]]
        if absent:
            failures.append("missing exact-chain gates: " + "; ".join(absent))
        false_missing = [
            row["gt_name"] for row in missing_results if row["falsely_matched"]
        ]
        if false_missing:
            failures.append("expected-missing gate was attached: " + "; ".join(false_missing))
        if len(matched) == 1:
            covered_sink_refs.update(expected["source_sink_records"])
            matched_gt_chain_ids.add(matched[0]["chain_id"])
            matched_gt_sink_ids.add(matched[0]["sink_id"])
        rows.append(
            {
                "record_id": expected["record_id"],
                "reports": ";".join(expected["report_paths"]),
                "tools": ";".join(expected["tool_names"]),
                "capability_class": expected["capability_class"],
                "controlled_facet": expected["controlled_facet"],
                "sink_witness": f"{expected['sink_file']}:{expected['sink_line']}",
                "matched_chain": matched[0]["chain_id"] if len(matched) == 1 else "",
                "existing_gate_refs": len(existing_results),
                "expected_missing_refs": len(missing_results),
                "status": "PASS" if not failures else "FAIL",
                "detail": "; ".join(failures) or "exact chain, gates, facet, and constraint matched",
            }
        )
        trace.append(
            {
                "record_id": expected["record_id"],
                "candidate_chain_ids": [row["chain_id"] for row in candidates],
                "selected_chain_ids": [row["chain_id"] for row in matched],
                "existing_gate_matches": existing_results,
                "expected_missing_checks": missing_results,
                "failures": failures,
            }
        )

    protected_results = []
    for gate in oracle["protected_sibling_evidence"]:
        ok = _gate_identity(gate) in all_gate_identities
        if ok:
            covered_gate_refs.add(gate["inventory_record_id"])
        protected_results.append({**gate, "matched": ok})

    sink_ref_ids = {
        row["record_id"] for row in inventory["records"] if row["kind"] == "sink"
    }
    present_gate_ids = {
        row["record_id"]
        for row in inventory["records"]
        if row["kind"] == "gate" and row["anchor_status"] != "expected-missing"
    }
    missing_gate_ids = {
        row["record_id"]
        for row in inventory["records"]
        if row["kind"] == "gate" and row["anchor_status"] == "expected-missing"
    }
    global_failures = []
    if covered_sink_refs != sink_ref_ids:
        global_failures.append("not all 15 GT sink references matched the 13 concrete chains")
    if covered_gate_refs != present_gate_ids:
        global_failures.append("not all 64 present/protected/defective gate refs matched")
    if checked_missing_refs != missing_gate_ids:
        global_failures.append("not all five expected-missing refs were checked")
    if any(not row["matched"] for row in protected_results):
        global_failures.append("protected sibling evidence is absent from its direct-navigation chain")
    if gate_manifest.get("counts", {}).get("slice_failures") != 0:
        global_failures.append("gate slice failures are nonzero")
    if len(matched_gt_sink_ids) != oracle["expected"]["concrete_sinks"]:
        global_failures.append("GT concrete sink cardinality drift")

    out_dir.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0])
    with (out_dir / "gt-coverage.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "oracle-matcher-trace.json").write_text(
        json.dumps(
            {
                "schema_version": "openclaw-cn-oracle-trace/v1",
                "records": trace,
                "protected_sibling_evidence": protected_results,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    statuses = Counter(row["status"] for row in rows)
    summary = {
        "schema_version": "openclaw-cn-static-coverage/v1",
        "project": "openclaw-cn",
        "revision": REVISION,
        "inventory_counts": inventory["counts"],
        "concrete_sink_records": len(rows),
        "covered_sink_references": len(covered_sink_refs),
        "covered_present_gate_references": len(covered_gate_refs),
        "checked_expected_missing_references": len(checked_missing_refs),
        # Compatibility aliases retain their historical meaning as full static totals.
        "chains": len(chains),
        "unique_constraints": len(constraints),
        "shared_audit_chains": len(chains),
        "shared_audit_constraints": len(constraints),
        "gt_matched_chains": len(matched_gt_chain_ids),
        "gt_matched_constraints": len(matched_gt_sink_ids),
        "additional_shared_chains": len(chains) - len(matched_gt_chain_ids),
        "additional_shared_constraints": len(constraints) - len(matched_gt_sink_ids),
        "eligible_chain_gate_rows": chain_manifest.get("counts", {}).get(
            "eligible_chain_gate_rows"
        ),
        "slice_failures": gate_manifest.get("counts", {}).get("slice_failures"),
        "statuses": dict(sorted(statuses.items())),
        "global_failures": global_failures,
    }
    (out_dir / "gt-coverage.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "# OpenClaw-CN revision-pinned D5 coverage",
        "",
        f"生成命令（仓库根目录）：`{command}`",
        "",
        f"固定 revision：`{REVISION}`；原始 GT 完整入账：**8 handlers / 43 extraction records / 69 gates / 15 sinks / 21 cross-component edges**。",
        "",
        f"13 concrete sink records：**{statuses.get('PASS', 0)}/{len(rows)} PASS**；15 sink refs：**{len(covered_sink_refs)}/15**；present/protected/defective gate refs：**{len(covered_gate_refs)}/64**；expected-missing：**{len(checked_missing_refs)}/5**。",
        "",
        f"共享 sink catalog audit：**{len(chains)} chains / {len(constraints)} constraints**；其中 GT exact witness 使用 **{len(matched_gt_chain_ids)} chains / {len(matched_gt_sink_ids)} constraints**。额外发现保留在静态输出中，不进入固定 GT 分母。",
        "",
        "| Reports | Tool | Capability/facet | Sink | Chain | Gates/missing | Status |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| `{row['reports']}` | `{row['tools']}` | `{row['capability_class']}` / `{row['controlled_facet']}` | `{row['sink_witness']}` | `{row['matched_chain'] or '-'} ` | {row['existing_gate_refs']}/{row['expected_missing_refs']} | **{row['status']}** |"
        )
    if global_failures:
        lines.extend(["", "Global failures: " + "; ".join(global_failures)])
    (out_dir / "gt-coverage.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if statuses.get("FAIL") or global_failures:
        raise ValueError("OpenClaw-CN static GT coverage failed")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--groundtruth", type=Path, default=DEFAULT_GT)
    parser.add_argument("--pipeline-output", type=Path, default=DEFAULT_PIPELINE)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    command_parts = [
        "python",
        "design/openclaw-cn/call-chain/debug/scripts/render_gt_coverage.py",
    ]
    if (
        args.pipeline_output.resolve() != DEFAULT_PIPELINE.resolve()
        or args.out_dir.resolve() != DEFAULT_OUT.resolve()
    ):
        command_parts.extend(
            [
                "--pipeline-output",
                str(args.pipeline_output),
                "--out-dir",
                str(args.out_dir),
            ]
        )
    command = shlex.join(command_parts)
    summary = render(
        oracle_path=args.oracle.resolve(),
        lock_path=args.lock.resolve(),
        inventory_path=args.inventory.resolve(),
        gt_root=args.groundtruth.resolve(),
        pipeline_output=args.pipeline_output.resolve(),
        out_dir=args.out_dir.resolve(),
        command=command,
    )
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Render exact-chain NanoClaw revision-pinned GT coverage."""

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
REVISION = "36cbf17e107fd0f8daea4ceb2ac523d9f0d88915"
DEFAULT_ORACLE = ROOT / "design/nanoclaw/inventory/nanoclaw-static-oracle.json"
DEFAULT_LOCK = ROOT / "design/nanoclaw/inventory/nanoclaw-groundtruth-lock.json"
DEFAULT_GT = ROOT / "design/nanoclaw/groundtruth/new-vuls"
DEFAULT_INVENTORY = ROOT / "design/nanoclaw/inventory/debug/groundtruth-inventory.json"
DEFAULT_PIPELINE = ROOT / "output/nanoclaw"
DEFAULT_OUT = ROOT / "design/nanoclaw/call-chain/debug"


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _lock_snapshot(gt_root: Path) -> list[dict[str, Any]]:
    reports = []
    for path in sorted(gt_root.glob("*.json")):
        payload = _json(path)
        reports.append(
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
    return reports


def _gate_identity(row: dict[str, str]) -> tuple[str, str, int]:
    return (
        row.get("gate_name", ""),
        row.get("gate_file", ""),
        int(row.get("gate_line", "0") or 0),
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
    if oracle.get("revision") != REVISION or inventory.get("revision") != REVISION:
        raise ValueError("NanoClaw oracle/inventory revision mismatch")
    if oracle.get("corpus_sha256") != lock.get("corpus_sha256"):
        raise ValueError("NanoClaw oracle and lock use different corpora")
    if lock.get("reports") != _lock_snapshot(gt_root):
        raise ValueError("NanoClaw ground-truth hash drift; inventory review required")
    expected_counts = {
        "reports": 4,
        "handlers": 4,
        "sinks": 6,
        "gates": 22,
        "cross_component_edges": 9,
        "extraction_records": 11,
    }
    if inventory.get("counts") != expected_counts:
        raise ValueError(
            "NanoClaw inventory does not fully account for 4/4/6/22/9/11 records"
        )

    root = pipeline_output / "static/call-chains"
    chains = _csv(root / "handler-sink-chains.csv")
    constraints = _csv(root / "sink-constraints.csv")
    chain_gates = _csv(root / "chain-gates.csv")
    gate_index = _csv(pipeline_output / "gate-semantics/gate-index.csv")
    gate_manifest = _json(pipeline_output / "static/gates/manifest.json")
    chain_manifest = _json(root / "manifest.json")

    constraints_by_sink: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in constraints:
        constraints_by_sink[row["sink_id"]].append(row)
    bad_constraints = sorted(
        key for key, rows in constraints_by_sink.items() if len(rows) != 1
    )
    if bad_constraints:
        raise ValueError("non-unique sink constraints: " + ", ".join(bad_constraints))

    gates_by_chain: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in chain_gates:
        if row.get("gate_uid"):
            gates_by_chain[row["chain_id"]].append(row)
    index_by_uid = {row["gate_uid"]: row for row in gate_index}

    rows: list[dict[str, str]] = []
    trace: list[dict[str, Any]] = []
    covered_gate_records: set[str] = set()
    missing_records: set[str] = set()
    false_missing_records: set[str] = set()
    for expected in oracle.get("eligible_sink_records", []):
        tools = set(expected.get("tool_names") or [])
        exact = [
            chain
            for chain in chains
            if chain.get("tool_name") in tools
            and chain.get("sink_file") == expected.get("sink_file")
            and int(chain.get("sink_line", "0") or 0)
            == int(expected.get("sink_line", 0))
        ]
        matched = []
        for chain in exact:
            card_rows = constraints_by_sink.get(chain["sink_id"], [])
            if len(card_rows) != 1:
                continue
            card = card_rows[0]
            facets = set(card.get("controlled_argument", "").split(";"))
            if card.get("capability_class") != expected.get("capability_class"):
                continue
            if (
                expected.get("controlled_facet")
                and expected["controlled_facet"] not in facets
            ):
                continue
            matched.append(chain)

        attached = [
            row
            for chain in matched
            for row in gates_by_chain.get(chain["chain_id"], [])
        ]
        attached_identities = {_gate_identity(row) for row in attached}
        existing_results = []
        for gate in expected.get("existing_gates", []):
            identity = (gate["gate_name"], gate["gate_file"], int(gate["gate_line"]))
            ok = identity in attached_identities
            if ok:
                covered_gate_records.add(gate["inventory_record_id"])
            existing_results.append({**gate, "matched": ok})

        missing_results = []
        for missing in expected.get("expected_missing", []):
            missing_records.add(missing["inventory_record_id"])
            forbidden = missing["forbidden_gate_name"]
            facet = missing["controlled_facet"]
            false_match = False
            for gate in attached:
                catalog = index_by_uid.get(gate["gate_uid"], {})
                expression = " ".join(
                    (
                        catalog.get("call_expression", ""),
                        catalog.get("checked_expression", ""),
                    )
                )
                if gate.get("gate_name") == forbidden:
                    false_match = True
                elif (
                    facet == "destination-path:target-inbox"
                    and gate.get("gate_name") == "isPathInside"
                    and "targetInbox" in expression
                ):
                    false_match = True
                elif (
                    facet == "source-path:workspace-root"
                    and gate.get("gate_file")
                    == "container/agent-runner/src/mcp-tools/core.ts"
                    and gate.get("gate_name") in {"isPathInside", "assertSandboxPath"}
                ):
                    false_match = True
            if false_match:
                false_missing_records.add(missing["inventory_record_id"])
            missing_results.append({**missing, "falsely_matched": false_match})

        failures = []
        if len(matched) != 1:
            failures.append(f"expected exactly one exact chain, got {len(matched)}")
        missing_existing = [
            row["gt_name"] for row in existing_results if not row["matched"]
        ]
        if missing_existing:
            failures.append("missing exact-chain gates: " + "; ".join(missing_existing))
        false_missing = [
            row["gt_name"] for row in missing_results if row["falsely_matched"]
        ]
        if false_missing:
            failures.append(
                "expected-missing control falsely matched: " + "; ".join(false_missing)
            )
        status = "PASS" if not failures else "FAIL"
        rows.append(
            {
                "record_id": expected["record_id"],
                "report_path": expected["report_path"],
                "tool_names": ";".join(sorted(tools)),
                "capability_class": expected["capability_class"],
                "controlled_facet": expected["controlled_facet"],
                "sink_witness": f"{expected['sink_file']}:{expected['sink_line']}",
                "matched_chain": matched[0]["chain_id"] if len(matched) == 1 else "",
                "existing_gates": str(len(existing_results)),
                "expected_missing": str(len(missing_results)),
                "status": status,
                "detail": "; ".join(failures)
                or "exact chain, sink facet, gates, and constraint matched",
            }
        )
        trace.append(
            {
                "record_id": expected["record_id"],
                "candidate_chain_ids": [row["chain_id"] for row in exact],
                "selected_chain_ids": [row["chain_id"] for row in matched],
                "existing_gate_matches": existing_results,
                "expected_missing_checks": missing_results,
                "status": status,
            }
        )

    expected_existing_ids = {
        row["record_id"]
        for row in inventory["records"]
        if row["kind"] == "gate" and row["anchor_status"] in {"current", "rebased"}
    }
    expected_missing_ids = {
        row["record_id"]
        for row in inventory["records"]
        if row["kind"] == "gate" and row["anchor_status"] == "expected-missing"
    }
    not_present_ids = {
        row["record_id"]
        for row in inventory["records"]
        if row["kind"] == "gate" and row["anchor_status"] == "not-present"
    }
    global_failures = []
    if covered_gate_records != expected_existing_ids:
        global_failures.append(
            "not all current/rebased gate records matched exact chains"
        )
    if missing_records != expected_missing_ids or false_missing_records:
        global_failures.append("expected-missing controls were not preserved exactly")
    if gate_manifest.get("counts", {}).get("slice_failures") != 0:
        global_failures.append("gate slice failures are nonzero")
    if len(constraints) != len(chains):
        global_failures.append(
            "each concrete chain sink must have one unique constraint"
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else []
    for name in ("gt-coverage.csv", "d5-item-coverage.csv"):
        with (out_dir / name).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
    (out_dir / "oracle-matcher-trace.json").write_text(
        json.dumps(
            {"schema_version": "nanoclaw-oracle-trace/v1", "records": trace}, indent=2
        )
        + "\n",
        encoding="utf-8",
    )
    statuses = Counter(row["status"] for row in rows)
    summary = {
        "schema_version": "nanoclaw-static-coverage/v1",
        "project": "nanoclaw",
        "revision": REVISION,
        "inventory_counts": expected_counts,
        "eligible_sink_records": len(rows),
        "current_or_rebased_gate_records": len(expected_existing_ids),
        "covered_gate_records": len(covered_gate_records),
        "expected_missing_records": len(expected_missing_ids),
        "not_present_records": len(not_present_ids),
        "chains": len(chains),
        "unique_constraints": len(constraints),
        "eligible_chain_gate_rows": chain_manifest.get("counts", {}).get(
            "eligible_chain_gate_rows"
        ),
        "slice_failures": gate_manifest.get("counts", {}).get("slice_failures"),
        "statuses": dict(sorted(statuses.items())),
        "global_failures": global_failures,
    }
    for name in ("gt-coverage.json", "d5-item-coverage.json"):
        (out_dir / name).write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8"
        )
    lines = [
        "# NanoClaw revision-pinned D5 coverage",
        "",
        f"生成命令（仓库根目录）：`{command}`",
        "",
        f"固定 revision：`{REVISION}`；原始 GT 完整入账：**4 handlers / 6 sinks / 22 gates / 9 cross-component edges / 11 extraction records**。",
        "",
        f"Eligible sink records: **{len(rows)}**；exact-chain PASS: **{statuses.get('PASS', 0)}**；"
        f"current/rebased gate coverage: **{len(covered_gate_records)}/{len(expected_existing_ids)}**；"
        f"expected-missing: **{len(expected_missing_ids)}**；not-present: **{len(not_present_ids)}**。",
        "",
        "| Record | Report | Tool | Capability/facet | Sink | Chain | Status |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| `{row['record_id']}` | `{row['report_path']}` | `{row['tool_names']}` | "
            f"`{row['capability_class']}:{row['controlled_facet']}` | `{row['sink_witness']}` | "
            f"`{row['matched_chain']}` | **{row['status']}** |"
        )
    lines.extend(
        [
            "",
            "Facet-specific negative oracle: source-outbox `isPathInside(realSourceDir, realSrc)` does not satisfy target-inbox containment, and `existsSync(resolvedPath)` does not satisfy workspace-root containment.",
        ]
    )
    if global_failures:
        lines.extend(["", "Global failures: " + "; ".join(global_failures)])
    markdown = "\n".join(lines) + "\n"
    (out_dir / "gt-coverage.md").write_text(markdown, encoding="utf-8")
    (out_dir / "d5-item-coverage.md").write_text(markdown, encoding="utf-8")
    if global_failures or statuses.get("FAIL", 0):
        raise ValueError(
            "NanoClaw GT coverage failed: "
            + "; ".join(global_failures or ["record mismatch"])
        )
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
            "design/nanoclaw/call-chain/debug/scripts/render_gt_coverage.py",
            "--oracle",
            "design/nanoclaw/inventory/nanoclaw-static-oracle.json",
            "--lock",
            "design/nanoclaw/inventory/nanoclaw-groundtruth-lock.json",
            "--inventory",
            "design/nanoclaw/inventory/debug/groundtruth-inventory.json",
            "--ground-truth",
            "design/nanoclaw/groundtruth/new-vuls",
            "--pipeline-output",
            "output/nanoclaw",
            "--out-dir",
            "design/nanoclaw/call-chain/debug",
        ]
    )
    summary = render(
        oracle_path=args.oracle.resolve(),
        lock_path=args.lock.resolve(),
        inventory_path=args.inventory.resolve(),
        gt_root=args.ground_truth.resolve(),
        pipeline_output=args.pipeline_output.resolve(),
        out_dir=args.out_dir.resolve(),
        command=command,
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Generate DroidClaw's revision-pinned GT lock, inventory, and static oracle."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shlex
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[5]
PROJECT = "droidclaw"
REVISION = "c7c991933e4a0c03cec6044aa7fb9067d391f4d4"
VERSION = "1.0.0"
DEFAULT_GT = ROOT / "design/droidclaw/groundtruth/new-vuls"
DEFAULT_SOURCE = ROOT / "benchmark/typescript/droidclaw"
DEFAULT_OUT = ROOT / "design/droidclaw/inventory/debug"
DEFAULT_LOCK = ROOT / "design/droidclaw/inventory/droidclaw-groundtruth-lock.json"
DEFAULT_ORACLE = ROOT / "design/droidclaw/inventory/droidclaw-static-oracle.json"
EXPECTED = {
    "reports": 1,
    "handlers": 1,
    "sinks": 1,
    "gates": 2,
    "cross_component_edges": 0,
    "extraction_records": 3,
}


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stable(prefix: str, *parts: object) -> str:
    raw = "|".join(str(part) for part in parts)
    return prefix + hashlib.sha256(raw.encode()).hexdigest()[:16]


def _items(payload: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    key = {
        "handler": "d5_tool_handler_entry",
        "sink": "d5_sink_points",
        "gate": "d5_gate_points",
        "cross_component": "d5_cross_component",
        "extraction": "d5_param_extraction",
    }[kind]
    value = payload.get(key) or []
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise ValueError(f"{key} must be a list of objects")
    return value


def _location(value: str) -> tuple[str, int]:
    match = re.match(r"^(.*):(\d+)$", value.strip())
    if not match:
        return value.strip(), 0
    return match.group(1), int(match.group(2))


def _line(source_root: Path, file: str, line: int) -> str:
    path = source_root / file
    if not path.is_file() or line <= 0:
        return ""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[line - 1].strip() if line <= len(lines) else ""


def build_lock(gt_root: Path) -> dict[str, Any]:
    reports = []
    totals = {key: 0 for key in EXPECTED if key != "reports"}
    for path in sorted(gt_root.glob("*.json")):
        payload = _json(path)
        counts = {
            "handlers": len(_items(payload, "handler")),
            "sinks": len(_items(payload, "sink")),
            "gates": len(_items(payload, "gate")),
            "cross_component_edges": len(_items(payload, "cross_component")),
            "extraction_records": len(_items(payload, "extraction")),
        }
        for key, value in counts.items():
            totals[key] += value
        reports.append({"path": path.name, "sha256": _sha(path), **counts})
    counts = {"reports": len(reports), **totals}
    if counts != EXPECTED:
        raise ValueError(f"DroidClaw GT cardinality changed: expected {EXPECTED}, got {counts}")
    corpus = hashlib.sha256(
        json.dumps(reports, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema_version": "droidclaw-groundtruth-lock/v1",
        "project": PROJECT,
        "version": VERSION,
        "revision": REVISION,
        "counts": counts,
        "corpus_sha256": corpus,
        "reports": reports,
    }


def build_inventory(
    gt_root: Path, source_root: Path, lock: dict[str, Any]
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for report in lock["reports"]:
        payload = _json(gt_root / report["path"])
        for kind in ("handler", "sink", "gate", "cross_component", "extraction"):
            for index, item in enumerate(_items(payload, kind), 1):
                name = str(item.get("name") or f"{kind}-{index}")
                original_file, original_line = _location(str(item.get("location") or ""))
                row: dict[str, Any] = {
                    "record_id": _stable("DCGT-", report["path"], kind, index, name),
                    "report_path": report["path"],
                    "kind": kind,
                    "source_index": index,
                    "name": name,
                    "original_location": str(item.get("location") or ""),
                    "evidence": str(item.get("evidence") or ""),
                    "anchor_status": "current",
                    "mapping_status": "canonical",
                    "current_file": original_file,
                    "current_line": original_line,
                    "expected_tool": "",
                    "expected_gate_name": "",
                    "canonical_sink_id": "",
                    "capability_class": "",
                    "controlled_facet": "",
                    "current_witness": "",
                    "review_note": "",
                }
                if kind == "handler":
                    row["expected_tool"] = "shell"
                elif kind == "sink":
                    row.update(
                        {
                            "canonical_sink_id": "DC-ACTION-SHELL",
                            "capability_class": "adb-shell-execution",
                            "controlled_facet": "command",
                        }
                    )
                elif kind == "gate":
                    if name == "non-empty shell command guard":
                        row["expected_tool"] = "shell"
                        row["expected_gate_name"] = "inlineCondition"
                    elif name == "missing shell action approval gate":
                        row.update(
                            {
                                "expected_tool": "shell",
                                "expected_gate_name": "shellActionApproval",
                                "anchor_status": "expected-missing",
                                "mapping_status": "expected-missing",
                                "review_note": "approval/deny policy is absent before runAdbCommand",
                            }
                        )
                    else:
                        raise ValueError(f"unknown DroidClaw gate {name!r}")
                row["current_witness"] = _line(
                    source_root, row["current_file"], int(row["current_line"])
                )
                if not row["current_witness"]:
                    raise ValueError(
                        f"DroidClaw {kind} anchor missing at "
                        f"{row['current_file']}:{row['current_line']}"
                    )
                records.append(row)
    if len(records) != 7:
        raise ValueError(f"expected 7 DroidClaw inventory records, got {len(records)}")
    return {
        "schema_version": "droidclaw-groundtruth-inventory/v1",
        "project": PROJECT,
        "version": VERSION,
        "revision": REVISION,
        "corpus_sha256": lock["corpus_sha256"],
        "counts": lock["counts"],
        "records": records,
    }


def build_oracle(inventory: dict[str, Any]) -> dict[str, Any]:
    records = inventory["records"]
    handler = next(row for row in records if row["kind"] == "handler")
    sink = next(row for row in records if row["kind"] == "sink")
    existing = next(
        row
        for row in records
        if row["kind"] == "gate" and row["mapping_status"] == "canonical"
    )
    missing = next(
        row
        for row in records
        if row["kind"] == "gate" and row["mapping_status"] == "expected-missing"
    )
    return {
        "schema_version": "droidclaw-static-oracle/v1",
        "project": PROJECT,
        "revision": REVISION,
        "corpus_sha256": inventory["corpus_sha256"],
        "expected_counts": inventory["counts"],
        "eligible_sink_records": [
            {
                "record_id": _stable("DCOR-", sink["record_id"]),
                "handler_inventory_record_id": handler["record_id"],
                "sink_inventory_record_id": sink["record_id"],
                "report_path": sink["report_path"],
                "tool_name": "shell",
                "handler_file": handler["current_file"],
                "handler_line": handler["current_line"],
                "canonical_sink_id": sink["canonical_sink_id"],
                "capability_class": sink["capability_class"],
                "sink_file": sink["current_file"],
                "sink_line": sink["current_line"],
                "controlled_facet": sink["controlled_facet"],
                "required_chain_markers": ["executeShell@actions.ts"],
            }
        ],
        "existing_gate_records": [
            {
                "record_id": existing["record_id"],
                "gate_name": existing["expected_gate_name"],
                "gate_file": existing["current_file"],
                "gate_line": existing["current_line"],
            }
        ],
        "expected_missing_records": [
            {
                "record_id": missing["record_id"],
                "gate_name": missing["expected_gate_name"],
                "gate_file": missing["current_file"],
                "gate_line": missing["current_line"],
                "controlled_facet": "command",
            }
        ],
        "extraction_record_ids": [
            row["record_id"] for row in records if row["kind"] == "extraction"
        ],
    }


def write_outputs(
    *,
    lock: dict[str, Any],
    inventory: dict[str, Any],
    oracle: dict[str, Any],
    out_dir: Path,
    lock_path: Path,
    oracle_path: Path,
    command: str,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    oracle_path.write_text(json.dumps(oracle, indent=2) + "\n", encoding="utf-8")
    (out_dir / "groundtruth-inventory.json").write_text(
        json.dumps(inventory, indent=2) + "\n", encoding="utf-8"
    )
    with (out_dir / "groundtruth-inventory.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(
            handle, fieldnames=list(inventory["records"][0]), lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(inventory["records"])
    lines = [
        "# DroidClaw ground-truth inventory",
        "",
        f"生成命令（仓库根目录）：`{command}`",
        "",
        f"固定 revision `{REVISION}`；corpus SHA-256 `{lock['corpus_sha256']}`。",
        "",
        "完整入账：**1 report / 1 handler / 1 sink / 2 gates / 0 cross-component edges / 3 extraction records**。",
        "",
        "| Record | Kind | Current anchor | Status | Mapping |",
        "|---|---|---|---|---|",
    ]
    for row in inventory["records"]:
        lines.append(
            f"| `{row['record_id']}` | {row['kind']} | `{row['current_file']}:{row['current_line']}` | "
            f"`{row['anchor_status']}` | `{row['mapping_status']}` |"
        )
    (out_dir / "groundtruth-inventory.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gt-root", type=Path, default=DEFAULT_GT)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    args = parser.parse_args()
    command = shlex.join(
        ["python", "design/droidclaw/inventory/debug/scripts/generate_inventory.py"]
    )
    lock = build_lock(args.gt_root)
    inventory = build_inventory(args.gt_root, args.source_root, lock)
    oracle = build_oracle(inventory)
    write_outputs(
        lock=lock,
        inventory=inventory,
        oracle=oracle,
        out_dir=args.out_dir,
        lock_path=args.lock,
        oracle_path=args.oracle,
        command=command,
    )
    print(json.dumps({"counts": lock["counts"], "corpus_sha256": lock["corpus_sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

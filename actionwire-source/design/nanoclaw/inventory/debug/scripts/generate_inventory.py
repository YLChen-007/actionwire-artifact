#!/usr/bin/env python3
"""Generate NanoClaw's revision-pinned GT lock, inventory, and static oracle."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shlex
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[5]
PROJECT = "nanoclaw"
REVISION = "36cbf17e107fd0f8daea4ceb2ac523d9f0d88915"
DEFAULT_GT = ROOT / "design/nanoclaw/groundtruth/new-vuls"
DEFAULT_SOURCE = ROOT / "benchmark/typescript/nanoclaw"
DEFAULT_OUT = ROOT / "design/nanoclaw/inventory/debug"
DEFAULT_LOCK = ROOT / "design/nanoclaw/inventory/nanoclaw-groundtruth-lock.json"
DEFAULT_ORACLE = ROOT / "design/nanoclaw/inventory/nanoclaw-static-oracle.json"
EXPECTED = {
    "reports": 4,
    "handlers": 4,
    "sinks": 6,
    "gates": 22,
    "cross_component_edges": 9,
    "extraction_records": 11,
}
LOCATION_RE = re.compile(
    r"(?P<path>(?:container/agent-runner/src|src)/[^:\s|]+):(?P<line>\d+)"
)


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


def _items(payload: dict[str, Any], kind: str) -> list[Any]:
    keys = {
        "handler": "d5_tool_handler_entry",
        "sink": "d5_sink_points",
        "gate": "d5_gate_points",
        "cross_component": "d5_cross_component",
        "extraction": "d5_param_extraction",
    }
    value = payload.get(keys[kind]) or []
    if not isinstance(value, list):
        raise ValueError(f"{keys[kind]} must be a list")
    return value


def build_lock(gt_root: Path) -> dict[str, Any]:
    reports: list[dict[str, Any]] = []
    totals = Counter()
    for path in sorted(gt_root.glob("*.json")):
        payload = _json(path)
        counts = {
            "handlers": len(_items(payload, "handler")),
            "sinks": len(_items(payload, "sink")),
            "gates": len(_items(payload, "gate")),
            "cross_component_edges": len(_items(payload, "cross_component")),
            "extraction_records": len(_items(payload, "extraction")),
        }
        totals.update(counts)
        reports.append(
            {
                "path": path.name,
                "sha256": _sha(path),
                **counts,
            }
        )
    counts = {"reports": len(reports), **dict(totals)}
    if counts != EXPECTED:
        raise ValueError(
            f"NanoClaw GT cardinality changed: expected {EXPECTED}, got {counts}"
        )
    corpus = hashlib.sha256(
        json.dumps(reports, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema_version": "nanoclaw-groundtruth-lock/v1",
        "project": PROJECT,
        "revision": REVISION,
        "counts": counts,
        "corpus_sha256": corpus,
        "reports": reports,
    }


# Detector anchors deliberately identify the call/condition on the selected chain. Function-kind
# GT entries retain their definition anchor separately in ``original``.
GATE_ANCHORS: dict[str, tuple[str, int, str, str]] = {
    "addMcpServer name/command required guard": (
        "container/agent-runner/src/mcp-tools/self-mod.ts",
        100,
        "inlineCondition",
        "current",
    ),
    "handleAddMcpServer host name/command guard": (
        "src/modules/self-mod/request.ts",
        74,
        "inlineCondition",
        "current",
    ),
    "handleAddMcpServer host name/command required guard": (
        "src/modules/self-mod/request.ts",
        74,
        "inlineCondition",
        "current",
    ),
    "handleAddMcpServer requestApproval question": (
        "src/modules/self-mod/request.ts",
        78,
        "requestApproval",
        "rebased",
    ),
    "handleAddMcpServer requestApproval construction": (
        "src/modules/self-mod/request.ts",
        78,
        "requestApproval",
        "current",
    ),
    "resolveRouting destination gate": (
        "container/agent-runner/src/mcp-tools/core.ts",
        153,
        "resolveRouting",
        "rebased",
    ),
    "A2A channel dispatch selector": (
        "src/delivery.ts",
        267,
        "inlineCondition",
        "current",
    ),
    "A2A destination ACL gate": (
        "src/modules/agent-to-agent/agent-route.ts",
        216,
        "inlineCondition",
        "rebased",
    ),
    "hasDestination": (
        "src/modules/agent-to-agent/agent-route.ts",
        217,
        "hasDestination",
        "rebased",
    ),
    "target agent group existence gate": (
        "src/modules/agent-to-agent/agent-route.ts",
        223,
        "getAgentGroup",
        "current",
    ),
    "optional A2A message approval hold": (
        "src/modules/agent-to-agent/agent-route.ts",
        0,
        "optionalA2AApproval",
        "not-present",
    ),
    "files[] string filter": (
        "src/modules/agent-to-agent/agent-route.ts",
        280,
        "filter",
        "rebased",
    ),
    "isSafeAttachmentName": (
        "src/modules/agent-to-agent/agent-route.ts",
        104,
        "isSafeAttachmentName",
        "rebased",
    ),
    "source filename basename gate": (
        "src/modules/agent-to-agent/agent-route.ts",
        104,
        "isSafeAttachmentName",
        "rebased",
    ),
    "source file symlink/type gate": (
        "src/modules/agent-to-agent/agent-route.ts",
        115,
        "inlineCondition",
        "rebased",
    ),
    "source file realpath canonicalization": (
        "src/modules/agent-to-agent/agent-route.ts",
        122,
        "realpathSync",
        "rebased",
    ),
    "source file realpath containment gate": (
        "src/modules/agent-to-agent/agent-route.ts",
        130,
        "isPathInside",
        "rebased",
    ),
    "missing target inbox lstat/realpath containment gate": (
        "src/modules/agent-to-agent/agent-route.ts",
        99,
        "targetInboxContainment",
        "expected-missing",
    ),
    "path argument required guard": (
        "container/agent-runner/src/mcp-tools/core.ts",
        151,
        "inlineCondition",
        "current",
    ),
    "file existence check": (
        "container/agent-runner/src/mcp-tools/core.ts",
        157,
        "existsSync",
        "current",
    ),
    "workspace/root containment gate": (
        "container/agent-runner/src/mcp-tools/core.ts",
        156,
        "workspaceRootContainment",
        "expected-missing",
    ),
}


SINK_ANCHORS: dict[str, tuple[str, int, str, str, str]] = {
    "better-sqlite3 Statement.run pending_approvals insert": (
        "src/db/sessions.ts",
        153,
        "NC-APPROVAL-PERSIST",
        "approval-persistence",
        "approval-payload",
    ),
    "better-sqlite3 Statement.run container_configs mcp_servers update": (
        "src/db/container-configs.ts",
        90,
        "NC-CONFIG-MUTATION",
        "runtime-config-mutation",
        "mcp-servers",
    ),
    "fs.copyFileSync(realSrc, dst)": (
        "src/modules/agent-to-agent/agent-route.ts",
        138,
        "NC-FILE-COPY",
        "file-copy",
        "destination-path",
    ),
    "fs.copyFileSync": (
        "container/agent-runner/src/mcp-tools/core.ts",
        164,
        "NC-FILE-COPY",
        "file-copy",
        "source-path",
    ),
    "ChannelDeliveryAdapter.deliver approval-card ask_question": (
        "src/modules/approvals/primitive.ts",
        243,
        "NC-APPROVAL-PRESENT",
        "approval-presentation",
        "approval-question",
    ),
}


def _location(raw: str) -> tuple[str, int]:
    match = LOCATION_RE.search(raw or "")
    return (match.group("path"), int(match.group("line"))) if match else ("", 0)


def _line(source_root: Path, path: str, line: int) -> str:
    target = source_root / path
    if not target.is_file() or line <= 0:
        return ""
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[line - 1].strip() if line <= len(lines) else ""


def _nearest_evidence(
    source_root: Path, raw_location: str, evidence: str
) -> tuple[str, int, str, str]:
    path, old_line = _location(raw_location)
    target = source_root / path
    if not target.is_file():
        return path, old_line, "not-present", "anchor file absent from pinned revision"
    source = target.read_text(encoding="utf-8", errors="replace")
    candidates = [
        part.strip()
        for part in re.split(r"\n---\n|\s+\|\s+", evidence or "")
        if part.strip()
    ]
    candidates.extend(
        line.strip()
        for line in (evidence or "").splitlines()
        if len(line.strip()) >= 12
    )
    matches: list[tuple[int, str]] = []
    for candidate in candidates:
        start = 0
        while candidate and (offset := source.find(candidate, start)) >= 0:
            line = source.count("\n", 0, offset) + 1
            matches.append((line, candidate))
            start = offset + 1
    if not matches:
        return (
            path,
            old_line,
            "not-present",
            "reported evidence absent from pinned revision",
        )
    line, witness = min(matches, key=lambda row: abs(row[0] - old_line))
    status = "current" if abs(line - old_line) <= 3 else "rebased"
    return path, line, status, witness


def _status_for_record(
    kind: str, item: dict[str, Any], source_root: Path
) -> tuple[str, int, str, str, str]:
    if kind == "sink":
        path, line, canonical, capability, _facet = SINK_ANCHORS[item["name"]]
        raw_path, raw_line = _location(str(item.get("location", "")))
        status = "current" if path == raw_path and line == raw_line else "rebased"
        return path, line, status, canonical, capability
    if kind == "gate":
        path, line, detector, status = GATE_ANCHORS[item["name"]]
        return path, line, status, detector, str(item.get("type", ""))
    raw_location = str(item.get("location") or item.get("from_location") or "")
    evidence = str(item.get("evidence", ""))
    path, line, status, witness = _nearest_evidence(source_root, raw_location, evidence)
    return path, line, status, "", witness


def build_inventory(
    gt_root: Path, source_root: Path, lock: dict[str, Any]
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    canonical_seen: set[tuple[str, int, str]] = set()
    for report in sorted(gt_root.glob("*.json")):
        payload = _json(report)
        report_name = str(payload.get("report_name") or report.stem)
        for kind in ("handler", "sink", "gate", "cross_component", "extraction"):
            for index, raw in enumerate(_items(payload, kind), 1):
                item = raw if isinstance(raw, dict) else {"value": raw}
                path, line, status, mapped, detail = _status_for_record(
                    kind, item, source_root
                )
                mapping_status = "canonical"
                capability = ""
                facet = ""
                if kind == "sink":
                    _p, _l, canonical, capability, facet = SINK_ANCHORS[item["name"]]
                    identity = (path, line, canonical)
                    mapping_status = (
                        "duplicate" if identity in canonical_seen else "canonical"
                    )
                    canonical_seen.add(identity)
                elif status in {"not-present", "expected-missing"}:
                    mapping_status = status
                records.append(
                    {
                        "record_id": _stable("NCGT-", report.name, kind, index),
                        "report_path": report.name,
                        "report_name": report_name,
                        "kind": kind,
                        "item_index": index,
                        "name": str(item.get("name") or item.get("mechanism") or kind),
                        "original": item,
                        "original_location": str(
                            item.get("location")
                            or f"{item.get('from_location', '')} -> {item.get('to_location', '')}"
                        ),
                        "anchor_status": status,
                        "current_file": path,
                        "current_line": line,
                        "current_witness": _line(source_root, path, line),
                        "mapping_status": mapping_status,
                        "canonical_sink_id": mapped if kind == "sink" else "",
                        "detector_name": mapped if kind == "gate" else "",
                        "capability_class": capability,
                        "controlled_facet": facet,
                        "detail": detail,
                    }
                )
    counts = Counter(row["kind"] for row in records)
    actual = {
        "reports": len(lock["reports"]),
        "handlers": counts["handler"],
        "sinks": counts["sink"],
        "gates": counts["gate"],
        "cross_component_edges": counts["cross_component"],
        "extraction_records": counts["extraction"],
    }
    if actual != EXPECTED:
        raise ValueError(f"inventory cardinality mismatch: {actual}")
    return {
        "schema_version": "nanoclaw-groundtruth-inventory/v1",
        "project": PROJECT,
        "revision": REVISION,
        "corpus_sha256": lock["corpus_sha256"],
        "counts": actual,
        "status_counts": dict(
            sorted(Counter(row["anchor_status"] for row in records).items())
        ),
        "records": records,
    }


def build_oracle(inventory: dict[str, Any]) -> dict[str, Any]:
    records = inventory["records"]
    handlers_by_report = {
        report: [
            row["name"]
            for row in records
            if row["report_path"] == report and row["kind"] == "handler"
        ]
        for report in {row["report_path"] for row in records}
    }
    gates_by_report = {
        report: [
            row
            for row in records
            if row["report_path"] == report and row["kind"] == "gate"
        ]
        for report in handlers_by_report
    }
    eligible: list[dict[str, Any]] = []
    for sink in (row for row in records if row["kind"] == "sink"):
        gate_rows = gates_by_report[sink["report_path"]]
        existing = [
            {
                "inventory_record_id": row["record_id"],
                "gt_name": row["name"],
                "gate_name": row["detector_name"],
                "gate_file": row["current_file"],
                "gate_line": row["current_line"],
            }
            for row in gate_rows
            if row["anchor_status"] in {"current", "rebased"}
        ]
        missing = []
        for row in gate_rows:
            if row["anchor_status"] != "expected-missing":
                continue
            facet = (
                "destination-path:target-inbox"
                if "target inbox" in row["name"]
                else "source-path:workspace-root"
            )
            missing.append(
                {
                    "inventory_record_id": row["record_id"],
                    "gt_name": row["name"],
                    "controlled_facet": facet,
                    "forbidden_gate_name": row["detector_name"],
                }
            )
        eligible.append(
            {
                "record_id": _stable("NCOR-", sink["record_id"]),
                "sink_inventory_record_id": sink["record_id"],
                "report_path": sink["report_path"],
                "tool_names": handlers_by_report[sink["report_path"]],
                "canonical_sink_id": sink["canonical_sink_id"],
                "capability_class": sink["capability_class"],
                "sink_file": sink["current_file"],
                "sink_line": sink["current_line"],
                "controlled_facet": sink["controlled_facet"],
                "existing_gates": existing,
                "expected_missing": missing,
            }
        )
    return {
        "schema_version": "nanoclaw-static-oracle/v1",
        "project": PROJECT,
        "revision": REVISION,
        "corpus_sha256": inventory["corpus_sha256"],
        "expected_counts": EXPECTED,
        "eligible_sink_records": eligible,
    }


def write_outputs(
    inventory: dict[str, Any], oracle: dict[str, Any], out_dir: Path, command: str
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "groundtruth-inventory.json").write_text(
        json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    fields = [
        "record_id",
        "report_path",
        "kind",
        "item_index",
        "name",
        "original_location",
        "anchor_status",
        "current_file",
        "current_line",
        "mapping_status",
        "canonical_sink_id",
        "detector_name",
        "capability_class",
        "controlled_facet",
        "detail",
    ]
    with (out_dir / "groundtruth-inventory.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(
            handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(inventory["records"])
    counts = inventory["counts"]
    lines = [
        "# NanoClaw ground-truth inventory",
        "",
        f"生成命令（仓库根目录）：`{command}`",
        "",
        f"固定 revision：`{REVISION}`；语料锁：`{inventory['corpus_sha256']}`。",
        "",
        f"完整入账：**{counts['reports']} reports / {counts['handlers']} handlers / "
        f"{counts['sinks']} sinks / {counts['gates']} gates / "
        f"{counts['cross_component_edges']} cross-component edges / "
        f"{counts['extraction_records']} extraction records**。",
        "",
        "| Record | Kind | Report | Original | Current | Status | Mapping |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in inventory["records"]:
        current = (
            f"{row['current_file']}:{row['current_line']}"
            if row["current_file"]
            else "-"
        )
        lines.append(
            f"| `{row['record_id']}` | {row['kind']} | `{row['report_path']}` | "
            f"`{row['original_location']}` | `{current}` | {row['anchor_status']} | "
            f"{row['mapping_status']} |"
        )
    (out_dir / "groundtruth-inventory.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ground-truth", type=Path, default=DEFAULT_GT)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--update-lock", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    command = shlex.join(
        [
            "python",
            "design/nanoclaw/inventory/debug/scripts/generate_inventory.py",
            "--ground-truth",
            "design/nanoclaw/groundtruth/new-vuls",
            "--source-root",
            "benchmark/typescript/nanoclaw",
            "--out-dir",
            "design/nanoclaw/inventory/debug",
            "--lock",
            "design/nanoclaw/inventory/nanoclaw-groundtruth-lock.json",
            "--oracle",
            "design/nanoclaw/inventory/nanoclaw-static-oracle.json",
        ]
    )
    current_lock = build_lock(args.ground_truth.resolve())
    if args.update_lock or not args.lock.is_file():
        args.lock.parent.mkdir(parents=True, exist_ok=True)
        args.lock.write_text(
            json.dumps(current_lock, indent=2) + "\n", encoding="utf-8"
        )
    elif _json(args.lock.resolve()) != current_lock:
        raise ValueError(
            "NanoClaw ground-truth hash drift; review and explicitly update the lock"
        )
    lock = _json(args.lock.resolve())
    inventory = build_inventory(
        args.ground_truth.resolve(), args.source_root.resolve(), lock
    )
    oracle = build_oracle(inventory)
    args.oracle.parent.mkdir(parents=True, exist_ok=True)
    args.oracle.write_text(
        json.dumps(oracle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    write_outputs(inventory, oracle, args.out_dir.resolve(), command)
    print(
        json.dumps(
            {"counts": inventory["counts"], "statuses": inventory["status_counts"]},
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Generate Mercury Agent's revision-pinned GT lock, inventory, and static oracle."""

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
PROJECT = "mercury-agent"
REVISION = "587fad1bf9449598d1b27833f8c7db55d164741a"
DEFAULT_GT = ROOT / "design/mercury-agent/groundtruth"
DEFAULT_SOURCE = ROOT / "benchmark/typescript/mercury-agent"
DEFAULT_OUT = ROOT / "design/mercury-agent/inventory/debug"
DEFAULT_LOCK = ROOT / "design/mercury-agent/inventory/mercury-agent-groundtruth-lock.json"
DEFAULT_ORACLE = ROOT / "design/mercury-agent/inventory/mercury-agent-static-oracle.json"
EXPECTED = {
    "reports": 5,
    "handlers": 5,
    "sinks": 5,
    "gates": 27,
    "cross_component_edges": 5,
    "extraction_records": 10,
}

HANDLERS = {
    "create_file": ("src/capabilities/filesystem/create-file.ts", 14),
    "delegate_task": ("src/capabilities/subagents/delegate-task.ts", 17),
    "edit_file": ("src/capabilities/filesystem/edit-file.ts", 15),
    "fetch_url": ("src/capabilities/web/fetch-url.ts", 51),
    "github_api": ("src/capabilities/github/github-api.ts", 49),
    "install_skill": ("src/capabilities/skills/install-skill.ts", 13),
    "read_file": ("src/capabilities/filesystem/read-file.ts", 13),
    "run_command": ("src/capabilities/shell/run-command.ts", 97),
    "use_skill": ("src/capabilities/skills/use-skill.ts", 12),
    "write_file": ("src/capabilities/filesystem/write-file.ts", 15),
}

TOOL_SINKS = {
    "create_file": ("src/capabilities/filesystem/create-file.ts", 31),
    "delegate_task": ("src/core/sub-agent.ts", 168),
    "edit_file": ("src/capabilities/filesystem/edit-file.ts", 36),
    "fetch_url": ("src/capabilities/web/fetch-url.ts", 58),
    "github_api": ("src/utils/github.ts", 52),
    "install_skill": ("src/skills/loader.ts", 214),
    "read_file": ("src/capabilities/filesystem/read-file.ts", 33),
    "run_command": ("src/capabilities/shell/run-command.ts", 29),
    "write_file": ("src/capabilities/filesystem/write-file.ts", 28),
}

SINK_MODELS = {
    "src/capabilities/shell/run-command.ts": {
        "tool": "run_command",
        "line": 29,
        "canonical_sink_id": "MA-PROCESS-SPAWN",
        "capability_class": "process-spawn",
        "facet": "command",
    },
    "src/capabilities/permissions.ts": {
        "tool": "run_command",
        "line": 514,
        "canonical_sink_id": "MA-COMMAND-APPROVAL",
        "capability_class": "user-consent",
        "facet": "command",
    },
    "src/capabilities/web/fetch-url.ts": {
        "tool": "fetch_url",
        "line": 58,
        "canonical_sink_id": "MA-NETWORK-FETCH",
        "capability_class": "network-egress",
        "facet": "url",
    },
    "src/utils/github.ts": {
        "tool": "github_api",
        "line": 52,
        "canonical_sink_id": "MA-NETWORK-FETCH",
        "capability_class": "network-egress",
        "facet": "url",
    },
    "src/skills/loader.ts": {
        "tool": "install_skill",
        "line": 214,
        "canonical_sink_id": "MA-FILE-WRITE",
        "capability_class": "file-write",
        "facet": "content",
    },
    "src/capabilities/filesystem/read-file.ts": {
        "tool": "read_file",
        "line": 33,
        "canonical_sink_id": "MA-FILE-READ",
        "capability_class": "file-read",
        "facet": "path",
    },
    "src/capabilities/filesystem/create-file.ts": {
        "tool": "create_file",
        "line": 31,
        "canonical_sink_id": "MA-FILE-WRITE",
        "capability_class": "file-write",
        "facet": "path",
    },
    "src/core/sub-agent.ts": {
        "tool": "delegate_task",
        "line": 168,
        "canonical_sink_id": "MA-SUBAGENT-TOOL-EXPOSURE",
        "capability_class": "tool-capability-exposure",
        "facet": "tool-map",
    },
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


def _reports(gt_root: Path) -> list[Path]:
    return sorted(gt_root.rglob("*.json"))


def _report_sink_for_tool(
    payload: dict[str, Any], tool: str
) -> tuple[str, int]:
    candidates: list[tuple[str, int]] = []
    for item in _items(payload, "sink"):
        file, _ = _location(str(item.get("location") or ""))
        model = SINK_MODELS.get(file)
        if model is not None and model["tool"] == tool:
            candidates.append((file, int(model["line"])))
    if len(candidates) > 1:
        raise ValueError(f"multiple Mercury sinks for tool {tool!r} in one report")
    return candidates[0] if candidates else TOOL_SINKS.get(tool, ("", 0))


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
    for path in _reports(gt_root):
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
        reports.append(
            {
                "path": path.relative_to(gt_root).as_posix(),
                "sha256": _sha(path),
                **counts,
            }
        )
    counts = {"reports": len(reports), **totals}
    if counts != EXPECTED:
        raise ValueError(f"Mercury GT cardinality changed: expected {EXPECTED}, got {counts}")
    corpus = hashlib.sha256(
        json.dumps(reports, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema_version": "mercury-agent-groundtruth-lock/v1",
        "project": PROJECT,
        "revision": REVISION,
        "counts": counts,
        "corpus_sha256": corpus,
        "reports": reports,
    }


def _report_gate_tool(report: str, file: str) -> str:
    if "filesystem-tools" in report:
        if file.endswith("write-file.ts"):
            return "write_file"
        if file.endswith("edit-file.ts"):
            return "edit_file"
        return "create_file"
    if "hardlink-scope" in report:
        return "read_file"
    if file.endswith("install-skill.ts"):
        return "install_skill"
    return "run_command"


def _gate_model(report: str, item: dict[str, Any]) -> dict[str, Any]:
    name = str(item.get("name") or "")
    file, line = _location(str(item.get("location") or ""))
    tool = _report_gate_tool(report, file)
    model: dict[str, Any] = {
        "expected_tool": tool,
        "gate_name": "",
        "file": file,
        "line": line,
        "definition_file": file,
        "definition_line": line,
        "mapping_status": "canonical",
    }
    if file.endswith("use-skill.ts") and line == 18:
        model.update(
            {
                "expected_tool": "use_skill",
                "mapping_status": "cross-tool-state",
                "gate_name": "allowedToolsPresence",
            }
        )
        return model
    direct = {
        ("src/capabilities/filesystem/read-file.ts", 14): ("resolve", 14),
        ("src/capabilities/filesystem/read-file.ts", 16): ("inlineCondition", 16),
        ("src/capabilities/filesystem/read-file.ts", 30): ("inlineCondition", 30),
        ("src/capabilities/filesystem/create-file.ts", 15): ("resolve", 15),
        ("src/capabilities/filesystem/create-file.ts", 17): ("inlineCondition", 17),
        ("src/capabilities/filesystem/write-file.ts", 16): ("resolve", 16),
        ("src/capabilities/filesystem/write-file.ts", 18): ("inlineCondition", 18),
        ("src/capabilities/filesystem/edit-file.ts", 16): ("resolve", 16),
        ("src/capabilities/filesystem/edit-file.ts", 19): ("inlineCondition", 19),
        ("src/capabilities/skills/install-skill.ts", 32): ("match", 32),
        ("src/capabilities/skills/install-skill.ts", 39): ("inlineCondition", 39),
    }
    if (file, line) in direct:
        model["gate_name"], model["line"] = direct[(file, line)]
        model["definition_file"], model["definition_line"] = file, model["line"]
        return model
    if file.endswith("run-command.ts"):
        if name in {
            "runCommandAllowedCheck",
            "run_command permission decision",
            "run_command permission-result guard",
        }:
            model.update({"gate_name": "checkShellCommand", "line": 98})
        else:
            model.update({"gate_name": "inlineCondition", "line": 99})
        model.update({"definition_file": file, "definition_line": model["line"]})
        return model
    if file != "src/capabilities/permissions.ts":
        raise ValueError(f"unmapped Mercury gate {name!r} at {file}:{line}")
    if line == 154:
        model.update(
            {
                "gate_name": "splitShellSegments",
                "line": 476,
                "definition_line": 154,
            }
        )
    elif line == 394:
        model.update({"gate_name": "resolve", "line": 394, "definition_line": 394})
    elif line == 400:
        model.update({"gate_name": "inlineCondition", "line": 400, "definition_line": 400})
    elif line == 406:
        model.update({"gate_name": "inlineCondition", "line": 406, "definition_line": 406})
    elif line == 415:
        model.update({"gate_name": "askHandler", "line": 415, "definition_line": 415})
    elif line == 458:
        model.update(
            {
                "gate_name": "checkShellCommand",
                "file": "src/capabilities/shell/run-command.ts",
                "line": 98,
                "definition_file": "src/capabilities/permissions.ts",
                "definition_line": 458,
            }
        )
    elif line in {459, 464}:
        model.update({"gate_name": "inlineCondition", "line": line, "definition_line": line})
    elif line in {481, 483}:
        model.update({"gate_name": "matchPattern", "line": 483, "definition_line": 602})
    elif line == 489 and "cwdOnly" in name:
        model.update({"gate_name": "inlineCondition", "line": 489, "definition_line": 489})
    elif line in {489, 491, 493}:
        model.update({"gate_name": "hasPathBeyondCwd", "line": 491, "definition_line": 611})
    elif line == 504:
        model.update({"gate_name": "allSegmentsSafeRead", "line": 504, "definition_line": 504})
    elif line == 513:
        model.update({"gate_name": "inlineCondition", "line": 513, "definition_line": 513})
    elif line == 514:
        model.update({"gate_name": "askHandler", "line": 514, "definition_line": 514})
    elif line == 558:
        model.update(
            {
                "gate_name": "findScope",
                "line": 395,
                "definition_line": 554,
            }
        )
    elif line == 595:
        model.update(
            {
                "gate_name": "findTempScope",
                "line": 396,
                "definition_line": 592,
            }
        )
    elif line == 602:
        model.update(
            {
                "gate_name": "matchPattern",
                "line": 483,
                "definition_line": 602,
            }
        )
    elif line == 611:
        model.update(
            {
                "gate_name": "hasPathBeyondCwd",
                "line": 491,
                "definition_line": 611,
            }
        )
    else:
        raise ValueError(f"unmapped Mercury permission gate {name!r} at line {line}")
    return model


def build_inventory(
    gt_root: Path, source_root: Path, lock: dict[str, Any]
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    seen: dict[str, set[tuple[object, ...]]] = {
        kind: set() for kind in ("handler", "sink", "gate", "cross_component", "extraction")
    }
    for report in lock["reports"]:
        payload = _json(gt_root / report["path"])
        for kind in ("handler", "sink", "gate", "cross_component", "extraction"):
            for index, item in enumerate(_items(payload, kind), 1):
                name = str(item.get("name") or f"{kind}-{index}")
                original = str(item.get("location") or "")
                row: dict[str, Any] = {
                    "record_id": _stable("MAGT-", report["path"], kind, index, name),
                    "report_path": report["path"],
                    "kind": kind,
                    "source_index": index,
                    "name": name,
                    "original_location": original,
                    "evidence": str(item.get("evidence") or ""),
                    "anchor_status": "current",
                    "mapping_status": "canonical",
                    "current_file": "",
                    "current_line": 0,
                    "definition_file": "",
                    "definition_line": 0,
                    "expected_tool": "",
                    "expected_sink_file": "",
                    "expected_sink_line": 0,
                    "expected_gate_name": "",
                    "canonical_sink_id": "",
                    "capability_class": "",
                    "controlled_facet": "",
                    "current_witness": "",
                    "review_note": "",
                }
                identity: tuple[object, ...]
                if kind == "handler":
                    tool = name
                    if tool not in HANDLERS:
                        raise ValueError(f"unknown Mercury handler {tool!r}")
                    file, line = HANDLERS[tool]
                    row.update(
                        {
                            "current_file": file,
                            "current_line": line,
                            "expected_tool": tool,
                            "current_witness": _line(source_root, file, line),
                        }
                    )
                    identity = (tool, file, line)
                elif kind == "sink":
                    original_file, original_line = _location(original)
                    model = SINK_MODELS.get(original_file)
                    if model is None:
                        raise ValueError(f"unmapped Mercury sink at {original}")
                    facet = str(model["facet"])
                    if original_file == "src/skills/loader.ts" and "path" in str(
                        item.get("problematic_parameter") or ""
                    ).lower():
                        facet = "path"
                    file, line = original_file, int(model["line"])
                    handler_file, handler_line = HANDLERS[str(model["tool"])]
                    row.update(
                        {
                            "anchor_status": "current" if original_line == line else "rebased",
                            "current_file": file,
                            "current_line": line,
                            "definition_file": file,
                            "definition_line": line,
                            "expected_tool": model["tool"],
                            "expected_sink_file": file,
                            "expected_sink_line": line,
                            "canonical_sink_id": model["canonical_sink_id"],
                            "capability_class": model["capability_class"],
                            "controlled_facet": facet,
                            "current_witness": _line(source_root, file, line),
                            "review_note": f"handler {handler_file}:{handler_line}",
                        }
                    )
                    identity = (file, line, facet)
                elif kind == "gate":
                    model = _gate_model(report["path"], item)
                    file, line = str(model["file"]), int(model["line"])
                    sink_file, sink_line = _report_sink_for_tool(
                        payload, str(model["expected_tool"])
                    )
                    original_file, original_line = _location(original)
                    row.update(
                        {
                            "anchor_status": (
                                "current"
                                if original_file == file and original_line == line
                                else "rebased"
                            ),
                            "mapping_status": model["mapping_status"],
                            "current_file": file,
                            "current_line": line,
                            "definition_file": model["definition_file"],
                            "definition_line": model["definition_line"],
                            "expected_tool": model["expected_tool"],
                            "expected_sink_file": sink_file,
                            "expected_sink_line": sink_line,
                            "expected_gate_name": model["gate_name"],
                            "current_witness": _line(source_root, file, line),
                            "review_note": (
                                "cross-tool permission state is inventoried but not attached to a single-source chain"
                                if model["mapping_status"] == "cross-tool-state"
                                else ""
                            ),
                        }
                    )
                    identity = (model["expected_tool"], file, line, model["gate_name"])
                elif kind == "cross_component":
                    from_file, from_line = _location(str(item.get("from_location") or ""))
                    to_file, to_line = _location(str(item.get("to_location") or ""))
                    row.update(
                        {
                            "name": str(item.get("mechanism") or name),
                            "original_location": f"{from_file}:{from_line} -> {to_file}:{to_line}",
                            "current_file": from_file,
                            "current_line": from_line,
                            "definition_file": to_file,
                            "definition_line": to_line,
                            "current_witness": _line(source_root, from_file, from_line),
                            "mapping_status": (
                                "cross-tool-state"
                                if from_file.endswith("use-skill.ts")
                                else "canonical"
                            ),
                        }
                    )
                    identity = (from_file, from_line, to_file, to_line)
                else:
                    file, line = _location(original)
                    row.update(
                        {
                            "current_file": file,
                            "current_line": line,
                            "current_witness": _line(source_root, file, line),
                        }
                    )
                    identity = (file, line, name)
                if not row["current_witness"]:
                    raise ValueError(
                        f"Mercury {kind} anchor is not present: {report['path']} {name} "
                        f"at {row['current_file']}:{row['current_line']}"
                    )
                if row["mapping_status"] == "canonical" and identity in seen[kind]:
                    row["mapping_status"] = "duplicate"
                seen[kind].add(identity)
                records.append(row)
    return {
        "schema_version": "mercury-agent-groundtruth-inventory/v1",
        "project": PROJECT,
        "revision": REVISION,
        "corpus_sha256": lock["corpus_sha256"],
        "counts": lock["counts"],
        "records": records,
    }


def build_oracle(inventory: dict[str, Any]) -> dict[str, Any]:
    records = inventory["records"]
    return {
        "schema_version": "mercury-agent-static-oracle/v1",
        "project": PROJECT,
        "revision": REVISION,
        "corpus_sha256": inventory["corpus_sha256"],
        "expected_counts": inventory["counts"],
        "handler_record_ids": [r["record_id"] for r in records if r["kind"] == "handler"],
        "eligible_sink_records": [
            {
                "record_id": _stable("MAOR-", r["record_id"]),
                "sink_inventory_record_id": r["record_id"],
                "report_path": r["report_path"],
                "tool_name": r["expected_tool"],
                "handler_file": HANDLERS[r["expected_tool"]][0],
                "handler_line": HANDLERS[r["expected_tool"]][1],
                "canonical_sink_id": r["canonical_sink_id"],
                "capability_class": r["capability_class"],
                "sink_file": r["expected_sink_file"],
                "sink_line": r["expected_sink_line"],
                "controlled_facet": r["controlled_facet"],
            }
            for r in records
            if r["kind"] == "sink"
        ],
        "eligible_gate_records": [
            {
                "record_id": _stable("MAGOR-", r["record_id"]),
                "gate_inventory_record_id": r["record_id"],
                "report_path": r["report_path"],
                "tool_name": r["expected_tool"],
                "sink_file": r["expected_sink_file"],
                "sink_line": r["expected_sink_line"],
                "gate_name": r["expected_gate_name"],
                "gate_file": r["current_file"],
                "gate_line": r["current_line"],
                "definition_file": r["definition_file"],
                "definition_line": r["definition_line"],
            }
            for r in records
            if r["kind"] == "gate" and r["mapping_status"] != "cross-tool-state"
        ],
        "cross_tool_state_record_ids": [
            r["record_id"]
            for r in records
            if r["mapping_status"] == "cross-tool-state"
        ],
        "cross_component_record_ids": [
            r["record_id"] for r in records if r["kind"] == "cross_component"
        ],
        "extraction_record_ids": [
            r["record_id"] for r in records if r["kind"] == "extraction"
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
    lock_path.write_text(json.dumps(lock, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    oracle_path.write_text(
        json.dumps(oracle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (out_dir / "groundtruth-inventory.json").write_text(
        json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    fields = list(inventory["records"][0])
    with (out_dir / "groundtruth-inventory.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(inventory["records"])
    lines = [
        "# Mercury Agent ground-truth inventory",
        "",
        f"生成命令（仓库根目录）：`{command}`",
        "",
        f"固定 revision：`{REVISION}`；corpus SHA-256：`{lock['corpus_sha256']}`。",
        "",
        "原始记录完整入账：**5 reports / 5 handlers / 5 sinks / 27 gates / 5 cross-component edges / 10 extraction records**。",
        "",
        "| Record | Kind | Report | Original | Current | Anchor | Mapping |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in inventory["records"]:
        lines.append(
            f"| `{row['record_id']}` | {row['kind']} | `{row['report_path']}` | "
            f"`{row['original_location']}` | `{row['current_file']}:{row['current_line']}` | "
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
        [
            "python",
            "design/mercury-agent/inventory/debug/scripts/generate_inventory.py",
        ]
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

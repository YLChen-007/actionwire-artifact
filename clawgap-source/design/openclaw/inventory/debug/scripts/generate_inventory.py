#!/usr/bin/env python3
"""Build the revision-pinned OpenClaw sink-seed inventory and oracle."""

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
DEFAULT_GT = ROOT / "design/openclaw/groundtruth"
DEFAULT_SOURCE = ROOT / "benchmark/typescript/openclaw"
DEFAULT_OUTPUT = ROOT / "design/openclaw/inventory/debug"
DEFAULT_REVISION = "d842b28a1517f95aae2a5bcd97f2f726e42b93d8"
SCHEMA = "openclaw-sink-inventory/v1"
LOCK_SCHEMA = "openclaw-groundtruth-lock/v1"
LOCATION_RE = re.compile(
    r"(?P<path>(?:src|packages|extensions|apps|node_modules)/[^:\s()]+):(?P<line>\d+)"
)

# These policy helpers existed in the pinned monolithic implementation but
# moved to different files in later reports.  Symbol fallback is deliberately
# limited to this audited set so a generic same-name function cannot make a
# later-only gate look current.
MOVED_POLICY_SYMBOLS = {
    "evaluateExecAllowlist",
    "evaluateSegments",
    "evaluateShellAllowlist",
    "isSafeBinUsage",
    "requiresExecApproval",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stable_id(prefix: str, *parts: object, length: int = 16) -> str:
    raw = "|".join(str(part) for part in parts)
    return prefix + hashlib.sha256(raw.encode()).hexdigest()[:length]


def parse_locations(raw: str) -> list[tuple[str, int]]:
    return [(match["path"], int(match["line"])) for match in LOCATION_RE.finditer(raw)]


def scope_for(path: str) -> str:
    if path.startswith("extensions/"):
        return "extensions"
    if path.startswith("node_modules/"):
        return "third-party"
    if path.startswith("apps/") or path.endswith(".swift"):
        return "swift-app"
    if path.startswith("packages/"):
        return "bundled-package"
    if path.startswith("src/plugins/"):
        return "plugin-implementation"
    if path.startswith("src/"):
        return "core-typescript"
    if path == "downstream":
        return "downstream"
    return "other"


def capability_for(name: str, evidence: str, parameter: str) -> str:
    text = " ".join((name, evidence, parameter)).lower()
    if any(token in text for token in ("response.text", "res.text", "full-buffer", "full buffer")):
        return "resource-consumption"
    if any(token in text for token in ("child_process", "spawn", "system.run", "runcommand", "process.run", "node-pty")):
        return "process-spawn"
    if any(token in text for token in ("unlink", "remove", "delete", "fs.rm", "rmdir")):
        return "file-delete"
    if any(token in text for token in ("writefile", "filehandle.write", "atomic config", "filesystem copy", "rename")):
        return "file-write"
    if any(token in text for token in ("readfile", "filehandle.read", "readlocal", "config snapshot read", "fs.open")):
        return "file-read"
    if any(token in text for token in ("fetch", "undici", "http", "request url")):
        return "network-egress"
    if any(token in text for token in ("browser", "opentab", "page.", "locator.", "/tabs/open")):
        return "browser-navigation"
    if any(token in text for token in ("message", "delivery", "send event", "sendmessage", "tool output")):
        return "delivery"
    if any(token in text for token in ("gateway", "node.invoke", "rpc", "calltool", "backend handler")):
        return "rpc-boundary"
    return "other-capability"


def api_identity(name: str, capability: str) -> str:
    text = name.lower()
    if capability == "process-spawn":
        if "node-pty" in text or "pty" in text:
            return "node-pty.spawn"
        if "system.run" in text:
            return "openclaw.system.run"
        if "supervisor" in text:
            return "openclaw.process-supervisor.spawn"
        return "node:child_process.spawn"
    if capability.startswith("file-"):
        return {
            "file-read": "node:fs.read",
            "file-write": "node:fs.write",
            "file-delete": "node:fs.delete",
        }[capability]
    if capability == "network-egress":
        return "javascript.fetch"
    if capability == "resource-consumption":
        return "javascript.response.text"
    if capability == "browser-navigation":
        return "openclaw.browser.navigation"
    if capability == "delivery":
        return "openclaw.message.delivery"
    if capability == "rpc-boundary":
        return "openclaw.capability-rpc"
    slug = re.sub(r"[^a-z0-9]+", "-", text).strip("-")[:48]
    return f"openclaw.boundary.{slug or 'unknown'}"


def parameter_role(parameter: str) -> str:
    text = parameter.lower()
    if any(token in text for token in ("argv", "command", "execpath", "pipeline")):
        return "command"
    if "url" in text or "endpoint" in text:
        return "url"
    if any(token in text for token in ("path", "file", "cwd", "root")):
        return "path"
    if any(token in text for token in ("content", "data", "base64", "script", "body")):
        return "content"
    if any(token in text for token in ("params", "payload", "arguments", "method")):
        return "payload"
    return "unspecified"


def _evidence_anchor(source: str, evidence: str) -> tuple[int, str] | None:
    evidence = evidence.strip()
    candidates = [evidence]
    candidates.extend(line.strip() for line in evidence.splitlines() if line.strip())
    for candidate in candidates:
        offset = source.find(candidate)
        if offset >= 0:
            return source.count("\n", 0, offset) + 1, candidate
    return None


def anchor_result(
    source_root: Path, raw_location: str, evidence: str
) -> tuple[str, str, int, str, str]:
    anchors = parse_locations(raw_location)
    if raw_location.strip().lower() == "downstream" or not anchors:
        return "out-of-model", "downstream", 0, "", "capability boundary has no in-snapshot source anchor"
    core_anchors = [(path, line) for path, line in anchors if scope_for(path) == "core-typescript"]
    if not core_anchors:
        path, line = anchors[0]
        scope = scope_for(path)
        return "out-of-model", path, line, "", f"{scope} is excluded from the v1 core TypeScript model"

    fallbacks: list[tuple[str, int, str]] = []
    for path, line in core_anchors:
        target = source_root / path
        if not target.is_file():
            fallbacks.append((path, line, ""))
            continue
        source = target.read_text(encoding="utf-8", errors="replace")
        found = _evidence_anchor(source, evidence)
        if found:
            current_line, witness = found
            status = "current" if abs(current_line - line) <= 3 else "rebased"
            return status, path, current_line, witness, "evidence matched the fixed source snapshot"
        lines = source.splitlines()
        witness = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
        fallbacks.append((path, line, witness))

    path, line, witness = fallbacks[0]
    target = source_root / path
    if not target.is_file():
        return "not-present", path, line, "", "anchor file does not exist in v2026.2.1"
    annotation = raw_location.lower()
    if "pre-patch" in annotation or "pre-fix" in annotation or "^" in raw_location:
        return "not-present", path, line, "", "explicit historical anchor is absent from the fixed snapshot"
    if witness:
        return "not-present", path, line, witness, "file exists but reported evidence does not match this revision"
    return "not-present", path, line, "", "reported line is outside the fixed source snapshot"


def _fixed_witness(source_root: Path, path: str, needle: str) -> tuple[int, str] | None:
    target = source_root / path
    if not target.is_file():
        return None
    source = target.read_text(encoding="utf-8", errors="replace")
    offset = source.find(needle)
    if offset < 0:
        return None
    return source.count("\n", 0, offset) + 1, needle


def sink_anchor_result(
    source_root: Path,
    name: str,
    raw_location: str,
    evidence: str,
    capability: str,
) -> tuple[str, str, int, str, str]:
    """Resolve a GT anchor, including audited cross-file implementation moves."""

    anchored = anchor_result(source_root, raw_location, evidence)
    if anchored[0] in {"current", "rebased", "out-of-model"}:
        return anchored
    locations = {path for path, _ in parse_locations(raw_location)}
    lowered = f"{name} {evidence}".lower()
    candidates: list[tuple[str, str]] = []
    if capability == "process-spawn" and "src/node-host/invoke.ts" in locations:
        candidates.append(
            ("src/node-host/runner.ts", "const child = spawn(argv[0], argv.slice(1), {")
        )
    if capability == "process-spawn" and (
        "src/agents/bash-tools.exec-runtime.ts" in locations or "supervisor.spawn" in lowered
    ):
        candidates.append(
            (
                "src/process/spawn-utils.ts",
                "const child = spawnImpl(argv[0], argv.slice(1), options);",
            )
        )
    for path, needle in candidates:
        found = _fixed_witness(source_root, path, needle)
        if found is not None:
            line, witness = found
            return (
                "rebased",
                path,
                line,
                witness,
                "dangerous capability/API identity rebased across files in v2026.2.1",
            )
    return anchored


def current_api_identity(api: str, capability: str, path: str, witness: str) -> str:
    if capability == "process-spawn" and path in {
        "src/node-host/runner.ts",
        "src/process/spawn-utils.ts",
    } and ("spawn(" in witness or "spawnImpl(" in witness):
        return "node:child_process.spawn"
    return api


def root_symbol(value: object) -> str:
    match = re.search(r"[A-Za-z_$][A-Za-z0-9_$]*", str(value or ""))
    return match.group(0) if match else ""


def _core_source_text(source_root: Path) -> str:
    chunks: list[str] = []
    for path in sorted((source_root / "src").rglob("*.ts")):
        rel = path.relative_to(source_root).as_posix()
        if rel.endswith((".test.ts", ".spec.ts")) or rel.startswith(
            ("src/plugins/", "src/channels/plugins/")
        ):
            continue
        chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def current_existing_gate_names(
    gate_points: list[dict[str, Any]], source_root: Path, core_source: str
) -> list[str]:
    names: set[str] = set()
    for gate in gate_points:
        if not isinstance(gate, dict) or gate.get("existed_pre_patch") is not True:
            continue
        symbol = root_symbol(gate.get("name"))
        if not symbol:
            continue
        status, *_ = anchor_result(
            source_root,
            str(gate.get("location") or ""),
            str(gate.get("evidence") or ""),
        )
        callable_symbol_present = re.search(
            rf"\b{re.escape(symbol)}\s*\(", core_source
        )
        moved_symbol_present = symbol in MOVED_POLICY_SYMBOLS and callable_symbol_present
        if callable_symbol_present and (
            status in {"current", "rebased"} or moved_symbol_present
        ):
            names.add(symbol)
    return sorted(names)


def corpus_lock(gt_root: Path) -> dict[str, Any]:
    reports = []
    for path in sorted(gt_root.rglob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        reports.append(
            {
                "path": path.relative_to(gt_root).as_posix(),
                "sha256": sha256(path),
                "sink_count": len(payload.get("d5_sink_points") or []),
            }
        )
    digest = hashlib.sha256(
        json.dumps(reports, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema_version": LOCK_SCHEMA,
        "report_count": len(reports),
        "sink_reference_count": sum(row["sink_count"] for row in reports),
        "corpus_sha256": digest,
        "reports": reports,
    }


def build_inventory(gt_root: Path, source_root: Path, revision: str) -> dict[str, Any]:
    lock = corpus_lock(gt_root)
    records: list[dict[str, Any]] = []
    canonical_owner: dict[str, str] = {}
    core_source = _core_source_text(source_root)
    for report in lock["reports"]:
        report_path = gt_root / report["path"]
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        handler_entry = payload.get("d5_tool_handler_entry")
        gate_points = payload.get("d5_gate_points") or []
        handler_rows = handler_entry if isinstance(handler_entry, list) else []
        tool_names = sorted(
            {
                str(row.get("name") or "").strip()
                for row in handler_rows
                if isinstance(row, dict) and str(row.get("name") or "").strip()
            }
        )
        existing_gate_names = current_existing_gate_names(
            gate_points, source_root, core_source
        )
        expected_missing_gate_names = sorted(
            {
                str(gate.get("name") or "").split()[0]
                for gate in gate_points
                if isinstance(gate, dict)
                and gate.get("existed_pre_patch") is False
                and re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", str(gate.get("name") or "").split()[0])
            }
        )
        expected_missing_gate_names = sorted(
            set(expected_missing_gate_names) - set(existing_gate_names)
        )
        gate_expectation = "existing" if existing_gate_names else "expected_missing"
        for index, sink in enumerate(payload.get("d5_sink_points") or []):
            name = str(sink.get("name") or "")
            kind = str(sink.get("kind") or "")
            location = str(sink.get("location") or "")
            parameter = str(sink.get("problematic_parameter") or "")
            evidence = str(sink.get("evidence") or "")
            capability = capability_for(name, evidence, parameter)
            status, current_file, current_line, witness, reason = sink_anchor_result(
                source_root, name, location, evidence, capability
            )
            original_anchors = [
                {"file": path, "line": line, "scope": scope_for(path)}
                for path, line in parse_locations(location)
            ]
            selected_scope = scope_for(current_file)
            boundary = (
                "excluded"
                if selected_scope in {"extensions", "third-party", "swift-app", "plugin-implementation"}
                else "rpc"
                if selected_scope == "downstream" or kind == "pipeline" or "boundary" in name.lower()
                else "in-process"
            )
            api = current_api_identity(
                api_identity(name, capability), capability, current_file, witness
            )
            role = parameter_role(parameter)
            canonical_key = "|".join((api, capability, role, boundary))
            canonical_id = stable_id("OCS-", canonical_key, length=14)
            record_id = stable_id("OCGT-", report["path"], index, location, name, length=16)
            if boundary == "excluded":
                mapping_status = "excluded-boundary"
                canonical_value: str | None = None
            elif boundary == "rpc":
                mapping_status = "core-boundary"
                canonical_value = canonical_id
            elif canonical_key in canonical_owner:
                mapping_status = "duplicate"
                canonical_value = canonical_id
            else:
                mapping_status = "canonical"
                canonical_value = canonical_id
            canonical_owner.setdefault(canonical_key, record_id)

            handler_text = json.dumps(handler_entry, ensure_ascii=False).lower()
            eligible = (
                status in {"current", "rebased"}
                and selected_scope == "core-typescript"
                and capability in {
                    "process-spawn", "network-egress", "file-read", "file-write",
                    "file-delete", "browser-navigation", "delivery", "rpc-boundary",
                    "resource-consumption",
                }
                and bool(handler_entry)
                and ("src/agents/" in handler_text or "tool" in handler_text)
            )
            records.append(
                {
                    "record_id": record_id,
                    "report_path": report["path"],
                    "report_sha256": report["sha256"],
                    "report_sink_index": index,
                    "vulnerability_id": payload.get("cve_id") or Path(report["path"]).stem,
                    "brief_description": payload.get("brief_description", ""),
                    "name": name,
                    "kind": kind,
                    "location": location,
                    "problematic_parameter": sink.get("problematic_parameter"),
                    "evidence": sink.get("evidence"),
                    "original_anchors": original_anchors,
                    "anchor_status": status,
                    "mapping_status": mapping_status,
                    "canonical_sink_id": canonical_value,
                    "canonical_api": api if canonical_value else None,
                    "capability_class": capability,
                    "controlled_parameter_role": role,
                    "boundary_kind": boundary,
                    "current_witness": {
                        "file": current_file,
                        "line": current_line,
                        "source": witness,
                    },
                    "status_reason": reason,
                    "tool_handler_entry": handler_entry,
                    "tool_names": tool_names,
                    "gate_expectation": gate_expectation,
                    "existing_gate_names": existing_gate_names,
                    "expected_missing_gate_names": expected_missing_gate_names,
                    "gate_points": gate_points,
                    "eligible": eligible,
                }
            )
    counts = {
        "reports": lock["report_count"],
        "sink_references": len(records),
        "canonical_definitions": len({r["canonical_sink_id"] for r in records if r["canonical_sink_id"]}),
        "eligible": sum(bool(r["eligible"]) for r in records),
        "anchor_status": dict(sorted(Counter(r["anchor_status"] for r in records).items())),
        "mapping_status": dict(sorted(Counter(r["mapping_status"] for r in records).items())),
        "capability_class": dict(sorted(Counter(r["capability_class"] for r in records).items())),
    }
    return {
        "schema_version": SCHEMA,
        "project": "openclaw",
        "upstream_version": "v2026.2.1",
        "revision": revision,
        "corpus_sha256": lock["corpus_sha256"],
        "counts": counts,
        "records": records,
    }


def write_outputs(inventory: dict[str, Any], output_dir: Path, command: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "sink-inventory.json"
    json_path.write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    fields = [
        "record_id", "report_path", "report_sha256", "report_sink_index", "vulnerability_id",
        "name", "kind", "location", "problematic_parameter", "anchor_status", "mapping_status",
        "canonical_sink_id", "canonical_api", "capability_class", "controlled_parameter_role",
        "boundary_kind", "eligible", "gate_expectation", "status_reason",
    ]
    with (output_dir / "sink-inventory.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(inventory["records"])
    counts = inventory["counts"]
    lines = [
        "# OpenClaw ground-truth sink inventory",
        "",
        f"生成命令（仓库根目录）：`{command}`",
        "",
        f"固定版本：`{inventory['upstream_version']}` / `{inventory['revision']}`",
        "",
        f"语料：{counts['reports']} 份 JSON，{counts['sink_references']} 条原始 sink 引用；"
        f"归并为 {counts['canonical_definitions']} 个 canonical capability/facet 定义。",
        "",
        "## 状态计数",
        "",
        f"- anchor_status: `{json.dumps(counts['anchor_status'], ensure_ascii=False, sort_keys=True)}`",
        f"- mapping_status: `{json.dumps(counts['mapping_status'], ensure_ascii=False, sort_keys=True)}`",
        f"- eligible revision-pinned oracle rows: `{counts['eligible']}`",
        "",
        "完整逐条 provenance、原始字段、当前 witness 与排除理由见 `sink-inventory.json` / `sink-inventory.csv`。",
    ]
    (output_dir / "sink-inventory.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ground-truth-root", type=Path, default=DEFAULT_GT)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--revision", default=DEFAULT_REVISION)
    parser.add_argument("--update-lock", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    gt_root = args.ground_truth_root.resolve()
    source_root = args.source_root.resolve()
    output_dir = args.output_dir.resolve()
    lock = corpus_lock(gt_root)
    lock_path = output_dir.parent / "openclaw-groundtruth-lock.json"
    if lock_path.is_file() and not args.update_lock:
        expected = json.loads(lock_path.read_text(encoding="utf-8"))
        if expected != lock:
            raise SystemExit("OpenClaw ground-truth corpus drifted; review and rerun with --update-lock")
    elif not lock_path.is_file() and not args.update_lock:
        raise SystemExit("OpenClaw ground-truth lock is missing; review and run once with --update-lock")
    if args.update_lock:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    inventory = build_inventory(gt_root, source_root, args.revision)
    command_parts = [
        "python", "design/openclaw/inventory/debug/scripts/generate_inventory.py",
        "--ground-truth-root", "design/openclaw/groundtruth",
        "--source-root", "benchmark/typescript/openclaw",
        "--output-dir", "design/openclaw/inventory/debug",
        "--revision", args.revision,
    ]
    if args.update_lock:
        command_parts.append("--update-lock")
    write_outputs(inventory, output_dir, shlex.join(command_parts))
    oracle = {
        "schema_version": "openclaw-static-oracle/v1",
        "project": "openclaw",
        "revision": args.revision,
        "corpus_sha256": inventory["corpus_sha256"],
        "eligible_records": [
            {
                "record_id": row["record_id"],
                "report_path": row["report_path"],
                "capability_class": row["capability_class"],
                "canonical_sink_id": row["canonical_sink_id"],
                "sink_file": row["current_witness"]["file"],
                "sink_line": row["current_witness"]["line"],
                "gate_expectation": row["gate_expectation"],
                "tool_names": row["tool_names"],
                "existing_gate_names": row["existing_gate_names"],
                "expected_missing_gate_names": row["expected_missing_gate_names"],
            }
            for row in inventory["records"]
            if row["eligible"]
        ],
    }
    (output_dir.parent / "openclaw-static-oracle.json").write_text(
        json.dumps(oracle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(inventory["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

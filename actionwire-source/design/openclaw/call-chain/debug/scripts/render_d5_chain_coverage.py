#!/usr/bin/env python3
"""Render OpenClaw new-vuls D5 coverage against the pinned TypeScript snapshot.

The raw reports may describe revisions newer than v2026.2.1 or implementation
outside the core ``src/**/*.ts`` model.  This renderer accounts for every raw
handler, sink, and gate item, but only treats a sink as detector-eligible when
the locked inventory says that the current/rebased sink belongs to the fixed
revision and has an LLM-source handler chain.  Out-of-model and later-only
items are classifications, not static-analysis misses.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shlex
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[5]
DEBUG_DIR = Path(__file__).resolve().parent.parent
DEFAULT_GT = ROOT / "design/openclaw/groundtruth/new-vuls"
DEFAULT_INVENTORY = ROOT / "design/openclaw/inventory/debug/sink-inventory.json"
DEFAULT_PIPELINE = ROOT / "output/openclaw"
DEFAULT_SOURCE = ROOT / "benchmark/typescript/openclaw"
DEFAULT_HANDLERS = ROOT / "design/openclaw/handler-entry/debug/tool-handler-entries.csv"
DEFAULT_OUT = DEBUG_DIR
REVISION = "d842b28a1517f95aae2a5bcd97f2f726e42b93d8"
MOVED_POLICY_SYMBOLS = {
    "evaluateExecAllowlist",
    "evaluateSegments",
    "evaluateShellAllowlist",
    "isSafeBinUsage",
    "requiresExecApproval",
}

LOCATION_RE = re.compile(
    r"(?P<path>(?:src|packages|extensions|apps|node_modules)/[^:\s()]+):(?P<line>\d+)"
)
IDENTIFIER_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")

ITEM_FIELDS = [
    "report_id",
    "json_file",
    "item_kind",
    "item_index",
    "gt_name",
    "gt_type",
    "gt_location",
    "existed_pre_patch",
    "anchor_status",
    "current_anchor",
    "model_status",
    "coverage_status",
    "match_kind",
    "chain_count",
    "chain_ids",
    "matched_gate_uids",
    "notes",
]

CHAIN_FIELDS = [
    "report_id",
    "chain_id",
    "tool_name",
    "handler_qualified_name",
    "source_parameter",
    "sink_id",
    "sink_api",
    "sink_file",
    "sink_line",
    "sink_argument",
    "constraint_id",
    "capability_class",
    "capability_card",
    "gate_count",
    "ordered_gates",
    "matched_gt_gates",
    "chain_semantic_status",
    "report_verdict",
    "call_chain",
]

DEBUG_FIELDS = [
    "report_id",
    "gate_index",
    "gt_name",
    "gt_type",
    "gt_location",
    "chain_scope",
    "chain_id",
    "candidate_gate_uid",
    "candidate_detector",
    "candidate_name",
    "candidate_file",
    "candidate_line",
    "candidate_verdict",
    "decision",
    "reason",
]


@dataclass(frozen=True)
class Anchor:
    status: str
    file: str
    line: int
    witness: str
    reason: str

    @property
    def rendered(self) -> str:
        if not self.file:
            return ""
        return f"{self.file}:{self.line}" if self.line else self.file


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise ValueError(f"required CSV is missing: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_csv(path: Path, fields: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize_path(value: str) -> str:
    return value.replace("\\", "/").lstrip("/")


def bool_text(value: object) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return ""


def join(values: Iterable[str]) -> str:
    return "; ".join(value for value in values if value)


def root_symbol(value: object) -> str:
    match = IDENTIFIER_RE.search(str(value or ""))
    return match.group(0) if match else ""


def parse_locations(value: object) -> list[tuple[str, int]]:
    return [
        (normalize_path(match["path"]), int(match["line"]))
        for match in LOCATION_RE.finditer(str(value or ""))
    ]


def scope_for(path: str) -> str:
    if path.startswith("src/") and path.endswith((".ts", ".tsx")):
        if path.endswith((".test.ts", ".spec.ts", ".test.tsx", ".spec.tsx")):
            return "test"
        if path.startswith(("src/plugins/", "src/channels/plugins/")):
            return "plugin"
        return "core-typescript"
    if path.startswith("extensions/"):
        return "extension"
    if path.startswith("node_modules/"):
        return "third-party"
    if path.startswith("apps/"):
        return "app"
    if path.startswith("packages/"):
        return "bundled-package"
    return "other"


def evidence_anchor(source: str, evidence: str) -> tuple[int, str] | None:
    evidence = evidence.strip()
    if not evidence:
        return None
    candidates = [evidence]
    candidates.extend(
        line.strip()
        for line in evidence.splitlines()
        if len(line.strip()) >= 12 and line.strip() not in {"...", "---"}
    )
    for candidate in candidates:
        offsets: list[int] = []
        start = 0
        while True:
            offset = source.find(candidate, start)
            if offset < 0:
                break
            offsets.append(offset)
            start = offset + 1
        if len(offsets) == 1:
            return source.count("\n", 0, offsets[0]) + 1, candidate
    return None


def locate_anchor(source_root: Path, item: dict[str, Any]) -> Anchor:
    locations = parse_locations(item.get("location"))
    if not locations:
        return Anchor("no-location", "", 0, "", "GT item has no parseable source anchor")
    core = [(path, line) for path, line in locations if scope_for(path) == "core-typescript"]
    if not core:
        path, line = locations[0]
        scope = scope_for(path)
        return Anchor("out-of-model", path, line, "", f"{scope} is outside core src/**/*.ts")

    evidence = str(item.get("evidence") or "")
    fallbacks: list[Anchor] = []
    for path, line in core:
        target = source_root / path
        if not target.is_file():
            fallbacks.append(
                Anchor("not-present", path, line, "", "anchor file is absent from v2026.2.1")
            )
            continue
        source = target.read_text(encoding="utf-8", errors="replace")
        found = evidence_anchor(source, evidence)
        if found is not None:
            current_line, witness = found
            status = "current" if abs(current_line - line) <= 3 else "rebased"
            return Anchor(status, path, current_line, witness, "evidence matched fixed source")
        lines = source.splitlines()
        witness = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
        reason = (
            "file exists but GT evidence is absent from this revision"
            if witness
            else "reported line is outside the fixed source snapshot"
        )
        fallbacks.append(Anchor("not-present", path, line, witness, reason))
    return fallbacks[0]


def locate_gate_anchor(source_root: Path, item: dict[str, Any]) -> Anchor:
    anchor = locate_anchor(source_root, item)
    if anchor.status == "out-of-model":
        return anchor
    symbol = root_symbol(item.get("name"))
    if str(item.get("kind") or "") == "function" and symbol:
        pattern = re.compile(rf"\b{re.escape(symbol)}\b")
        symbol_present = False
        for target in sorted((source_root / "src").rglob("*.ts")):
            rel = target.relative_to(source_root).as_posix()
            if scope_for(rel) != "core-typescript":
                continue
            source = target.read_text(encoding="utf-8", errors="replace")
            if pattern.search(source):
                symbol_present = True
                break
        if not symbol_present:
            locations = [
                (path, line)
                for path, line in parse_locations(item.get("location"))
                if scope_for(path) == "core-typescript"
            ]
            path, line = locations[0] if locations else (anchor.file, anchor.line)
            reason = f"GT function symbol is absent from {REVISION[:12]}"
            if anchor.status in {"current", "rebased"}:
                reason += "; matching body text exists only inside a different function"
            return Anchor(
                "not-present",
                path,
                line,
                anchor.witness,
                reason,
            )
    if anchor.status in {"current", "rebased"}:
        return anchor
    if symbol not in MOVED_POLICY_SYMBOLS:
        return anchor
    pattern = re.compile(rf"\b{re.escape(symbol)}\b")
    for target in sorted((source_root / "src").rglob("*.ts")):
        rel = target.relative_to(source_root).as_posix()
        if scope_for(rel) != "core-typescript":
            continue
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        for line, source in enumerate(lines, start=1):
            if pattern.search(source):
                return Anchor(
                    "rebased",
                    rel,
                    line,
                    source.strip(),
                    "audited policy symbol moved within the fixed TypeScript snapshot",
                )
    return anchor


def pipeline_revision(manifest: dict[str, Any]) -> str:
    project = manifest.get("project")
    if isinstance(project, dict):
        return str(project.get("revision") or "")
    return str(manifest.get("revision") or "")


def load_pipeline(pipeline_root: Path) -> dict[str, Any]:
    static = pipeline_root / "static/call-chains"
    chains = read_csv(static / "handler-sink-chains.csv")
    gates = read_csv(static / "chain-gates.csv")
    constraints = read_csv(static / "sink-constraints.csv")
    manifest = read_json(pipeline_root / "pipeline-manifest.json")
    if pipeline_revision(manifest) != REVISION:
        raise ValueError("OpenClaw pipeline output is not pinned to the expected revision")

    chains_by_tool: dict[str, list[dict[str, str]]] = defaultdict(list)
    chains_by_id: dict[str, dict[str, str]] = {}
    for row in chains:
        chains_by_tool[row.get("tool_name", "")].append(row)
        chains_by_id[row["chain_id"]] = row

    gates_by_chain: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in gates:
        if row.get("gate_uid"):
            gates_by_chain[row["chain_id"]].append(row)
    for rows in gates_by_chain.values():
        rows.sort(key=lambda row: (int(row.get("gate_seq") or 0), row.get("gate_uid", "")))

    constraints_by_sink: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in constraints:
        constraints_by_sink[row["sink_id"]].append(row)

    semantic_status = {
        str(row.get("chain_id")): str(row.get("status", ""))
        for row in read_jsonl(
            pipeline_root / "call-chain-semantics/call-chain-semantics.jsonl"
        )
    }
    return {
        "chains": chains,
        "chains_by_tool": chains_by_tool,
        "chains_by_id": chains_by_id,
        "gates_by_chain": gates_by_chain,
        "constraints_by_sink": constraints_by_sink,
        "semantic_status": semantic_status,
    }


def match_sink_chains(
    record: dict[str, Any], pipeline: dict[str, Any]
) -> list[dict[str, str]]:
    if not record.get("eligible"):
        return []
    witness = record.get("current_witness") or {}
    expected_file = normalize_path(str(witness.get("file") or ""))
    expected_line = int(witness.get("line") or 0)
    tools = set(record.get("tool_names") or [])
    matches: list[dict[str, str]] = []
    for chain in pipeline["chains"]:
        if tools and chain.get("tool_name") not in tools:
            continue
        if normalize_path(chain.get("sink_file", "")) != expected_file:
            continue
        if int(chain.get("sink_line") or 0) != expected_line:
            continue
        constraints = pipeline["constraints_by_sink"].get(chain["sink_id"], [])
        if len(constraints) != 1:
            continue
        if constraints[0].get("capability_class") != record.get("capability_class"):
            continue
        matches.append(chain)
    return sorted(matches, key=lambda row: row["chain_id"])


def scope_status(sink_records: list[dict[str, Any]]) -> str:
    if any(record.get("eligible") for record in sink_records):
        return "eligible"
    statuses = {str(record.get("anchor_status")) for record in sink_records}
    if statuses == {"not-present"}:
        return "not-present"
    if statuses == {"out-of-model"}:
        return "out-of-model"
    if statuses & {"current", "rebased"}:
        return "inventory-only"
    return "mixed-out-of-scope"


def render(
    *,
    ground_truth_dir: Path,
    inventory_path: Path,
    pipeline_output: Path,
    source_root: Path,
    handler_inventory_path: Path,
    out_dir: Path,
    command: str,
) -> dict[str, Any]:
    inventory = read_json(inventory_path)
    if inventory.get("revision") != REVISION:
        raise ValueError("OpenClaw sink inventory revision mismatch")
    pipeline = load_pipeline(pipeline_output)
    handlers = read_csv(handler_inventory_path)
    handlers_by_tool: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in handlers:
        handlers_by_tool[row.get("tool_name", "")].append(row)

    inventory_by_report: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in inventory.get("records", []):
        if str(record.get("report_path", "")).startswith("new-vuls/"):
            inventory_by_report[str(record["report_path"])].append(record)
    for rows in inventory_by_report.values():
        rows.sort(key=lambda row: int(row.get("report_sink_index") or 0))

    reports: list[tuple[Path, dict[str, Any], list[dict[str, Any]]]] = []
    for path in sorted(ground_truth_dir.glob("*.json")):
        payload = read_json(path)
        report_key = f"new-vuls/{path.name}"
        sink_records = inventory_by_report.get(report_key, [])
        raw_sinks = payload.get("d5_sink_points") or []
        if len(sink_records) != len(raw_sinks):
            raise ValueError(f"inventory does not account for every sink in {report_key}")
        if any(record.get("report_sha256") != sha256(path) for record in sink_records):
            raise ValueError(f"ground-truth hash drift for {report_key}")
        if [int(row.get("report_sink_index") or 0) for row in sink_records] != list(
            range(len(raw_sinks))
        ):
            raise ValueError(f"inventory sink indices are incomplete for {report_key}")
        reports.append((path, payload, sink_records))
    if not reports:
        raise ValueError(f"no OpenClaw new-vuls JSON files found under {ground_truth_dir}")

    item_rows: list[dict[str, Any]] = []
    chain_rows: list[dict[str, Any]] = []
    debug_rows: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []

    for path, payload, sink_records in reports:
        report_id = str(payload.get("report_name") or path.stem)
        tools: set[str] = set()
        report_items: list[dict[str, Any]] = []
        selected_chains: dict[str, dict[str, str]] = {}
        matched_gate_labels: dict[str, list[str]] = defaultdict(list)

        handler_items = payload.get("d5_tool_handler_entry") or []
        for index, item in enumerate(handler_items, start=1):
            if not isinstance(item, dict):
                raise ValueError(f"invalid handler item in {path.name}")
            tool = str(item.get("name") or "")
            if tool:
                tools.add(tool)
            anchor = locate_anchor(source_root, item)
            current_handlers = handlers_by_tool.get(tool, [])
            candidate_chains = pipeline["chains_by_tool"].get(tool, [])
            if current_handlers and anchor.status in {"current", "rebased"}:
                coverage = "covered"
                match_kind = "tool-and-source-anchor"
            elif current_handlers:
                coverage = "tool-name-only"
                match_kind = "tool-name"
            elif anchor.status == "out-of-model":
                coverage = "out-of-model"
                match_kind = ""
            else:
                coverage = "not-present"
                match_kind = ""
            row = {
                "report_id": report_id,
                "json_file": f"design/openclaw/groundtruth/new-vuls/{path.name}",
                "item_kind": "handler",
                "item_index": index,
                "gt_name": tool,
                "gt_type": "tool-handler",
                "gt_location": str(item.get("location") or ""),
                "existed_pre_patch": "",
                "anchor_status": anchor.status,
                "current_anchor": anchor.rendered,
                "model_status": "core-tool" if current_handlers else anchor.status,
                "coverage_status": coverage,
                "match_kind": match_kind,
                "chain_count": len(candidate_chains),
                "chain_ids": join(sorted(row["chain_id"] for row in candidate_chains)),
                "matched_gate_uids": "",
                "notes": anchor.reason,
            }
            report_items.append(row)

        for index, (item, record) in enumerate(
            zip(payload.get("d5_sink_points") or [], sink_records), start=1
        ):
            matches = match_sink_chains(record, pipeline)
            selected_chains.update((row["chain_id"], row) for row in matches)
            if matches:
                coverage = "covered"
                match_kind = "current-witness"
            elif record.get("eligible"):
                coverage = "uncovered"
                match_kind = ""
            elif record.get("anchor_status") == "not-present":
                coverage = "not-present"
                match_kind = "inventory-classification"
            elif record.get("anchor_status") == "out-of-model":
                coverage = "out-of-model"
                match_kind = "inventory-classification"
            else:
                coverage = "inventory-only"
                match_kind = "current-anchor-no-supported-capability-chain"
            witness = record.get("current_witness") or {}
            current_anchor = normalize_path(str(witness.get("file") or ""))
            if witness.get("line"):
                current_anchor += f":{witness['line']}"
            row = {
                "report_id": report_id,
                "json_file": f"design/openclaw/groundtruth/new-vuls/{path.name}",
                "item_kind": "sink",
                "item_index": index,
                "gt_name": str(item.get("name") or ""),
                "gt_type": str(item.get("kind") or ""),
                "gt_location": str(item.get("location") or ""),
                "existed_pre_patch": "",
                "anchor_status": str(record.get("anchor_status") or ""),
                "current_anchor": current_anchor,
                "model_status": str(record.get("mapping_status") or ""),
                "coverage_status": coverage,
                "match_kind": match_kind,
                "chain_count": len(matches),
                "chain_ids": join(row["chain_id"] for row in matches),
                "matched_gate_uids": "",
                "notes": join(
                    [
                        str(record.get("status_reason") or ""),
                        f"capability={record.get('capability_class', '')}",
                        f"boundary={record.get('boundary_kind', '')}",
                        f"eligible={str(bool(record.get('eligible'))).lower()}",
                    ]
                ),
            }
            report_items.append(row)

        eligible_chain_ids = set(selected_chains)
        tool_chain_ids = {
            chain["chain_id"]
            for tool in tools
            for chain in pipeline["chains_by_tool"].get(tool, [])
        }
        gate_items = payload.get("d5_gate_points") or []
        for index, item in enumerate(gate_items, start=1):
            if not isinstance(item, dict):
                raise ValueError(f"invalid gate item in {path.name}")
            anchor = locate_gate_anchor(source_root, item)
            symbol = root_symbol(item.get("name"))
            expected_missing = item.get("existed_pre_patch") is False
            candidate_rows: list[tuple[str, dict[str, str]]] = []
            for chain_id in sorted(tool_chain_ids):
                for candidate in pipeline["gates_by_chain"].get(chain_id, []):
                    candidate_rows.append((chain_id, candidate))
            matching = [
                (chain_id, candidate)
                for chain_id, candidate in candidate_rows
                if symbol and candidate.get("gate_name") == symbol
            ]
            eligible_matching = [
                (chain_id, candidate)
                for chain_id, candidate in matching
                if chain_id in eligible_chain_ids
            ]
            for chain_id, candidate in candidate_rows:
                name_match = bool(symbol and candidate.get("gate_name") == symbol)
                if name_match and chain_id in eligible_chain_ids:
                    decision = "matched"
                    reason = "same report sink chain and exact gate symbol"
                    chain_scope = "eligible-sink-chain"
                elif name_match:
                    decision = "candidate-only"
                    reason = "exact gate symbol exists on same-tool chain, but report sink is ineligible"
                    chain_scope = "same-tool-chain"
                else:
                    decision = "rejected"
                    reason = "gate symbol differs"
                    chain_scope = "same-tool-chain"
                debug_rows.append(
                    {
                        "report_id": report_id,
                        "gate_index": index,
                        "gt_name": str(item.get("name") or ""),
                        "gt_type": str(item.get("type") or ""),
                        "gt_location": str(item.get("location") or ""),
                        "chain_scope": chain_scope,
                        "chain_id": chain_id,
                        "candidate_gate_uid": candidate.get("gate_uid", ""),
                        "candidate_detector": candidate.get("detector", ""),
                        "candidate_name": candidate.get("gate_name", ""),
                        "candidate_file": candidate.get("gate_file", ""),
                        "candidate_line": candidate.get("gate_line", ""),
                        "candidate_verdict": candidate.get("static_verdict", ""),
                        "decision": decision,
                        "reason": reason,
                    }
                )

            if expected_missing:
                if anchor.status == "out-of-model":
                    coverage = "expected-missing-out-of-model"
                elif anchor.status in {"current", "rebased"}:
                    coverage = "expected-missing-present-in-snapshot"
                else:
                    coverage = "expected-missing"
                match_kind = "source-anchor" if anchor.status in {"current", "rebased"} else ""
            elif anchor.status == "out-of-model":
                coverage = "out-of-model"
                match_kind = ""
            elif anchor.status not in {"current", "rebased"}:
                coverage = "candidate-only" if matching else "not-present"
                match_kind = "same-tool-gate-symbol" if matching else ""
            elif eligible_matching:
                coverage = "covered"
                match_kind = "eligible-chain-gate-symbol"
            elif eligible_chain_ids:
                coverage = "uncovered"
                match_kind = ""
            elif matching:
                coverage = "candidate-only"
                match_kind = "same-tool-gate-symbol"
            else:
                coverage = "not-evaluable"
                match_kind = ""

            matched_uids = sorted(
                {candidate.get("gate_uid", "") for _, candidate in eligible_matching}
            )
            for chain_id, candidate in eligible_matching:
                matched_gate_labels[chain_id].append(
                    f"G{index}:{item.get('name', '')}"
                )
            row = {
                "report_id": report_id,
                "json_file": f"design/openclaw/groundtruth/new-vuls/{path.name}",
                "item_kind": "gate",
                "item_index": index,
                "gt_name": str(item.get("name") or ""),
                "gt_type": str(item.get("type") or ""),
                "gt_location": str(item.get("location") or ""),
                "existed_pre_patch": bool_text(item.get("existed_pre_patch")),
                "anchor_status": anchor.status,
                "current_anchor": anchor.rendered,
                "model_status": "eligible-chain" if eligible_chain_ids else "no-eligible-sink-chain",
                "coverage_status": coverage,
                "match_kind": match_kind,
                "chain_count": len({chain_id for chain_id, _ in eligible_matching}),
                "chain_ids": join(sorted({chain_id for chain_id, _ in eligible_matching})),
                "matched_gate_uids": join(matched_uids),
                "notes": anchor.reason,
            }
            report_items.append(row)

        sink_scope = scope_status(sink_records)
        eligible_sinks = [record for record in sink_records if record.get("eligible")]
        covered_sinks = [
            row
            for row in report_items
            if row["item_kind"] == "sink" and row["coverage_status"] == "covered"
        ]
        eligible_existing_gates = [
            row
            for row in report_items
            if row["item_kind"] == "gate"
            and row["existed_pre_patch"] == "true"
            and row["anchor_status"] in {"current", "rebased"}
            and eligible_chain_ids
        ]
        covered_existing_gates = [
            row for row in eligible_existing_gates if row["coverage_status"] == "covered"
        ]
        eligible_gap_count = len(eligible_sinks) - len(covered_sinks) + len(
            eligible_existing_gates
        ) - len(covered_existing_gates)
        if not eligible_sinks:
            verdict = sink_scope
        elif eligible_gap_count:
            verdict = "partial"
        else:
            verdict = "pass"

        summaries.append(
            {
                "report_id": report_id,
                "json_file": path.name,
                "scope_status": sink_scope,
                "handler_items": len(handler_items),
                "current_handler_names": sum(
                    row["coverage_status"] in {"covered", "tool-name-only"}
                    for row in report_items
                    if row["item_kind"] == "handler"
                ),
                "sink_items": len(sink_records),
                "eligible_sinks": len(eligible_sinks),
                "covered_sinks": len(covered_sinks),
                "gate_items": len(gate_items),
                "eligible_existing_gates": len(eligible_existing_gates),
                "covered_existing_gates": len(covered_existing_gates),
                "candidate_only_gates": sum(
                    row["coverage_status"] == "candidate-only"
                    for row in report_items
                    if row["item_kind"] == "gate"
                ),
                "chain_count": len(selected_chains),
                "eligible_gap_count": eligible_gap_count,
                "verdict": verdict,
            }
        )
        item_rows.extend(report_items)

        for chain_id, chain in sorted(selected_chains.items()):
            constraints = pipeline["constraints_by_sink"].get(chain["sink_id"], [])
            constraint = constraints[0] if len(constraints) == 1 else {}
            gates = pipeline["gates_by_chain"].get(chain_id, [])
            chain_rows.append(
                {
                    "report_id": report_id,
                    "chain_id": chain_id,
                    "tool_name": chain.get("tool_name", ""),
                    "handler_qualified_name": chain.get("handler_qualified_name", ""),
                    "source_parameter": chain.get("source_parameter", ""),
                    "sink_id": chain.get("sink_id", ""),
                    "sink_api": constraint.get("sink_api", chain.get("sink_label", "")),
                    "sink_file": chain.get("sink_file", ""),
                    "sink_line": chain.get("sink_line", ""),
                    "sink_argument": chain.get("sink_argument", ""),
                    "constraint_id": constraint.get("constraint_id", ""),
                    "capability_class": constraint.get("capability_class", ""),
                    "capability_card": constraint.get("capability_card", ""),
                    "gate_count": len(gates),
                    "ordered_gates": join(
                        f"{gate.get('gate_seq')}:{gate.get('gate_uid')}:{gate.get('gate_name')}"
                        for gate in gates
                    ),
                    "matched_gt_gates": join(matched_gate_labels.get(chain_id, [])),
                    "chain_semantic_status": pipeline["semantic_status"].get(chain_id, ""),
                    "report_verdict": verdict,
                    "call_chain": chain.get("call_chain", ""),
                }
            )

    item_counts = Counter(row["item_kind"] for row in item_rows)
    scope_counts = Counter(summary["scope_status"] for summary in summaries)
    sink_status_counts = Counter(
        row["coverage_status"] for row in item_rows if row["item_kind"] == "sink"
    )
    gate_status_counts = Counter(
        row["coverage_status"] for row in item_rows if row["item_kind"] == "gate"
    )
    stats = {
        "schema_version": "openclaw-d5-chain-coverage/v1",
        "project": "openclaw",
        "revision": REVISION,
        "ground_truth_scope": "design/openclaw/groundtruth/new-vuls",
        "reports": len(reports),
        "items": dict(sorted(item_counts.items())),
        "total_items": len(item_rows),
        "scope_status": dict(sorted(scope_counts.items())),
        "sink_status": dict(sorted(sink_status_counts.items())),
        "gate_status": dict(sorted(gate_status_counts.items())),
        "eligible_sink_items": sum(summary["eligible_sinks"] for summary in summaries),
        "covered_eligible_sink_items": sum(summary["covered_sinks"] for summary in summaries),
        "eligible_existing_gate_items": sum(
            summary["eligible_existing_gates"] for summary in summaries
        ),
        "covered_eligible_existing_gate_items": sum(
            summary["covered_existing_gates"] for summary in summaries
        ),
        "eligible_gap_count": sum(summary["eligible_gap_count"] for summary in summaries),
        "chain_rows": len(chain_rows),
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(out_dir / "d5-chain-coverage-items.csv", ITEM_FIELDS, item_rows)
    write_csv(out_dir / "d5-chain-coverage.csv", CHAIN_FIELDS, chain_rows)
    write_csv(out_dir / "d5-chain-coverage-debug.csv", DEBUG_FIELDS, debug_rows)
    (out_dir / "d5-chain-coverage-summary.json").write_text(
        json.dumps({**stats, "report_summaries": summaries}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# OpenClaw new-vuls D5 coverage",
        "",
        f"生成命令（仓库根目录）：`{command}`",
        "",
        f"固定 revision：`{REVISION}`；GT scope：`design/openclaw/groundtruth/new-vuls/`。",
        "",
        "> 本报告逐条统计 new-vuls 的原始 D5 handler/sink/gate。`not-present`、`out-of-model` 和",
        "> `inventory-only` 不进入静态 detector recall 分母，不能记为 CodeQL 漏检。",
        "",
        "## Summary",
        "",
        f"- Reports: **{stats['reports']}**；accounted D5 items: **{stats['total_items']}** "
        f"(handlers={item_counts.get('handler', 0)}, sinks={item_counts.get('sink', 0)}, "
        f"gates={item_counts.get('gate', 0)})。",
        f"- Sink classifications: `{json.dumps(stats['sink_status'], ensure_ascii=False, sort_keys=True)}`。",
        f"- Report scope: `{json.dumps(stats['scope_status'], ensure_ascii=False, sort_keys=True)}`。",
        f"- Eligible current/rebased sinks: **{stats['covered_eligible_sink_items']}/"
        f"{stats['eligible_sink_items']}**；eligible existing gates: "
        f"**{stats['covered_eligible_existing_gate_items']}/{stats['eligible_existing_gate_items']}**。",
        f"- Eligible detector gaps: **{stats['eligible_gap_count']}**；matched structural chain rows: "
        f"**{stats['chain_rows']}**。",
        "",
        "Outputs: `d5-chain-coverage-items.csv`, `d5-chain-coverage.csv`, "
        "`d5-chain-coverage-debug.csv`, `d5-chain-coverage-summary.json`。",
        "",
        "### Per-report coverage",
        "",
        "| Report | Scope | Handler names | Sinks | Eligible sinks | Eligible existing gates | Candidate-only gates | Chains | Verdict |",
        "|---|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    for summary in summaries:
        lines.append(
            f"| `{summary['report_id']}` | `{summary['scope_status']}` | "
            f"{summary['current_handler_names']}/{summary['handler_items']} | "
            f"{summary['sink_items']} | {summary['covered_sinks']}/{summary['eligible_sinks']} | "
            f"{summary['covered_existing_gates']}/{summary['eligible_existing_gates']} | "
            f"{summary['candidate_only_gates']} | {summary['chain_count']} | "
            f"`{summary['verdict']}` |"
        )

    for summary in summaries:
        report_rows = [row for row in item_rows if row["report_id"] == summary["report_id"]]
        lines.extend(
            [
                "",
                f"## `{summary['report_id']}`",
                "",
                f"JSON: `design/openclaw/groundtruth/new-vuls/{summary['json_file']}`",
                "",
                f"Scope verdict: `{summary['scope_status']}`；eligible chains: {summary['chain_count']}。",
                "",
                "| Kind | # | GT item | Type | Pre-patch | Anchor | Status | Match | Chains |",
                "|---|---:|---|---|---|---|---|---|---:|",
            ]
        )
        for row in report_rows:
            lines.append(
                f"| {row['item_kind']} | {row['item_index']} | {str(row['gt_name']).replace('|', '\\|')} | "
                f"{row['gt_type']} | {row['existed_pre_patch']} | "
                f"{row['anchor_status']} `{row['current_anchor']}` | `{row['coverage_status']}` | "
                f"{row['match_kind']} | {row['chain_count']} |"
            )

    (out_dir / "d5-chain-coverage.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return stats


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth-dir", type=Path, default=DEFAULT_GT)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--pipeline-output", type=Path, default=DEFAULT_PIPELINE)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--handler-inventory", type=Path, default=DEFAULT_HANDLERS)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--fail-on-eligible-gap", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    command_parts = [
        "python",
        "design/openclaw/call-chain/debug/scripts/render_d5_chain_coverage.py",
        "--ground-truth-dir",
        "design/openclaw/groundtruth/new-vuls",
        "--inventory",
        "design/openclaw/inventory/debug/sink-inventory.json",
        "--pipeline-output",
        "output/openclaw",
        "--source-root",
        "benchmark/typescript/openclaw",
        "--handler-inventory",
        "design/openclaw/handler-entry/debug/tool-handler-entries.csv",
        "--out-dir",
        "design/openclaw/call-chain/debug",
    ]
    if args.fail_on_eligible_gap:
        command_parts.append("--fail-on-eligible-gap")
    try:
        stats = render(
            ground_truth_dir=args.ground_truth_dir.resolve(),
            inventory_path=args.inventory.resolve(),
            pipeline_output=args.pipeline_output.resolve(),
            source_root=args.source_root.resolve(),
            handler_inventory_path=args.handler_inventory.resolve(),
            out_dir=args.out_dir.resolve(),
            command=shlex.join(command_parts),
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc))
        return 1
    print(json.dumps(stats, indent=2, ensure_ascii=False))
    if args.fail_on_eligible_gap and stats["eligible_gap_count"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

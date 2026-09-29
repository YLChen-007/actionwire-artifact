#!/usr/bin/env python3
"""Build OpenClaw-CN's pinned source/GT lock, inventory, and static oracle."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shlex
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[5]
PROJECT = "openclaw-cn"
TAG = "v0.2.1"
REVISION = "558f272e6c90e7e0c37644e505e161b91ef738f0"
DEFAULT_SOURCE = ROOT / "benchmark/typescript/openclaw-cn"
DEFAULT_GT = ROOT / "design/openclaw-cn/groundtruth/new-vuls"
DEFAULT_OUT = ROOT / "design/openclaw-cn/inventory/debug"
DEFAULT_LOCK = ROOT / "design/openclaw-cn/inventory/openclaw-cn-source-gt-lock.json"
DEFAULT_ORACLE = ROOT / "design/openclaw-cn/inventory/openclaw-cn-static-oracle.json"
EXPECTED = {
    "reports": 8,
    "handlers": 8,
    "extraction_records": 43,
    "gates": 69,
    "sinks": 15,
    "cross_component_edges": 21,
}
LOCATION_RE = re.compile(r"(?P<path>(?:src|extensions)/[^:\s|]+):(?P<line>\d+)")


HANDLERS = {
    "browser": ("src/agents/tools/browser-tool.ts", 271),
    "exec": ("src/agents/bash-tools.exec.ts", 743),
    "apply_patch": ("src/agents/apply-patch.ts", 94),
    "message": ("src/agents/tools/message-tool.ts", 398),
}


SINKS = {
    "page-evaluate": (
        "src/browser/pw-tools-core.interactions.ts",
        257,
        "OCCN-BROWSER-EVALUATE",
        "page.evaluate",
        "code-eval",
        "function-text",
    ),
    "locator-evaluate": (
        "src/browser/pw-tools-core.interactions.ts",
        240,
        "OCCN-BROWSER-EVALUATE",
        "locator.evaluate",
        "code-eval",
        "function-text",
    ),
    "locator-click": (
        "src/browser/pw-tools-core.interactions.ts",
        52,
        "OCCN-BROWSER-INTERACTION",
        "locator.click",
        "browser-interaction",
        "locator-ref",
    ),
    "locator-dblclick": (
        "src/browser/pw-tools-core.interactions.ts",
        46,
        "OCCN-BROWSER-INTERACTION",
        "locator.dblclick",
        "browser-interaction",
        "locator-ref",
    ),
    "snapshot-goto": (
        "src/browser/pw-tools-core.snapshot.ts",
        175,
        "OCCN-BROWSER-PAGE-GOTO",
        "page.goto",
        "browser-navigation",
        "url",
    ),
    "node-host-spawn": (
        "src/node-host/runner.ts",
        373,
        "OCCN-NODE-HOST-SPAWN",
        "child_process.spawn:node-host",
        "process-spawn",
        "command",
    ),
    "apply-patch-write": (
        "src/agents/apply-patch.ts",
        243,
        "OCCN-APPLY-PATCH-WRITE",
        "fs.writeFile:apply-patch",
        "file-write",
        "path",
    ),
    "feishu-fetch": (
        "extensions/feishu/src/media.ts",
        537,
        "OCCN-FEISHU-MEDIA-FETCH",
        "fetch:feishu-media",
        "network-egress",
        "url",
    ),
    "cdp-create-target": (
        "src/browser/cdp.ts",
        100,
        "OCCN-BROWSER-CDP-CREATE-TARGET",
        "CDP.Target.createTarget",
        "browser-navigation",
        "url",
    ),
    "playwright-open-goto": (
        "src/browser/pw-session.ts",
        525,
        "OCCN-BROWSER-PAGE-GOTO",
        "page.goto",
        "browser-navigation",
        "url",
    ),
    "cdp-json-new": (
        "src/browser/cdp.helpers.ts",
        106,
        "OCCN-BROWSER-JSON-NEW",
        "fetch:/json/new",
        "browser-navigation",
        "url",
    ),
    "gateway-spawn": (
        "src/process/spawn-utils.ts",
        57,
        "OCCN-GATEWAY-SPAWN",
        "spawnImpl",
        "process-spawn",
        "command",
    ),
    "gateway-pty": (
        "src/agents/bash-tools.exec.ts",
        414,
        "OCCN-GATEWAY-PTY-SPAWN",
        "node-pty.spawn",
        "process-spawn",
        "argv",
    ),
}


EXPECTED_MISSING = {
    "missing post-evaluate navigation revalidation": "assertBrowserNavigationAllowed",
    "missing post-click navigation validation in /act": "assertBrowserNavigationAllowed",
    "missing Feishu remote-media SSRF guard": "resolvePinnedHostnameWithPolicy",
    "registerBrowserAgentActRoutes evaluate missing navigation guard": "assertBrowserNavigationAllowed",
    "evaluateViaPlaywright missing sink capability restriction": "restrictEvaluationCapability",
}


GATES: dict[str, tuple[str, int, str]] = {
    "browser tool act request object guard": (
        "src/agents/tools/browser-tool.ts",
        846,
        "inlineCondition",
    ),
    "act route action kind allowlist": (
        "src/browser/routes/agent.act.ts",
        39,
        "isActKind",
    ),
    "isActKind": ("src/browser/routes/agent.act.ts", 39, "isActKind"),
    "evaluate fn presence guard": (
        "src/browser/routes/agent.act.ts",
        255,
        "inlineCondition",
    ),
    "evaluateViaPlaywright fnText presence guard": (
        "src/browser/pw-tools-core.interactions.ts",
        218,
        "inlineCondition",
    ),
    "agent.act kind allowlist": (
        "src/browser/routes/agent.act.ts",
        39,
        "isActKind",
    ),
    "agent.act click ref required": (
        "src/browser/routes/agent.act.ts",
        57,
        "inlineCondition",
    ),
    "requireRef": ("src/browser/pw-tools-core.interactions.ts", 41, "requireRef"),
    "refLocator role ref existence check": (
        "src/browser/pw-session.ts",
        431,
        "inlineCondition",
    ),
    "navigateViaPlaywright pre-goto SSRF gate": (
        "src/browser/pw-tools-core.snapshot.ts",
        169,
        "assertBrowserNavigationAllowed",
    ),
    "assertBrowserNavigationAllowed": (
        "src/browser/pw-tools-core.snapshot.ts",
        169,
        "assertBrowserNavigationAllowed",
    ),
    "assertBrowserNavigationAllowed protocol branch": (
        "src/browser/navigation-guard.ts",
        21,
        "inlineCondition",
    ),
    "resolvePinnedHostnameWithPolicy hostname allowlist": (
        "src/infra/net/ssrf.ts",
        401,
        "matchesHostnameAllowlist",
    ),
    "resolvePinnedHostnameWithPolicy blocked hostname denylist": (
        "src/infra/net/ssrf.ts",
        406,
        "isBlockedHostname",
    ),
    "resolvePinnedHostnameWithPolicy literal private IP block": (
        "src/infra/net/ssrf.ts",
        410,
        "isPrivateIpAddress",
    ),
    "resolvePinnedHostnameWithPolicy resolved private IP block": (
        "src/infra/net/ssrf.ts",
        423,
        "isPrivateIpAddress",
    ),
    "exec tool node precheck evaluateShellAllowlist": (
        "src/agents/bash-tools.exec.ts",
        967,
        "evaluateShellAllowlist",
    ),
    "exec tool approval-required branch": (
        "src/agents/bash-tools.exec.ts",
        1016,
        "inlineCondition",
    ),
    "node-host system.run evaluateShellAllowlist": (
        "src/node-host/runner.ts",
        855,
        "evaluateShellAllowlist",
    ),
    "evaluateExecAllowlist": ("src/node-host/runner.ts", 872, "evaluateExecAllowlist"),
    "evaluateSegments": ("src/infra/exec-approvals.ts", 1149, "evaluateSegments"),
    "matchAllowlist": ("src/infra/exec-approvals.ts", 1115, "matchAllowlist"),
    "isSafeBinUsage": ("src/infra/exec-approvals.ts", 1117, "isSafeBinUsage"),
    "skill-bin auto allow": ("src/infra/exec-approvals.ts", 1124, "skillAllow"),
    "node-host approval-required branch": (
        "src/node-host/runner.ts",
        1009,
        "inlineCondition",
    ),
    "system.run allowlist miss deny branch": (
        "src/node-host/runner.ts",
        1041,
        "inlineCondition",
    ),
    "resolveSandboxPath lexical containment": (
        "src/agents/sandbox-paths.ts",
        48,
        "inlineCondition",
    ),
    "assertSandboxPath symlink escape check": (
        "src/agents/sandbox-paths.ts",
        61,
        "assertNoSymlinkEscape",
    ),
    "tryRealpath lexical fallback": ("src/agents/sandbox-paths.ts", 145, "resolve"),
    "assertNoSymlinkEscape symlink target containment": (
        "src/agents/sandbox-paths.ts",
        125,
        "isPathInside",
    ),
    "isPathInside relative containment predicate": (
        "src/infra/path-guards.ts",
        25,
        "startsWith",
    ),
    "assertNoSymlinkEscape missing-component return": (
        "src/agents/sandbox-paths.ts",
        133,
        "isNotFoundPathError",
    ),
    "navigateViaPlaywright assertBrowserNavigationAllowed call": (
        "src/browser/pw-tools-core.snapshot.ts",
        169,
        "assertBrowserNavigationAllowed",
    ),
    "assertBrowserNavigationAllowed protocol selector": (
        "src/browser/navigation-guard.ts",
        21,
        "inlineCondition",
    ),
    "assertBrowserNavigationAllowed hostname policy call": (
        "src/browser/navigation-guard.ts",
        25,
        "resolvePinnedHostnameWithPolicy",
    ),
    "resolvePinnedHostnameWithPolicy private hostname and IP literal checks": (
        "src/infra/net/ssrf.ts",
        410,
        "isPrivateIpAddress",
    ),
    "resolvePinnedHostnameWithPolicy private DNS result checks": (
        "src/infra/net/ssrf.ts",
        423,
        "isPrivateIpAddress",
    ),
    "assertMediaNotDataUrl": (
        "src/infra/outbound/message-action-runner.ts",
        372,
        "assertMediaNotDataUrl",
    ),
    "isLocalPath remote-media branch selector": (
        "extensions/feishu/src/media.ts",
        524,
        "isLocalPath",
    ),
    "tabs/open url required guard": (
        "src/browser/routes/tabs.ts",
        34,
        "inlineCondition",
    ),
    "openTab navigation guard invocation": (
        "src/browser/server-context.ts",
        153,
        "assertBrowserNavigationAllowed",
    ),
    "assertBrowserNavigationAllowed empty-url guard": (
        "src/browser/navigation-guard.ts",
        10,
        "inlineCondition",
    ),
    "assertBrowserNavigationAllowed URL parser guard": (
        "src/browser/navigation-guard.ts",
        16,
        "URL",
    ),
    "assertBrowserNavigationAllowed non-network scheme branch": (
        "src/browser/navigation-guard.ts",
        21,
        "inlineCondition",
    ),
    "resolvePinnedHostnameWithPolicy dispatch": (
        "src/browser/navigation-guard.ts",
        25,
        "resolvePinnedHostnameWithPolicy",
    ),
    "resolvePinnedHostnameWithPolicy blocked hostname guard": (
        "src/infra/net/ssrf.ts",
        406,
        "isBlockedHostname",
    ),
    "resolvePinnedHostnameWithPolicy literal private IP guard": (
        "src/infra/net/ssrf.ts",
        410,
        "isPrivateIpAddress",
    ),
    "resolvePinnedHostnameWithPolicy resolved private IP guard": (
        "src/infra/net/ssrf.ts",
        423,
        "isPrivateIpAddress",
    ),
    "createTargetViaCdp navigation guard invocation": (
        "src/browser/cdp.ts",
        86,
        "assertBrowserNavigationAllowed",
    ),
    "createPageViaPlaywright targetUrl normalization": (
        "src/browser/pw-session.ts",
        519,
        "trim",
    ),
    "createPageViaPlaywright navigation guard invocation": (
        "src/browser/pw-session.ts",
        521,
        "assertBrowserNavigationAllowed",
    ),
    "Chrome DevTools /json/new query encoder": (
        "src/browser/server-context.ts",
        198,
        "encodeURIComponent",
    ),
    "Chrome DevTools /json/new searchParams setter": (
        "src/browser/server-context.ts",
        210,
        "set",
    ),
    "evaluateShellAllowlist": (
        "src/agents/bash-tools.exec.ts",
        1175,
        "evaluateShellAllowlist",
    ),
    "approval decision deny/allow": (
        "src/agents/bash-tools.exec.ts",
        1240,
        "inlineCondition",
    ),
    "resolveAllowAlwaysPatterns": (
        "src/agents/bash-tools.exec.ts",
        1259,
        "resolveAllowAlwaysPatterns",
    ),
    "isShellWrapperSegment": (
        "src/infra/exec-approvals-allowlist.ts",
        331,
        "isShellWrapperSegment",
    ),
    "collectAllowAlwaysPatterns non-wrapper persistence": (
        "src/infra/exec-approvals-allowlist.ts",
        331,
        "isShellWrapperSegment",
    ),
    "allowlist-miss denial": (
        "src/agents/bash-tools.exec.ts",
        1378,
        "inlineCondition",
    ),
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


def _scope_files(source_root: Path) -> list[Path]:
    selected = []
    for path in sorted((source_root / "src").rglob("*.ts")):
        relative = path.relative_to(source_root).as_posix()
        if relative.endswith((".test.ts", ".spec.ts")):
            continue
        if relative.startswith(("src/plugins/", "src/channels/plugins/agent-tools/")):
            continue
        if "/test-helpers/" in relative:
            continue
        selected.append(path)
    selected.extend(
        source_root / relative
        for relative in (
            "extensions/feishu/src/outbound.ts",
            "extensions/feishu/src/media.ts",
        )
    )
    missing = [path for path in selected if not path.is_file()]
    if missing:
        raise ValueError(f"missing bounded-scope source: {missing[0]}")
    return sorted(set(selected))


def _scope_snapshot(source_root: Path) -> dict[str, Any]:
    entries = [
        {"path": path.relative_to(source_root).as_posix(), "sha256": _sha(path)}
        for path in _scope_files(source_root)
    ]
    digest = hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {"file_count": len(entries), "sha256": digest}


def build_lock(gt_root: Path, source_root: Path) -> dict[str, Any]:
    reports = []
    totals = Counter()
    for path in sorted(gt_root.glob("*.json")):
        payload = _json(path)
        counts = {
            "handlers": len(_items(payload, "handler")),
            "extraction_records": len(_items(payload, "extraction")),
            "gates": len(_items(payload, "gate")),
            "sinks": len(_items(payload, "sink")),
            "cross_component_edges": len(_items(payload, "cross_component")),
        }
        totals.update(counts)
        reports.append({"path": path.name, "sha256": _sha(path), **counts})
    counts = {"reports": len(reports), **dict(totals)}
    if counts != EXPECTED:
        raise ValueError(f"OpenClaw-CN GT cardinality changed: expected {EXPECTED}, got {counts}")
    corpus_sha256 = hashlib.sha256(
        json.dumps(reports, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema_version": "openclaw-cn-source-gt-lock/v1",
        "project": PROJECT,
        "tag": TAG,
        "revision": REVISION,
        "analysis_scope": {
            "include": ["src/**/*.ts", "extensions/feishu/src/outbound.ts", "extensions/feishu/src/media.ts"],
            "exclude": [
                "**/*.test.ts",
                "**/*.spec.ts",
                "src/plugins/**",
                "src/channels/plugins/agent-tools/**",
                "**/test-helpers/**",
                "apps/**",
                "vendor/**",
                "dist/**",
                "scripts/**",
            ],
            **_scope_snapshot(source_root),
        },
        "counts": counts,
        "corpus_sha256": corpus_sha256,
        "reports": reports,
    }


def _location(value: object) -> tuple[str, int]:
    match = LOCATION_RE.search(str(value or ""))
    return (match.group("path"), int(match.group("line"))) if match else ("", 0)


def _sink_key(name: str, location: str) -> str:
    lowered = name.lower()
    if "locator.evaluate" in lowered:
        return "locator-evaluate"
    if "page.evaluate" in lowered:
        return "page-evaluate"
    if "dblclick" in lowered:
        return "locator-dblclick"
    if "locator.click" in lowered:
        return "locator-click"
    if "node-host" in lowered:
        return "node-host-spawn"
    if "apply_patch" in lowered:
        return "apply-patch-write"
    if name == "global fetch":
        return "feishu-fetch"
    if "target.createtarget" in lowered:
        return "cdp-create-target"
    if "/json/new" in lowered:
        return "cdp-json-new"
    if "gateway non-pty" in lowered:
        return "gateway-spawn"
    if "node-pty" in lowered:
        return "gateway-pty"
    if "page.goto" in lowered and "pw-session" in location:
        return "playwright-open-goto"
    if "page.goto" in lowered:
        return "snapshot-goto"
    raise ValueError(f"unmapped OpenClaw-CN sink: {name} at {location}")


def _gate_mapping(report: str, name: str) -> tuple[str, int, str]:
    if name == "requiresExecApproval":
        return (
            "src/agents/bash-tools.exec.ts",
            1187 if report.startswith("openclaw-cn-") else 982,
            "requiresExecApproval",
        )
    try:
        return GATES[name]
    except KeyError as exc:
        raise ValueError(f"unmapped OpenClaw-CN gate: {report}: {name}") from exc


def _protected_sibling(report: str, name: str) -> bool:
    if report.startswith("Advisory-GHSA-qmwg-"):
        return name not in EXPECTED_MISSING
    if report.startswith("Advisory-GHSA-536q-"):
        return name in {
            "navigateViaPlaywright pre-goto SSRF gate",
            "assertBrowserNavigationAllowed",
            "assertBrowserNavigationAllowed protocol branch",
            "resolvePinnedHostnameWithPolicy hostname allowlist",
            "resolvePinnedHostnameWithPolicy blocked hostname denylist",
            "resolvePinnedHostnameWithPolicy literal private IP block",
            "resolvePinnedHostnameWithPolicy resolved private IP block",
        }
    return False


def build_inventory(gt_root: Path, lock: dict[str, Any]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    seen_sinks: set[tuple[str, int]] = set()
    for report_path in sorted(gt_root.glob("*.json")):
        report = report_path.name
        payload = _json(report_path)
        for kind in ("handler", "extraction", "gate", "sink", "cross_component"):
            for index, raw in enumerate(_items(payload, kind), 1):
                item = raw if isinstance(raw, dict) else {"value": raw}
                name = str(item.get("name") or item.get("value") or f"{kind}-{index}")
                original_location = str(
                    item.get("location")
                    or item.get("from_location")
                    or item.get("to_location")
                    or ""
                )
                record: dict[str, Any] = {
                    "record_id": _stable("OCN-", report, kind, index, name),
                    "report_path": report,
                    "kind": kind,
                    "ordinal": index,
                    "name": name,
                    "original_location": original_location,
                    "original": item,
                    "anchor_status": "current",
                    "mapping_status": "provenance-only",
                }
                if kind == "handler":
                    current_file, current_line = HANDLERS[name]
                    record.update(
                        current_file=current_file,
                        current_line=current_line,
                        mapping_status="canonical-handler",
                    )
                elif kind == "sink":
                    key = _sink_key(name, original_location)
                    current_file, current_line, canonical, label, capability, facet = SINKS[key]
                    concrete = (current_file, current_line)
                    record.update(
                        current_file=current_file,
                        current_line=current_line,
                        canonical_sink_id=canonical,
                        sink_label=label,
                        capability_class=capability,
                        controlled_facet=facet,
                        mapping_status="duplicate" if concrete in seen_sinks else "canonical",
                    )
                    seen_sinks.add(concrete)
                elif kind == "gate":
                    if name in EXPECTED_MISSING:
                        current_file, current_line = _location(original_location)
                        record.update(
                            current_file=current_file,
                            current_line=current_line,
                            gate_name=EXPECTED_MISSING[name],
                            anchor_status="expected-missing",
                            mapping_status="expected-missing",
                            forbidden_gate_name=EXPECTED_MISSING[name],
                        )
                    else:
                        current_file, current_line, gate_name = _gate_mapping(report, name)
                        original_file, original_line = _location(original_location)
                        status = (
                            "current"
                            if (original_file, original_line) == (current_file, current_line)
                            else "rebased"
                        )
                        mapping = (
                            "protected-sibling"
                            if _protected_sibling(report, name)
                            else "defective-control"
                            if name == "isLocalPath remote-media branch selector"
                            else "exact-chain"
                        )
                        record.update(
                            current_file=current_file,
                            current_line=current_line,
                            gate_name=gate_name,
                            anchor_status=status,
                            mapping_status=mapping,
                        )
                records.append(record)

    counts = Counter(record["kind"] for record in records)
    normalized_counts = {
        "reports": EXPECTED["reports"],
        "handlers": counts["handler"],
        "extraction_records": counts["extraction"],
        "gates": counts["gate"],
        "sinks": counts["sink"],
        "cross_component_edges": counts["cross_component"],
    }
    if normalized_counts != EXPECTED:
        raise ValueError(f"inventory accounting mismatch: {normalized_counts}")
    gate_statuses = Counter(
        record["mapping_status"] for record in records if record["kind"] == "gate"
    )
    if gate_statuses["expected-missing"] != 5:
        raise ValueError(f"expected five missing gate refs, got {gate_statuses}")
    if sum(value for key, value in gate_statuses.items() if key != "expected-missing") != 64:
        raise ValueError(f"expected 64 present/protected control refs, got {gate_statuses}")
    if len(seen_sinks) != 13:
        raise ValueError(f"expected 13 concrete sinks, got {len(seen_sinks)}")
    return {
        "schema_version": "openclaw-cn-groundtruth-inventory/v1",
        "project": PROJECT,
        "tag": TAG,
        "revision": REVISION,
        "corpus_sha256": lock["corpus_sha256"],
        "analysis_scope_sha256": lock["analysis_scope"]["sha256"],
        "counts": EXPECTED,
        "derived_counts": {
            "concrete_sinks": len(seen_sinks),
            "existing_protected_or_defective_gate_refs": 64,
            "expected_missing_gate_refs": 5,
        },
        "records": records,
    }


def build_oracle(inventory: dict[str, Any]) -> dict[str, Any]:
    records = inventory["records"]
    sink_groups: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if record["kind"] == "sink":
            sink_groups[(record["current_file"], record["current_line"])].append(record)

    report_tools = {
        record["report_path"]: record["name"]
        for record in records
        if record["kind"] == "handler"
    }
    gates_by_report: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if record["kind"] == "gate":
            gates_by_report[record["report_path"]].append(record)

    open_tab_common = {
        "tabs/open url required guard",
        "openTab navigation guard invocation",
        "assertBrowserNavigationAllowed empty-url guard",
        "assertBrowserNavigationAllowed URL parser guard",
        "assertBrowserNavigationAllowed non-network scheme branch",
        "resolvePinnedHostnameWithPolicy dispatch",
        "resolvePinnedHostnameWithPolicy hostname allowlist",
        "resolvePinnedHostnameWithPolicy blocked hostname guard",
        "resolvePinnedHostnameWithPolicy literal private IP guard",
        "resolvePinnedHostnameWithPolicy resolved private IP guard",
    }

    def applies(report: str, gate: dict[str, Any], sink_file: str) -> bool:
        name = gate["name"]
        if report.startswith("Advisory-GHSA-536q-"):
            return (
                gate["mapping_status"] != "protected-sibling"
                and sink_file == "src/browser/pw-tools-core.interactions.ts"
            )
        if report.startswith("Advisory-GHSA-qmwg-"):
            return gate["anchor_status"] == "expected-missing"
        if report == "CVE-2026-32008-openTab-file-scheme.json":
            if name in open_tab_common:
                return True
            if name == "createTargetViaCdp navigation guard invocation":
                return sink_file == "src/browser/cdp.ts"
            if name in {
                "createPageViaPlaywright targetUrl normalization",
                "createPageViaPlaywright navigation guard invocation",
            }:
                return sink_file == "src/browser/pw-session.ts"
            if name in {
                "Chrome DevTools /json/new query encoder",
                "Chrome DevTools /json/new searchParams setter",
            }:
                return sink_file == "src/browser/cdp.helpers.ts"
        return True

    expectations = []
    for (sink_file, sink_line), sink_refs in sorted(sink_groups.items()):
        reports = sorted({row["report_path"] for row in sink_refs})
        tool_names = sorted({report_tools[report] for report in reports})
        exact_gates = []
        missing = []
        for report in reports:
            for gate in gates_by_report[report]:
                if not applies(report, gate, sink_file):
                    continue
                if gate["anchor_status"] == "expected-missing":
                    missing.append(
                        {
                            "inventory_record_id": gate["record_id"],
                            "gt_name": gate["name"],
                            "forbidden_gate_name": gate["forbidden_gate_name"],
                        }
                    )
                elif gate["mapping_status"] != "protected-sibling":
                    exact_gates.append(
                        {
                            "inventory_record_id": gate["record_id"],
                            "gt_name": gate["name"],
                            "gate_name": gate["gate_name"],
                            "gate_file": gate["current_file"],
                            "gate_line": gate["current_line"],
                        }
                    )
        representative = sink_refs[0]
        expectations.append(
            {
                "record_id": _stable("OCN-SINK-", sink_file, sink_line),
                "source_sink_records": [row["record_id"] for row in sink_refs],
                "report_paths": reports,
                "tool_names": tool_names,
                "sink_file": sink_file,
                "sink_line": sink_line,
                "canonical_sink_id": representative["canonical_sink_id"],
                "sink_label": representative["sink_label"],
                "capability_class": representative["capability_class"],
                "controlled_facet": representative["controlled_facet"],
                "existing_gates": exact_gates,
                "expected_missing": missing,
            }
        )

    protected = [
        {
            "inventory_record_id": record["record_id"],
            "report_path": record["report_path"],
            "gt_name": record["name"],
            "gate_name": record["gate_name"],
            "gate_file": record["current_file"],
            "gate_line": record["current_line"],
        }
        for record in records
        if record["kind"] == "gate" and record["mapping_status"] == "protected-sibling"
    ]
    return {
        "schema_version": "openclaw-cn-static-oracle/v1",
        "project": PROJECT,
        "tag": TAG,
        "revision": REVISION,
        "corpus_sha256": inventory["corpus_sha256"],
        "analysis_scope_sha256": inventory["analysis_scope_sha256"],
        "expected": {
            **EXPECTED,
            "unique_tool_names": 25,
            "handler_rows": 28,
            "concrete_sinks": 13,
            "structural_chains": 14,
            "sink_constraints": 13,
            "existing_protected_or_defective_gate_refs": 64,
            "expected_missing_gate_refs": 5,
        },
        "eligible_sink_records": expectations,
        "protected_sibling_evidence": protected,
    }


def _write_inventory(inventory: dict[str, Any], out_dir: Path, command: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "groundtruth-inventory.json").write_text(
        json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    fields = [
        "record_id",
        "report_path",
        "kind",
        "ordinal",
        "name",
        "original_location",
        "anchor_status",
        "mapping_status",
        "current_file",
        "current_line",
        "canonical_sink_id",
        "capability_class",
        "controlled_facet",
    ]
    with (out_dir / "groundtruth-inventory.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(inventory["records"])
    statuses = Counter(
        record["mapping_status"] for record in inventory["records"] if record["kind"] == "gate"
    )
    lines = [
        "# OpenClaw-CN revision-pinned ground-truth inventory",
        "",
        f"生成命令（仓库根目录）：`{command}`",
        "",
        f"固定 `{TAG}` / `{REVISION}`；原始 GT 完整入账：**8 handlers / 43 extraction records / 69 gates / 15 sinks / 21 cross-component edges**。",
        "",
        f"15 条 sink 引用映射到 **13** 个 concrete callsites；gate refs：**64** 条现存、protected sibling 或 defective-control，**{statuses['expected-missing']}** 条 expected-missing。",
        "",
        "逐条 provenance、原始对象、重定位 witness、canonical sink 和 controlled facet 见 `groundtruth-inventory.json` 与 CSV。",
    ]
    (out_dir / "groundtruth-inventory.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--groundtruth", type=Path, default=DEFAULT_GT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--update-lock", action="store_true")
    args = parser.parse_args()
    command_parts = [
        "python",
        "design/openclaw-cn/inventory/debug/scripts/generate_inventory.py",
    ]
    if args.update_lock:
        command_parts.append("--update-lock")
    command = shlex.join(command_parts)
    snapshot = build_lock(args.groundtruth.resolve(), args.source_root.resolve())
    if args.update_lock:
        args.lock.parent.mkdir(parents=True, exist_ok=True)
        args.lock.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    elif not args.lock.is_file() or _json(args.lock) != snapshot:
        raise ValueError("OpenClaw-CN source/GT lock drift; review and rerun with --update-lock")
    inventory = build_inventory(args.groundtruth.resolve(), snapshot)
    oracle = build_oracle(inventory)
    _write_inventory(inventory, args.out_dir.resolve(), command)
    args.oracle.parent.mkdir(parents=True, exist_ok=True)
    args.oracle.write_text(json.dumps(oracle, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"counts": EXPECTED, "concrete_sinks": 13, "expected_missing": 5}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

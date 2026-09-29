#!/usr/bin/env python3
"""Generate the revision-pinned zero filter/transform gate audit."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.projects import get_project  # noqa: E402


SCHEMA = "clawgap-zero-gate-audit/v1"
GENERATION_COMMAND = "python design/paperdata/script/generate_zero_gate_audit.py"
MANIFEST_PATH = REPO_ROOT / "design/paperdata/zero-gate-audit.json"
REPORT_PATH = REPO_ROOT / "design/paperdata/debug/zero-gate-audit.md"

AUDITED_CELLS = (
    ("nanobot", "filter"),
    ("chatgpt-on-wechat", "filter"),
    ("poco-agent", "filter"),
    ("openclaw", "filter"),
    ("openclaw-cn", "filter"),
    ("mercury-agent", "filter"),
    ("lettabot", "filter"),
    ("nanobot", "transform"),
    ("chatgpt-on-wechat", "transform"),
    ("QwenPaw", "transform"),
    ("poco-agent", "transform"),
    ("lettabot", "transform"),
)

DETECTED_WITNESSES: dict[tuple[str, str], dict[str, object]] = {
    ("openclaw", "filter"): {
        "targets": (
            {
                "tool_names": {"apply_patch"},
                "sink_file": "src/agents/apply-patch.ts",
                "sink_lines": {143, 150, 161, 162, 165},
                "gate_file": "src/agents/apply-patch.ts",
                "gate_line": 117,
                "gate_names": {"parsePatchText"},
                "rationale": (
                    "The LLM-derived patch input enters parsePatchText; only validated hunks "
                    "are admitted before the file write/delete sinks."
                ),
            },
            {
                "tool_names": {"nodes"},
                "sink_file": "src/agents/tools/nodes-tool.ts",
                "sink_lines": {424},
                "gate_file": "src/agents/tools/nodes-tool.ts",
                "gate_line": 417,
                "gate_names": {"parseEnvPairs"},
                "rationale": (
                    "The LLM-derived nodes env array enters parseEnvPairs; malformed entries "
                    "are rejected before the admitted dictionary enters node.invoke."
                ),
            },
            {
                "tool_names": {"exec", "nodes"},
                "sink_file": "src/node-host/runner.ts",
                "sink_lines": {405},
                "gate_file": "src/node-host/runner.ts",
                "gate_line": 893,
                "gate_names": {"sanitizeEnv"},
                "rationale": (
                    "The RPC-carried LLM tool environment re-enters as params.env; sanitizeEnv "
                    "conditionally admits allowed entries into spawn's environment."
                ),
            },
        ),
    },
    ("openclaw-cn", "filter"): {
        "targets": (
            {
                "tool_names": {"apply_patch"},
                "sink_file": "src/agents/apply-patch.ts",
                "sink_lines": {243},
                "gate_file": "src/agents/apply-patch.ts",
                "gate_line": 125,
                "gate_names": {"parsePatchText"},
                "rationale": (
                    "The LLM-derived patch input enters parsePatchText; only validated hunks "
                    "are admitted before the callback-owned file write sink."
                ),
            },
            {
                "tool_names": {"nodes"},
                "sink_file": "src/agents/tools/nodes-tool.ts",
                "sink_lines": {457},
                "gate_file": "src/agents/tools/nodes-tool.ts",
                "gate_line": 438,
                "gate_names": {"parseEnvPairs"},
                "rationale": (
                    "The LLM-derived nodes env array enters parseEnvPairs; malformed entries "
                    "are rejected before the admitted dictionary enters named runParams.env."
                ),
            },
            {
                "tool_names": {"exec", "nodes"},
                "sink_file": "src/node-host/runner.ts",
                "sink_lines": {373},
                "gate_file": "src/node-host/runner.ts",
                "gate_line": 847,
                "gate_names": {"sanitizeEnv"},
                "rationale": (
                    "The RPC-carried LLM tool environment re-enters as params.env; sanitizeEnv "
                    "conditionally admits allowed request entries into spawn's environment."
                ),
            },
        ),
    },
    ("chatgpt-on-wechat", "transform"): {
        "tool_names": {"read"},
        "sink_file": "agent/tools/read/read.py",
        "sink_lines": {248},
        "gate_file": "agent/tools/read/read.py",
        "gate_line": 80,
        "gate_names": {"_resolve_path"},
        "rationale": (
            "Read expands and resolves the handler-derived path through the approved "
            "Read._resolve_path signature before the value reaches open."
        ),
    },
    ("poco-agent", "filter"): {
        "tool_names": {"memory_create", "memory_create_conversation"},
        "sink_file": "executor/app/core/memory.py",
        "sink_lines": {42},
        "excluded_path_fragments": {"MemoryClient.create_memory_text"},
        "gate_file": "executor/app/core/memory.py",
        "gate_line": 155,
        "gate_names": {"isinstance"},
        "rationale": (
            "The source-derived conversation element is rejected unless role and content are "
            "strings, then the normalized object is admitted to the RPC-bound messages list."
        ),
    },
    ("nanobot", "transform"): {
        "tool_names": {"read_file"},
        "sink_file": "nanobot/agent/tools/filesystem.py",
        "sink_lines": {102},
        "gate_file": "nanobot/agent/tools/filesystem.py",
        "gate_line": 50,
        "gate_names": {"_resolve_path"},
        "rationale": (
            "The approved _resolve_path result returns through _resolve and becomes the "
            "filesystem receiver at fp.read_text."
        ),
    },
    ("QwenPaw", "transform"): {
        "tool_names": {"execute_shell_command"},
        "sink_file": "src/qwenpaw/agents/tools/shell.py",
        "sink_lines": {300, 447},
        "gate_file": "src/qwenpaw/agents/tools/shell.py",
        "gate_line": 399,
        "gate_names": {"_collapse_embedded_newlines"},
        "rationale": (
            "The approved _collapse_embedded_newlines output reaches the pinned synchronous "
            "or asynchronous subprocess sink on the same command flow."
        ),
    },
}

CELL_SCOPE = {
    "filter": (
        "Conditional admission only: a handler-source-derived checked value must control an "
        "append/add/set/filter result whose collection reaches the canonical sink."
    ),
    "transform": (
        "Signature-driven transforms only: an approved exact signature must rewrite the same "
        "handler-source value that reaches the canonical sink; generic rewrites remain review-only."
    ),
}


class AuditError(ValueError):
    """Raised for malformed audit inputs."""


def read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise AuditError(f"missing JSON artifact: {path}") from error
    if not isinstance(value, dict):
        raise AuditError(f"expected JSON object: {path}")
    return value


def read_csv(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                raise AuditError(f"CSV has no header: {path}")
            return list(reader)
    except FileNotFoundError as error:
        raise AuditError(f"missing CSV artifact: {path}") from error


def _integer(value: object, context: str) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError) as error:
        raise AuditError(f"{context} is not an integer: {value!r}") from error


def _gate_evidence(
    gate_rows: Iterable[Mapping[str, str]], policy: Mapping[str, object], mode: str
) -> list[dict[str, object]]:
    matches: dict[str, dict[str, object]] = {}
    for row in gate_rows:
        if row.get("mode") != mode:
            continue
        if row.get("callsite_file") != policy["gate_file"]:
            continue
        if _integer(row.get("callsite_line"), "gate callsite_line") != policy["gate_line"]:
            continue
        if row.get("gate_name") not in policy["gate_names"]:
            continue
        uid = str(row.get("gate_uid", "")).strip()
        if not uid:
            raise AuditError("eligible gate row has an empty gate_uid")
        matches[uid] = {
            "gate_uid": uid,
            "gate_name": row.get("gate_name", ""),
            "callsite": f"{row.get('callsite_file')}:{row.get('callsite_line')}",
            "checked_expression": row.get("checked_expression", ""),
            "static_verdict": row.get("static_verdict", ""),
        }
    return [matches[uid] for uid in sorted(matches)]


def _policies(policy: Mapping[str, object] | None) -> tuple[Mapping[str, object], ...]:
    if policy is None:
        return ()
    targets = policy.get("targets")
    if targets is None:
        return (policy,)
    if not isinstance(targets, tuple) or not all(isinstance(item, Mapping) for item in targets):
        raise AuditError("detected witness targets must be a tuple of policy mappings")
    return targets


def _matching_policy(
    row: Mapping[str, str], policy: Mapping[str, object] | None
) -> Mapping[str, object] | None:
    return next((item for item in _policies(policy) if _matches_witness(row, item)), None)


def _matches_witness(row: Mapping[str, str], policy: Mapping[str, object]) -> bool:
    excluded_path_fragments = policy.get("excluded_path_fragments", set())
    return (
        row.get("tool_name") in policy["tool_names"]
        and row.get("sink_file") == policy["sink_file"]
        and _integer(row.get("sink_line"), "chain sink_line") in policy["sink_lines"]
        and not any(
            fragment in str(row.get("call_chain", ""))
            for fragment in excluded_path_fragments
        )
    )


def _record(
    project: str,
    revision: str,
    mode: str,
    chain: Mapping[str, str],
    policy: Mapping[str, object] | None,
    gates: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    matched_policy = _matching_policy(chain, policy)
    detected_target = matched_policy is not None
    if detected_target and gates:
        classification = "detected"
        rationale = str(matched_policy["rationale"])
    elif detected_target:
        classification = "detector-gap"
        rationale = (
            "The revision-pinned source witness matches an approved detector target, but no "
            "eligible detector UID is present."
        )
    else:
        classification = "confirmed-zero"
        rationale = (
            "Source-to-sink review found no in-taxonomy conditional admission."
            if mode == "filter"
            else "Source-to-sink review found no approved security-relevant rewrite."
        )

    gate_evidence = list(gates) if detected_target else []
    return {
        "project": project,
        "revision": revision,
        "witness_id": chain.get("chain_id", ""),
        "mode": mode,
        "classification": classification,
        "source_evidence": {
            "handler_source": (
                f"{chain.get('handler_qualified_name')}@{chain.get('handler_file')}:"
                f"{chain.get('handler_line')} source={chain.get('source_parameter')}"
            ),
            "ordered_path": chain.get("call_chain", ""),
            "sink": (
                f"{chain.get('sink_label')}@{chain.get('sink_file')}:"
                f"{chain.get('sink_line')}:{chain.get('sink_column')}"
            ),
            "gate_evidence": gate_evidence,
        },
        "rationale": rationale,
        "matching_detector_uids": [gate["gate_uid"] for gate in gate_evidence],
    }


def build_manifest(output_root: Path = REPO_ROOT / "output") -> dict[str, object]:
    records: list[dict[str, object]] = []
    cells: list[dict[str, object]] = []
    build_issues: list[str] = []

    for project, mode in AUDITED_CELLS:
        spec = get_project(project).resolved()
        root = output_root / project
        gate_manifest = read_json(root / "static/gates/manifest.json")
        chain_manifest = read_json(root / "static/call-chains/manifest.json")
        chains = read_csv(root / "static/call-chains/handler-sink-chains.csv")
        raw_rows = read_csv(root / f"static/gates/{mode}.csv")
        eligible_rows = read_csv(root / "gate-semantics/gate-index.csv")

        for label, artifact in (("gate", gate_manifest), ("chain", chain_manifest)):
            if artifact.get("project") != project:
                build_issues.append(
                    f"{project} {label} manifest project is {artifact.get('project')!r}"
                )
            if artifact.get("revision") != spec.analysis_revision:
                build_issues.append(
                    f"{project} {label} manifest revision {artifact.get('revision')!r} is stale; "
                    f"expected {spec.analysis_revision}"
                )

        witness_ids = [str(row.get("chain_id", "")).strip() for row in chains]
        if not witness_ids or any(not witness_id for witness_id in witness_ids):
            build_issues.append(f"{project} has missing canonical witness IDs")
        if len(witness_ids) != len(set(witness_ids)):
            build_issues.append(f"{project} has duplicate canonical witness IDs")

        policy = DETECTED_WITNESSES.get((project, mode))
        policy_gates = {
            id(target): _gate_evidence(eligible_rows, target, mode)
            for target in _policies(policy)
        }
        cell_records = [
            _record(
                project,
                spec.analysis_revision,
                mode,
                chain,
                policy,
                policy_gates.get(id(_matching_policy(chain, policy)), []),
            )
            for chain in chains
        ]
        for target in _policies(policy):
            if not any(_matches_witness(chain, target) for chain in chains):
                build_issues.append(f"{project} {mode} has no matching canonical target witness")
        records.extend(cell_records)

        eligible_uids = {
            str(row.get("gate_uid", "")).strip()
            for row in eligible_rows
            if row.get("mode") == mode and str(row.get("gate_uid", "")).strip()
        }
        classifications = Counter(record["classification"] for record in cell_records)
        cells.append(
            {
                "project": project,
                "revision": spec.analysis_revision,
                "mode": mode,
                "original_table_count": 0,
                "raw_detector_rows": len(raw_rows),
                "eligible_gate_uids": len(eligible_uids),
                "canonical_witnesses": len(chains),
                "classifications": dict(sorted(classifications.items())),
                "detector_scope": CELL_SCOPE[mode],
            }
        )

    manifest: dict[str, object] = {
        "schema_version": SCHEMA,
        "generation_command": GENERATION_COMMAND,
        "cells": cells,
        "records": records,
        "issues": build_issues,
    }
    manifest["issues"] = validate_manifest(manifest) + build_issues
    manifest["issues"] = list(dict.fromkeys(manifest["issues"]))
    return manifest


def validate_manifest(manifest: Mapping[str, object]) -> list[str]:
    issues: list[str] = []
    if manifest.get("schema_version") != SCHEMA:
        issues.append(f"schema must be {SCHEMA}")
    if manifest.get("generation_command") != GENERATION_COMMAND:
        issues.append("generation command is missing or non-canonical")

    cells = manifest.get("cells")
    records = manifest.get("records")
    if not isinstance(cells, list) or not isinstance(records, list):
        return issues + ["cells and records must be arrays"]

    cell_map = {
        (cell.get("project"), cell.get("mode")): cell
        for cell in cells
        if isinstance(cell, Mapping)
    }
    if set(cell_map) != set(AUDITED_CELLS):
        issues.append("audited cell set is incomplete or contains extras")

    records_by_cell: dict[tuple[object, object], list[Mapping[str, object]]] = {}
    for record in records:
        if not isinstance(record, Mapping):
            issues.append("audit record is not an object")
            continue
        key = (record.get("project"), record.get("mode"))
        records_by_cell.setdefault(key, []).append(record)
        if not record.get("witness_id"):
            issues.append(f"{key} record has no canonical witness ID")
        classification = record.get("classification")
        if classification not in {"detected", "detector-gap", "confirmed-zero"}:
            issues.append(f"{key} has invalid classification {classification!r}")
        if classification == "detected" and not record.get("matching_detector_uids"):
            issues.append(f"{key} detected record has no matching detector UID")
        if classification == "detector-gap":
            issues.append(f"{key} retains an unresolved detector gap")

    for key, cell in cell_map.items():
        revision = get_project(str(key[0])).analysis_revision
        if cell.get("revision") != revision:
            issues.append(f"{key} cell revision is stale")
        raw = cell.get("raw_detector_rows")
        eligible = cell.get("eligible_gate_uids")
        if not isinstance(raw, int) or not isinstance(eligible, int):
            issues.append(f"{key} lacks raw-versus-eligible counts")
        elif raw < eligible:
            issues.append(f"{key} eligible UID count exceeds raw detector rows")
        cell_records = records_by_cell.get(key, [])
        if len(cell_records) != cell.get("canonical_witnesses"):
            issues.append(f"{key} canonical witness coverage is incomplete")
        witness_ids = [record.get("witness_id") for record in cell_records]
        if len(witness_ids) != len(set(witness_ids)):
            issues.append(f"{key} contains duplicate witness records")
        for record in cell_records:
            if record.get("revision") != revision:
                issues.append(f"{key} record revision is stale")
    return list(dict.fromkeys(issues))


def render_report(manifest: Mapping[str, object]) -> str:
    issues = manifest.get("issues", [])
    lines = [
        f"<!-- Generate from repository root: {GENERATION_COMMAND} -->",
        "",
        "# Zero filter/transform gate audit",
        "",
        f"Schema: `{SCHEMA}`.",
        "",
        "The table separates raw detector rows from distinct eligible gate UIDs. "
        "`needs-review` candidates may appear only in the raw column.",
        "",
        "| Project | Mode | Raw rows | Eligible UIDs | Witnesses | Detected | Confirmed zero | Gaps |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for cell in manifest.get("cells", []):
        counts = cell.get("classifications", {})
        lines.append(
            "| {project} | {mode} | {raw} | {eligible} | {witnesses} | {detected} | "
            "{zero} | {gaps} |".format(
                project=cell.get("project"),
                mode=cell.get("mode"),
                raw=cell.get("raw_detector_rows"),
                eligible=cell.get("eligible_gate_uids"),
                witnesses=cell.get("canonical_witnesses"),
                detected=counts.get("detected", 0),
                zero=counts.get("confirmed-zero", 0),
                gaps=counts.get("detector-gap", 0),
            )
        )

    lines.extend(["", "## Detector scope", ""])
    for mode in ("filter", "transform"):
        lines.append(f"- `{mode}`: {CELL_SCOPE[mode]}")

    lines.extend(["", "## Resolved gaps", ""])
    detected = [
        record for record in manifest.get("records", [])
        if record.get("classification") == "detected"
    ]
    for record in detected:
        evidence = record["source_evidence"]
        lines.append(
            f"- `{record['project']}` `{record['mode']}` `{record['witness_id']}`: "
            f"{record['rationale']} UIDs: "
            f"{', '.join(record['matching_detector_uids'])}. Path: `{evidence['ordered_path']}`"
        )

    lines.extend(["", "## Audit status", ""])
    if issues:
        lines.append("The audit is incomplete:")
        lines.extend(f"- {issue}" for issue in issues)
    else:
        lines.append(
            "Complete: every originally-zero cell covers every canonical witness, no revision "
            "is stale, and no detector gap remains."
        )
    return "\n".join(lines) + "\n"


def write_outputs(manifest: Mapping[str, object]) -> None:
    MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(render_report(manifest), encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=REPO_ROOT / "output")
    parser.add_argument("--strict", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    manifest = build_manifest(args.output_root.resolve())
    write_outputs(manifest)
    print(
        json.dumps(
            {
                "schema_version": SCHEMA,
                "cells": len(manifest["cells"]),
                "records": len(manifest["records"]),
                "issues": len(manifest["issues"]),
            }
        )
    )
    return 1 if args.strict and manifest["issues"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

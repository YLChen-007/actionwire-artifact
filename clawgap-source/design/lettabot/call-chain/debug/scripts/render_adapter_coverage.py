#!/usr/bin/env python3
"""Render LettaBot static adapter evidence; no project GT corpus exists."""

from __future__ import annotations

import argparse
import csv
import json
import shlex
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[5]
REVISION = "99c3b5dd73550fe0a4eac2ee31b1c3229ca9e550"
DEFAULT_PIPELINE = ROOT / "output/lettabot"
DEFAULT_OUT = ROOT / "design/lettabot/call-chain/debug"
GT_ROOT = ROOT / "design/lettabot/groundtruth"


def _csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def render(*, pipeline_output: Path, out_dir: Path, command: str) -> dict[str, Any]:
    if GT_ROOT.exists() and any(GT_ROOT.rglob("*.json")):
        raise ValueError(
            "LettaBot now has ground truth; replace N/A acceptance with a locked oracle"
        )
    static = pipeline_output / "static/call-chains"
    model = _csv(static / "project-model.csv")
    chains = _csv(static / "handler-sink-chains.csv")
    constraints = _csv(static / "sink-constraints.csv")
    chain_gates = _csv(static / "chain-gates.csv")
    gate_manifest = _json(pipeline_output / "static/gates/manifest.json")
    gate_index = _csv(pipeline_output / "gate-semantics/gate-index.csv")
    failures = []
    if model != [{"project_id": "lettabot", "adapter_name": "lettabot-ts"}]:
        failures.append(f"expected exactly one lettabot-ts adapter row, got {model}")
    expected_chains = {
        "Bash": 2,
        "Read": 2,
        "Edit": 1,
        "Write": 1,
        "Glob": 1,
        "Grep": 1,
        "Task": 2,
        "manage_todo": 5,
    }
    chain_counts = Counter(row["tool_name"] for row in chains)
    if chain_counts != Counter(expected_chains):
        failures.append(
            f"expected complete Letta Code/todo chain counts {expected_chains}, got {dict(chain_counts)}"
        )
    unique_constraints = len({row["constraint_id"] for row in constraints})
    if unique_constraints != 11:
        failures.append(
            f"expected ten semantic effect witnesses plus one todo write constraint, got {unique_constraints}"
        )
    semantic_labels = {"Bash", "Read", "Edit", "Write", "Glob", "Grep", "Task"}
    detected_labels = {row["sink_label"] for row in chains}
    if not semantic_labels <= detected_labels:
        failures.append(
            f"missing handler-named semantic sinks: {sorted(semantic_labels - detected_labels)}"
        )
    mode_counts = Counter(row["mode"] for row in gate_index)
    dominance_gates = mode_counts["predicate"]
    transform_gates = mode_counts["transform"]
    eligible_gates = len(gate_index)
    if dominance_gates != 24:
        failures.append(
            f"expected 24 revision-pinned dominance gates, got {dominance_gates}"
        )
    if transform_gates != 0:
        failures.append(
            f"expected no security-relevant LettaBot transforms, got {transform_gates}"
        )
    if eligible_gates != 24:
        failures.append(f"expected 24 total eligible gates, got {eligible_gates}")
    manifest_eligible = gate_manifest.get("counts", {}).get("eligible_catalog_gates")
    if manifest_eligible != eligible_gates:
        failures.append(
            f"gate manifest/index mismatch: manifest {manifest_eligible}, index {eligible_gates}"
        )
    eligible_chain_gate_rows = sum(bool(row.get("gate_uid")) for row in chain_gates)
    chain_ids = {row["chain_id"] for row in chains}
    gated_chain_ids = {row["chain_id"] for row in chain_gates if row.get("gate_uid")}
    zero_gate_chains = len(chain_ids - gated_chain_ids)
    if eligible_chain_gate_rows != 34:
        failures.append(
            f"expected 34 exact-chain gate attachments, got {eligible_chain_gate_rows}"
        )
    if zero_gate_chains:
        failures.append(
            f"expected every LettaBot chain to have a gate, got {zero_gate_chains} zero-gate chains"
        )
    if gate_manifest.get("counts", {}).get("slice_failures") != 0:
        failures.append("gate slicing has failures")
    summary = {
        "schema_version": "lettabot-adapter-coverage/v1",
        "project": "lettabot",
        "revision": REVISION,
        "groundtruth": {
            "status": "not-applicable",
            "reason": "no groundtruth JSON corpus",
        },
        "adapter_rows": len(model),
        "chains": len(chains),
        "handler_chain_counts": dict(sorted(chain_counts.items())),
        "semantic_sink_labels": sorted(semantic_labels & detected_labels),
        "unique_constraints": unique_constraints,
        "dominance_gates": dominance_gates,
        "transform_gates": transform_gates,
        "eligible_catalog_gates": eligible_gates,
        "eligible_chain_gate_rows": eligible_chain_gate_rows,
        "zero_gate_chains": zero_gate_chains,
        "slice_failures": gate_manifest.get("counts", {}).get("slice_failures", 0),
        "failures": failures,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "adapter-coverage.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "# LettaBot adapter coverage",
        "",
        f"生成命令（仓库根目录）：`{command}`",
        "",
        f"固定 revision `{REVISION}`。",
        "",
        "Ground truth coverage: **not applicable** — this project currently has no groundtruth JSON corpus.",
        "",
        f"Static evidence: adapters **{summary['adapter_rows']}**；source-bearing handlers **8**；handler-named semantic capabilities **{len(summary['semantic_sink_labels'])}/7**；effect/todo chains **{summary['chains']}**；constraints **{summary['unique_constraints']}**；dominance gates **{summary['dominance_gates']}**；transform gates **{summary['transform_gates']}**；eligible gates **{summary['eligible_catalog_gates']}**；chain-gate attachments **{summary['eligible_chain_gate_rows']}**；zero-gate chains **{summary['zero_gate_chains']}**；slice failures **{summary['slice_failures']}**。",
    ]
    (out_dir / "adapter-coverage.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pipeline-output", type=Path, default=DEFAULT_PIPELINE)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    pipeline_arg = (
        args.pipeline_output.relative_to(ROOT)
        if args.pipeline_output.is_relative_to(ROOT)
        else args.pipeline_output
    )
    command = shlex.join(
        [
            "python",
            "design/lettabot/call-chain/debug/scripts/render_adapter_coverage.py",
            "--pipeline-output",
            str(pipeline_arg),
        ]
    )
    summary = render(
        pipeline_output=args.pipeline_output, out_dir=args.out_dir, command=command
    )
    print(json.dumps(summary, indent=2))
    return 1 if summary["failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

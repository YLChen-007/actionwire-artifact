#!/usr/bin/env python3
"""Generate the shared sink audit and OpenClaw-CN's 13-witness GT coverage."""

from __future__ import annotations

import csv
import json
import shlex
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT))

from src.pipeline.codeql import run_query  # noqa: E402
from src.projects import get_project  # noqa: E402


def main() -> int:
    spec = get_project("openclaw-cn")
    out = ROOT / "design/openclaw-cn/sink/debug"
    out.mkdir(parents=True, exist_ok=True)
    command = shlex.join(
        ["python", "design/openclaw-cn/sink/debug/scripts/generate_sink_data.py"]
    )
    sinks = run_query(
        spec.codeql_database,
        "get_sinks.ql",
        out / "sink-calls.csv",
        query_pack=spec.query_pack,
        expected_language=spec.codeql_language,
    )
    detected = {(row["file"], int(row["line"])) for row in sinks}
    inventory = json.loads(
        (ROOT / "design/openclaw-cn/inventory/debug/groundtruth-inventory.json").read_text(
            encoding="utf-8"
        )
    )
    coverage = []
    for record in inventory["records"]:
        if record["kind"] != "sink":
            continue
        exact = (record["current_file"], int(record["current_line"])) in detected
        coverage.append(
            {
                "record_id": record["record_id"],
                "report_path": record["report_path"],
                "name": record["name"],
                "original_location": record["original_location"],
                "current_file": record["current_file"],
                "current_line": record["current_line"],
                "anchor_status": record["anchor_status"],
                "mapping_status": record["mapping_status"],
                "canonical_sink_id": record["canonical_sink_id"],
                "capability_class": record["capability_class"],
                "controlled_facet": record["controlled_facet"],
                "status": "COVERED" if exact else "MISS",
            }
        )
    with (out / "sink-ground-truth-coverage.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(coverage[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(coverage)
    statuses = Counter(row["status"] for row in coverage)
    gt_calls = {
        (row["current_file"], int(row["current_line"]))
        for row in coverage
        if row["status"] == "COVERED"
    }
    lines = [
        "# OpenClaw-CN sink inventory and GT coverage",
        "",
        f"生成命令（仓库根目录）：`{command}`",
        "",
        f"固定 revision：`{spec.analysis_revision}`；共享 QL sink audit：**{len(sinks)}** 个 production callsite；GT concrete witnesses：**{len(gt_calls)}/13**；GT sink refs：**{statuses.get('COVERED', 0)}/{len(coverage)}**。",
        "",
        "15 条引用映射到 13 个 concrete callsites；两个 browser-evaluate 报告复用 page/locator evaluate 两个 current witnesses。",
        "",
        "完整逐条 provenance 见 `sink-ground-truth-coverage.csv`，QL 原始结果见 `sink-calls.csv`。",
    ]
    (out / "sink-coverage.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if len(gt_calls) != 13 or len(coverage) != 15 or statuses.get("COVERED") != 15:
        raise ValueError("OpenClaw-CN sink acceptance failed")
    print(
        json.dumps(
            {
                "shared_sink_calls": len(sinks),
                "gt_concrete_sinks": len(gt_calls),
                "gt_sink_refs": len(coverage),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

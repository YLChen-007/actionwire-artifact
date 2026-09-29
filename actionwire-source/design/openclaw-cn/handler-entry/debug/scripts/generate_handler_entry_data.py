#!/usr/bin/env python3
"""Generate OpenClaw-CN's 25-name/28-row handler inventory and GT coverage."""

from __future__ import annotations

import csv
import json
import shlex
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT))

from src.pipeline.codeql import run_query  # noqa: E402
from src.projects import get_project  # noqa: E402


EXPECTED_TOOLS = {
    "agents_list",
    "apply_patch",
    "browser",
    "canvas",
    "cron",
    "edit",
    "exec",
    "gateway",
    "image",
    "memory_get",
    "memory_search",
    "message",
    "nodes",
    "process",
    "read",
    "session_status",
    "sessions_history",
    "sessions_list",
    "sessions_send",
    "sessions_spawn",
    "subagents",
    "tts",
    "web_fetch",
    "web_search",
    "write",
}


def main() -> int:
    spec = get_project("openclaw-cn")
    out = ROOT / "design/openclaw-cn/handler-entry/debug"
    out.mkdir(parents=True, exist_ok=True)
    command = shlex.join(
        [
            "python",
            "design/openclaw-cn/handler-entry/debug/scripts/generate_handler_entry_data.py",
        ]
    )
    handlers = run_query(
        spec.codeql_database,
        "get_tool_handlers.ql",
        out / "tool-handler-entries.csv",
        query_pack=spec.query_pack,
        expected_language=spec.codeql_language,
    )
    names = {row["tool_name"] for row in handlers}
    inventory = json.loads(
        (ROOT / "design/openclaw-cn/inventory/debug/groundtruth-inventory.json").read_text(
            encoding="utf-8"
        )
    )
    coverage = []
    for record in inventory["records"]:
        if record["kind"] != "handler":
            continue
        exact = [
            row
            for row in handlers
            if row["tool_name"] == record["name"]
            and row["file"] == record["current_file"]
            and int(row["line"]) == int(record["current_line"])
        ]
        coverage.append(
            {
                "record_id": record["record_id"],
                "report_path": record["report_path"],
                "tool_name": record["name"],
                "expected_witness": f"{record['current_file']}:{record['current_line']}",
                "matched_rows": len(exact),
                "status": "COVERED" if len(exact) == 1 else "MISS",
            }
        )
    with (out / "entry-ground-truth-coverage.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(coverage[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(coverage)
    lines = [
        "# OpenClaw-CN tool-handler inventory",
        "",
        f"生成命令（仓库根目录）：`{command}`",
        "",
        f"固定 revision：`{spec.analysis_revision}`；检测到 **{len(names)}** 个唯一工具名、**{len(handlers)}** 条 execute 记录；8 条 GT handler 引用：**{sum(row['status'] == 'COVERED' for row in coverage)}/8**。",
        "",
        "| Tool | Form | Handler | Location |",
        "|---|---|---|---|",
    ]
    for row in handlers:
        lines.append(
            f"| `{row['tool_name']}` | `{row['form']}` | `{row['handler_func']}` | `{row['file']}:{row['line']}` |"
        )
    (out / "handler-inventory.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    coverage_lines = [
        "# OpenClaw-CN handler-entry GT coverage",
        "",
        f"生成命令（仓库根目录）：`{command}`",
        "",
        f"8 条原始 handler 引用按工具名和 execute witness 精确匹配：**{sum(row['status'] == 'COVERED' for row in coverage)}/8**；完整 25-name/28-row inventory 见 `handler-inventory.md`。",
    ]
    (out / "entry-ground-truth-coverage.md").write_text(
        "\n".join(coverage_lines) + "\n", encoding="utf-8"
    )
    if len(handlers) != 28 or names != EXPECTED_TOOLS or any(
        row["status"] != "COVERED" for row in coverage
    ):
        raise ValueError("OpenClaw-CN handler acceptance failed")
    print(json.dumps({"handler_rows": len(handlers), "unique_tool_names": len(names), "gt_handlers": 8}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

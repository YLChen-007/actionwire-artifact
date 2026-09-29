#!/usr/bin/env python3
"""Generate LettaBot's source-bearing handlers and separate tool boundaries."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT))

from src.pipeline.codeql import run_query  # noqa: E402
from src.projects import get_project  # noqa: E402


DEFAULT_OUT = ROOT / "design/lettabot/handler-entry/debug"
VENDORED_TOOLS = {
    "Bash",
    "Read",
    "Edit",
    "Write",
    "Glob",
    "Grep",
    "Task",
}
DEFAULT_BOUNDARIES = {
    *VENDORED_TOOLS,
    "web_search",
    "conversation_search",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    spec = get_project("lettabot")
    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    command_parts = [
        "python",
        "design/lettabot/handler-entry/debug/scripts/generate_handler_entry_data.py",
    ]
    if out != DEFAULT_OUT:
        rendered_out = out.relative_to(ROOT) if out.is_relative_to(ROOT) else out
        command_parts.extend(["--out-dir", str(rendered_out)])
    command = shlex.join(command_parts)
    handlers = run_query(
        spec.codeql_database,
        "get_tool_handlers.ql",
        out / "tool-handler-entries.csv",
        query_pack=spec.query_pack,
        expected_language=spec.codeql_language,
    )
    boundaries = run_query(
        spec.codeql_database,
        "get_tool_boundaries.ql",
        out / "tool-boundaries.csv",
        query_pack=spec.query_pack,
        expected_language=spec.codeql_language,
    )
    local = [row for row in handlers if row["form"] == "session-registered-local-tool"]
    vendored = [
        row
        for row in handlers
        if row["form"] == "allowed-vendored-letta-code-tool:0.19.5"
    ]
    lines = [
        "# LettaBot source-bearing handler inventory",
        "",
        f"生成命令（仓库根目录）：`{command}`",
        "",
        f"固定 revision `{spec.analysis_revision}`；公开 Handler inventory 检测到 **{len(handlers)}** 个 source-bearing handler：1 个 LettaBot local handler 和 **{len(vendored)}** 个 pinned Letta Code handler。",
        "",
        "| Tool | Registration model | Handler | Location |",
        "|---|---|---|---|",
    ]
    for row in handlers:
        lines.append(
            f"| `{row['tool_name']}` | `{row['form']}` | `{row['handler_func']}` | `{row['file']}:{row['line']}` |"
        )
    lines.extend(
        [
            "",
            "## Default tool boundary audit（不计入 Handler）",
            "",
            f"`baseSessionOptions` 的 `allowedTools` 转发仍暴露 **{len(boundaries)}** 个默认 boundary；其中 7 个由 pinned CLI source 解析为上面的 handler，2 个 server-side tool 没有可分析 body/source。",
            "",
            "| Tool boundary | Form | Anchor | Location |",
            "|---|---|---|---|",
        ]
    )
    for row in boundaries:
        lines.append(
            f"| `{row['tool_name']}` | `{row['form']}` | `{row['handler_func']}` | `{row['file']}:{row['line']}` |"
        )
    (out / "handler-inventory.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if len(local) != 1 or local[0]["tool_name"] != "manage_todo":
        raise ValueError(f"LettaBot local-handler acceptance failed: {local}")
    vendored_names = {row["tool_name"] for row in vendored}
    if vendored_names != VENDORED_TOOLS or len(vendored) != len(VENDORED_TOOLS):
        raise ValueError(
            "LettaBot vendored-handler acceptance failed: "
            f"expected={sorted(VENDORED_TOOLS)}, got={sorted(vendored_names)}"
        )
    boundary_names = {row["tool_name"] for row in boundaries}
    if boundary_names != DEFAULT_BOUNDARIES or len(boundaries) != len(DEFAULT_BOUNDARIES):
        raise ValueError(
            "LettaBot tool-boundary acceptance failed: "
            f"expected={sorted(DEFAULT_BOUNDARIES)}, got={sorted(boundary_names)}"
        )
    if any(
        row["handler_func"] != "baseSessionOptions"
        or row["file"] != "src/core/session-manager.ts"
        for row in boundaries
    ):
        raise ValueError(
            f"LettaBot SDK boundaries have an invalid anchor: {boundaries}"
        )
    print(
        json.dumps(
            {
                "entries": len(handlers),
                "local_handlers": len(local),
                "vendored_handlers": len(vendored),
                "default_boundaries": len(boundaries),
                "server_only_boundaries": len(DEFAULT_BOUNDARIES - VENDORED_TOOLS),
                "groundtruth": "not-applicable",
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

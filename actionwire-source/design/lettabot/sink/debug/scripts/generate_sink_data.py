#!/usr/bin/env python3
"""Generate LettaBot's semantic Code-tool and local todo-store sinks."""

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


DEFAULT_OUT = ROOT / "design/lettabot/sink/debug"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    spec = get_project("lettabot")
    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    command_parts = [
        "python",
        "design/lettabot/sink/debug/scripts/generate_sink_data.py",
    ]
    if out != DEFAULT_OUT:
        rendered_out = out.relative_to(ROOT) if out.is_relative_to(ROOT) else out
        command_parts.extend(["--out-dir", str(rendered_out)])
    command = shlex.join(command_parts)
    sinks = run_query(
        spec.codeql_database,
        "get_sinks.ql",
        out / "sink-calls.csv",
        query_pack=spec.query_pack,
        expected_language=spec.codeql_language,
    )
    expected = {
        (
            "vendor-source/letta-code-v0.19.5/src/tools/impl/Bash.ts",
            "185",
            "Bash",
        ),
        (
            "vendor-source/letta-code-v0.19.5/src/tools/impl/Bash.ts",
            "252",
            "Bash",
        ),
        (
            "vendor-source/letta-code-v0.19.5/src/tools/impl/Read.ts",
            "239",
            "Read",
        ),
        (
            "vendor-source/letta-code-v0.19.5/src/tools/impl/Read.ts",
            "251",
            "Read",
        ),
        (
            "vendor-source/letta-code-v0.19.5/src/tools/impl/Edit.ts",
            "210",
            "Edit",
        ),
        (
            "vendor-source/letta-code-v0.19.5/src/tools/impl/Write.ts",
            "31",
            "Write",
        ),
        (
            "vendor-source/letta-code-v0.19.5/src/tools/impl/Glob.ts",
            "93",
            "Glob",
        ),
        (
            "vendor-source/letta-code-v0.19.5/src/tools/impl/Grep.ts",
            "102",
            "Grep",
        ),
        (
            "vendor-source/letta-code-v0.19.5/src/tools/impl/Task.ts",
            "484",
            "Task",
        ),
        (
            "vendor-source/letta-code-v0.19.5/src/tools/impl/Task.ts",
            "518",
            "Task",
        ),
        ("src/todo/store.ts", "142", "readFileSync:todo-store"),
        ("src/todo/store.ts", "154", "writeFileSync:todo-store"),
    }
    adapter_sinks = {
        (row["file"], row["line"], row["sink"]) for row in sinks
    } & expected
    lines = [
        "# LettaBot sink inventory",
        "",
        f"生成命令（仓库根目录）：`{command}`",
        "",
        f"固定 revision `{spec.analysis_revision}`；共享 sink audit 检测到 **{len(sinks)}** 个 production callsite，其中 LettaBot adapter witness 为 **{len(adapter_sinks)}/{len(expected)}**（7 个语义能力、10 个执行分支及 2 个 todo-store primitive）。",
        "",
        "| Sink | Location |",
        "|---|---|",
    ]
    for row in sinks:
        lines.append(f"| `{row['sink']}` | `{row['file']}:{row['line']}` |")
    (out / "sink-inventory.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if adapter_sinks != expected:
        raise ValueError("LettaBot sink acceptance failed")
    print(
        json.dumps(
            {
                "shared_sink_calls": len(sinks),
                "adapter_sinks": len(adapter_sinks),
                "semantic_effect_branches": 10,
                "semantic_capabilities": 7,
                "groundtruth": "not-applicable",
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

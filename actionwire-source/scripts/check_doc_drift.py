#!/usr/bin/env python3
"""文档↔代码漂移检查 —— Stop / PostToolUse / SessionStart 三 hook 共用。

单一事实源：仓库根 docs-map.yaml（见其头部注释）。混合强制力度：
  --stop    Stop hook。仅对 kind:spec 的边硬门禁——某工具代码改了、其 spec 文档没一起改，
            就输出 {"decision":"block","reason":...} 让 Claude 回去补文档。生成物/外部锚点不硬拦。
  --file    PostToolUse hook。从 stdin JSON 取 tool_input.file_path，若命中 spec 的 code 或
            generated 的 inputs，回 hookSpecificOutput.additionalContext 做**陈述句**提醒（不阻断）。
  --report  SessionStart hook。把当前工作区的未配对漂移以陈述句打到 stdout（注入上下文）。

设计约束：
  * hook 输入是 stdin 上的 JSON（不是环境变量）。
  * 任何异常都静默降级为「无输出、退出 0」，绝不因本脚本打断会话。
  * 注入文本用陈述句而非命令句，避免触发注入防御。
"""
from __future__ import annotations

import fnmatch
import json
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except Exception:  # pyyaml 缺失 → 静默降级
    yaml = None


# ── 基础设施：仓库根、docs-map 加载、git 改动集合 ───────────────────────────

def repo_root() -> Path | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, cwd=Path(__file__).resolve().parent,
        )
        if out.returncode == 0:
            return Path(out.stdout.strip())
    except Exception:
        pass
    return None


def load_map(root: Path) -> dict:
    if yaml is None:
        return {}
    f = root / "docs-map.yaml"
    if not f.exists():
        return {}
    try:
        return yaml.safe_load(f.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def _git_paths(root: Path, args: list[str]) -> list[str]:
    try:
        out = subprocess.run(
            ["git", *args], capture_output=True, text=True, cwd=root,
        )
        if out.returncode != 0:
            return []
        return [p for p in out.stdout.split("\0") if p]
    except Exception:
        return []


def changed_paths(root: Path) -> set[str]:
    """工作区相对 HEAD 的全部改动（tracked 改动 + untracked），仓库相对路径。

    用 -z + --no-renames 避免非 ASCII 路径被引号包裹、避免 rename 歧义。
    """
    tracked = _git_paths(root, ["diff", "HEAD", "--name-only", "--no-renames", "-z"])
    untracked = _git_paths(root, ["ls-files", "--others", "--exclude-standard", "-z"])
    return set(tracked) | set(untracked)


# ── 映射视图 ──────────────────────────────────────────────────────────────

def _match_any(path: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(path, pat) for pat in (patterns or []))


def iter_spec_edges(m: dict):
    for proj in (m.get("projects") or {}).values():
        for edge in (proj.get("spec") or []):
            doc = edge.get("doc")
            code = edge.get("code") or []
            if doc and code:
                yield doc, code


def iter_generated_edges(m: dict):
    for proj in (m.get("projects") or {}).values():
        for edge in (proj.get("generated") or []):
            doc = edge.get("doc")
            inputs = edge.get("inputs") or []
            gen = edge.get("generator") or ""
            if doc:
                yield doc, inputs, gen


def all_spec_docs(m: dict) -> set[str]:
    return {doc for doc, _ in iter_spec_edges(m)}


def all_generated_doc_globs(m: dict) -> list[str]:
    return [doc for doc, _, _ in iter_generated_edges(m)]


def is_generated_output(path: str, m: dict) -> bool:
    return _match_any(path, all_generated_doc_globs(m))


# ── 核心：spec 漂移（code 改了 doc 没改）───────────────────────────────────

def spec_drifts(root: Path, m: dict) -> list[tuple[str, list[str]]]:
    """返回 [(spec_doc, [触发的已改 code 文件]), ...]，仅当 code 改了而该 doc 未改。"""
    changed = changed_paths(root)
    spec_docs = all_spec_docs(m)
    drifts: list[tuple[str, list[str]]] = []
    for doc, code_globs in iter_spec_edges(m):
        hits = [
            c for c in sorted(changed)
            if _match_any(c, code_globs)
            and c not in spec_docs                 # 别把「文档侧」当成 code 改动
            and not is_generated_output(c, m)      # 生成物不驱动 spec
        ]
        if hits and doc not in changed:
            drifts.append((doc, hits))
    return drifts


# ── 三个 hook 模式 ────────────────────────────────────────────────────────

def mode_stop() -> int:
    raw = sys.stdin.read() if not sys.stdin.isatty() else ""
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        payload = {}
    # 防无限循环：已在 stop-hook 续跑里就不再阻断
    if payload.get("stop_hook_active"):
        return 0

    root = repo_root()
    if root is None:
        return 0
    m = load_map(root)
    drifts = spec_drifts(root, m)
    if not drifts:
        return 0

    lines = ["检测到工具代码改动未同步对应 spec 文档："]
    for doc, hits in drifts:
        lines.append(f"- 已改 {', '.join(hits)}，但其 spec {doc} 未一起更新。")
    lines.append("请在结束前同步对应 spec 小节（或在文档中说明为何无需更新），然后再结束。")
    print(json.dumps({"decision": "block", "reason": "\n".join(lines)}, ensure_ascii=False))
    return 0


def mode_file() -> int:
    raw = sys.stdin.read() if not sys.stdin.isatty() else ""
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        payload = {}
    fp = (payload.get("tool_input") or {}).get("file_path")
    if not fp:
        return 0
    root = repo_root()
    if root is None:
        return 0
    try:
        rel = str(Path(fp).resolve().relative_to(root))
    except Exception:
        return 0
    m = load_map(root)

    notes: list[str] = []
    # spec：编辑了某 spec 的 code
    for doc, code_globs in iter_spec_edges(m):
        if _match_any(rel, code_globs) and rel not in all_spec_docs(m) \
                and not is_generated_output(rel, m):
            notes.append(f"已编辑 {rel}，其 spec 为 {doc}；如行为有变化，该文档对应小节需同步。")
    # generated：编辑了某生成物的 input
    for doc, inputs, gen in iter_generated_edges(m):
        if _match_any(rel, inputs):
            tail = f"；如影响其内容，需重跑生成器：{gen}" if gen else "。"
            notes.append(f"已编辑 {rel}，它是生成物 {doc} 的输入{tail}")

    if not notes:
        return 0
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "[docs-sync] " + " ".join(notes),
        }
    }, ensure_ascii=False))
    return 0


def mode_report() -> int:
    root = repo_root()
    if root is None:
        return 0
    m = load_map(root)
    drifts = spec_drifts(root, m)
    if not drifts:
        return 0
    print("[docs-sync] 当前工作区存在未与 spec 文档配对的代码改动：")
    for doc, hits in drifts:
        print(f"- {', '.join(hits)} 已改动，但其 spec {doc} 尚未一起更新。")
    print("（映射见 docs-map.yaml；改动工具代码时对应 spec 应同步维护。）")
    return 0


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "--stop":
        return mode_stop()
    if mode == "--file":
        return mode_file()
    if mode == "--report":
        return mode_report()
    sys.stderr.write("usage: check_doc_drift.py [--stop|--file|--report]\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

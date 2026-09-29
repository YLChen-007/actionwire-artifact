"""Agent runner: drive the `claude` CLI (Claude Code) headless, backed by DeepSeek.

We do NOT call the DeepSeek HTTP API directly. Instead we shell out to the `claude`
CLI in print mode (`-p`), pointed at DeepSeek's Anthropic-compatible endpoint
(`https://api.deepseek.com/anthropic`). This gives the model real tools (Read/Grep/
Glob), so for project-internal sink APIs we just tell it the implementation location
and let it read the function — and follow what it calls down to the real primitive —
by itself, instead of us pre-embedding a source snippet.
"""
from __future__ import annotations

import os
import subprocess

CLAUDE_BIN = os.environ.get("SINKCAP_CLAUDE_BIN", "claude")
DEEPSEEK_ANTHROPIC_BASE = os.environ.get(
    "DEEPSEEK_ANTHROPIC_BASE_URL", "https://api.deepseek.com/anthropic"
)
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
DEFAULT_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-flash")

READONLY_TOOLS = ("Read", "Grep", "Glob")


class AgentError(RuntimeError):
    pass


def run_agent(
    system: str,
    user: str,
    *,
    model: str = DEFAULT_MODEL,
    add_dirs: list[str] | None = None,
    allowed_tools: tuple[str, ...] = READONLY_TOOLS,
    max_turns: int = 20,
    timeout: int = 900,
) -> str:
    """Run one headless claude session (DeepSeek backend) and return its final text."""
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)              # force token-auth path
    env["ANTHROPIC_BASE_URL"] = DEEPSEEK_ANTHROPIC_BASE
    env["ANTHROPIC_AUTH_TOKEN"] = DEEPSEEK_API_KEY
    env["ANTHROPIC_MODEL"] = model
    # Claude user settings may contain a different provider/model and take
    # precedence over process env. Keep this dedicated runner on its declared
    # backend, including helper requests such as title/summary generation.
    env["ANTHROPIC_DEFAULT_HAIKU_MODEL"] = model
    env["ANTHROPIC_DEFAULT_SONNET_MODEL"] = model
    env["ANTHROPIC_DEFAULT_OPUS_MODEL"] = model
    env["CLAUDE_CODE_ENTRYPOINT"] = "sink-capacity"  # avoid nested-session quirks

    prompt = user.strip()
    cmd = [
        CLAUDE_BIN, "-p", prompt,
        "--system-prompt", system.strip(),
        "--model", model,
        "--output-format", "text",
        "--permission-mode", "bypassPermissions",
        "--max-turns", str(max_turns),
        # Restrict the built-in inventory itself. This remains compatible when
        # Claude CLI removes or renames mutating tools (for example MultiEdit).
        "--tools", ",".join(allowed_tools),
        "--allowedTools", *allowed_tools,
        # Ignore ~/.claude/settings.json provider overrides. Project settings
        # (notably documentation-drift hooks) remain active.
        "--setting-sources", "project",
        "--no-session-persistence",
    ]
    for d in add_dirs or []:
        cmd += ["--add-dir", d]

    try:
        r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise AgentError(f"claude timed out after {timeout}s") from e
    if r.returncode != 0:
        raise AgentError(f"claude exit {r.returncode}: {(r.stderr or r.stdout)[-1500:]}")
    out = (r.stdout or "").strip()
    if not out:
        raise AgentError("claude returned empty output")
    return out

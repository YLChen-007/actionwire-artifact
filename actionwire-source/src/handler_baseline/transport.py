"""Claude Code transport inside a fail-closed read-only Bubblewrap sandbox."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .contracts import (
    ALL_FINDINGS_POLICY,
    BaselineError,
    TRANSPORT_VERSION,
    normalize_token_usage,
    redact_credentials,
    response_json_schema,
)


DEFAULT_MODEL = "deepseek-v4-flash"
DEFAULT_BASE_URL = "https://api.deepseek.com/anthropic"
READ_ONLY_TOOLS = ("Read", "Grep", "Glob")


class TrialTimeout(TimeoutError):
    """Raised after the complete handler budget is exhausted."""


@dataclass(frozen=True)
class TransportCall:
    phase: str
    system_prompt: str
    user_prompt: str
    elapsed_seconds: float
    returncode: int | None
    usage: Mapping[str, int | bool]
    provider_reported: bool
    raw_envelope: str
    error: str | None

    def record(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "system_prompt": self.system_prompt,
            "user_prompt": self.user_prompt,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "returncode": self.returncode,
            "usage": dict(self.usage),
            "provider_reported": self.provider_reported,
            "raw_envelope": self.raw_envelope,
            "error": self.error,
        }


def claude_version(claude_bin: str = "claude") -> str:
    executable = shutil.which(claude_bin)
    if not executable:
        raise BaselineError(f"Claude Code executable not found: {claude_bin}")
    completed = subprocess.run(
        [executable, "--version"], capture_output=True, text=True, timeout=15, check=False
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise BaselineError("unable to determine Claude Code version")
    return " ".join(completed.stdout.split())


def assert_sandbox_available(bwrap_bin: str = "bwrap") -> str:
    executable = shutil.which(bwrap_bin)
    if not executable:
        raise BaselineError("Bubblewrap is required; refusing to run the blind phase unsandboxed")
    completed = subprocess.run(
        [
            executable,
            "--die-with-parent",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/bin", "/bin",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64",
            "--ro-bind", "/etc", "/etc",
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
            "--", "/usr/bin/true",
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    if completed.returncode != 0:
        raise BaselineError(
            "Bubblewrap self-test failed; refusing unsandboxed execution: "
            + (completed.stderr or completed.stdout)[-1000:]
        )
    return executable


def _usage_from_envelope(raw: str) -> dict[str, int | bool]:
    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError:
        return normalize_token_usage(None)
    if not isinstance(envelope, dict):
        return normalize_token_usage(None)
    return normalize_token_usage(
        envelope.get("usage") or envelope.get("modelUsage") or envelope.get("model_usage")
    )


class SandboxedClaudeCode:
    """Run one or more calls for one handler under one total wall-clock deadline."""

    def __init__(
        self,
        *,
        source_root: Path,
        timeout: int,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        credential_env: str = "DEEPSEEK_API_KEY",
        claude_bin: str = "claude",
        bwrap_bin: str = "bwrap",
        report_policy: str = ALL_FINDINGS_POLICY,
    ) -> None:
        if timeout < 1:
            raise BaselineError("timeout must be positive")
        self.source_root = source_root.resolve()
        if not self.source_root.is_dir():
            raise BaselineError(f"source root is not a directory: {self.source_root}")
        self.timeout = timeout
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.credential_env = credential_env
        self.claude_bin = shutil.which(claude_bin) or claude_bin
        self.bwrap_bin = assert_sandbox_available(bwrap_bin)
        self.report_policy = report_policy
        self.version = claude_version(claude_bin)
        self.started = time.monotonic()
        self.calls: list[TransportCall] = []

    def remaining(self) -> float:
        return max(0.0, self.timeout - (time.monotonic() - self.started))

    def _environment(self) -> dict[str, str]:
        credential = os.environ.get(self.credential_env, "").strip()
        if not credential:
            raise BaselineError(f"missing LLM credential: set {self.credential_env}")
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/tmp/home",
            "XDG_CONFIG_HOME": "/tmp/home/.config",
            "XDG_CACHE_HOME": "/tmp/home/.cache",
            "TMPDIR": "/tmp",
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "ANTHROPIC_BASE_URL": self.base_url,
            "ANTHROPIC_AUTH_TOKEN": credential,
            "ANTHROPIC_MODEL": self.model,
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": self.model,
            "ANTHROPIC_DEFAULT_SONNET_MODEL": self.model,
            "ANTHROPIC_DEFAULT_OPUS_MODEL": self.model,
            "CLAUDE_CODE_ENTRYPOINT": "clawgap-handler-baseline",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        }
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY"):
            if os.environ.get(name):
                environment[name] = os.environ[name]
        return environment

    def _command(self, system: str, user: str) -> list[str]:
        schema = json.dumps(
            response_json_schema(getattr(self, "report_policy", ALL_FINDINGS_POLICY)),
            separators=(",", ":"),
        )
        sandbox_claude = self.claude_bin
        extra_mounts: list[str] = []
        try:
            Path(self.claude_bin).resolve().relative_to("/usr")
        except ValueError:
            try:
                Path(self.claude_bin).resolve().relative_to("/bin")
            except ValueError:
                sandbox_claude = "/tmp/claude-bin"
                extra_mounts = ["--ro-bind", str(Path(self.claude_bin).resolve()), sandbox_claude]
        return [
            self.bwrap_bin,
            "--die-with-parent",
            "--new-session",
            "--unshare-pid",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/bin", "/bin",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64",
            "--ro-bind", "/etc", "/etc",
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
            "--dir", "/tmp/home",
            *extra_mounts,
            "--dir", "/workspace",
            "--ro-bind", str(self.source_root), "/workspace",
            "--chdir", "/workspace",
            "--setenv", "HOME", "/tmp/home",
            "--setenv", "XDG_CONFIG_HOME", "/tmp/home/.config",
            "--setenv", "XDG_CACHE_HOME", "/tmp/home/.cache",
            "--",
            sandbox_claude,
            "-p", user.strip(),
            "--system-prompt", system.strip(),
            "--model", self.model,
            "--output-format", "json",
            "--json-schema", schema,
            "--permission-mode", "dontAsk",
            "--tools", ",".join(READ_ONLY_TOOLS),
            "--allowedTools", *READ_ONLY_TOOLS,
            "--safe-mode",
            "--no-session-persistence",
            "--prompt-suggestions", "false",
        ]

    def call(self, *, phase: str, system: str, user: str) -> tuple[str, dict[str, Any]]:
        remaining = self.remaining()
        if remaining <= 0:
            raise TrialTimeout(f"handler deadline exhausted after {self.timeout}s")
        started = time.monotonic()
        process = subprocess.Popen(
            self._command(system, user),
            cwd="/",
            env=self._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        raw = ""
        stderr = ""
        try:
            raw, stderr = process.communicate(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                raw, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                raw, stderr = process.communicate()
            elapsed = time.monotonic() - started
            usage = _usage_from_envelope(raw)
            error = f"Claude Code timed out after {self.timeout}s total handler budget"
            self.calls.append(
                TransportCall(
                    phase, system, user, elapsed, None, usage,
                    bool(usage["provider_reported"]), redact_credentials(raw), error,
                )
            )
            raise TrialTimeout(error) from exc
        elapsed = time.monotonic() - started
        usage = _usage_from_envelope(raw)
        if process.returncode != 0:
            error = f"Claude Code exit {process.returncode}: {(stderr or raw)[-1500:]}"
            self.calls.append(
                TransportCall(
                    phase, system, user, elapsed, process.returncode, usage,
                    bool(usage["provider_reported"]), redact_credentials(raw),
                    redact_credentials(error),
                )
            )
            raise BaselineError(error)
        self.calls.append(
            TransportCall(
                phase, system, user, elapsed, process.returncode, usage,
                bool(usage["provider_reported"]), redact_credentials(raw), None,
            )
        )
        return raw, {"stderr_tail": redact_credentials(stderr)[-1500:]}

    def audit_payload(self) -> dict[str, Any]:
        payload = {
            "transport": TRANSPORT_VERSION,
            "model": self.model,
            "base_url": self.base_url,
            "credential_env": self.credential_env,
            "claude_version": self.version,
            "available_tools": list(READ_ONLY_TOOLS),
            "sandbox": "bubblewrap-read-only-workspace/v1",
            "timeout_seconds": self.timeout,
            "calls": [row.record() for row in self.calls],
        }
        if self.report_policy != ALL_FINDINGS_POLICY:
            payload["report_policy"] = self.report_policy
        return payload

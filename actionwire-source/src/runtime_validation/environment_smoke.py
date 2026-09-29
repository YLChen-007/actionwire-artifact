"""Disposable all-project launch-environment smoke validation."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.projects import get_project

from .contracts import (
    ValidationError,
    atomic_write_json,
    atomic_write_text,
    contains_credentials,
    redact_text,
    sha256_file,
)


SCHEMA_VERSION = "clawgap-runtime-environment-smoke/v1"
REPO_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_PROJECTS = (
    "AstrBot",
    "QwenPaw",
    "chatgpt-on-wechat",
    "droidclaw",
    "lettabot",
    "mercury-agent",
    "nanobot",
    "nanoclaw",
    "openclaw",
    "openclaw-cn",
    "hermes-agent",
)
EXPECTED_STATUS_COUNTS = {"launch-confirmed": 11}
_INITIAL_PASSWORD = re.compile(
    r"(?i)(initial(?: username| password)?(?: password)?[ \t]*:[ \t]*)\S+"
)


@dataclass(frozen=True)
class EnvironmentProjectSpec:
    project: str
    runtime: str
    setup_command: str
    launch_command: str
    readiness_pattern: str
    expected_launch_status: str
    expected_reason: str
    binding_files: tuple[str, ...]
    readiness_is_blocker: bool = False
    launch_fixture: str = "source-native"
    fixture_files: tuple[str, ...] = ()


@dataclass(frozen=True)
class EnvironmentSmokeRequest:
    out_dir: Path
    projects: Sequence[str] = EXPECTED_PROJECTS
    setup_timeout: int = 1200
    launch_timeout: int = 60
    require_all_confirmed: bool = False

    def __post_init__(self) -> None:
        projects = tuple(self.projects)
        if not projects:
            raise ValidationError("environment smoke requires at least one project")
        if len(projects) != len(set(projects)):
            raise ValidationError("environment smoke projects must be unique")
        unknown = [project for project in projects if project not in EXPECTED_PROJECTS]
        if unknown:
            raise ValidationError(f"unknown environment-smoke projects: {unknown}")
        if self.setup_timeout < 1 or self.launch_timeout < 1:
            raise ValidationError("environment-smoke timeouts must be positive")


@dataclass(frozen=True)
class EnvironmentSmokeResult:
    project: str
    setup_status: str
    launch_status: str
    expected_launch_status: str
    readiness_observed: bool
    reasons: tuple[str, ...]
    launch_exit_code: int | None
    setup_log: str
    launch_log: str
    revision: str
    source_hashes: Mapping[str, str]
    source_drift: bool
    disposable_workspace_removed: bool
    credential_scan: str
    launch_fixture: str
    l2_ready: bool = False


PROJECT_SPECS: tuple[EnvironmentProjectSpec, ...] = (
    EnvironmentProjectSpec(
        project="AstrBot",
        runtime="python",
        setup_command=(
            "python -m venv .clawgap-venv && "
            ".clawgap-venv/bin/pip install --disable-pip-version-check -e . && "
            "mkdir -p .astrbot data/config data/plugins data/temp astrbot/dashboard/dist && "
            ": > astrbot/dashboard/dist/index.html"
        ),
        launch_command=".clawgap-venv/bin/astrbot run --port 18080",
        readiness_pattern="AstrBot started.",
        expected_launch_status="launch-confirmed",
        expected_reason="WebUI and core lifecycle reached ready state",
        binding_files=("pyproject.toml", "astrbot/cli/__main__.py"),
    ),
    EnvironmentProjectSpec(
        project="QwenPaw",
        runtime="python",
        setup_command=(
            "python -m venv .clawgap-venv && "
            ".clawgap-venv/bin/pip install --disable-pip-version-check -e . && "
            ".clawgap-venv/bin/pip install --disable-pip-version-check "
            "'agent-client-protocol==0.9.0'"
        ),
        launch_command=".clawgap-venv/bin/qwenpaw app --host 127.0.0.1 --port 18081",
        readiness_pattern="Application startup complete",
        expected_launch_status="launch-confirmed",
        expected_reason="HTTP application completed startup and graceful shutdown",
        binding_files=("pyproject.toml", "src/qwenpaw/cli/main.py"),
    ),
    EnvironmentProjectSpec(
        project="chatgpt-on-wechat",
        runtime="python",
        setup_command=(
            "python -m venv .clawgap-venv && "
            ".clawgap-venv/bin/pip install --disable-pip-version-check -e . && "
            ".clawgap-venv/bin/pip install --disable-pip-version-check -r requirements.txt && "
            "python -c 'import json; p=\"config.json\"; d=json.load(open(p)); "
            "d[\"channel_type\"]=\"terminal\"; d[\"web_console\"]=False; "
            "json.dump(d, open(p, \"w\"))'"
        ),
        launch_command="sleep 90 | script -qec '.clawgap-venv/bin/python app.py' /dev/null",
        readiness_pattern="Please input your question:",
        expected_launch_status="launch-confirmed",
        expected_reason="local terminal channel reached its interactive prompt",
        binding_files=("pyproject.toml", "app.py", "requirements.txt"),
    ),
    EnvironmentProjectSpec(
        project="droidclaw",
        runtime="bun",
        setup_command="bun install",
        launch_command=(
            "printf 'environment smoke\\n' | LLM_PROVIDER=ollama "
            "OLLAMA_BASE_URL=http://127.0.0.1:11434/v1 bun run src/kernel.ts"
        ),
        readiness_pattern="Scanning screen...",
        expected_launch_status="launch-confirmed",
        expected_reason="kernel accepted a goal and entered its agent loop",
        binding_files=("package.json", "src/kernel.ts", "src/config.ts"),
    ),
    EnvironmentProjectSpec(
        project="lettabot",
        runtime="npm",
        setup_command="npm run build",
        launch_command=(
            "cat > lettabot.yaml <<'EOF'\n"
            "server:\n  mode: docker\n"
            "  baseUrl: http://127.0.0.1:18084\n"
            "  api:\n    host: 127.0.0.1\n    port: 18085\n"
            "agent:\n  id: clawgap-fake-agent\n  name: ClawGapMockChannelProbe\n"
            "channels:\n  mock:\n    enabled: true\n"
            "features:\n  cron: false\n  heartbeat:\n    enabled: false\n"
            "polling:\n  enabled: false\nEOF\n"
            "node --import ./lettabot_mock_channel_register.mjs dist/main.js"
        ),
        readiness_pattern="Started channel: Mock (Testing)",
        expected_launch_status="launch-confirmed",
        expected_reason="real entrypoint started the in-memory mock test channel",
        binding_files=(
            "package.json",
            "src/main.ts",
            "src/config/types.ts",
            "src/channels/factory.ts",
            "src/test/mock-channel.ts",
        ),
        launch_fixture="mock-channel-bridge",
        fixture_files=(
            "src/runtime_validation/l2_instrumentation/node/lettabot_mock_channel_register.mjs",
            "src/runtime_validation/l2_instrumentation/node/lettabot_mock_channel_hooks.mjs",
        ),
    ),
    EnvironmentProjectSpec(
        project="mercury-agent",
        runtime="npm",
        setup_command="npm run build",
        launch_command=(
            "mkdir -p \"$HOME/.mercury\" && cat > \"$HOME/.mercury/mercury.yaml\" <<'EOF'\n"
            "identity:\n  name: Mercury\n  owner: ClawGapEnvironmentProbe\n  creator: ClawGap\n"
            "providers:\n  default: ollamaLocal\n  ollamaLocal:\n"
            "    apiKey: \"\"\n    baseUrl: http://127.0.0.1:11434/api\n"
            "    model: clawgap-fake\n    enabled: true\nchannels:\n  telegram:\n"
            "    enabled: false\n    botToken: \"\"\n    admins: []\n    members: []\n"
            "    pending: []\nweb:\n  enabled: false\n  port: 6174\nEOF\n"
            "sleep 90 | script -qec 'node dist/index.js' /dev/null"
        ),
        readiness_pattern="Core ready",
        expected_launch_status="launch-confirmed",
        expected_reason="core, provider surface, and interactive UI reached ready state",
        binding_files=("package.json", "src/index.ts", "src/utils/config.ts"),
    ),
    EnvironmentProjectSpec(
        project="nanobot",
        runtime="python",
        setup_command=(
            "python -m venv .clawgap-venv && "
            ".clawgap-venv/bin/pip install --disable-pip-version-check -e ."
        ),
        launch_command=(
            "mkdir -p \"$HOME/.nanobot\" && cat > \"$HOME/.nanobot/config.json\" <<'EOF'\n"
            "{\"agents\":{\"defaults\":{\"model\":\"custom/fake\",\"provider\":\"custom\",\"workspace\":\".\"}},"
            "\"providers\":{\"custom\":{\"apiKey\":\"clawgap-loopback-mock\",\"apiBase\":\"http://127.0.0.1:18082/v1\"}},"
            "\"gateway\":{\"host\":\"127.0.0.1\",\"port\":18083}}\nEOF\n"
            "sleep 90 | .clawgap-venv/bin/nanobot agent"
        ),
        readiness_pattern="Interactive mode",
        expected_launch_status="launch-confirmed",
        expected_reason="interactive agent initialized with disposable loopback configuration",
        binding_files=("pyproject.toml", "nanobot/cli/commands.py"),
    ),
    EnvironmentProjectSpec(
        project="nanoclaw",
        runtime="pnpm",
        setup_command=(
            "CI=true pnpm install --frozen-lockfile && "
            "pnpm rebuild better-sqlite3 && pnpm run build"
        ),
        launch_command="node --import tsx scripts/upgrade-state.ts set && node dist/index.js",
        readiness_pattern="NanoClaw running",
        expected_launch_status="launch-confirmed",
        expected_reason="database migrations, CLI sockets, and host sweep started",
        binding_files=("package.json", "src/index.ts", "src/db/connection.ts"),
    ),
    EnvironmentProjectSpec(
        project="openclaw",
        runtime="pnpm",
        setup_command="CI=true pnpm install --frozen-lockfile && pnpm run build",
        launch_command=(
            "mkdir -p .clawgap-state && cat > .clawgap-state/openclaw.json <<'EOF'\n"
            "{\"gateway\":{\"mode\":\"local\",\"auth\":{\"mode\":\"token\",\"token\":\"clawgap-loopback-mock\"}}}\nEOF\n"
            "OPENCLAW_STATE_DIR=\"$PWD/.clawgap-state\" "
            "OPENCLAW_CONFIG_PATH=\"$PWD/.clawgap-state/openclaw.json\" "
            "node dist/entry.js gateway run --port 18789"
        ),
        readiness_pattern="gateway] listening on ws://127.0.0.1:18789",
        expected_launch_status="launch-confirmed",
        expected_reason="loopback WebSocket gateway reached listening state",
        binding_files=("package.json", "src/cli/gateway-cli/register.ts", "src/gateway/server.ts"),
    ),
    EnvironmentProjectSpec(
        project="openclaw-cn",
        runtime="pnpm",
        setup_command="CI=true pnpm install --frozen-lockfile && pnpm run build",
        launch_command=(
            "mkdir -p .clawgap-state && cat > .clawgap-state/openclaw.json <<'EOF'\n"
            "{\"gateway\":{\"mode\":\"local\",\"auth\":{\"mode\":\"token\",\"token\":\"clawgap-loopback-mock\"}}}\nEOF\n"
            "OPENCLAW_STATE_DIR=\"$PWD/.clawgap-state\" "
            "OPENCLAW_CONFIG_PATH=\"$PWD/.clawgap-state/openclaw.json\" "
            "node dist/entry.js gateway run --port 18789"
        ),
        readiness_pattern="gateway] listening on ws://127.0.0.1:18789",
        expected_launch_status="launch-confirmed",
        expected_reason="loopback WebSocket gateway reached listening state",
        binding_files=("package.json", "src/cli/gateway-cli/register.ts", "src/gateway/server.ts"),
    ),
    EnvironmentProjectSpec(
        project="hermes-agent",
        runtime="python",
        setup_command=(
            "python -m venv .clawgap-venv && "
            ".clawgap-venv/bin/pip install --disable-pip-version-check -e ."
        ),
        launch_command="./hermes gateway run",
        readiness_pattern="Hermes Gateway Starting...",
        expected_launch_status="launch-confirmed",
        expected_reason="real Hermes gateway entrypoint reached startup state",
        binding_files=("pyproject.toml", "hermes", "hermes_cli/main.py"),
    ),
)


def project_specs() -> tuple[EnvironmentProjectSpec, ...]:
    return PROJECT_SPECS


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    content = "".join(json.dumps(dict(row), sort_keys=True, ensure_ascii=False) + "\n" for row in rows)
    atomic_write_text(path, content)


def _redact_environment_text(value: str, secrets: Sequence[str]) -> str:
    return _INITIAL_PASSWORD.sub(r"\1[REDACTED_CREDENTIAL]", redact_text(value, secrets))


def _setup_environment(network: bool) -> dict[str, str]:
    environment: dict[str, str] = {}
    if network:
        proxy_names = (
            "http_proxy",
            "https_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "no_proxy",
        )
        for name in ("PATH", *proxy_names):
            if name in os.environ:
                environment[name] = os.environ[name]
    else:
        environment["PATH"] = os.environ.get(
            "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        )
    environment.update(
        {
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "PYTHONUNBUFFERED": "1",
            "NO_COLOR": "1",
            "HOME": "/tmp",
        }
    )
    return environment


def _runtime_secrets() -> tuple[str, ...]:
    keys = (
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "DEEPSEEK_API_KEY",
        "GROQ_API_KEY",
        "OPENROUTER_API_KEY",
        "MERCURY_API_KEY",
    )
    return tuple(value for key in keys if (value := os.environ.get(key)))


def _overlay_setup_script() -> str:
    return """#!/bin/bash
set -euo pipefail
root="$CLAWGAP_PROJECT_ROOT"
state="$CLAWGAP_STATE_ROOT"
mkdir -p "$state/lower" "$state/upper" "$state/work" "$state/merged" "$state/home"
mount --bind "$root" "$state/lower"
mount -t overlay overlay \
  -o "lowerdir=$state/lower,upperdir=$state/upper,workdir=$state/work" \
  "$state/merged"
mount --bind "$state/merged" "$root"
cd "$root"
export HOME="$state/home"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_DATA_HOME="$HOME/.local/share"
bash -lc "$CLAWGAP_SETUP_COMMAND" >> "$CLAWGAP_SETUP_LOG" 2>&1
"""


def _overlay_launch_script() -> str:
    return """#!/bin/bash
set -euo pipefail
root="$CLAWGAP_PROJECT_ROOT"
state="$CLAWGAP_STATE_ROOT"
mkdir -p "$state/lower" "$state/reuse" "$state/launch-upper" "$state/launch-work" \
  "$state/merged" "$state/launch-home" "$state/proc"
mount --bind "$root" "$state/lower"
mount --bind "$state/upper" "$state/reuse"
mount -t overlay overlay \
  -o "lowerdir=$state/reuse:$state/lower,upperdir=$state/launch-upper,workdir=$state/launch-work" \
  "$state/merged"
mount --bind "$state/merged" "$root"
mount -t proc proc "$state/proc"
ip link set lo up
cd "$root"
export HOME="$state/launch-home"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_DATA_HOME="$HOME/.local/share"
export NO_COLOR=1

setsid bash -lc "$CLAWGAP_LAUNCH_COMMAND" >> "$CLAWGAP_LAUNCH_LOG" 2>&1 &
pid=$!
cleanup() {
  kill -TERM -- -$pid 2>/dev/null || true
  for _ in $(seq 1 20); do
    kill -0 -- -$pid 2>/dev/null || break
    sleep 0.1
  done
  kill -KILL -- -$pid 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
for _ in $(seq 1 "$CLAWGAP_LAUNCH_TIMEOUT"); do
  kill -0 "$pid" 2>/dev/null || break
  stat="$(ps -o stat= -p "$pid" 2>/dev/null || true)"
  [[ "$stat" != Z* ]] || break
  sleep 1
done
cleanup
trap - EXIT INT TERM
set +e
wait "$pid"
code=$?
set -e
printf '%s\\n' "$code" > "$CLAWGAP_LAUNCH_EXIT_FILE"
exit 0
"""


def _source_hashes(project: str, files: Sequence[str]) -> dict[str, str]:
    root = get_project(project).source_root
    result: dict[str, str] = {}
    for relative in files:
        path = root / relative
        if not path.is_file():
            raise ValidationError(f"{project}: environment-smoke binding missing: {relative}")
        result[relative] = sha256_file(path)
    return result


def _run_process(
    command: Sequence[str],
    environment: Mapping[str, str],
    timeout: int,
) -> tuple[int | None, str]:
    try:
        completed = subprocess.run(
            [str(part) for part in command],
            env=dict(environment),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stdout
    except subprocess.TimeoutExpired as exc:
        value = exc.stdout or ""
        if not isinstance(value, str):
            value = value.decode("utf-8", errors="replace")
        return None, value


def _run_project(
    spec: EnvironmentProjectSpec,
    request: EnvironmentSmokeRequest,
    setup_log_path: Path,
    launch_log_path: Path,
) -> EnvironmentSmokeResult:
    registered = get_project(spec.project)
    root = registered.source_root
    secrets = _runtime_secrets()
    before = _source_hashes(spec.project, spec.binding_files)
    setup_exit: int | None = None
    launch_exit: int | None = None
    workspace_removed = False
    reasons: list[str] = []

    required_commands = ("unshare", "mount", "ip", "bash", "script", "ps", "seq")
    missing_commands = [name for name in required_commands if shutil.which(name) is None]
    if missing_commands:
        reasons.append(f"required namespace tools unavailable: {', '.join(missing_commands)}")

    if not missing_commands:
        with tempfile.TemporaryDirectory(prefix=f"clawgap-env-{spec.project}-") as temporary:
            state = Path(temporary) / "state"
            state.mkdir()
            raw_setup_log = Path(temporary) / "setup.log"
            raw_launch_log = Path(temporary) / "launch.log"
            exit_file = Path(temporary) / "launch-exit"
            scripts: dict[str, Path] = {}
            for name, value in (
                ("setup.sh", _overlay_setup_script()),
                ("launch.sh", _overlay_launch_script()),
            ):
                path = Path(temporary) / name
                path.write_text(value, encoding="utf-8")
                path.chmod(0o700)
                scripts[name] = path

            setup_environment = _setup_environment(network=True) | {
                "CLAWGAP_PROJECT_ROOT": str(root),
                "CLAWGAP_STATE_ROOT": str(state),
                "CLAWGAP_SETUP_LOG": str(raw_setup_log),
                "CLAWGAP_SETUP_COMMAND": spec.setup_command,
            }
            setup_exit, setup_output = _run_process(
                ("unshare", "--mount", "--propagation", "private", str(scripts["setup.sh"])),
                setup_environment,
                request.setup_timeout,
            )
            setup_log = raw_setup_log.read_text(errors="replace") if raw_setup_log.exists() else ""
            setup_log += setup_output
            atomic_write_text(
                setup_log_path,
                _redact_environment_text(setup_log, secrets),
            )

            if setup_exit != 0:
                reasons.append(
                    f"dependency/build phase failed with exit code {setup_exit}"
                    if setup_exit is not None
                    else "dependency/build phase timed out"
                )
            else:
                for relative in spec.fixture_files:
                    fixture_source = REPO_ROOT / relative
                    if not fixture_source.is_file():
                        raise ValidationError(
                            f"{spec.project}: environment-smoke fixture missing: {relative}"
                        )
                    shutil.copy2(fixture_source, state / "upper" / fixture_source.name)
                launch_environment = _setup_environment(network=False) | {
                    "CLAWGAP_PROJECT_ROOT": str(root),
                    "CLAWGAP_STATE_ROOT": str(state),
                    "CLAWGAP_LAUNCH_LOG": str(raw_launch_log),
                    "CLAWGAP_LAUNCH_EXIT_FILE": str(exit_file),
                    "CLAWGAP_LAUNCH_COMMAND": spec.launch_command,
                    "CLAWGAP_LAUNCH_TIMEOUT": str(request.launch_timeout),
                }
                launch_exit, launch_output = _run_process(
                    (
                        "unshare",
                        "--mount",
                        "--net",
                        "--pid",
                        "--fork",
                        "--propagation",
                        "private",
                        str(scripts["launch.sh"]),
                    ),
                    launch_environment,
                    request.launch_timeout + 20,
                )
                launch_log = (
                    raw_launch_log.read_text(errors="replace") if raw_launch_log.exists() else ""
                )
                launch_log += launch_output
                if exit_file.exists():
                    try:
                        launch_exit = int(exit_file.read_text(encoding="utf-8").strip())
                    except ValueError:
                        launch_exit = None
                if launch_exit is None:
                    reasons.append("launch supervisor timed out or did not record an exit code")
                atomic_write_text(
                    launch_log_path,
                    _redact_environment_text(launch_log, secrets),
                )
            workspace_removed = True

    setup_status = "setup-confirmed" if setup_exit == 0 else "setup-blocked"
    launch_text = launch_log_path.read_text(errors="replace") if launch_log_path.exists() else ""
    readiness_observed = spec.readiness_pattern in launch_text
    launch_status = (
        "launch-confirmed"
        if setup_exit == 0 and readiness_observed and not spec.readiness_is_blocker
        else "launch-blocked"
    )
    if setup_exit == 0 and not readiness_observed:
        reasons.append(f"readiness marker not observed: {spec.readiness_pattern}")
    if launch_status != spec.expected_launch_status:
        reasons.append(
            f"observed status {launch_status} does not match expected {spec.expected_launch_status}"
        )

    after = _source_hashes(spec.project, spec.binding_files)
    source_drift = before != after
    if source_drift:
        reasons.append("source binding hash drift after launch")
    if not workspace_removed:
        reasons.append("disposable workspace retained after cleanup")

    setup_text = setup_log_path.read_text(errors="replace")
    credential_scan = (
        "failed"
        if any(contains_credentials(value, secrets) for value in (setup_text, launch_text) if value)
        else "passed"
    )
    if credential_scan == "failed":
        reasons.append("credential-shaped value remained in persisted logs")

    return EnvironmentSmokeResult(
        project=spec.project,
        setup_status=setup_status,
        launch_status=launch_status,
        expected_launch_status=spec.expected_launch_status,
        readiness_observed=readiness_observed,
        reasons=(spec.expected_reason, *reasons),
        launch_exit_code=launch_exit,
        setup_log=str(setup_log_path),
        launch_log=str(launch_log_path),
        revision=registered.analysis_revision,
        source_hashes=before,
        source_drift=source_drift,
        disposable_workspace_removed=workspace_removed,
        credential_scan=credential_scan,
        launch_fixture=spec.launch_fixture,
    )


def _result_record(result: EnvironmentSmokeResult) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "project": result.project,
        "setup_status": result.setup_status,
        "launch_status": result.launch_status,
        "expected_launch_status": result.expected_launch_status,
        "readiness_observed": result.readiness_observed,
        "reasons": list(result.reasons),
        "launch_exit_code": result.launch_exit_code,
        "setup_log": result.setup_log,
        "launch_log": result.launch_log,
        "revision": result.revision,
        "source_hashes": dict(result.source_hashes),
        "source_drift": result.source_drift,
        "disposable_workspace_removed": result.disposable_workspace_removed,
        "credential_scan": result.credential_scan,
        "launch_fixture": result.launch_fixture,
        "native_channel": result.launch_fixture == "source-native",
        "instrumented_channel_bridge": result.launch_fixture == "mock-channel-bridge",
        "loopback_only_network": True,
        "overlay_isolated_source": True,
        "l2_ready": result.l2_ready,
    }


def _command(request: EnvironmentSmokeRequest) -> str:
    project_options = ""
    if set(request.projects) != set(EXPECTED_PROJECTS):
        project_options = "".join(f" --project {project}" for project in request.projects)
    return (
        "python -m src.runtime_validation run-environment-smoke "
        f"--out-dir {request.out_dir} "
        f"--setup-timeout {request.setup_timeout} "
        f"--launch-timeout {request.launch_timeout}"
        f"{project_options}"
    )


def run_environment_smoke(request: EnvironmentSmokeRequest) -> dict[str, Any]:
    requested = set(request.projects)
    specs = [spec for spec in PROJECT_SPECS if spec.project in requested]
    if {spec.project for spec in specs} != requested:
        raise ValidationError("environment-smoke project/spec identity drift")

    out = request.out_dir.resolve()
    if out.exists():
        shutil.rmtree(out)
    setup_dir = out / "setup-logs"
    launch_dir = out / "launch-logs"
    setup_dir.mkdir(parents=True)
    launch_dir.mkdir(parents=True)

    results = [
        _run_project(
            spec,
            request,
            setup_dir / f"{spec.project}.setup.log",
            launch_dir / f"{spec.project}.launch.log",
        )
        for spec in specs
    ]
    records = [_result_record(result) for result in results]
    _write_jsonl(out / "launch-ledger.jsonl", records)

    counts: dict[str, int] = {}
    for record in records:
        counts[record["launch_status"]] = counts.get(record["launch_status"], 0) + 1
    fixture_counts: dict[str, int] = {}
    for record in records:
        fixture_counts[record["launch_fixture"]] = (
            fixture_counts.get(record["launch_fixture"], 0) + 1
        )
    complete = len(records) == len(request.projects)
    expected = complete and all(
        record["launch_status"] == record["expected_launch_status"]
        and record["setup_status"] == "setup-confirmed"
        and not record["source_drift"]
        and record["credential_scan"] == "passed"
        and record["disposable_workspace_removed"]
        for record in records
    )
    command = _command(request)
    harness_binding = {"environment_smoke": sha256_file(Path(__file__))}
    for spec in specs:
        for relative in spec.fixture_files:
            harness_binding[relative] = sha256_file(REPO_ROOT / relative)

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "campaign_id": "runtime-environment-smoke-v1",
        "project_count": len(records),
        "status_counts": counts,
        "complete_denominator": complete,
        "expected_outcome": expected,
        "all_launch_confirmed": counts == {"launch-confirmed": len(records)},
        "canonical_l2_publication_ready": False,
        "generation_command": command,
        "harness_binding": harness_binding,
        "launch_fixture_counts": fixture_counts,
        "source_bindings": {
            result.project: {
                "revision": result.revision,
                "files": dict(result.source_hashes),
            }
            for result in results
        },
        "disposable_workspaces_removed": all(
            result.disposable_workspace_removed for result in results
        ),
        "credential_scan": (
            "passed"
            if all(result.credential_scan == "passed" for result in results)
            else "failed"
        ),
    }
    if request.require_all_confirmed and not manifest["all_launch_confirmed"]:
        manifest["truth_gate"] = "all-launch-confirmed-required"
    atomic_write_json(out / "manifest.json", manifest)

    blocked = "\n".join(
        f"- **{record['project']}**: {', '.join(record['reasons'])}"
        for record in records
        if record["launch_status"] == "launch-blocked"
    )
    atomic_write_text(
        out / "summary.md",
        "# Runtime Launch-Environment Smoke\n\n"
        f"> Complete reproduction command: `{command}`\n\n"
        f"Projects accounted for: **{len(records)}/{len(request.projects)}**.\n\n"
        f"Launch confirmed: **{counts.get('launch-confirmed', 0)}**; "
        f"blocked: **{counts.get('launch-blocked', 0)}**.\n\n"
        "Launch fixtures: "
        f"**{fixture_counts.get('source-native', 0)} source-native**, "
        f"**{fixture_counts.get('mock-channel-bridge', 0)} mock-channel-bridge**.\n\n"
        "This campaign tests normal project startup only. It does not publish or imply "
        "canonical L2 dynamic-trigger validation.\n\n"
        "## Blocked Environments\n\n"
        f"{blocked if blocked else 'None.'}\n",
    )
    return manifest

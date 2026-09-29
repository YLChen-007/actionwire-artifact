"""Source-revised native BrowserTool L2 runtime for the CowAgent file report."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from src.projects import get_project

from .contracts import (
    ValidationError,
    atomic_write_json,
    atomic_write_text,
    redact_text,
    sha256_file,
)
from .chatgpt_on_wechat_l2 import (
    DEFAULT_SOURCE_CAMPAIGN,
    CowAgentFixtureServer,
    PairOutcome,
    _artifact_credential_scan,
    _cleanup_role,
    _expected_stages,
    _launch_role,
    _normalize_events,
    _prepare_build,
    _read_jsonl,
    _remove_path,
    _replace_once,
    _select_cases,
    _source_bindings as _canonical_source_bindings,
    _write_jsonl,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT = get_project("chatgpt-on-wechat")
SOURCE_ROOT = PROJECT.source_root
REPORT_ID = "GT-e03e7f2d88091689"
REPORT_NAME = "CVE-2026-32008-browser-file-scheme-navigation"
ADDITIVE_CANDIDATE_ID = "CAND-9f4a67b9b5e1917a"
SOURCE_REVISION = (
    "55aaf60a57ea6e9f4b8a54797572d98f65e88d2f"
    "+native-file-browser-source-v1"
)
CAMPAIGN_ID = "runtime-dynamic-trigger-chatgpt-on-wechat-native-file-l2-v1"
RESULT_SCHEMA_VERSION = (
    "clawgap-dynamic-trigger-chatgpt-on-wechat-native-file-l2-result/v1"
)
EVIDENCE_SCOPE = "source-revised-native-tool"
EVIDENCE_TIER = "L2-forced-provider-E2E-source-revised"
TOOL_NAME = "browser"
SINK_ANCHOR = "agent/tools/browser/browser_service.py:504"
EXPLOIT_URL = "file:///tmp/clawgap-browser-file-canary.txt"
CONTROL_URL = "https://clawgap-control.invalid/safe-navigation"
CANARY_CONTENT = "clawgap-chatgpt-additive-browser-canary\n"
PLAYWRIGHT_BROWSERS_PATH = Path("/root/.cache/ms-playwright")


@dataclass(frozen=True)
class ChatGPTOnWeChatFileNativeL2RunRequest:
    out_dir: Path
    attempts: int = 3
    timeout: int = 150
    build_timeout: int = 1800
    build_dir: Path | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _arguments(role: str) -> dict[str, Any]:
    return {
        "action": "navigate",
        "url": EXPLOIT_URL if role == "exploit" else CONTROL_URL,
        "timeout": 10000,
    }


def _case() -> dict[str, Any]:
    return {
        "schema_version": "clawgap-chatgpt-on-wechat-native-file-case/v1",
        "project": "chatgpt-on-wechat",
        "report_id": REPORT_ID,
        "revision": SOURCE_REVISION,
        "base_revision": PROJECT.analysis_revision,
        "case_id": "AL2-cowagent-native-file-browser-v1",
        "candidate_binding": {
            "candidate_id": ADDITIVE_CANDIDATE_ID,
            "selection_mode": EVIDENCE_SCOPE,
            "canonical_input": False,
        },
        "handler": {
            "argument_path": ["url"],
            "tool_name": TOOL_NAME,
        },
        "gates": [],
        "sink": {
            "family": "browser-navigation",
            "anchor": SINK_ANCHOR,
            "payload_role": "page.goto(url)",
        },
        "tool_or_action_name": TOOL_NAME,
        "forced_tool_calls": [
            {"role": "exploit", "arguments": _arguments("exploit")},
            {"role": "control", "arguments": _arguments("control")},
        ],
        "execution_eligible": True,
    }


def _source_bindings() -> dict[str, str]:
    canonical_cases = _select_cases(DEFAULT_SOURCE_CAMPAIGN)
    bindings = dict(_canonical_source_bindings(canonical_cases))
    extra_files = (
        "agent/tools/__init__.py",
        "agent/tools/browser/browser_service.py",
        "agent/tools/browser/browser_tool.py",
    )
    for relative in extra_files:
        source = SOURCE_ROOT / relative
        if not source.is_file():
            raise ValidationError(f"CowAgent native source is missing: {relative}")
        bindings[relative] = sha256_file(source)

    tools_init = (
        SOURCE_ROOT / "agent/tools/__init__.py"
    ).read_text(encoding="utf-8")
    browser_source = (
        SOURCE_ROOT / "agent/tools/browser/browser_tool.py"
    ).read_text(encoding="utf-8")
    if "ClawGapAdditiveBrowserTool" in tools_init:
        raise ValidationError(
            "CowAgent retired additive browser tool remains registered"
        )
    if 'CLAWGAP_SOURCE_REVISED_FILE_SCHEME' not in browser_source:
        raise ValidationError(
            "CowAgent BrowserTool source-revised file-scheme marker drifted"
        )
    return bindings


def _apply_additive_transform(project: Path) -> dict[str, str]:
    helper_path = project / "clawgap_l2_runtime.py"
    if not helper_path.is_file():
        raise ValidationError("canonical CowAgent instrumentation helper is missing")
    helper = helper_path.read_text(encoding="utf-8")
    if "def clawgap_browser_sink(" not in helper:
        helper += '''

def clawgap_browser_sink(page, url, timeout):
    detail = {
        "url": url,
        "timeout": timeout,
        "call": "page.goto(url, wait_until='domcontentloaded', timeout=timeout)",
    }
    _emit_sink(
        "agent/tools/browser/browser_service.py:504",
        detail,
    )

    class _ClawGapNavigationResponse:
        status = 200

    return _ClawGapNavigationResponse()
'''
        helper_path.write_text(helper, encoding="utf-8")

    service_path = project / "agent/tools/browser/browser_service.py"
    service = service_path.read_text(encoding="utf-8")
    service = (
        "from clawgap_l2_runtime import clawgap_browser_sink\n" + service
    )
    service = _replace_once(
        service,
        '            resp = page.goto(url, wait_until="domcontentloaded", timeout=timeout)\n',
        '            resp = clawgap_browser_sink(page, url, timeout)\n',
        "additive BrowserService goto sink",
    )
    service_path.write_text(service, encoding="utf-8")

    browser_path = project / "agent/tools/browser/browser_tool.py"
    browser = browser_path.read_text(encoding="utf-8")
    browser = (
        "from clawgap_l2_runtime import (\n"
        "    clawgap_controlled,\n"
        "    clawgap_handler,\n"
        "    clawgap_missing_check,\n"
        ")\n" + browser
    )
    browser = _replace_once(
        browser,
        "    def execute(self, args: Dict[str, Any]) -> ToolResult:\n        action = args.get(\"action\", \"\").strip().lower()\n",
        "    def execute(self, args: Dict[str, Any]) -> ToolResult:\n"
        "        clawgap_handler(\"browser\", args)\n"
        "        action = args.get(\"action\", \"\").strip().lower()\n",
        "native browser handler entry",
    )
    browser = _replace_once(
        browser,
        "        timeout = args.get(\"timeout\", 30000)\n        service = self._get_service()\n",
        "        clawgap_controlled([\"url\"], url)\n"
        "        clawgap_missing_check(\n"
        "            {\n"
        "                \"policy\": \"browser-navigation-scheme-allowlist\",\n"
        "                \"url\": url,\n"
        "                \"preserved_explicit_scheme\": \"://\" in url,\n"
        "            }\n"
        "        )\n"
        "        timeout = args.get(\"timeout\", 30000)\n"
        "        service = self._get_service()\n",
        "native browser controlled URL and missing-check boundary",
    )
    browser_path.write_text(browser, encoding="utf-8")

    transformed = (
        "clawgap_l2_runtime.py",
        "agent/tools/browser/browser_tool.py",
        "agent/tools/browser/browser_service.py",
    )
    return {relative: sha256_file(project / relative) for relative in transformed}


def _prepare_additive_build(
    directory: Path,
    source_bindings: Mapping[str, str],
    timeout: int,
) -> dict[str, Any]:
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    canonical_dir = directory / "canonical"
    manifest_path = directory / "transformed-source-manifest.json"
    harness_path = REPO_ROOT / "src/runtime_validation/chatgpt_on_wechat_file_native_l2.py"
    harness_sha256 = sha256_file(harness_path)
    canonical_keys = (
        "requirements.txt",
        "app.py",
        "config.py",
        "channel/terminal/terminal_channel.py",
        "channel/chat_channel.py",
        "bridge/agent_bridge.py",
        "bridge/agent_initializer.py",
        "agent/protocol/agent_stream.py",
        "agent/tools/tool_manager.py",
        "agent/tools/base_tool.py",
        "models/openai/openai_http_client.py",
        "models/openai_compatible_bot.py",
        "agent/tools/bash/bash.py",
        "agent/tools/read/read.py",
        "agent/tools/web_fetch/web_fetch.py",
        "agent/tools/vision/vision.py",
        "agent/tools/browser/browser_tool.py",
    )
    canonical_bindings = {key: source_bindings[key] for key in canonical_keys}
    venv_python = canonical_dir / ".clawgap-venv/bin/python"
    if manifest_path.is_file() and venv_python.is_file():
        try:
            prior = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prior = {}
        if (
            prior.get("schema_version")
            == "clawgap-chatgpt-on-wechat-native-file-transformed-source-manifest/v1"
            and prior.get("runtime_source_revision") == SOURCE_REVISION
            and prior.get("original") == dict(source_bindings)
            and prior.get("harness_sha256") == harness_sha256
            and prior.get("interpreter_sha256") == sha256_file(venv_python)
        ):
            return prior
        _remove_path(canonical_dir)
    elif canonical_dir.exists():
        _remove_path(canonical_dir)

    canonical_manifest = dict(
        _prepare_build(canonical_dir, canonical_bindings, timeout)
    )
    transformed = _apply_additive_transform(canonical_dir / "project")
    probe_env = {
        "PATH": f"{canonical_dir / '.clawgap-venv/bin'}:{os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
        "HOME": str(directory / "build-home"),
        "PLAYWRIGHT_BROWSERS_PATH": str(PLAYWRIGHT_BROWSERS_PATH),
        "NO_COLOR": "1",
    }
    directory.joinpath("build-home").mkdir(parents=True, exist_ok=True)
    probe = subprocess.run(
        [
            str(venv_python),
            "-c",
            (
                "import app; import agent.tools as tools; "
                "from agent.tools.browser.browser_tool import BrowserTool; "
                "assert BrowserTool().name == 'browser'; "
                "assert 'ClawGapAdditiveBrowserTool' not in tools.__all__"
            ),
        ],
        cwd=canonical_dir / "project",
        env=probe_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=60,
        check=False,
    )
    atomic_write_text(directory / "additive-build-probe.log", redact_text(probe.stdout))
    if probe.returncode != 0:
        raise ValidationError("instrumented CowAgent additive build probe failed")

    manifest = {
        "schema_version": (
            "clawgap-chatgpt-on-wechat-native-file-transformed-source-manifest/v1"
        ),
        "base_revision": PROJECT.analysis_revision,
        "runtime_source_revision": SOURCE_REVISION,
        "original": dict(source_bindings),
        "canonical_original": canonical_bindings,
        "canonical_transformed": canonical_manifest.get("transformed", {}),
        "transformed": transformed,
        "native_tool": "browser",
        "source_revised_profile": "CLAWGAP_SOURCE_REVISED_FILE_SCHEME=1",
        "dependency_requirements_sha256": sha256_file(
            SOURCE_ROOT / "requirements.txt"
        ),
        "harness_sha256": harness_sha256,
        "interpreter_sha256": sha256_file(venv_python),
        "playwright_browsers_root": str(PLAYWRIGHT_BROWSERS_PATH),
    }
    atomic_write_json(manifest_path, manifest)
    shutil.rmtree(directory / "build-home", ignore_errors=True)
    return manifest


def _prepare_role(
    directory: Path,
    base_url: str,
    case: Mapping[str, Any],
    role: str,
    build_project: Path,
) -> tuple[Path, Path, Path, Path, Path, Path]:
    from .chatgpt_on_wechat_l2 import _prepare_role as _prepare_canonical_role

    runtime, home, state, workspace, temporary, config_path = _prepare_canonical_role(
        directory, base_url, case, role, build_project
    )
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["tools"][TOOL_NAME] = {
        "headless": True,
        "launch_args": ["--disable-dev-shm-usage"],
        "idle_timeout": 10,
    }
    config_path.write_text(json.dumps(config, indent=2, sort_keys=True), encoding="utf-8")

    canary_path = temporary / "clawgap-browser-file-canary.txt"
    atomic_write_text(canary_path, CANARY_CONTENT)
    fixture_path = directory / "fixture-manifest.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    fixture["files"][str(config_path)] = sha256_file(config_path)
    fixture["files"][str(canary_path)] = sha256_file(canary_path)
    fixture["native_browser"] = {
        "tool_name": TOOL_NAME,
        "exploit_url": EXPLOIT_URL,
        "control_url": CONTROL_URL,
        "canary_path": str(canary_path),
        "canary_value_disclosed": False,
        "playwright_browsers_root": str(PLAYWRIGHT_BROWSERS_PATH),
    }
    atomic_write_json(fixture_path, fixture)
    return runtime, home, state, workspace, temporary, config_path


def _sink_matches(role: str, sink: Mapping[str, Any]) -> bool:
    url = str(sink.get("detail", {}).get("url", ""))
    return role == "exploit" and url.startswith("file:///")


def _transcript_errors_additive(
    fixture: CowAgentFixtureServer,
    provider_rows: list[Mapping[str, Any]],
) -> list[str]:
    errors: list[str] = []
    expected = ["forced-tool-call", "continuation"]
    if fixture.requests != expected:
        errors.append(
            "provider sequence drift: "
            f"expected {expected}, observed {fixture.requests}"
        )
    if fixture.unsupported:
        errors.append(f"unsupported provider endpoints: {fixture.unsupported}")
    if any(row.get("valid") is not True for row in provider_rows):
        errors.append("one or more real provider requests failed contract validation")
    forced = [
        row for row in provider_rows if row.get("request_kind") == "forced-tool-call"
    ]
    if len(forced) != 1:
        errors.append("exactly one forced provider tool-call turn was not observed")
        return errors
    request = forced[0]
    body = request.get("body") or {}
    tool_names = {
        str(row.get("function", {}).get("name"))
        for row in body.get("tools", [])
        if isinstance(row, dict)
    }
    if (
        request.get("path") != "/v1/chat/completions"
        or body.get("model") != "clawgap-cowagent-l2"
        or TOOL_NAME not in tool_names
        or body.get("stream") is not True
    ):
        errors.append("forced provider request did not match the additive contract")
    return errors


def _evaluate_role(
    case: Mapping[str, Any],
    role: str,
    events: list[Mapping[str, Any]],
    fixture: CowAgentFixtureServer,
    provider_rows: list[Mapping[str, Any]],
    process_exit: int,
    cleanup_errors: list[str],
) -> PairOutcome:
    errors = [*cleanup_errors, *_transcript_errors_additive(fixture, provider_rows)]
    if process_exit not in {0, -signal.SIGINT, 130}:
        errors.append(f"real CowAgent process exited with {process_exit}")
    if not events:
        return PairOutcome(False, False, [*errors, "empty additive event trace"])

    stages = [str(row.get("stage")) for row in events]
    if stages != _expected_stages(case):
        errors.append(f"additive event sequence mismatch: {stages}")
    identity_keys = (
        "candidate_id",
        "case_id",
        "attempt",
        "role",
        "correlation_id",
        "fixture_id",
    )
    identity = {key: events[0].get(key) for key in identity_keys}
    if any({key: row.get(key) for key in identity_keys} != identity for row in events):
        errors.append("additive event identity drift")

    handler = next(
        (row for row in events if row.get("stage") == "handler_entered"), None
    )
    if handler is None or handler.get("detail", {}).get("tool_name") != TOOL_NAME:
        errors.append("additive native CowAgent handler was not entered")
    controlled = next(
        (
            row
            for row in events
            if row.get("stage") == "controlled_argument_recorded"
        ),
        None,
    )
    expected_url = _arguments(role)["url"]
    if controlled is None or controlled.get("detail", {}).get("value") != expected_url:
        errors.append("additive model-controlled URL drifted before navigation")
    missing = next(
        (
            row
            for row in events
            if row.get("stage") == "missing_check_boundary_confirmed"
        ),
        None,
    )
    missing_observations = (
        missing.get("detail", {}).get("observations", [])
        if missing is not None
        else []
    )
    if not any(
        row.get("policy") == "browser-navigation-scheme-allowlist"
        for row in missing_observations
    ):
        errors.append("additive scheme-allowlist missing-check boundary was absent")

    sink = next((row for row in events if row.get("stage") == "sink_reached"), None)
    interception = next(
        (row for row in events if row.get("stage") == "pre_effect_interception"),
        None,
    )
    if sink is None or interception is None:
        errors.append("additive BrowserService sink boundary was incomplete")
    else:
        if sink.get("detail", {}).get("sink_anchor") != SINK_ANCHOR:
            errors.append("additive URL did not reach the cited page.goto anchor")
        if sink.get("detail", {}).get("url") != expected_url:
            errors.append("additive URL drifted into the page.goto boundary")
        if interception.get("detail", {}).get("executed") is not False:
            errors.append("additive page.goto was not intercepted pre-effect")

    triggered = sink is not None and _sink_matches(role, sink)
    if role == "control" and triggered:
        errors.append("safe additive control satisfied the file-scheme witness")
    if role == "exploit" and not triggered:
        errors.append("additive exploit did not preserve the file-scheme witness")
    return PairOutcome(not errors, triggered, errors)


def _run_role_attempt(
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    directory: Path,
    build_project: Path,
    python: Path,
    request: ChatGPTOnWeChatFileNativeL2RunRequest,
) -> tuple[PairOutcome, list[dict[str, Any]]]:
    directory = directory.resolve()
    _remove_path(directory)
    directory.mkdir(parents=True)
    transcript_path = directory / "provider-transcript.jsonl"
    event_path = directory / "events.raw.jsonl"
    complete_path = directory / "complete.marker"
    launch_log = directory / "launch.log"
    atomic_write_text(transcript_path, "")
    atomic_write_text(event_path, "")
    fixture = CowAgentFixtureServer(
        role=role,
        tool_name=TOOL_NAME,
        arguments=_arguments(role),
        family="browser-native-file",
        transcript_path=transcript_path,
    )
    fixture.start()
    process_exit = 124
    output = ""
    runtime = home = state = workspace = temporary = Path("/")
    try:
        base_url = f"http://127.0.0.1:{fixture.port}/v1"
        runtime, home, state, workspace, temporary, _config = _prepare_role(
            directory, base_url, case, role, build_project
        )
        fixture_manifest = json.loads(
            (directory / "fixture-manifest.json").read_text(encoding="utf-8")
        )
        fixture_files = dict(fixture_manifest["files"])
        shutil.copy2(
            build_project.parent.parent / "transformed-source-manifest.json",
            directory / "transformed-source-manifest.json",
        )
        environment = {
            "PATH": f"{build_project.parent / '.clawgap-venv/bin'}:{os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
            "HOME": str(home),
            "TMPDIR": str(temporary),
            "OPENAI_API_KEY": "clawgap-loopback-mock",
            "OPENAI_API_BASE": base_url,
            "PLAYWRIGHT_BROWSERS_PATH": str(PLAYWRIGHT_BROWSERS_PATH),
            "NO_COLOR": "1",
            "NO_PROXY": "127.0.0.1,localhost,::1",
            "no_proxy": "127.0.0.1,localhost,::1",
            "PYTHONUNBUFFERED": "1",
            "CLAWGAP_L2_EVENT_PATH": str(event_path),
            "CLAWGAP_L2_COMPLETE_PATH": str(complete_path),
            "CLAWGAP_L2_CANDIDATE_ID": ADDITIVE_CANDIDATE_ID,
            "CLAWGAP_L2_CASE_ID": str(case["case_id"]),
            "CLAWGAP_L2_ATTEMPT": str(attempt),
            "CLAWGAP_L2_ROLE": role,
            "CLAWGAP_L2_CORRELATION_ID": f"{case['case_id']}:{attempt}:{role}",
            "CLAWGAP_L2_FIXTURE_ID": (
                f"chatgpt-on-wechat-additive-l2:{case['case_id']}:{role}"
            ),
            "CLAWGAP_L2_FAMILY": "browser-native-file",
            "CLAWGAP_SOURCE_REVISED_FILE_SCHEME": "1",
            "CLAWGAP_L2_GATE_IDS": "",
        }
        process_exit, output = _launch_role(
            runtime=runtime,
            python=python,
            app_path=build_project / "app.py",
            environment=environment,
            temporary=temporary,
            complete_path=complete_path,
            timeout=request.timeout,
        )
        atomic_write_text(launch_log, redact_text(output))
    except Exception as exc:
        atomic_write_text(
            launch_log,
            redact_text(output + f"\nCLAWGAP_ERROR: {type(exc).__name__}: {exc}\n"),
        )
        cleanup_errors = (
            _cleanup_role(directory, runtime, home, state, workspace, temporary)
            if runtime != Path("/")
            else []
        )
        return PairOutcome(
            False,
            False,
            [f"{type(exc).__name__}: {exc}", *cleanup_errors],
        ), []
    finally:
        fixture.stop()

    raw_events = _read_jsonl(event_path)
    provider_rows = _read_jsonl(transcript_path)
    cleanup_errors = _cleanup_role(
        directory, runtime, home, state, workspace, temporary
    )
    try:
        events = _normalize_events(
            raw_events,
            provider_rows,
            case,
            attempt,
            role,
            fixture_files,
        )
        if cleanup_errors and events:
            events[-1]["detail"]["cleanup_errors"] = cleanup_errors
        _write_jsonl(directory / "events.jsonl", events)
        outcome = _evaluate_role(
            case,
            role,
            events,
            fixture,
            provider_rows,
            process_exit,
            cleanup_errors,
        )
        return outcome, events
    except Exception as exc:
        return PairOutcome(False, False, [f"{type(exc).__name__}: {exc}"]), []


def _reproduction_command(request: ChatGPTOnWeChatFileNativeL2RunRequest) -> str:
    command = (
        "python -m src.runtime_validation "
        "run-dynamic-trigger-source-revised-native-l2 "
        "--project chatgpt-on-wechat "
        f"--out-dir {request.out_dir} --attempts {request.attempts}"
    )
    if request.build_dir is not None:
        command += f" --build-dir {request.build_dir}"
    return command


def _artifact_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): sha256_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "manifest.json"
    }


def run_chatgpt_on_wechat_file_native_l2(
    request: ChatGPTOnWeChatFileNativeL2RunRequest,
) -> dict[str, Any]:
    started = time.time()
    if request.attempts < 1 or request.timeout < 5 or request.build_timeout < 5:
        raise ValidationError("CowAgent source-revised native L2 parameters must be positive")
    if not PLAYWRIGHT_BROWSERS_PATH.is_dir():
        raise ValidationError("local Playwright browser root is unavailable")

    request.out_dir.mkdir(parents=True, exist_ok=True)
    source_bindings = _source_bindings()
    build_dir = (
        request.build_dir
        if request.build_dir is not None
        else request.out_dir / "native-build"
    ).resolve()
    build_manifest = _prepare_additive_build(
        build_dir, source_bindings, request.build_timeout
    )
    build_project = build_dir / "canonical/project"
    python = build_dir / "canonical/.clawgap-venv/bin/python"
    case = _case()
    pairs: list[PairOutcome] = []
    pair_errors: list[list[str]] = []
    for attempt in range(1, request.attempts + 1):
        outcomes: dict[str, PairOutcome] = {}
        for role in ("exploit", "control"):
            outcome, _events = _run_role_attempt(
                case,
                role,
                attempt,
                request.out_dir / "runs" / f"attempt-{attempt}" / role,
                build_project,
                python,
                request,
            )
            outcomes[role] = outcome
        exploit = outcomes["exploit"]
        control = outcomes["control"]
        pair = PairOutcome(
            exploit.healthy and control.healthy,
            exploit.healthy and control.healthy and exploit.triggered,
            [*exploit.errors, *control.errors],
        )
        pairs.append(pair)
        pair_errors.append(pair.errors)

    if any(not pair.healthy for pair in pairs):
        disposition = "inconclusive"
        reason = "one or more source-revised native pairs had infrastructure or trace failures"
    elif all(pair.triggered for pair in pairs):
        disposition = "runtime-confirmed"
        reason = (
            "all native BrowserTool E2E pairs preserved the exact file:// "
            "URL through real BrowserService dispatch to the intercepted page.goto "
            "boundary, while https controls did not satisfy the file-scheme witness"
        )
    else:
        disposition = "not-reproduced"
        reason = "source-revised native pairs completed without the file-scheme witness"

    result = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "campaign_id": CAMPAIGN_ID,
        "report_id": REPORT_ID,
        "report_name": REPORT_NAME,
        "project": "chatgpt-on-wechat",
        "disposition": disposition,
        "reason": reason,
        "evidence_scope": EVIDENCE_SCOPE,
        "evidence_tier": EVIDENCE_TIER,
        "canonical_revision": PROJECT.analysis_revision,
        "runtime_source_revision": SOURCE_REVISION,
        "additive_candidate_id": ADDITIVE_CANDIDATE_ID,
        "canonical_candidate_id": None,
        "canonical_accounting_affected": False,
        "attempts": request.attempts,
        "attempt_errors": [errors for errors in pair_errors if errors],
        "trace_accounting": {
            "expected": request.attempts * 2,
            "valid": sum(pair.healthy for pair in pairs) * 2,
            "blocked": sum(not pair.healthy for pair in pairs) * 2,
            "not_launched": 0
            if all(pair.healthy for pair in pairs)
            else sum(2 for pair in pairs if not pair.healthy),
        },
    }
    _write_jsonl(request.out_dir / "report-results.jsonl", [result])
    _write_jsonl(request.out_dir / "candidate-results.jsonl", [result])
    atomic_write_json(
        request.out_dir / "candidate.json",
        {
            "schema_version": "clawgap-source-revised-native-candidate/v1",
            "candidate_id": ADDITIVE_CANDIDATE_ID,
            "project": "chatgpt-on-wechat",
            "report_id": REPORT_ID,
            "tool_name": TOOL_NAME,
            "selection_mode": EVIDENCE_SCOPE,
            "canonical_input": False,
            "base_revision": PROJECT.analysis_revision,
            "revision": SOURCE_REVISION,
            "canonical_browser_tool_unchanged": True,
        },
    )
    _write_jsonl(
        request.out_dir / "qualification.jsonl",
        [
            {
                "report_id": REPORT_ID,
                "project": "chatgpt-on-wechat",
                "status": disposition,
                "evidence_scope": EVIDENCE_SCOPE,
                "evidence_tier": EVIDENCE_TIER,
            }
        ],
    )

    for path in (
        path
        for path in (request.out_dir / "runs").rglob("*")
        if path.name in {"home", "state", "workspace", "runtime", "tmp"}
    ):
        try:
            _remove_path(path)
        except OSError:
            pass
    disposable_roots_removed = not any(
        path.is_dir()
        for path in (request.out_dir / "runs").rglob("*")
        if path.name in {"runtime", "home", "state", "workspace", "tmp"}
    )

    credential_scan = _artifact_credential_scan(request.out_dir.resolve())
    if credential_scan != "passed" or not disposable_roots_removed:
        result["disposition"] = "inconclusive"
        result["reason"] = "campaign-level credential or cleanup gate failed"
        _write_jsonl(request.out_dir / "report-results.jsonl", [result])
        _write_jsonl(request.out_dir / "candidate-results.jsonl", [result])

    if request.build_dir is None:
        _remove_path(build_dir)
    summary = (
        "# ChatGPT-on-WeChat File-Scheme Additive Runtime Overlay\n\n"
        f"Report: `{REPORT_ID}`\n\n"
        f"Additive candidate: `{ADDITIVE_CANDIDATE_ID}`\n\n"
        f"Disposition: **{result['disposition']}**\n\n"
        "This is source-revised native-tool evidence. It does not change the "
        "canonical 81-candidate denominator, the 43-report eligible boundary, or "
        "the canonical `41/43` runtime result.\n"
    )
    atomic_write_text(request.out_dir / "summary.md", summary)
    manifest = {
        "schema_version": (
            "clawgap-dynamic-trigger-chatgpt-on-wechat-native-file-l2-manifest/v1"
        ),
        "campaign_id": CAMPAIGN_ID,
        "report_count": 1,
        "attempt_pairs": request.attempts,
        "status_counts": {result["disposition"]: 1},
        "evidence_scope": EVIDENCE_SCOPE,
        "canonical_accounting_affected": False,
        "source_bindings": source_bindings,
        "transformed_source_manifest": build_manifest,
        "credential_scan": credential_scan,
        "disposable_roots_removed": disposable_roots_removed,
        "artifact_sha256": _artifact_hashes(request.out_dir.resolve()),
        "reproduction_command": _reproduction_command(request),
        "started_at": datetime.fromtimestamp(started, timezone.utc).isoformat(),
        "completed_at": _utc_now(),
        "elapsed_seconds": round(time.time() - started, 3),
    }
    atomic_write_json(request.out_dir.resolve() / "manifest.json", manifest)
    return manifest

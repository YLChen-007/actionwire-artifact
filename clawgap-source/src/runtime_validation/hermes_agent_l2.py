"""Targeted forced-provider L2 runtime for GT-linked Hermes Agent candidates."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping

from src.projects import get_project

from .contracts import (
    ValidationError,
    atomic_write_json,
    atomic_write_text,
    contains_credentials,
    redact_text,
    redact_value,
    sha256_file,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT = get_project("hermes-agent")
SOURCE_ROOT = PROJECT.source_root
RUNTIME_SOURCE_REVISION = (
    PROJECT.analysis_revision + "+legacy-command-bypass-source-v1"
)
DEFAULT_SOURCE_CAMPAIGN = (
    REPO_ROOT / "output/cross-project/runtime-dynamic-trigger-all-candidates-expanded-v3"
)
TARGET_CANDIDATES = (
    "CAND-925c9d1319c3ccbd",
    "CAND-1ba6a7fa9223b90a",
    "CAND-24816bf2edb0a656",
    "CAND-2cbc162a54cd0fca",
    "CAND-5e68c0fe5fc73614",
    "CAND-ba282dbbfa91c115",
    "CAND-3c75802d17295ad7",
    "CAND-613daf7aa801ec6b",
    "CAND-67f09a66703d2c4b",
    "CAND-7f9f3480fd062417",
    "CAND-fa23b4eea72e2409",
    "CAND-9c11291212f7d4c4",
    "CAND-c405955b2c535623",
    "CAND-fe9844acd2a48e57",
    "CAND-2bb4433b7deba02c",
)
CAMPAIGN_ID = "runtime-dynamic-trigger-hermes-agent-source-revised-l2-v1"
L2_EVIDENCE_TIER = "L2-forced-provider-E2E"
RESULT_SCHEMA_VERSION = "clawgap-dynamic-trigger-hermes-agent-l2-result/v1"
EVENT_SCHEMA_VERSION = "clawgap-dynamic-trigger-hermes-agent-l2-event/v1"
MODEL_NAME = "clawgap-hermes-l2"
PROVIDER_CREDENTIAL = "clawgap-loopback-mock"
CANARY_CONTENT = "CLAWGAP_HERMES_OUTSIDE_CANARY=must-not-disclose\n"
NORMALIZED_STAGES = (
    "case_bound",
    "source_verified",
    "fixture_prepared",
    "launch_started",
    "prompt_received",
    "provider_request",
    "provider_tool_call_or_decision",
    "registry_or_native_dispatch",
    "handler_entered",
    "controlled_argument_recorded",
    "gate_observed",
    "missing_check_boundary_confirmed",
    "sink_reached",
    "pre_effect_interception",
    "target_completed",
    "cleanup_verified",
)

CITED_SOURCE_HASHES = {
    "pyproject.toml": "1d5a3f24b0f29fc0f90a97aaa9cab9568fc5bc4231466448f9b164f05c593468",
    "uv.lock": "8c6722730c8e9720e642d2dfd72ab43eb5ab2e8d072b0f413fb76b4b93e210ce",
    "hermes": "6e1adae1e73ce67121d4ec380a5b66b8fb84f02dd8004b3a9988c39660139417",
    "hermes_cli/main.py": "ba7c7cd5f7478b9dc29e0530c135db594c4c60067adab01155e658e48976a959",
    "hermes_cli/runtime_provider.py": "badeee3e2eed2594a45cc97ea6c1da245ad6a18f08fd4edc298440755ffcb3bf",
    "hermes_cli/oneshot.py": "ce74fcb2ea27e5c1643a9910695d34f5728a2e3b4caa1d229588e467aa49a555",
    "cron/scheduler.py": "792212ff89421ede61fc63b3a8ea590777e6f6d9f276457cffe32bf05a84df61",
    "model_tools.py": "370312c62f69bb6a12284f7e9ba4b3fe524f296ec13e8b4004a0f89f77bc1041",
    "tools/registry.py": "aa2e7adc81df459b225bf7421018f03096a9a9b168231047daf6cfe63e9ceb86",
    "tools/file_tools.py": "7fa122dec862fcbc5e9980f1c50301a75e4e3620c7c40c99539949994c7cc657",
    "tools/file_operations.py": "e1110c8bd43ebb40172d191952517d95881889732dc63e96c6f0dc05ebc84fb0",
    "tools/environments/local.py": "d6faa2badddaa16331b46b0a6e915c9e2e0506170f9bfd954a8cbd576e2fd23b",
    "tools/terminal_tool.py": "1cebd9ab9d0c0164a2b8d8c35728a06cce444ff4d8164b18eb877a350be9ce22",
    "tools/approval.py": "3c3c85d12ad1aa936ee7600f49a69ba3136ecd1949af3e19635e225ed2f6e180",
    "tools/code_execution_tool.py": "37aac3ba77c61e64f5937e62dc28fa19232543264f696f525515d76352a8e511",
    "tools/browser_tool.py": "a458caeddab2fee5720173719a3a29228112f1a23a2088778cc44a3bc8957b47",
    "tools/send_message_tool.py": "dfec3f2317e19e8d8d83e3449c8d5f9f103aa8ba293b0b78280411f743aa33d2",
    "gateway/config.py": "7bfaf819d12efb92cc966632396a212fada1bf03904d479d223c96575c42d3ed",
    "gateway/platforms/matrix.py": "a49b3687ec4844b99602bbed1344555c6825af62432202b8762bf9b5907a97f4",
    "tools/skills_tool.py": "a3f04ba2b6ec57b6e98bcf430aa6635f02eba1cfe64c94a07a7056209d8f6342",
}


@dataclass(frozen=True)
class HermesAgentL2RunRequest:
    campaign: Path = DEFAULT_SOURCE_CAMPAIGN
    out_dir: Path = ...
    attempts: int = 3
    timeout: int = 180
    build_timeout: int = 1800
    candidate_id: str | None = None
    build_dir: Path | None = None


@dataclass
class PairOutcome:
    healthy: bool
    triggered: bool
    errors: list[str]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return rows
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"{path}:{number}: invalid JSON") from exc
        if not isinstance(value, dict):
            raise ValidationError(f"{path}:{number}: expected object")
        rows.append(value)
    return rows


def _write_jsonl(path: Path, rows: list[Mapping[str, Any]]) -> None:
    atomic_write_text(
        path,
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
    )


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.exists():
        shutil.rmtree(path)


def _select_cases(
    campaign: Path, candidate_id: str | None = None
) -> list[dict[str, Any]]:
    cases = _read_jsonl(campaign / "cases.jsonl")
    selected = {
        str(row.get("candidate_binding", {}).get("candidate_id")): row
        for row in cases
        if row.get("project") == "hermes-agent"
    }
    expected = set(TARGET_CANDIDATES)
    if candidate_id is None and not expected.issubset(selected):
        missing = sorted(expected - set(selected))
        raise ValidationError(
            "Hermes targeted L2 source campaign is missing GT-linked "
            "candidates: " + ", ".join(missing)
        )
    if candidate_id is not None and candidate_id not in expected:
        raise ValidationError(
            "requested Hermes Agent candidate is not GT-linked targeted L2"
        )
    if candidate_id is not None and candidate_id not in selected:
        missing = sorted(expected - set(selected))
        raise ValidationError(
            "Hermes targeted L2 source campaign is missing GT-linked "
            "candidates: " + ", ".join(missing)
        )
    if candidate_id is not None:
        cases = [selected[candidate_id]]
    else:
        cases = [selected[item] for item in TARGET_CANDIDATES if item in selected]
    for case in cases:
        case["base_analysis_revision"] = PROJECT.analysis_revision
        case["revision"] = RUNTIME_SOURCE_REVISION
    return cases


def _candidate_id(case: Mapping[str, Any]) -> str:
    return str(case["candidate_binding"]["candidate_id"])


def _case_id(case: Mapping[str, Any]) -> str:
    return str(case["case_id"])


def _native_tool(case: Mapping[str, Any]) -> str:
    handler_tool = str(case.get("handler", {}).get("tool_name", ""))
    return {
        "_handle_read_file": "read_file",
        "_handle_terminal": "terminal",
        "send_message_tool": "send_message",
        "_skill_view_with_bump": "skill_view",
    }.get(handler_tool, handler_tool)


def _role_arguments(case: Mapping[str, Any], role: str) -> dict[str, Any]:
    row = next(item for item in case["forced_tool_calls"] if item["role"] == role)
    return dict(row["arguments"])


def _family(case: Mapping[str, Any]) -> str:
    candidate_id = _candidate_id(case)
    return {
        "CAND-925c9d1319c3ccbd": "device-read",
        "CAND-1ba6a7fa9223b90a": "interactive-shell-pattern",
        "CAND-5e68c0fe5fc73614": "cron-approval",
        "CAND-9c11291212f7d4c4": "credential-environment",
        "CAND-ba282dbbfa91c115": "execute-code",
        "CAND-24816bf2edb0a656": "matrix-markdown-link",
        "CAND-2cbc162a54cd0fca": "matrix-markdown-plain",
        "CAND-c405955b2c535623": "slack-mention",
        "CAND-fe9844acd2a48e57": "mattermost-mention",
        "CAND-2bb4433b7deba02c": "skill-view-traversal",
    }.get(candidate_id, "browser-eval")


def _entrypoint_mode(case: Mapping[str, Any]) -> str:
    family = _family(case)
    if family == "interactive-shell-pattern":
        return "chat-query-pty"
    if family == "cron-approval":
        return "cron-run-tick"
    return "oneshot"


def _toolset(case: Mapping[str, Any]) -> str:
    return {
        "device-read": "file",
        "interactive-shell-pattern": "terminal",
        "cron-approval": "terminal",
        "credential-environment": "terminal",
        "execute-code": "code_execution",
        "browser-eval": "browser",
        "matrix-markdown-link": "messaging",
        "matrix-markdown-plain": "messaging",
        "slack-mention": "messaging",
        "mattermost-mention": "messaging",
        "skill-view-traversal": "skills",
    }[_family(case)]


def _anchors(case: Mapping[str, Any]) -> dict[str, str]:
    rows = case.get("instrumentation_anchors") or case.get("observations", [])
    result: dict[str, str] = {}
    for row in rows:
        kind = str(row.get("kind", ""))
        anchor = str(row.get("anchor") or row.get("source_anchor"))
        if kind in {"handler", "gate", "sink", "pre-effect"} and kind not in result:
            result[kind] = anchor
    if "pre-effect" not in result:
        result["pre-effect"] = result.get("sink", "")
    return result


def _sink_anchor(case: Mapping[str, Any]) -> str:
    family = _family(case)
    if family in {"matrix-markdown-link", "matrix-markdown-plain"}:
        return "gateway/platforms/matrix.py:940"
    if family == "slack-mention":
        return "tools/send_message_tool.py:1042"
    if family == "mattermost-mention":
        return "tools/send_message_tool.py:1364"
    if family == "skill-view-traversal":
        return "tools/skills_tool.py:1162"
    anchors = _anchors(case)
    return anchors.get("sink", "tools/environments/local.py:413")


def _expected_gate_ids(case: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(str(row.get("id")) for row in case.get("gates", []))


def _controlled_value(case: Mapping[str, Any], role: str) -> str:
    arguments = _role_arguments(case, role)
    family = _family(case)
    if family == "device-read":
        return str(arguments["path"])
    if family in {"interactive-shell-pattern", "cron-approval", "credential-environment"}:
        return str(arguments["command"])
    if family == "execute-code":
        return str(arguments["code"])
    if family == "browser-eval":
        return str(arguments["expression"])
    if family in {"matrix-markdown-link", "matrix-markdown-plain", "slack-mention", "mattermost-mention"}:
        return str(arguments["message"])
    if family == "skill-view-traversal":
        return json.dumps(
            {"file_path": arguments.get("file_path"), "name": arguments.get("name")},
            sort_keys=True,
        )
    raise ValidationError(f"unsupported Hermes family: {family}")


def _source_bindings(cases: list[Mapping[str, Any]]) -> dict[str, str]:
    required = set(CITED_SOURCE_HASHES)
    for case in cases:
        binding = case.get("source_binding", {})
        for row in binding.get("files", []):
            required.add(str(row["path"]))
        for row in case.get("instrumentation_anchors", []):
            anchor = str(row.get("anchor", "")).rsplit(":", 1)[0]
            if anchor:
                required.add(anchor)
    actual: dict[str, str] = {}
    for relative in sorted(required):
        path = SOURCE_ROOT / relative
        if not path.is_file():
            raise ValidationError(f"Hermes source binding is missing: {relative}")
        actual[relative] = sha256_file(path)
    for relative, expected in CITED_SOURCE_HASHES.items():
        if actual[relative] != expected:
            raise ValidationError(
                f"Hermes source hash drift: {relative}; expected "
                f"{expected}, got {actual[relative]}"
            )
    approval = (SOURCE_ROOT / "tools/approval.py").read_text(encoding="utf-8")
    if "_CLAWGAP_LEGACY_BYPASS_COMMANDS" not in approval:
        raise ValidationError(
            "Hermes source-revised approval carrier is missing the exact legacy set"
        )
    if (
        'if command in _CLAWGAP_LEGACY_BYPASS_COMMANDS:\n'
        '        tirith_result = {"action": "allow", "findings": [], "summary": ""}\n'
        not in approval
    ):
        raise ValidationError("Hermes exact legacy-command bypass marker drifted")
    return actual


def _replace_once(
    source: str, old: str, new: str, label: str
) -> str:
    count = source.count(old)
    if count != 1:
        raise ValidationError(
            f"Hermes instrumentation marker {label!r} matched {count} times"
        )
    return source.replace(old, new, 1)


def _instrumentation_helper() -> str:
    return r'''from __future__ import annotations

import asyncio
import inspect
import json
import os
import pathlib
import subprocess
import threading
import time
import uuid
from typing import Any

_ORIGINAL_POPEN = subprocess.Popen
_ORIGINAL_READ_TEXT = pathlib.Path.read_text
_STATE = {
    "tool": None,
    "value": None,
    "sink_emitted": False,
    "ordinal": 0,
}
_EMITTED_STAGES = set()
_LOCK = threading.Lock()


def _event(stage, detail=None, source_anchor=None):
    path = os.environ.get("CLAWGAP_HERMES_L2_EVENT_PATH")
    if not path:
        return
    if stage != "gate_observed" and stage in _EMITTED_STAGES:
        return
    _EMITTED_STAGES.add(stage)
    with _LOCK:
        _STATE["ordinal"] += 1
        row = {
            "schema_version": "clawgap-dynamic-trigger-hermes-agent-l2-event/v1",
            "event_id": "HE-" + uuid.uuid4().hex,
            "stage": stage,
            "candidate_id": os.environ.get("CLAWGAP_HERMES_L2_CANDIDATE_ID"),
            "case_id": os.environ.get("CLAWGAP_HERMES_L2_CASE_ID"),
            "attempt": int(os.environ.get("CLAWGAP_HERMES_L2_ATTEMPT", "0")),
            "role": os.environ.get("CLAWGAP_HERMES_L2_ROLE"),
            "correlation_id": os.environ.get("CLAWGAP_HERMES_L2_CORRELATION_ID"),
            "fixture_id": os.environ.get("CLAWGAP_HERMES_L2_FIXTURE_ID"),
            "source_anchor": source_anchor,
            "ordinal": _STATE["ordinal"],
            "process_identity": "hermes-agent",
            "monotonic_ns": time.monotonic_ns(),
            "detail": redact(detail or {}),
        }
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, sort_keys=True) + "\n")


def redact(value):
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        for key in (
            "WECOM_SECRET",
            "FEISHU_APP_SECRET",
            "MATRIX_PASSWORD",
            "SLACK_BOT_TOKEN",
            "MATTERMOST_TOKEN",
        ):
            if os.environ.get(key) and os.environ[key] in value:
                value = value.replace(os.environ[key], "[REDACTED_CREDENTIAL]")
        if value == os.environ.get("CLAWGAP_HERMES_L2_PROVIDER_KEY"):
            return "[REDACTED_CREDENTIAL]"
    return value


def _complete():
    marker = os.environ.get("CLAWGAP_HERMES_L2_COMPLETE_PATH")
    if marker:
        pathlib.Path(marker).write_text(str(time.time()), encoding="utf-8")


def _family():
    return os.environ.get("CLAWGAP_HERMES_L2_FAMILY", "")


def _role():
    return os.environ.get("CLAWGAP_HERMES_L2_ROLE", "")


def _control_sink_allowed():
    return os.environ.get("CLAWGAP_HERMES_L2_CONTROL_SINK") == "true"


def clawgap_dispatch(tool_name, arguments):
    _event(
        "registry_or_native_dispatch",
        {"tool_name": tool_name, "runtime": "tools.registry.ToolRegistry.dispatch"},
        "tools/registry.py:347",
    )


def clawgap_handler(tool_name, arguments):
    _STATE["tool"] = tool_name
    _STATE["sink_emitted"] = False
    _event(
        "handler_entered",
        {"tool_name": tool_name, "arguments": arguments},
        os.environ.get("CLAWGAP_HERMES_L2_HANDLER_ANCHOR"),
    )
    value = arguments.get(
        "path",
        arguments.get(
            "command",
            arguments.get(
                "code",
                arguments.get(
                    "expression",
                    arguments.get(
                        "message",
                        json.dumps(
                            {
                                "name": arguments.get("name"),
                                "file_path": arguments.get("file_path"),
                            },
                            sort_keys=True,
                        ),
                    ),
                ),
            ),
        ),
    )
    _STATE["value"] = value
    _event(
        "controlled_argument_recorded",
        {
            "tool_name": tool_name,
            "value": value,
            "argument_path": os.environ.get("CLAWGAP_HERMES_L2_ARGUMENT_PATH", "").split(","),
        },
        os.environ.get("CLAWGAP_HERMES_L2_HANDLER_ANCHOR"),
    )
    family = _family()
    if tool_name == "browser_console":
        _event(
            "gate_observed",
            {
                "gate_ids": [],
                "name": "browser expression presence",
                "admitted": arguments.get("expression") is not None,
                "expression": arguments.get("expression"),
            },
            "tools/browser_tool.py:2532",
        )
        _event(
            "missing_check_boundary_confirmed",
            {
                "missing_check": True,
                "policy": "post-browser-eval-destination-revalidation",
            },
            "tools/browser_tool.py:2533",
        )
    elif family in {"execute-code", "credential-environment", "slack-mention", "mattermost-mention"}:
        policies = {
            "execute-code": "execute-code-approval",
            "credential-environment": "messaging-credential-environment-removal",
            "slack-mention": "broadcast-mention-neutralization-and-allowed-mentions",
            "mattermost-mention": "broadcast-mention-neutralization-and-companion-control",
        }
        _event(
            "gate_observed",
            {"gate_ids": [], "name": family + "-boundary", "admitted": True},
            os.environ.get("CLAWGAP_HERMES_L2_HANDLER_ANCHOR"),
        )
        _event(
            "missing_check_boundary_confirmed",
            {"missing_check": True, "policy": policies[family]},
            os.environ.get("CLAWGAP_HERMES_L2_SINK_ANCHOR"),
        )


def clawgap_command_gate(command, decision, entrypoint):
    _event(
        "gate_observed",
        {
            "gate_ids": ["GU12b0b728e6cee94199f6"],
            "name": "check_all_command_guards",
            "command": command,
            "approved": bool(decision.get("approved")),
            "status": decision.get("status", ""),
            "entrypoint": entrypoint,
            "cron_session": os.environ.get("HERMES_CRON_SESSION") == "1",
            "yolo": os.environ.get("HERMES_YOLO_MODE") == "1",
            "interactive": os.environ.get("HERMES_INTERACTIVE") == "1",
        },
        "tools/terminal_tool.py:1831",
    )
    if _family() in {"interactive-shell-pattern", "cron-approval"}:
        _event(
            "missing_check_boundary_confirmed",
            {
                "missing_check": True,
                "policy": (
                    "nested-interpreter-remote-content-grammar"
                    if _family() == "interactive-shell-pattern"
                    else "cron-approval-fail-closed-policy"
                ),
            },
            "tools/approval.py:920",
        )


def clawgap_environment_boundary(environment):
    family = _family()
    marker_keys = ["WECOM_SECRET", "FEISHU_APP_SECRET", "MATRIX_PASSWORD"]
    _event(
        "gate_observed",
        {
            "gate_ids": [],
            "name": "local environment construction",
            "provider_blocklist_applied": True,
            "credential_keys_present": [key for key in marker_keys if key in environment],
        },
        "tools/environments/local.py:222",
    )
    if family == "credential-environment":
        _event(
            "missing_check_boundary_confirmed",
            {
                "missing_check": True,
                "policy": "messaging-credential-environment-removal",
                "credential_keys_present": [key for key in marker_keys if key in environment],
                "credential_values": "[redacted]" if any(key in environment for key in marker_keys) else None,
            },
            "tools/environments/local.py:222",
        )
    elif family == "device-read":
        _event(
            "missing_check_boundary_confirmed",
            {
                "missing_check": True,
                "policy": "canonical-device-path-policy-after-expansion",
            },
            "tools/file_operations.py:719",
        )


def clawgap_matrix_markdown(text, html, path):
    _event(
        "gate_observed",
        {
            "gate_ids": ["GU4cada63c16ecfa970a1b", "GU6ecf67609101523d71c6"],
            "name": "Matrix markdown conversion path",
            "conversion_path": path,
            "fallback_sanitizer_exercised": path == "fallback",
            "text": text,
            "formatted_body": html,
        },
        "gateway/platforms/matrix.py:2576",
    )
    _event(
        "missing_check_boundary_confirmed",
        {
            "missing_check": True,
            "policy": "library-path-link-scheme-and-raw-html-sanitization",
            "conversion_path": path,
        },
        "gateway/platforms/matrix.py:2585",
    )


def clawgap_skill_path(search_dir, name, direct_path, selected):
    skills_root = pathlib.Path(os.environ.get("CLAWGAP_HERMES_L2_SKILLS_ROOT", ""))
    selected_path = pathlib.Path(str(direct_path))
    try:
        outside = not selected_path.resolve().is_relative_to(skills_root.resolve())
    except (OSError, ValueError):
        outside = True
    _event(
        "gate_observed",
        {
            "gate_ids": [],
            "name": "pre-join skill-name root containment",
            "search_dir": str(search_dir),
            "name": name,
            "direct_path": str(direct_path),
            "selected": bool(selected),
            "resolved_outside_skills_root": outside,
        },
        "tools/skills_tool.py:952",
    )
    _event(
        "missing_check_boundary_confirmed",
        {
            "missing_check": True,
            "policy": "skill-name-traversal-before-root-selection",
            "resolved_outside_skills_root": outside,
        },
        "tools/skills_tool.py:952",
    )


def _emit_sink(detail):
    if _STATE["sink_emitted"]:
        return False
    _STATE["sink_emitted"] = True
    payload = dict(detail)
    payload["sink_anchor"] = os.environ.get("CLAWGAP_HERMES_L2_SINK_ANCHOR")
    _event("sink_reached", payload, payload["sink_anchor"])
    _event("pre_effect_interception", {**payload, "executed": False}, payload["sink_anchor"])
    _event("target_completed", {"executed": False}, payload["sink_anchor"])
    _complete()
    return True


class _FakeProcess:
    def __init__(self, args, output="clawgap intercepted before execution\n"):
        self.args = args
        self.output = output
        self.returncode = 0
        self.pid = 424242
        self._hermes_pgid = 424242

    def communicate(self, timeout=None, *_args, **_kwargs):
        return self.output, ""

    def wait(self, timeout=None, *_args, **_kwargs):
        return 0

    def kill(self):
        return None

    def terminate(self):
        return None

    def poll(self):
        return 0

    def __enter__(self):
        return self

    def __aenter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def __aexit__(self, *_args):
        return False


def _output_for(arguments):
    text = repr(arguments)
    if "wc -c" in text:
        return "0\n"
    if "head -c" in text:
        return "clawgap intercepted read sample\n"
    if "sed -n" in text:
        return "clawgap intercepted file read\n"
    return "clawgap intercepted process before execution\n"


def _instrumented_popen(*args, **kwargs):
    family = _family()
    role = _role()
    arguments = args[0] if args else kwargs.get("args")
    text = repr(arguments)
    value = str(_STATE.get("value") or "")
    matches = False
    if family in {"device-read", "interactive-shell-pattern", "cron-approval", "credential-environment"}:
        target_shell = isinstance(arguments, str) or (
            isinstance(arguments, (list, tuple))
            and bool(arguments)
            and "bash" in str(arguments[0])
        )
        matches = value in text and target_shell and (
            _STATE.get("tool") == "terminal"
            or (_STATE.get("tool") == "read_file" and value in text)
        )
    elif family == "execute-code":
        matches = _STATE.get("tool") == "execute_code"
    elif family == "browser-eval":
        matches = _STATE.get("tool") == "browser_console" and value in text
    if matches and (role == "exploit" or _control_sink_allowed()):
        if family == "device-read":
            detail = {
                "command": text,
                "argv": [str(item) for item in arguments] if isinstance(arguments, (list, tuple)) else [text],
                "canonical_exploit_path": os.path.realpath("/dev/./zero"),
                "controlled_value": value,
            }
        else:
            detail = {
                "command": text,
                "argv": [str(item) for item in arguments] if isinstance(arguments, (list, tuple)) else [text],
                "controlled_value": value,
                "environment_keys": sorted((kwargs.get("env") or {}).keys())
                if isinstance(kwargs.get("env"), dict)
                else [],
            }
            if family == "credential-environment":
                environment = kwargs.get("env") or {}
                detail["credential_keys_present"] = [
                    key
                    for key in ("WECOM_SECRET", "FEISHU_APP_SECRET", "MATRIX_PASSWORD")
                    if key in environment
                ]
                detail["credential_values"] = "[redacted]"
        _emit_sink(detail)
        if family == "browser-eval":
            stdout = kwargs.get("stdout")
            if isinstance(stdout, int) and stdout > 2:
                os.write(
                    stdout,
                    b'{"success":true,"data":{"result":"clawgap-intercepted"}}\n',
                )
        return _FakeProcess(arguments, _output_for(arguments))
    if matches and role == "control":
        _event("target_completed", {"executed": False, "control_intercepted": True})
        _complete()
        return _FakeProcess(arguments, _output_for(arguments))
    return _ORIGINAL_POPEN(*args, **kwargs)


def clawgap_local_process_sink(arguments, environment):
    if _family() != "credential-environment" or _STATE.get("tool") != "terminal":
        return None
    if not isinstance(environment, dict):
        return None
    marker_keys = ("WECOM_SECRET", "FEISHU_APP_SECRET", "MATRIX_PASSWORD")
    present = [key for key in marker_keys if key in environment]
    if not present:
        return None
    detail = {
        "argv": [str(item) for item in arguments]
        if isinstance(arguments, (list, tuple))
        else [str(arguments)],
        "command": repr(arguments),
        "controlled_value": _STATE.get("value"),
        "credential_keys_present": present,
        "credential_values": "[redacted]",
        "environment_keys": sorted(environment),
    }
    if _role() == "exploit" or _control_sink_allowed():
        _emit_sink(detail)
    else:
        _event("target_completed", {"executed": False, "control_intercepted": True})
        _complete()
    return _FakeProcess(arguments)


def _instrumented_read_text(self, *args, **kwargs):
    family = _family()
    if family == "skill-view-traversal" and _STATE.get("tool") == "skill_view":
        role = _role()
        target = str(self)
        terminal = target.endswith("/.env") or target.endswith("api.md")
        if terminal and (role == "exploit" or _control_sink_allowed()):
            skills_root = pathlib.Path(os.environ.get("CLAWGAP_HERMES_L2_SKILLS_ROOT", ""))
            detail = {
                "path": target,
                "realpath": str(pathlib.Path(target).resolve()),
                "outside_skills_root": not pathlib.Path(target).resolve().is_relative_to(
                    skills_root.resolve()
                ),
                "content_returned": "[pre-effect fixture response]",
            }
            _emit_sink(detail)
            return (
                "CLAWGAP_INTERCEPTED_OUTSIDE_SKILL_CONTENT\n"
                if role == "exploit"
                else "clawgap intercepted in-skill reference\n"
            )
        if terminal:
            _event("target_completed", {"executed": False, "control_intercepted": True})
            _complete()
            return "clawgap intercepted in-skill reference\n"
    return _ORIGINAL_READ_TEXT(self, *args, **kwargs)


class _FakeAsyncResponse:
    def __init__(self, payload):
        self.payload = payload
        self.status = 200

    async def json(self):
        return self.payload

    async def text(self):
        return json.dumps(self.payload)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


async def _instrumented_session_post(self, url, *args, **kwargs):
    family = _family()
    if family in {"slack-mention", "mattermost-mention"} and _STATE.get("tool") == "send_message":
        payload = kwargs.get("json") or {}
        _emit_sink(
            {
                "url": str(url),
                "payload": payload,
                "mention_present": "@channel" in str(payload.get("text", payload.get("message", ""))),
                "allowed_mentions_present": "allowed_mentions" in payload or "props" in payload,
            }
        )
        if family == "slack-mention":
            return _FakeAsyncResponse({"ok": True, "ts": "clawgap-intercepted"})
        return _FakeAsyncResponse({"id": "clawgap-intercepted"})
    original = getattr(self.__class__, "_clawgap_original_post", None)
    if original is None:
        raise RuntimeError("aiohttp post original binding was not retained")
    return await original(self, url, *args, **kwargs)


async def _instrumented_matrix_send(self, room_id, event_type, content):
    if _family() in {"matrix-markdown-link", "matrix-markdown-plain"} and _STATE.get("tool") == "send_message":
        _emit_sink(
            {
                "room_id": str(room_id),
                "event_type": str(event_type),
                "msg_content": content,
                "formatted_body": content.get("formatted_body", ""),
            }
        )
        return "clawgap-intercepted"
    original = getattr(self.__class__, "_clawgap_original_matrix_send", None)
    if original is None:
        raise RuntimeError("Matrix send original binding was not retained")
    return await original(self, room_id, event_type, content)


async def clawgap_session_post_sink(_session, url, **kwargs):
    if _family() not in {"slack-mention", "mattermost-mention"}:
        return _session.post(url, **kwargs)
    payload = kwargs.get("json") or {}
    _emit_sink(
        {
            "url": str(url),
            "payload": payload,
            "mention_present": "@channel" in str(payload.get("text", payload.get("message", ""))),
            "allowed_mentions_present": "allowed_mentions" in payload or "props" in payload,
        }
    )
    if _family() == "slack-mention":
        return _FakeAsyncResponse({"ok": True, "ts": "clawgap-intercepted"})
    return _FakeAsyncResponse({"id": "clawgap-intercepted"})


subprocess.Popen = _instrumented_popen
pathlib.Path.read_text = _instrumented_read_text
try:
    import aiohttp

    if not hasattr(aiohttp.ClientSession, "_clawgap_original_post"):
        aiohttp.ClientSession._clawgap_original_post = aiohttp.ClientSession.post
        aiohttp.ClientSession.post = _instrumented_session_post
except Exception:
    pass
try:
    from mautrix.client import Client as _MatrixClient

    if not hasattr(_MatrixClient, "_clawgap_original_matrix_send"):
        _MatrixClient._clawgap_original_matrix_send = _MatrixClient.send_message_event
        _MatrixClient.send_message_event = _instrumented_matrix_send
except Exception:
    pass
try:
    import agent.model_metadata as _model_metadata

    def _clawgap_context_length(*_args, **_kwargs):
        return 128000

    def _clawgap_endpoint_metadata(*_args, **_kwargs):
        return {}

    def _clawgap_no_local_server(*_args, **_kwargs):
        return None

    _model_metadata.get_model_context_length = _clawgap_context_length
    _model_metadata.fetch_endpoint_model_metadata = _clawgap_endpoint_metadata
    _model_metadata.detect_local_server_type = _clawgap_no_local_server
except Exception:
    pass
'''


def _instrument_project(project: Path) -> dict[str, str]:
    helper_path = project / "clawgap_hermes_l2_runtime.py"
    atomic_write_text(helper_path, _instrumentation_helper())
    transformed = {"clawgap_hermes_l2_runtime.py": sha256_file(helper_path)}

    launcher = project / "hermes"
    source = launcher.read_text(encoding="utf-8")
    source = _replace_once(
        source,
        'if __name__ == "__main__":\n',
        'if __name__ == "__main__":\n    import clawgap_hermes_l2_runtime\n',
        "launcher helper import",
    )
    launcher.write_text(source, encoding="utf-8")
    transformed["hermes"] = sha256_file(launcher)

    main_path = project / "hermes_cli/main.py"
    source = main_path.read_text(encoding="utf-8")
    source = _replace_once(
        source,
        "#!/usr/bin/env python3\n",
        "#!/usr/bin/env python3\nimport clawgap_hermes_l2_runtime\n",
        "main entrypoint helper import",
    )
    main_path.write_text(source, encoding="utf-8")
    transformed["hermes_cli/main.py"] = sha256_file(main_path)

    model_tools_path = project / "model_tools.py"
    source = model_tools_path.read_text(encoding="utf-8")
    source = _replace_once(
        source,
        "import time\n",
        "import time\n\nfrom clawgap_hermes_l2_runtime import clawgap_dispatch\n",
        "model_tools helper import",
    )
    source = _replace_once(
        source,
        "    function_args = coerce_tool_args(function_name, function_args)\n",
        "    clawgap_dispatch(function_name, function_args)\n    function_args = coerce_tool_args(function_name, function_args)\n",
        "model_tools native dispatch instrumentation",
    )
    model_tools_path.write_text(source, encoding="utf-8")
    transformed["model_tools.py"] = sha256_file(model_tools_path)

    registry = project / "tools/registry.py"
    source = registry.read_text(encoding="utf-8")
    source = _replace_once(
        source,
        "import time\nfrom pathlib import Path\n",
        "import time\nfrom pathlib import Path\n\nfrom clawgap_hermes_l2_runtime import clawgap_dispatch\n",
        "registry helper import",
    )
    source = _replace_once(
        source,
        '        entry = self.get_entry(name)\n        if not entry:\n',
        '        clawgap_dispatch(name, args)\n        entry = self.get_entry(name)\n        if not entry:\n',
        "registry dispatch instrumentation",
    )
    registry.write_text(source, encoding="utf-8")
    transformed["tools/registry.py"] = sha256_file(registry)

    replacements: list[tuple[Path, str, str, str]] = [
        (
            project / "tools/file_tools.py",
            "def _handle_read_file(args, **kw):\n",
            "def _handle_read_file(args, **kw):\n    clawgap_handler(\"read_file\", args)\n",
            "read handler",
        ),
        (
            project / "tools/terminal_tool.py",
            "def _handle_terminal(args, **kw):\n",
            "def _handle_terminal(args, **kw):\n    clawgap_handler(\"terminal\", args)\n",
            "terminal handler",
        ),
        (
            project / "tools/terminal_tool.py",
            "            approval = _check_all_guards(command, env_type)\n",
            "            approval = _check_all_guards(command, env_type)\n            clawgap_command_gate(command, approval, os.environ.get(\"CLAWGAP_HERMES_L2_ENTRYPOINT\", \"\"))\n",
            "terminal command gate",
        ),
        (
            project / "tools/code_execution_tool.py",
            "    if not SANDBOX_AVAILABLE:\n        return json.dumps({\n            \"error\": \"execute_code is not available on Windows. Use normal tool calls instead.\"\n        })\n",
            "    clawgap_handler(\"execute_code\", {\"code\": code, \"task_id\": task_id, \"enabled_tools\": enabled_tools})\n    if not SANDBOX_AVAILABLE:\n        return json.dumps({\n            \"error\": \"execute_code is not available on Windows. Use normal tool calls instead.\"\n        })\n",
            "execute-code handler",
        ),
        (
            project / "tools/browser_tool.py",
            "    # --- JS evaluation mode ---\n    if expression is not None:\n",
            "    # --- JS evaluation mode ---\n    if expression is not None:\n        clawgap_handler(\"browser_console\", {\"clear\": clear, \"expression\": expression, \"task_id\": task_id})\n",
            "browser handler",
        ),
        (
            project / "tools/send_message_tool.py",
            "def send_message_tool(args, **kw):\n",
            "def send_message_tool(args, **kw):\n    clawgap_handler(\"send_message\", args)\n",
            "send-message handler",
        ),
        (
            project / "tools/skills_tool.py",
            "def _skill_view_with_bump(args, **kw):\n",
            "def _skill_view_with_bump(args, **kw):\n    clawgap_handler(\"skill_view\", args)\n",
            "skill handler",
        ),
    ]
    for path, old, new, label in replacements:
        source = path.read_text(encoding="utf-8")
        source = _replace_once(source, old, new, label)
        path.write_text(source, encoding="utf-8")
        transformed[str(path.relative_to(project))] = sha256_file(path)

    local_path = project / "tools/environments/local.py"
    source = local_path.read_text(encoding="utf-8")
    source = _replace_once(
        source,
        "import time\n\nfrom tools.environments.base import BaseEnvironment, _pipe_stdin\n",
        "import time\n\nfrom clawgap_hermes_l2_runtime import (\n    clawgap_environment_boundary,\n    clawgap_local_process_sink,\n)\nfrom tools.environments.base import BaseEnvironment, _pipe_stdin\n",
        "environment helper import",
    )
    source = _replace_once(
        source,
        "        proc = subprocess.Popen(\n",
        "        clawgap_proc = clawgap_local_process_sink(args, run_env)\n        if clawgap_proc is not None:\n            return clawgap_proc\n        proc = subprocess.Popen(\n",
        "local credential process interception",
    )
    source = _replace_once(
        source,
        "    # Per-profile HOME isolation: redirect system tool configs (git, ssh, gh,\n",
        "    clawgap_environment_boundary(run_env)\n    # Per-profile HOME isolation: redirect system tool configs (git, ssh, gh,\n",
        "environment boundary event",
    )
    local_path.write_text(source, encoding="utf-8")
    transformed[str(local_path.relative_to(project))] = sha256_file(local_path)

    terminal_path = project / "tools/terminal_tool.py"
    source = terminal_path.read_text(encoding="utf-8")
    if "from clawgap_hermes_l2_runtime import clawgap_handler" not in source:
        source = _replace_once(
            source,
            "import time\n",
            "import time\n\nfrom clawgap_hermes_l2_runtime import clawgap_command_gate, clawgap_handler\n",
            "terminal helper imports",
        )
    terminal_path.write_text(source, encoding="utf-8")
    transformed[str(terminal_path.relative_to(project))] = sha256_file(terminal_path)

    imports = {
        "tools/file_tools.py": "clawgap_handler",
        "tools/code_execution_tool.py": "clawgap_handler",
        "tools/browser_tool.py": "clawgap_handler",
        "tools/send_message_tool.py": "clawgap_handler",
        "tools/skills_tool.py": "clawgap_handler",
    }
    for relative, symbol in imports.items():
        path = project / relative
        source = path.read_text(encoding="utf-8")
        if f"from clawgap_hermes_l2_runtime import {symbol}" not in source:
            statement = f"from clawgap_hermes_l2_runtime import {symbol}\n"
            if source.startswith("#!"):
                first_newline = source.index("\n") + 1
                source = source[:first_newline] + statement + source[first_newline:]
            else:
                source = statement + source
            path.write_text(source, encoding="utf-8")
        transformed[relative] = sha256_file(path)

    matrix_path = project / "gateway/platforms/matrix.py"
    source = matrix_path.read_text(encoding="utf-8")
    source = _replace_once(
        source,
        "from dataclasses import dataclass\n",
        "from dataclasses import dataclass\n\nfrom clawgap_hermes_l2_runtime import clawgap_matrix_markdown\n",
        "Matrix helper import",
    )
    source = _replace_once(
        source,
        "            html = md.convert(text)\n            md.reset()\n",
        "            html = md.convert(text)\n            clawgap_matrix_markdown(text, html, \"library\")\n            md.reset()\n",
        "Matrix library conversion",
    )
    source = _replace_once(
        source,
        "        return self._markdown_to_html_fallback(text)\n",
        "        result = self._markdown_to_html_fallback(text)\n        clawgap_matrix_markdown(text, result, \"fallback\")\n        return result\n",
        "Matrix fallback conversion",
    )
    matrix_path.write_text(source, encoding="utf-8")
    transformed["gateway/platforms/matrix.py"] = sha256_file(matrix_path)

    send_path = project / "tools/send_message_tool.py"
    source = send_path.read_text(encoding="utf-8")
    source = _replace_once(
        source,
        "from clawgap_hermes_l2_runtime import clawgap_handler\n",
        "from clawgap_hermes_l2_runtime import clawgap_handler, clawgap_session_post_sink\n",
        "delivery sink helper import",
    )
    source = _replace_once(
        source,
        "            async with session.post(url, headers=headers, json=payload, **_req_kw) as resp:\n",
        "            async with await clawgap_session_post_sink(session, url, headers=headers, json=payload, **_req_kw) as resp:\n",
        "Slack HTTP sink instrumentation",
    )
    source = _replace_once(
        source,
        "            async with session.post(url, headers=headers, json={\"channel_id\": chat_id, \"message\": message}) as resp:\n",
        "            async with await clawgap_session_post_sink(session, url, headers=headers, json={\"channel_id\": chat_id, \"message\": message}) as resp:\n",
        "Mattermost HTTP sink instrumentation",
    )
    source = _replace_once(
        source,
        "        elif platform == Platform.MATRIX:\n            result = await _send_matrix(pconfig.token, pconfig.extra, chat_id, chunk)\n",
        "        elif platform == Platform.MATRIX:\n            result = await _send_matrix_via_adapter(pconfig, chat_id, chunk)\n",
        "Matrix text routing to the cited native adapter",
    )
    send_path.write_text(source, encoding="utf-8")
    transformed["tools/send_message_tool.py"] = sha256_file(send_path)

    skills_path = project / "tools/skills_tool.py"
    source = skills_path.read_text(encoding="utf-8")
    source = _replace_once(
        source,
        "from clawgap_hermes_l2_runtime import clawgap_handler\n",
        "from clawgap_hermes_l2_runtime import clawgap_handler, clawgap_skill_path\n",
        "skills helper import",
    )
    source = _replace_once(
        source,
        "            direct_path = search_dir / name\n",
        "            direct_path = search_dir / name\n            clawgap_skill_path(search_dir, name, direct_path, skill_dir is None)\n",
        "skill direct path boundary",
    )
    skills_path.write_text(source, encoding="utf-8")
    transformed["tools/skills_tool.py"] = sha256_file(skills_path)
    return transformed


def _run(
    command: list[str],
    *,
    cwd: Path,
    log_path: Path,
    timeout: int,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=None if env is None else dict(env),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    atomic_write_text(
        log_path,
        redact_text(
            f"$ {shlex.join(command)}\nexit={completed.returncode}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
            secrets=(PROVIDER_CREDENTIAL,),
        ),
    )
    return completed


def _prepare_build(directory: Path, source_bindings: Mapping[str, str], timeout: int) -> dict[str, Any]:
    manifest_path = directory / "transformed-source-manifest.json"
    project = directory / "project"
    harness = Path(__file__).resolve()
    harness_sha = sha256_file(harness)
    if project.is_dir():
        try:
            prior = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prior = {}
        if (
            prior.get("schema_version") == "clawgap-hermes-transformed-source-manifest/v1"
            and prior.get("source_hashes") == dict(source_bindings)
            and prior.get("harness_sha256") == harness_sha
            and (project / ".venv/bin/hermes").is_file()
        ):
            return prior
        _remove_path(directory)

    directory.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        SOURCE_ROOT,
        project,
        ignore=shutil.ignore_patterns(
            ".git", ".venv", "__pycache__", ".pytest_cache", "*.pyc"
        ),
    )
    for relative, expected in source_bindings.items():
        actual = sha256_file(project / relative)
        if actual != expected:
            raise ValidationError(f"copied Hermes source drift: {relative}")
    transformed = _instrument_project(project)
    sync = _run(
        ["uv", "sync", "--frozen", "--extra", "messaging"],
        cwd=project,
        log_path=directory / "uv-sync.log",
        timeout=timeout,
        env={
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(directory / "build-home"),
            "UV_CACHE_DIR": str(directory / "uv-cache"),
            "NO_COLOR": "1",
        },
    )
    if sync.returncode != 0:
        raise ValidationError(f"Hermes locked dependency build failed: {sync.returncode}")
    matrix_install = _run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(project / ".venv/bin/python"),
            "mautrix==0.21.0",
            "Markdown==3.10.2",
            "aiosqlite==0.22.1",
            "asyncpg==0.31.0",
            "aiohttp-socks==0.11.0",
        ],
        cwd=project,
        log_path=directory / "uv-matrix-install.log",
        timeout=timeout,
        env={
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(directory / "build-home"),
            "UV_CACHE_DIR": str(directory / "uv-cache"),
            "NO_COLOR": "1",
        },
    )
    if matrix_install.returncode != 0:
        raise ValidationError(
            f"Hermes locked no-E2EE Matrix profile failed: {matrix_install.returncode}"
        )
    probe = _run(
 [
            str(project / ".venv/bin/python"),
            "-c",
            "import aiohttp, markdown, mautrix.client, model_tools, tools.registry; import clawgap_hermes_l2_runtime",
        ],
        cwd=project,
        log_path=directory / "import-probe.log",
        timeout=60,
        env={"PATH": str(project / ".venv/bin") + ":/usr/bin:/bin", "HOME": str(directory)},
    )
    if probe.returncode != 0:
        raise ValidationError("instrumented Hermes import probe failed")
    manifest = {
        "schema_version": "clawgap-hermes-transformed-source-manifest/v1",
        "source_root": str(SOURCE_ROOT),
        "base_analysis_revision": PROJECT.analysis_revision,
        "runtime_source_revision": RUNTIME_SOURCE_REVISION,
        "source_hashes": dict(source_bindings),
        "transformed": transformed,
        "dependency_lock_sha256": sha256_file(SOURCE_ROOT / "uv.lock"),
        "build_command": (
            "uv sync --frozen --extra messaging && "
            "uv pip install mautrix==0.21.0 Markdown==3.10.2 "
            "aiosqlite==0.22.1 asyncpg==0.31.0 aiohttp-socks==0.11.0"
        ),
        "dependency_profile": "uv-lock-derived-matrix-no-e2ee",
        "harness_sha256": harness_sha,
        "instrumentation_scope": (
            "real Hermes entrypoint, native registry, handlers, factual gates, "
            "and pre-effect process/read/network sinks"
        ),
    }
    atomic_write_json(manifest_path, manifest)
    _remove_path(directory / "build-home")
    return manifest


class HermesProviderServer:
    """Loopback OpenAI and minimal Matrix readiness fixture."""

    def __init__(
        self,
        *,
        role: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        transcript_path: Path,
    ):
        self.role = role
        self.tool_name = tool_name
        self.arguments = dict(arguments)
        self.transcript_path = transcript_path
        self.requests: list[str] = []
        self.valid_request = False
        self.unsupported: list[str] = []
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args: Any) -> None:
                return

            def _record(self, body: str, kind: str, valid: bool, reason: str = "") -> None:
                try:
                    parsed = json.loads(body) if body else None
                except json.JSONDecodeError:
                    parsed = None
                row = {
                    "schema_version": "clawgap-hermes-provider-transcript/v1",
                    "timestamp": _utc_now(),
                    "method": self.command,
                    "path": self.path,
                    "request_kind": kind,
                    "authorization": "Bearer [REDACTED_CREDENTIAL]",
                    "valid": valid,
                    "reason": reason,
                    "body": redact_value(parsed, secrets=(PROVIDER_CREDENTIAL,)),
                }
                with server.transcript_path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(row, sort_keys=True) + "\n")

            def _json(self, value: Mapping[str, Any]) -> None:
                payload = json.dumps(value, sort_keys=True).encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _sse(self, chunks: list[Mapping[str, Any]]) -> None:
                payload = "".join(
                    f"data: {json.dumps(chunk, sort_keys=True)}\n\n" for chunk in chunks
                ).encode("utf-8") + b"data: [DONE]\n\n"
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("cache-control", "no-cache")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _route(self) -> None:
                path = self.path.split("?", 1)[0]
                size = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(size).decode("utf-8", errors="replace") if size else ""
                if self.command == "GET" and path.endswith("/account/whoami"):
                    self._record(raw, "matrix-whoami", True)
                    self._json({"user_id": "@clawgap:example.org", "device_id": "CLAWGAP"})
                    return
                if self.command == "GET" and path.endswith("/sync"):
                    self._record(raw, "matrix-sync", True)
                    self._json({"next_batch": "clawgap", "rooms": {"join": {}}})
                    return
                if self.command == "GET" and path.endswith("/account_data/m.direct"):
                    self._record(raw, "matrix-account-data", True)
                    self._json({})
                    return
                if self.command != "POST" or path != "/v1/chat/completions":
                    server.unsupported.append(f"{self.command} {path}")
                    self._record(raw, "unsupported", False, "unsupported endpoint")
                    self._json({"error": {"message": "unsupported ClawGap endpoint"}})
                    return
                try:
                    body = json.loads(raw)
                except json.JSONDecodeError:
                    body = None
                tools = body.get("tools") or [] if isinstance(body, dict) else []
                tool_names = {
                    str(row.get("function", {}).get("name"))
                    for row in tools
                    if isinstance(row, dict)
                }
                messages = body.get("messages") if isinstance(body, dict) else None
                has_tool_result = any(
                    isinstance(row, dict) and row.get("role") == "tool"
                    for row in messages or []
                )
                kind = (
                    "continuation"
                    if has_tool_result
                    else "forced-tool-call"
                    if server.tool_name in tool_names
                    else "unknown"
                )
                valid = (
                    isinstance(body, dict)
                    and body.get("model") == MODEL_NAME
                    and isinstance(messages, list)
                    and bool(messages)
                    and self.headers.get("Authorization") == f"Bearer {PROVIDER_CREDENTIAL}"
                    and body.get("stream") is True
                    and (kind != "forced-tool-call" or server.tool_name in tool_names)
                )
                server.valid_request = server.valid_request or valid
                self._record(raw, kind, valid, "" if valid else "provider request drift")
                if not valid or kind == "unknown":
                    self._json({"error": {"message": "request does not match fixture"}})
                    return
                with server._lock:
                    server.requests.append(kind)
                    number = len(server.requests)
                if number > 2 or kind != ("forced-tool-call" if number == 1 else "continuation"):
                    self._json({"error": {"message": "provider sequence drift"}})
                    return
                if kind == "forced-tool-call":
                    call_id = f"call-clawgap-{server.role}"
                    self._sse(
                        [
                            {
                                "id": "chatcmpl-hermes-clawgap",
                                "object": "chat.completion.chunk",
                                "created": 1,
                                "model": MODEL_NAME,
                                "choices": [
                                    {
                                        "index": 0,
                                        "delta": {
                                            "tool_calls": [
                                                {
                                                    "index": 0,
                                                    "id": call_id,
                                                    "type": "function",
                                                    "function": {"name": server.tool_name, "arguments": ""},
                                                }
                                            ]
                                        },
                                        "finish_reason": None,
                                    }
                                ],
                            },
                            {
                                "id": "chatcmpl-hermes-clawgap",
                                "object": "chat.completion.chunk",
                                "created": 1,
                                "model": MODEL_NAME,
                                "choices": [
                                    {
                                        "index": 0,
                                        "delta": {
                                            "tool_calls": [
                                                {
                                                    "index": 0,
                                                    "function": {
                                                        "arguments": json.dumps(
                                                            server.arguments, sort_keys=True
                                                        )
                                                    }
                                                }
                                            ]
                                        },
                                        "finish_reason": None,
                                    }
                                ],
                            },
                            {
                                "id": "chatcmpl-hermes-clawgap",
                                "object": "chat.completion.chunk",
                                "created": 1,
                                "model": MODEL_NAME,
                                "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
                            },
                        ]
                    )
                    return
                self._sse(
                    [
                        {
                            "id": "chatcmpl-hermes-final",
                            "object": "chat.completion.chunk",
                            "created": 1,
                            "model": MODEL_NAME,
                            "choices": [
                                {"index": 0, "delta": {"content": "done"}, "finish_reason": None}
                            ],
                        },
                        {
                            "id": "chatcmpl-hermes-final",
                            "object": "chat.completion.chunk",
                            "created": 1,
                            "model": MODEL_NAME,
                            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                        },
                    ]
                )

            do_GET = _route
            do_POST = _route
            do_PUT = _route
            do_PATCH = _route
            do_DELETE = _route

        return Handler

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        shutdown = threading.Thread(target=self._server.shutdown, daemon=True)
        shutdown.start()
        shutdown.join(timeout=5)
        self._server.server_close()
        self._thread.join(timeout=5)


def _terminate_group(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        process.kill()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass


def _write_config(home: Path, provider_port: int, family: str) -> None:
    home.mkdir(parents=True, exist_ok=True)
    config = {
        "model": {
            "default": MODEL_NAME,
            "provider": "clawgap-loopback",
            "context_length": 128000,
        },
        "custom_providers": [
            {
                "name": "clawgap-loopback",
                "base_url": f"http://127.0.0.1:{provider_port}/v1",
                "api_key": "${CLAWGAP_FAKE_PROVIDER_KEY}",
                "model": MODEL_NAME,
                "context_length": 128000,
            }
        ],
        "model_catalog": {"enabled": False},
        "approvals": {"cron_mode": "approve"},
        "security": {"redact_secrets": True},
    }
    atomic_write_text(home / "config.yaml", json.dumps(config, indent=2) + "\n")
    atomic_write_text(home / ".env", "")
    cache = home / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    atomic_write_text(
        cache / "context_length_cache.yaml",
        (
            "context_lengths:\n"
            f'  "{MODEL_NAME}@http://127.0.0.1:{provider_port}/v1": 128000\n'
        ),
    )
    if family == "mattermost-mention":
        atomic_write_json(
            home / "channel_directory.json",
            {
                "updated_at": "2026-01-01T00:00:00",
                "platforms": {
                    "mattermost": [
                        {
                            "id": "clawgap-mattermost-channel",
                            "name": "test-channel",
                            "type": "channel",
                        }
                    ]
                },
            },
        )
    if family == "matrix-markdown-link" or family == "matrix-markdown-plain":
        (home / "matrix").mkdir(exist_ok=True)


def _prepare_fixture(home: Path, workspace: Path, family: str) -> dict[str, Any]:
    workspace.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "schema_version": "clawgap-hermes-l2-fixture-manifest/v1",
        "family": family,
        "workspace": str(workspace),
    }
    if family == "skill-view-traversal":
        skills = home / "skills"
        legit = skills / "legit-skill"
        references = legit / "references"
        references.mkdir(parents=True, exist_ok=True)
        (legit / "SKILL.md").write_text("# Legit skill\n", encoding="utf-8")
        (references / "api.md").write_text("legit reference\n", encoding="utf-8")
        outside = home / "outside-skill"
        outside.mkdir(parents=True, exist_ok=True)
        (outside / "SKILL.md").write_text("# Outside skill\n", encoding="utf-8")
        (outside / ".env").write_text(CANARY_CONTENT, encoding="utf-8")
        manifest.update(
            {
                "skills_root": str(skills),
                "outside_target": str(outside / ".env"),
                "outside_canary_sha256": sha256_file(outside / ".env"),
            }
        )
    return manifest


def _base_environment(
    *,
    directory: Path,
    home: Path,
    workspace: Path,
    build_project: Path,
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    fixture_id: str,
    provider_port: int,
    family: str,
) -> dict[str, str]:
    anchors = _anchors(case)
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "HOME": str(home),
        "HERMES_HOME": str(home),
        "TMPDIR": str(workspace / "tmp"),
        "TERMINAL_ENV": "local",
        "TERMINAL_CWD": str(workspace),
        "HERMES_IGNORE_RULES": "1",
        "HERMES_MAX_ITERATIONS": "2",
        "HERMES_INFERENCE_MODEL": MODEL_NAME,
        "HERMES_INFERENCE_PROVIDER": "clawgap-loopback",
        "CLAWGAP_FAKE_PROVIDER_KEY": PROVIDER_CREDENTIAL,
        "NO_PROXY": "127.0.0.1,localhost,::1",
        "no_proxy": "127.0.0.1,localhost,::1",
        "PYTHONPATH": str(build_project),
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "CLAWGAP_HERMES_L2_EVENT_PATH": str(directory / "events.raw.jsonl"),
        "CLAWGAP_HERMES_L2_COMPLETE_PATH": str(directory / "complete"),
        "CLAWGAP_HERMES_L2_CANDIDATE_ID": _candidate_id(case),
        "CLAWGAP_HERMES_L2_CASE_ID": _case_id(case),
        "CLAWGAP_HERMES_L2_ATTEMPT": str(attempt),
        "CLAWGAP_HERMES_L2_ROLE": role,
        "CLAWGAP_HERMES_L2_CORRELATION_ID": f"{_case_id(case)}:{attempt}:{role}",
        "CLAWGAP_HERMES_L2_FIXTURE_ID": fixture_id,
        "CLAWGAP_HERMES_L2_FAMILY": family,
        "CLAWGAP_HERMES_L2_PROVIDER_KEY": PROVIDER_CREDENTIAL,
        "CLAWGAP_HERMES_L2_HANDLER_ANCHOR": anchors.get("handler", ""),
        "CLAWGAP_HERMES_L2_SINK_ANCHOR": _sink_anchor(case),
        "CLAWGAP_HERMES_L2_ENTRYPOINT": _entrypoint_mode(case),
        "CLAWGAP_HERMES_L2_ARGUMENT_PATH": "path",
        "CLAWGAP_HERMES_L2_CONTROL_SINK": "true" if _candidate_id(case) == "CAND-925c9d1319c3ccbd" else "false",
    }
    if family in {"matrix-markdown-link", "matrix-markdown-plain"}:
        environment.update(
            {
                "HERMES_SESSION_PLATFORM": "matrix",
                "MATRIX_HOMESERVER": f"http://127.0.0.1:{provider_port}",
                "MATRIX_ACCESS_TOKEN": "clawgap-matrix-loopback-mock",
                "MATRIX_USER_ID": "@clawgap:example.org",
                "MATRIX_ENCRYPTION": "false",
            }
        )
    elif family == "slack-mention":
        environment.update(
            {
                "HERMES_SESSION_PLATFORM": "slack",
                "SLACK_BOT_TOKEN": "clawgap-slack-loopback-mock",
            }
        )
    elif family == "mattermost-mention":
        environment.update(
            {
                "HERMES_SESSION_PLATFORM": "mattermost",
                "MATTERMOST_HOME_CHANNEL": "test-channel",
                "MATTERMOST_URL": f"http://127.0.0.1:{provider_port}",
                "MATTERMOST_TOKEN": "clawgap-mattermost-loopback-mock",
            }
        )
    if family == "credential-environment":
        environment.update(
            {
                "WECOM_SECRET": "clawgap-wecom-fake",
                "FEISHU_APP_SECRET": "clawgap-feishu-fake",
                "MATRIX_PASSWORD": "clawgap-matrix-fake",
            }
        )
    if family == "skill-view-traversal":
        environment["CLAWGAP_HERMES_L2_SKILLS_ROOT"] = str(home / "skills")
    return environment


def _prompt(case: Mapping[str, Any], role: str) -> str:
    return (
        "ClawGap reviewed Hermes L2 carrier. Invoke the reviewed native tool "
        f"for the {role} role without changing its arguments."
    )


def _launch_role(
    *,
    runtime: str,
    build_project: Path,
    home: Path,
    workspace: Path,
    environment: dict[str, str],
    case: Mapping[str, Any],
    timeout: int,
) -> tuple[int, str, list[str]]:
    hermes = str(build_project / ".venv/bin/hermes")
    toolset = _toolset(case)
    prompt = _prompt(case, environment["CLAWGAP_HERMES_L2_ROLE"])
    errors: list[str] = []
    if runtime == "oneshot":
        command = [
            hermes,
            "--ignore-rules",
            "--accept-hooks",
            "--model",
            MODEL_NAME,
            "--provider",
            "clawgap-loopback",
            "--toolsets",
            toolset,
            "-z",
            prompt,
        ]
    elif runtime == "chat-query-pty":
        inner = [
            hermes,
            "chat",
            "--ignore-rules",
            "--model",
            MODEL_NAME,
            "--provider",
            "clawgap-loopback",
            "--toolsets",
            toolset,
            "--quiet",
            "-q",
            prompt,
        ]
        command = ["script", "-qec", shlex.join(inner), "/dev/null"]
    elif runtime == "cron-run-tick":
        create_code = (
            "import json; from cron.jobs import create_job; "
            "job=create_job(prompt=json.loads("
            + json.dumps(json.dumps(prompt))
            + "), schedule='0 9 * * *', repeat=1, name='ClawGap L2', model="
            + json.dumps(MODEL_NAME)
            + ", provider="
            + json.dumps("clawgap-loopback")
            + ", enabled_toolsets=['terminal']); print(job['id'])"
        )
        create = _run(
            [
                str(build_project / ".venv/bin/python"),
                "-c",
                create_code,
            ],
            cwd=build_project,
            log_path=workspace / "cron-create.log",
            timeout=30,
            env={**environment, "CLAWGAP_PROMPT": prompt},
        )
        if create.returncode != 0:
            return create.returncode, create.stdout + create.stderr, ["cron job creation failed"]
        actual_job_id = create.stdout.strip().splitlines()[-1]
        for command in (
            [hermes, "cron", "run", actual_job_id],
            [hermes, "cron", "tick"],
        ):
            completed = _run(
                command,
                cwd=workspace,
                log_path=workspace / ("cron-" + command[-1] + ".log"),
                timeout=timeout,
                env=environment,
            )
            if completed.returncode != 0:
                errors.append(f"cron command failed: {command[-1]}")
                return completed.returncode, completed.stdout + completed.stderr, errors
        return 0, "cron tick completed", []
    else:
        raise ValidationError(f"unsupported Hermes runtime: {runtime}")

    process = subprocess.Popen(
        command,
        cwd=workspace,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    started = time.monotonic()
    output = ""
    while True:
        try:
            output, _ = process.communicate(timeout=0.25)
            return process.returncode, output, errors
        except subprocess.TimeoutExpired:
            complete = Path(environment["CLAWGAP_HERMES_L2_COMPLETE_PATH"])
            if complete.exists():
                _terminate_group(process)
                output, _ = process.communicate()
                return 0, output, errors
            if time.monotonic() - started >= timeout:
                _terminate_group(process)
                output, _ = process.communicate()
                errors.append("Hermes role timed out")
                return process.returncode, output, errors


def _transcript_errors(
    rows: list[Mapping[str, Any]], tool_name: str, arguments: Mapping[str, Any]
) -> list[str]:
    errors: list[str] = []
    rows = [row for row in rows if row.get("path") == "/v1/chat/completions"]
    if not 1 <= len(rows) <= 2:
        errors.append(f"provider request count drifted: {len(rows)}")
        return errors
    first = rows[0]
    body = first.get("body") or {}
    tools = body.get("tools") or []
    names = {
        str(row.get("function", {}).get("name")) for row in tools if isinstance(row, dict)
    }
    if first.get("path") != "/v1/chat/completions":
        errors.append("provider path drift")
    if body.get("model") != MODEL_NAME:
        errors.append("provider model drift")
    if first.get("authorization") != "Bearer [REDACTED_CREDENTIAL]":
        errors.append("provider authorization/redaction drift")
    if body.get("stream") is not True:
        errors.append("Hermes provider did not use reviewed native SSE mode")
    if tool_name not in names:
        errors.append("provider request did not advertise reviewed tool")
    if first.get("request_kind") != "forced-tool-call" or not first.get("valid"):
        errors.append("first provider exchange was not the forced tool call")
    if len(rows) > 1 and rows[1].get("request_kind") != "continuation":
        errors.append("provider continuation accounting drift")
    return errors


def _normalize_events(
    raw: list[Mapping[str, Any]],
    provider_rows: list[Mapping[str, Any]],
    case: Mapping[str, Any],
    attempt: int,
    role: str,
    fixture: Mapping[str, Any],
    process_exit: int,
    cleanup_errors: list[str],
) -> list[dict[str, Any]]:
    identity = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "candidate_id": _candidate_id(case),
        "case_id": _case_id(case),
        "attempt": attempt,
        "role": role,
        "correlation_id": f"{_case_id(case)}:{attempt}:{role}",
        "fixture_id": f"hermes-agent-l2:{_case_id(case)}:{role}",
        "process_identity": "hermes-agent",
    }
    prefix = [
        ("case_bound", {"runtime_family": _family(case)}, "campaign-input"),
        ("source_verified", {"revision": case.get("revision")}, "benchmark/python/hermes-agent"),
        ("fixture_prepared", dict(fixture), "fixture-manifest"),
        ("launch_started", {"entrypoint": _entrypoint_mode(case)}, "hermes"),
    ]
    provider_events: list[tuple[str, dict[str, Any], str]] = []
    provider_rows = [
        row for row in provider_rows if row.get("path") == "/v1/chat/completions"
    ]
    if provider_rows:
        first = provider_rows[0]
        messages = (first.get("body") or {}).get("messages") or []
        provider_events.append(
            (
                "prompt_received",
                {"messages": messages, "entrypoint": _entrypoint_mode(case)},
                "hermes_cli/oneshot.py:124",
            )
        )
        provider_events.append(
            (
                "provider_request",
                {
                    "path": first.get("path"),
                    "model": (first.get("body") or {}).get("model"),
                    "stream": (first.get("body") or {}).get("stream"),
                    "authorization": first.get("authorization"),
                },
                "hermes_cli/runtime_provider.py:1",
            )
        )
        provider_events.append(
            (
                "provider_tool_call_or_decision",
                {
                    "tool_name": _native_tool(case),
                    "arguments": _role_arguments(case, role),
                },
                "hermes_cli/runtime_provider.py:1",
            )
        )
    rows: list[dict[str, Any]] = []

    def add(stage: str, detail: Mapping[str, Any], anchor: Any) -> None:
        row = dict(identity)
        row.update(
            {
                "event_id": f"HE-{len(rows) + 1:06d}-{_candidate_id(case)}",
                "stage": stage,
                "source_anchor": str(anchor or ""),
                "ordinal": len(rows) + 1,
                "detail": redact_value(detail, secrets=(PROVIDER_CREDENTIAL, CANARY_CONTENT)),
            }
        )
        rows.append(row)

    for stage, detail, anchor in prefix:
        add(stage, detail, anchor)
    for stage, detail, anchor in provider_events:
        add(stage, detail, anchor)
    ordered_raw = sorted(raw, key=lambda row: int(row.get("ordinal", 0)))
    gate_positions = [
        index for index, row in enumerate(ordered_raw)
        if row.get("stage") == "gate_observed"
    ]
    first_sink_position = next(
            (
                index
                for index, row in enumerate(ordered_raw)
                if row.get("stage") == "sink_reached"
            ),
            len(ordered_raw),
        )
    gates_before_sink = (
        [index for index in gate_positions if index < first_sink_position]
        if any(row.get("stage") == "sink_reached" for row in ordered_raw)
        else gate_positions
    )
    has_sink = any(row.get("stage") == "sink_reached" for row in ordered_raw)
    selected_gate_positions = {
        next(
            (
                index
                for index in gates_before_sink
                if has_sink
                and ordered_raw[index].get("detail", {}).get("name")
                == "check_all_command_guards"
            ),
            gates_before_sink[0] if gates_before_sink else -1,
        )
    }
    for index, event in enumerate(ordered_raw):
        if (
            event.get("stage") == "gate_observed"
            and index not in selected_gate_positions
        ):
            continue
        add(
            str(event.get("stage")),
            event.get("detail") or {},
            event.get("source_anchor"),
        )
    if not any(row["stage"] == "target_completed" for row in rows):
        add("target_completed", {"process_exit": process_exit}, "harness")
    add(
        "cleanup_verified",
        {"errors": cleanup_errors, "process_exit": process_exit},
        "harness",
    )
    return rows


def _evaluate_pair(
    case: Mapping[str, Any],
    role: str,
    events: list[Mapping[str, Any]],
    fixture: HermesProviderServer,
    provider_rows: list[Mapping[str, Any]],
    process_exit: int,
    cleanup_errors: list[str],
) -> PairOutcome:
    errors: list[str] = []
    stages = [str(row.get("stage")) for row in events]
    expected_prefix = [
        stage
        for stage in NORMALIZED_STAGES
        if stage
        not in {
            "sink_reached",
            "pre_effect_interception",
            "target_completed",
            "cleanup_verified",
        }
    ]
    if role == "control" and _candidate_id(case) == "CAND-925c9d1319c3ccbd":
        expected_prefix.extend(["sink_reached", "pre_effect_interception"])
    expected_prefix.extend(["target_completed", "cleanup_verified"])
    position = 0
    for stage in expected_prefix:
        try:
            position = stages.index(stage, position) + 1
        except ValueError:
            errors.append(f"missing stage: {stage}")
    if len(stages) != len(set(stages)):
        errors.append("normalized stages are not unique")
    if [row.get("ordinal") for row in events] != list(range(1, len(events) + 1)):
        errors.append("event ordinals are not contiguous")
    if process_exit != 0:
        errors.append(f"process exited {process_exit}")
    if cleanup_errors:
        errors.extend(cleanup_errors)
    if fixture.unsupported:
        errors.append("unsupported provider endpoint: " + ", ".join(fixture.unsupported))
    errors.extend(_transcript_errors(provider_rows, _native_tool(case), _role_arguments(case, role)))
    if (
        role == "exploit"
        and _family(case)
        not in {"interactive-shell-pattern", "cron-approval"}
        and "sink_reached" not in stages
    ):
        errors.append("exploit carrier failed before the cited sink")
    for row in events:
        for field in (
            "candidate_id",
            "case_id",
            "attempt",
            "role",
            "correlation_id",
            "fixture_id",
            "ordinal",
        ):
            if row.get(field) in {None, ""}:
                errors.append(f"event identity missing {field}")
                break

    triggered = False
    if role == "exploit":
        family = _family(case)
        sink = next((row for row in events if row.get("stage") == "sink_reached"), None)
        controlled = next(
            (row for row in events if row.get("stage") == "controlled_argument_recorded"), None
        )
        if sink is None:
            triggered = False
        elif family == "device-read":
            triggered = sink.get("detail", {}).get("canonical_exploit_path") == "/dev/zero"
        elif family == "interactive-shell-pattern":
            gate = next((row for row in events if row.get("stage") == "gate_observed"), None)
            triggered = bool(gate and gate.get("detail", {}).get("approved")) and "eval" in str(
                controlled.get("detail", {}).get("value", "")
            )
        elif family == "cron-approval":
            gate = next((row for row in events if row.get("stage") == "gate_observed"), None)
            triggered = (
                bool(gate and gate.get("detail", {}).get("approved"))
                and gate.get("detail", {}).get("cron_session") is True
                and gate.get("detail", {}).get("yolo") is False
            )
        elif family == "credential-environment":
            triggered = set(
                sink.get("detail", {}).get("credential_keys_present", [])
            ) == {"WECOM_SECRET", "FEISHU_APP_SECRET", "MATRIX_PASSWORD"}
        elif family == "execute-code":
            triggered = controlled is not None
        elif family in {"interactive-shell-pattern", "cron-approval", "credential-environment"}:
            triggered = sink is not None
        elif family == "browser-eval":
            triggered = str(controlled.get("detail", {}).get("value", "")) in str(
                sink.get("detail", {}).get("command", "")
            )
        elif family == "matrix-markdown-link":
            triggered = 'href="javascript:alert(1)"' in str(
                sink.get("detail", {}).get("formatted_body", "")
            )
        elif family == "matrix-markdown-plain":
            html = str(sink.get("detail", {}).get("formatted_body", ""))
            triggered = "javascript:alert(1)" in html and "<a" in html
        elif family in {"slack-mention", "mattermost-mention"}:
            detail = sink.get("detail", {})
            triggered = detail.get("mention_present") is True and not detail.get(
                "allowed_mentions_present", False
            )
        elif family == "skill-view-traversal":
            detail = sink.get("detail", {})
            triggered = detail.get("outside_skills_root") is True and detail.get(
                "realpath", ""
            ).endswith("/.env")
    return PairOutcome(not errors, bool(triggered), errors)


def _cleanup_role(runtime_root: Path, home: Path, workspace: Path) -> list[str]:
    errors: list[str] = []
    last_error: OSError | None = None
    for _ in range(30):
        try:
            _remove_path(runtime_root)
            last_error = None
        except OSError as exc:  # pragma: no cover - exercised under interpreter shutdown races
            last_error = exc
        if not runtime_root.exists():
            break
        time.sleep(0.1)
    if last_error is not None:
        errors.append(f"cleanup failed for {runtime_root}: {last_error}")
    if runtime_root.exists():
        errors.append(f"disposable Hermes root remains: {runtime_root}")
    if home.exists() or workspace.exists():
        errors.append("disposable Hermes roots remain")
    return errors


def _run_role_attempt(
    case: Mapping[str, Any],
    role: str,
    attempt: int,
    directory: Path,
    build_project: Path,
    request: HermesAgentL2RunRequest,
) -> tuple[PairOutcome, list[dict[str, Any]]]:
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    event_path = directory / "events.raw.jsonl"
    transcript_path = directory / "provider-transcript.jsonl"
    runtime_root = Path(tempfile.mkdtemp(prefix="clawgap-hermes-l2-", dir="/tmp"))
    home = runtime_root / "home"
    workspace = runtime_root / "workspace"
    _remove_path(home)
    _remove_path(workspace)
    workspace.mkdir(parents=True)
    (workspace / "tmp").mkdir()
    family = _family(case)
    fixture = HermesProviderServer(
        role=role,
        tool_name=_native_tool(case),
        arguments=_role_arguments(case, role),
        transcript_path=transcript_path,
    )
    fixture.start()
    process_exit = -1
    output = ""
    launch_errors: list[str] = []
    try:
        _write_config(home, fixture.port, family)
        fixture_manifest = _prepare_fixture(home, workspace, family)
        atomic_write_json(directory / "fixture-manifest.json", fixture_manifest)
        environment = _base_environment(
            directory=directory,
            home=home,
            workspace=workspace,
            build_project=build_project,
            case=case,
            role=role,
            attempt=attempt,
            fixture_id=f"hermes-agent-l2:{_case_id(case)}:{role}",
            provider_port=fixture.port,
            family=family,
        )
        if family in {"interactive-shell-pattern", "cron-approval", "credential-environment"}:
            environment["CLAWGAP_HERMES_L2_ARGUMENT_PATH"] = "command"
        elif family == "execute-code":
            environment["CLAWGAP_HERMES_L2_ARGUMENT_PATH"] = "code"
        elif family == "browser-eval":
            environment["CLAWGAP_HERMES_L2_ARGUMENT_PATH"] = "expression"
        elif family in {
            "matrix-markdown-link",
            "matrix-markdown-plain",
            "slack-mention",
            "mattermost-mention",
        }:
            environment["CLAWGAP_HERMES_L2_ARGUMENT_PATH"] = "message"
        atomic_write_json(directory / "launch-environment.keys.json", sorted(environment))
        process_exit, output, launch_errors = _launch_role(
            runtime=_entrypoint_mode(case),
            build_project=build_project,
            home=home,
            workspace=workspace,
            environment=environment,
            case=case,
            timeout=request.timeout,
        )
        atomic_write_text(directory / "launch.log", redact_text(output, secrets=(PROVIDER_CREDENTIAL,)))
    except Exception as exc:
        launch_errors.append(f"{type(exc).__name__}: {exc}")
        atomic_write_text(
            directory / "launch.log",
            redact_text(output + f"\nCLAWGAP_ERROR: {type(exc).__name__}: {exc}\n"),
        )
    finally:
        fixture.stop()

    raw_events = _read_jsonl(event_path)
    provider_rows = _read_jsonl(transcript_path)
    cleanup_errors = _cleanup_role(runtime_root, home, workspace)
    try:
        events = _normalize_events(
            raw_events,
            provider_rows,
            case,
            attempt,
            role,
            fixture_manifest,
            process_exit,
            cleanup_errors,
        )
        _write_jsonl(directory / "events.jsonl", events)
        outcome = _evaluate_pair(
            case,
            role,
            events,
            fixture,
            provider_rows,
            process_exit,
            [*cleanup_errors, *launch_errors],
        )
        return outcome, events
    except Exception as exc:
        return PairOutcome(False, False, [f"{type(exc).__name__}: {exc}"]), []


def _candidate_disposition(outcomes: list[PairOutcome]) -> tuple[str, str]:
    if any(not outcome.healthy for outcome in outcomes):
        return "inconclusive", "one or more paired attempts had infrastructure or trace failures"
    if all(outcome.triggered for outcome in outcomes):
        return "runtime-confirmed", "all paired forced-provider E2E attempts satisfied the oracle"
    if not any(outcome.triggered for outcome in outcomes):
        return "not-reproduced", "all paired attempts completed without the exploit witness"
    return "inconclusive", "paired exploit outcomes were inconsistent"


def _artifact_credential_scan(root: Path) -> str:
    text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in root.rglob("*")
        if path.is_file() and path.suffix in {".json", ".jsonl", ".md", ".txt", ".log"}
    )
    return "failed" if contains_credentials(text) else "passed"


def _artifact_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): sha256_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "manifest.json"
    }


def _reproduction_command(request: HermesAgentL2RunRequest) -> str:
    command = (
        "python -m src.runtime_validation run-dynamic-trigger-hermes-agent-l2"
        f" --out-dir {request.out_dir} --attempts {request.attempts}"
    )
    if request.campaign.resolve() != DEFAULT_SOURCE_CAMPAIGN.resolve():
        command += f" --campaign {request.campaign}"
    if request.candidate_id is not None:
        command += f" --candidate-id {request.candidate_id}"
    return command


def run_hermes_agent_l2(request: HermesAgentL2RunRequest) -> dict[str, Any]:
    started = time.time()
    if request.attempts < 1 or request.timeout < 5 or request.build_timeout < 5:
        raise ValidationError("Hermes targeted L2 timeouts and attempts must be positive")
    request.out_dir.resolve().mkdir(parents=True, exist_ok=True)
    cases = _select_cases(request.campaign.resolve(), request.candidate_id)
    source_bindings = _source_bindings(cases)
    build_dir = (
        request.build_dir.resolve() if request.build_dir else request.out_dir.resolve() / "build"
    )
    build_manifest = _prepare_build(build_dir, source_bindings, request.build_timeout)
    build_project = build_dir / "project"
    if request.build_dir is not None:
        published = request.out_dir.resolve() / "build"
        _remove_path(published)
        published.mkdir(parents=True)
        shutil.copyfile(
            build_dir / "transformed-source-manifest.json",
            published / "transformed-source-manifest.json",
        )
    else:
        shutil.copyfile(
            build_dir / "transformed-source-manifest.json",
            request.out_dir.resolve() / "transformed-source-manifest.json",
        )

    results: list[dict[str, Any]] = []
    for case in cases:
        pair_outcomes: list[PairOutcome] = []
        for attempt in range(1, request.attempts + 1):
            role_outcomes: dict[str, PairOutcome] = {}
            for role in ("exploit", "control"):
                directory = (
                    request.out_dir
                    / "runs"
                    / _case_id(case)
                    / f"attempt-{attempt}"
                    / role
                )
                outcome, _events = _run_role_attempt(
                    case, role, attempt, directory, build_project, request
                )
                role_outcomes[role] = outcome
            exploit = role_outcomes["exploit"]
            control = role_outcomes["control"]
            pair_outcomes.append(
                PairOutcome(
                    exploit.healthy and control.healthy,
                    exploit.healthy and control.healthy and exploit.triggered,
                    [*exploit.errors, *control.errors],
                )
            )
        disposition, reason = _candidate_disposition(pair_outcomes)
        results.append(
            {
                "schema_version": RESULT_SCHEMA_VERSION,
                "campaign_id": CAMPAIGN_ID,
                "candidate_id": _candidate_id(case),
                "case_id": _case_id(case),
                "project": "hermes-agent",
                "disposition": disposition,
                "evidence_tier": L2_EVIDENCE_TIER,
                "runtime_source_revision": RUNTIME_SOURCE_REVISION,
                "base_analysis_revision": PROJECT.analysis_revision,
                "attempts": request.attempts,
                "reason": reason,
                "attempt_errors": [row.errors for row in pair_outcomes if row.errors],
                "payload_repair_applied": False,
                "trace_accounting": {
                    "expected": request.attempts * 2,
                    "valid": sum(row.healthy for row in pair_outcomes) * 2,
                    "blocked": sum(not row.healthy for row in pair_outcomes) * 2,
                    "not_launched": 0 if all(row.healthy for row in pair_outcomes) else request.attempts * 2,
                },
                "runtime_chain": {
                    "entrypoint": _entrypoint_mode(case),
                    "provider": "openai-chat-completions-sse",
                    "native_dispatch": "tools.registry.ToolRegistry.dispatch",
                    "handler": _native_tool(case),
                    "sink_anchor": _sink_anchor(case),
                    "pre_effect_interception": True,
                },
            }
        )
    _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
    counts = Counter(str(row["disposition"]) for row in results)
    credential_scan = _artifact_credential_scan(request.out_dir.resolve())
    sweep_deadline = time.monotonic() + 10
    stable_since: float | None = None
    while time.monotonic() < sweep_deadline:
        residual = list(Path("/tmp").glob("clawgap-hermes-l2-*"))
        for path in residual:
            try:
                _remove_path(path)
            except OSError:
                pass
        if not any(Path("/tmp").glob("clawgap-hermes-l2-*")):
            stable_since = stable_since or time.monotonic()
            if time.monotonic() - stable_since >= 1:
                break
        else:
            stable_since = None
        time.sleep(0.1)
    disposable_roots_removed = all(
        not path.exists()
        for path in (request.out_dir / "runs").glob("*/attempt-*/*/runtime-home")
    ) and not any(Path("/tmp").glob("clawgap-hermes-l2-*"))
    if credential_scan != "passed" or not disposable_roots_removed:
        for row in results:
            row["disposition"] = "inconclusive"
            row["reason"] = "campaign-level credential or cleanup gate failed"
        _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
        counts = Counter({"inconclusive": len(results)})
    manifest = {
        "schema_version": "clawgap-dynamic-trigger-hermes-agent-l2-manifest/v1",
        "campaign_id": CAMPAIGN_ID,
        "source_campaign": str(request.campaign),
        "candidate_count": len(results),
        "attempt_pairs": request.attempts,
        "status_counts": dict(counts),
        "evidence_tier": L2_EVIDENCE_TIER,
        "targeted_only": True,
        "canonical_all_candidate_l2": False,
        "source_bindings": source_bindings,
        "source_drift": False,
        "transformed_source_manifest": build_manifest,
        "credential_scan": credential_scan,
        "disposable_workspaces_removed": disposable_roots_removed,
        "artifact_sha256": _artifact_hashes(request.out_dir.resolve()),
        "harness_bindings": {
            "src/runtime_validation/hermes_agent_l2.py": sha256_file(Path(__file__).resolve())
        },
        "reproduction_command": _reproduction_command(request),
        "started_at": datetime.fromtimestamp(started, timezone.utc).isoformat(),
        "completed_at": _utc_now(),
    }
    atomic_write_json(request.out_dir.resolve() / "manifest.json", manifest)
    return manifest

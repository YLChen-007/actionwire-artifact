"""Prompt-to-sink value tracer injected into the real Hermes target process."""

from __future__ import annotations

import fcntl
import inspect
import json
import os
import shlex
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from types import FrameType
from typing import Any, Mapping

from .propagation_contracts import PROPAGATION_EVENT_SCHEMA_VERSION, stable_value_id


_INSTALLED = False
_CASE: dict[str, Any] = {}
_EVENT_PATH: Path | None = None
_ROLE = ""
_TIER = ""
_ATTEMPT = 0
_CAMPAIGN_ID = ""
_CASE_ID = ""
_CORRELATION_ID = ""
_EXPECTED = ""
_VALUE_ID = ""
_GATE_FRAMES: set[int] = set()
_ORIGINAL_POPEN = subprocess.Popen
_ORIGINAL_CONNECT = socket.socket.connect
_ORIGINAL_CONNECT_EX = socket.socket.connect_ex


class PropagationSinkIntercepted(RuntimeError):
    """Raised immediately before the matching child process could be created."""


def _append(stage: str, kind: str, relation: str, **details: Any) -> None:
    if _EVENT_PATH is None:
        return
    row = {
        "schema_version": PROPAGATION_EVENT_SCHEMA_VERSION,
        "event_id": f"PE-{uuid.uuid4().hex}",
        "stage": stage,
        "kind": kind,
        "relation": relation,
        "monotonic_ns": time.monotonic_ns(),
        "pid": os.getpid(),
        "thread_id": threading.get_ident(),
        "tier": _TIER,
        "attempt": _ATTEMPT,
        "role": _ROLE,
        "campaign_id": _CAMPAIGN_ID,
        "case_id": _CASE_ID,
        "correlation_id": _CORRELATION_ID,
        "value_id": _VALUE_ID,
        "details": details,
    }
    payload = (json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode()
    _EVENT_PATH.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(_EVENT_PATH, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _file(frame: FrameType) -> str:
    return frame.f_code.co_filename.replace("\\", "/")


def _matches(frame: FrameType, suffix: str, function: str) -> bool:
    filename = _file(frame)
    return (
        (filename == suffix or filename.endswith("/" + suffix))
        and frame.f_code.co_name == function
    )


def _equals(value: Any) -> bool:
    return isinstance(value, str) and value == _EXPECTED


def _contains(value: Any) -> bool:
    return shlex.quote(_EXPECTED) in str(value)


def _trace(frame: FrameType, event: str, arg: Any):
    try:
        if event == "call":
            if _TIER == "mocked-provider-e2e" and _matches(
                frame, "hermes_cli/oneshot.py", "run_oneshot"
            ) and _contains(frame.f_locals.get("prompt")):
                _append("prompt_received", "prompt", "equals", value=_EXPECTED)
            elif _matches(frame, "tools/registry.py", "dispatch"):
                arguments = frame.f_locals.get("args")
                if (
                    frame.f_locals.get("name") == "read_file"
                    and isinstance(arguments, Mapping)
                    and _equals(arguments.get("path"))
                ):
                    _append("registry_dispatch", "dispatch", "equals", value=_EXPECTED)
            elif _matches(frame, "tools/file_tools.py", "_handle_read_file"):
                arguments = frame.f_locals.get("args")
                if isinstance(arguments, Mapping) and _equals(arguments.get("path")):
                    _append("handler_argument", "handler", "equals", value=_EXPECTED)
            elif _matches(frame, "tools/file_tools.py", "read_file_tool") and _equals(
                frame.f_locals.get("path")
            ):
                _append("read_file_argument", "propagation", "equals", value=_EXPECTED)
            elif _matches(frame, "tools/file_tools.py", "_is_blocked_device") and _equals(
                frame.f_locals.get("filepath")
            ):
                _GATE_FRAMES.add(id(frame))
                _append("gate_input", "gate-input", "equals", value=_EXPECTED)
            elif _matches(frame, "tools/file_operations.py", "read_file") and _equals(
                frame.f_locals.get("path")
            ):
                _append("shell_read_argument", "propagation", "equals", value=_EXPECTED)
            elif _matches(frame, "tools/file_operations.py", "_exec") and _contains(
                frame.f_locals.get("command")
            ):
                _append(
                    "shell_exec_command",
                    "propagation",
                    "contains-shell-quoted-value",
                    value=_EXPECTED,
                    command=str(frame.f_locals.get("command"))[:4000],
                )
            elif _matches(frame, "tools/environments/base.py", "execute") and _contains(
                frame.f_locals.get("command")
            ):
                _append(
                    "environment_execute_command",
                    "propagation",
                    "contains-shell-quoted-value",
                    value=_EXPECTED,
                    command=str(frame.f_locals.get("command"))[:4000],
                )
            elif _matches(frame, "tools/environments/local.py", "_run_bash") and _contains(
                frame.f_locals.get("cmd_string")
            ):
                _append(
                    "local_run_bash_command",
                    "propagation",
                    "contains-shell-quoted-value",
                    value=_EXPECTED,
                    command=str(frame.f_locals.get("cmd_string"))[:4000],
                )
        elif event == "return" and id(frame) in _GATE_FRAMES:
            _GATE_FRAMES.remove(id(frame))
            _append(
                "gate_return",
                "gate-return",
                "gate-return",
                value=_EXPECTED,
                return_value=bool(arg),
            )
    except Exception as exc:
        try:
            _append(
                "instrumentation_error",
                "propagation",
                "equals",
                error=f"{type(exc).__name__}: {exc}",
            )
        except Exception:
            pass
    return _trace


def _popen_payload(args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> str:
    value = args[0] if args else kwargs.get("args", kwargs)
    return repr(value)[:8000]


def _matching_sink_stack() -> bool:
    return any(
        _matches(item.frame, "tools/environments/local.py", "_run_bash")
        and item.lineno == 413
        for item in inspect.stack(context=0)
    )


def _instrumented_popen(*args: Any, **kwargs: Any):
    payload = _popen_payload(args, kwargs)
    if _EXPECTED in payload and _matching_sink_stack():
        _append(
            "popen_sink_argument",
            "sink",
            "contains-shell-quoted-value",
            value=_EXPECTED,
            payload=payload,
        )
        _append(
            "sink_intercepted",
            "sink-intercepted",
            "contains-shell-quoted-value",
            value=_EXPECTED,
            process_created=False,
        )
        raise PropagationSinkIntercepted(
            "ClawGap intercepted matching Popen before process creation"
        )
    return _ORIGINAL_POPEN(*args, **kwargs)


def _loopback(address: Any) -> bool:
    if isinstance(address, str):
        return True  # AF_UNIX
    if not isinstance(address, tuple) or not address:
        return False
    return str(address[0]) in {"127.0.0.1", "::1", "localhost"}


def _guarded_connect(sock: socket.socket, address: Any):
    if not _loopback(address):
        raise OSError("ClawGap propagation target denies non-loopback network")
    return _ORIGINAL_CONNECT(sock, address)


def _guarded_connect_ex(sock: socket.socket, address: Any):
    if not _loopback(address):
        return 101
    return _ORIGINAL_CONNECT_EX(sock, address)


def install_from_environment() -> None:
    global _ATTEMPT, _CAMPAIGN_ID, _CASE, _CASE_ID, _CORRELATION_ID
    global _EVENT_PATH, _EXPECTED
    global _INSTALLED, _ROLE, _TIER, _VALUE_ID
    if _INSTALLED:
        return
    case_path = os.getenv("CLAWGAP_PROPAGATION_CASE_PATH", "").strip()
    event_path = os.getenv("CLAWGAP_PROPAGATION_EVENTS_PATH", "").strip()
    if not case_path or not event_path:
        raise RuntimeError("propagation case and event paths are required")
    _CASE = json.loads(Path(case_path).read_text(encoding="utf-8"))
    _EVENT_PATH = Path(event_path)
    _ROLE = os.environ["CLAWGAP_PROPAGATION_ROLE"]
    _TIER = os.environ["CLAWGAP_PROPAGATION_TIER"]
    _ATTEMPT = int(os.environ["CLAWGAP_PROPAGATION_ATTEMPT"])
    _CAMPAIGN_ID = os.environ["CLAWGAP_PROPAGATION_CAMPAIGN_ID"]
    _CASE_ID = os.environ["CLAWGAP_PROPAGATION_CASE_ID"]
    if _CASE_ID != _CASE["case_id"]:
        raise RuntimeError("propagation case identity does not match the bound case")
    _CORRELATION_ID = os.environ["CLAWGAP_PROPAGATION_CORRELATION_ID"]
    _EXPECTED = _CASE["values"][_ROLE]
    _VALUE_ID = stable_value_id(_EXPECTED)
    subprocess.Popen = _instrumented_popen  # type: ignore[assignment]
    socket.socket.connect = _guarded_connect  # type: ignore[assignment]
    socket.socket.connect_ex = _guarded_connect_ex  # type: ignore[assignment]
    sys.settrace(_trace)
    threading.settrace(_trace)
    _INSTALLED = True
    _append(
        "instrumentation_ready",
        "propagation",
        "equals",
        value=_EXPECTED,
        source_hashes=[row["sha256"] for row in _CASE["source_bindings"]],
    )

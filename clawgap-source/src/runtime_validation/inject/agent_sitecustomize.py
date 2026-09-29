"""Config-driven tracer injected into the opted-in Hermes target process.

This file is intentionally standalone: the target's first ``PYTHONPATH`` entry
contains it, while the instrumentation plan is supplied as a JSON file and never
generated from controller Python code.
"""

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


class AgentRuntimeSinkIntercepted(RuntimeError):
    """Raised before the reviewed process effect is created."""


_CONFIG: dict[str, Any] = {}
_EVENT_PATH: Path | None = None
_ERROR_PATH: Path | None = None
_OWNER_PID = 0
_INSTALLED = False
_CALL_ANCHORS: list[dict[str, Any]] = []
_GATE_ANCHORS: list[dict[str, Any]] = []
_SINK_ANCHOR: dict[str, Any] | None = None
_ACTIVE_GATES: dict[int, dict[str, Any]] = {}
_ORIGINAL_POPEN = subprocess.Popen
_ORIGINAL_CONNECT = socket.socket.connect
_ORIGINAL_CONNECT_EX = socket.socket.connect_ex


def _append(stage: str, kind: str, relation: str, **details: Any) -> None:
    if _EVENT_PATH is None:
        return
    row = {
        "schema_version": "clawgap-agent-runtime-event/v1",
        "event_id": f"AE-{uuid.uuid4().hex}",
        "campaign_id": _CONFIG["campaign_id"],
        "candidate_id": _CONFIG["candidate_id"],
        "plan_hash": _CONFIG["plan_hash"],
        "trial_id": _CONFIG["trial_id"],
        "attempt": _CONFIG["attempt"],
        "role": _CONFIG["role"],
        "correlation_id": _CONFIG["correlation_id"],
        "value_id": _CONFIG["value_id"],
        "stage": stage,
        "kind": kind,
        "relation": relation,
        "sequence": time.monotonic_ns(),
        "monotonic_ns": time.monotonic_ns(),
        "pid": os.getpid(),
        "thread_id": threading.get_ident(),
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


def _nested(value: Any, path: list[str]) -> Any:
    for item in path:
        if not isinstance(value, Mapping):
            return None
        value = value.get(item)
    return value


def _relation_matches(value: Any, relation: str, expected: str) -> bool:
    if relation == "equals":
        return isinstance(value, str) and value == expected
    if relation == "contains":
        return isinstance(value, str) and expected in value
    if relation == "contains-shell-quoted-value":
        return shlex.quote(expected) in str(value)
    if relation == "gate-return":
        return isinstance(value, str) and value == expected
    return False


def _frame_file(frame: FrameType) -> str:
    return frame.f_code.co_filename.replace("\\", "/")


def _anchor_matches(frame: FrameType, anchor: Mapping[str, Any]) -> bool:
    filename = _frame_file(frame)
    expected = str(anchor.get("file") or "")
    return (
        bool(expected)
        and (filename == expected or filename.endswith("/" + expected))
        and frame.f_code.co_name == anchor.get("function")
    )


def _trace(frame: FrameType, event: str, arg: Any):
    try:
        expected = _CONFIG["value"]
        if event == "call":
            for anchor in _CALL_ANCHORS:
                if not _anchor_matches(frame, anchor):
                    continue
                raw = _nested(frame.f_locals, list(anchor.get("argument_path") or []))
                if not _relation_matches(raw, anchor["relation"], expected):
                    if anchor["stage"] == "prompt_received":
                        _append(
                            "prompt_relation_mismatch",
                            "diagnostic",
                            "equals",
                            value=expected,
                            observed=repr(raw)[:2000],
                        )
                    continue
                if anchor["kind"] == "registry-dispatch" and frame.f_locals.get("name") != _CONFIG["tool_name"]:
                    continue
                if anchor["kind"].startswith("gate-"):
                    _ACTIVE_GATES[id(frame)] = anchor
                details: dict[str, Any] = {"value": expected}
                if isinstance(raw, str) and len(raw) <= 8000:
                    details["observed"] = raw
                elif isinstance(raw, str):
                    details["observed_prefix"] = raw[:8000]
                _append(anchor["stage"], anchor["kind"], anchor["relation"], **details)
                break
        elif event == "return":
            anchor = _ACTIVE_GATES.pop(id(frame), None)
            if anchor is not None:
                return_anchor = next(
                    (
                        item
                        for item in _GATE_ANCHORS
                        if item["file"] == anchor["file"]
                        and item["function"] == anchor["function"]
                        and item["stage"] == "gate_return"
                    ),
                    None,
                )
                if return_anchor is not None:
                    _append(
                        "gate_return",
                        return_anchor["kind"],
                        "gate-return",
                        value=expected,
                        return_value=bool(arg),
                    )
    except Exception as exc:
        try:
            _append(
                "instrumentation_error",
                "instrumentation",
                "equals",
                error=f"{type(exc).__name__}: {exc}",
            )
        except Exception:
            pass
    return _trace


def _popen_payload(args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> str:
    value = args[0] if args else kwargs.get("args", kwargs)
    return repr(value)[:12000]


def _matching_sink_stack() -> bool:
    if _SINK_ANCHOR is None:
        return False
    return any(
        _anchor_matches(item.frame, _SINK_ANCHOR)
        for item in inspect.stack(context=0)
    )


def _instrumented_popen(*args: Any, **kwargs: Any) -> Any:
    payload = _popen_payload(args, kwargs)
    expected = _CONFIG["value"]
    if _SINK_ANCHOR is not None and shlex.quote(expected) in payload and _matching_sink_stack():
        _append(
            _SINK_ANCHOR["stage"],
            _SINK_ANCHOR["kind"],
            _SINK_ANCHOR["relation"],
            value=expected,
            payload=payload,
        )
        _append(
            "sink_intercepted",
            "sink-intercepted",
            _SINK_ANCHOR["relation"],
            value=expected,
            process_created=False,
        )
        raise AgentRuntimeSinkIntercepted(
            "ClawGap intercepted the reviewed Hermes effect before process creation"
        )
    return _ORIGINAL_POPEN(*args, **kwargs)


def _loopback(address: Any) -> bool:
    if isinstance(address, str):
        return address.startswith("/") or address.startswith("@"
        )
    if not isinstance(address, tuple) or not address:
        return False
    return str(address[0]) in {"127.0.0.1", "::1", "localhost"}


def _guarded_connect(sock: socket.socket, address: Any) -> Any:
    if not _loopback(address):
        raise OSError("ClawGap agent runtime denies non-loopback network access")
    return _ORIGINAL_CONNECT(sock, address)


def _guarded_connect_ex(sock: socket.socket, address: Any) -> int:
    if not _loopback(address):
        return 101
    return _ORIGINAL_CONNECT_EX(sock, address)


def install_from_environment() -> None:
    global _ACTIVE_GATES, _CALL_ANCHORS, _CONFIG, _EVENT_PATH, _ERROR_PATH
    global _GATE_ANCHORS, _INSTALLED, _OWNER_PID, _SINK_ANCHOR
    config_path = os.getenv("CLAWGAP_AGENT_INSTRUMENTATION_PATH", "").strip()
    event_path = os.getenv("CLAWGAP_AGENT_EVENTS_PATH", "").strip()
    if not config_path or not event_path:
        raise RuntimeError("agent instrumentation and event paths are required")
    _CONFIG = json.loads(Path(config_path).read_text(encoding="utf-8"))
    _EVENT_PATH = Path(event_path)
    _ERROR_PATH = Path(os.getenv("CLAWGAP_RUNTIME_ERROR_PATH", ""))
    _OWNER_PID = int(_CONFIG["owner_pid"])
    if os.getpid() != _OWNER_PID:
        return
    if _INSTALLED:
        return
    anchors = list(_CONFIG.get("anchors") or [])
    if not anchors:
        raise RuntimeError("instrumentation plan has no anchors")
    _CALL_ANCHORS = [
        row
        for row in anchors
        if row.get("file")
        and row.get("function")
        and row.get("stage") != "gate_return"
    ]
    _GATE_ANCHORS = [row for row in anchors if row.get("stage") == "gate_return"]
    _SINK_ANCHOR = next(
        (row for row in anchors if row.get("kind") == "process-sink"), None
    )
    if _SINK_ANCHOR is None:
        raise RuntimeError("instrumentation plan has no terminal process sink")
    subprocess.Popen = _instrumented_popen  # type: ignore[assignment]
    socket.socket.connect = _guarded_connect  # type: ignore[assignment]
    socket.socket.connect_ex = _guarded_connect_ex  # type: ignore[assignment]
    sys.settrace(_trace)
    threading.settrace(_trace)
    _INSTALLED = True
    _append(
        "instrumentation_ready",
        "instrumentation",
        "equals",
        value=_CONFIG["value"],
        source_hashes=[row["sha256"] for row in _CONFIG["source_bindings"]],
        owner_pid=_OWNER_PID,
    )

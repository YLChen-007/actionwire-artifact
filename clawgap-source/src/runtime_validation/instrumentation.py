"""Injected Python tracer and narrow sink interceptor.

This module is imported inside the target agent process by ``sitecustomize``.
It intentionally depends only on the Python standard library.
"""

from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import FrameType
from typing import Any, Mapping

from .contracts import EVENT_SCHEMA_VERSION, redact_value


_LOCK = threading.Lock()
_TLS = threading.local()
_INSTALLED = False
_SEQUENCE = 0
_INVOCATIONS = 0
_ORACLE: dict[str, Any] = {}
_EVENT_PATH: Path | None = None
_REDACTIONS: tuple[str, ...] = ()
_ORIGINAL_POPEN = subprocess.Popen


class RuntimeEffectIntercepted(RuntimeError):
    """Raised in the target after evidence is recorded and before the effect."""


def _next_sequence() -> int:
    global _SEQUENCE
    with _LOCK:
        _SEQUENCE += 1
        return _SEQUENCE


def _next_invocation_id() -> str:
    global _INVOCATIONS
    with _LOCK:
        _INVOCATIONS += 1
        value = _INVOCATIONS
    return f"{os.getpid()}-{threading.get_ident()}-{value}"


def _append_event(
    event: str, *, invocation_id: str | None = None, **details: Any
) -> None:
    path = _EVENT_PATH
    if path is None:
        return
    sequence = _next_sequence()
    row = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": f"E-{os.getpid()}-{sequence}",
        "event": event,
        "sequence": sequence,
        "monotonic_ns": time.monotonic_ns(),
        "pid": os.getpid(),
        "thread_id": threading.get_ident(),
        "invocation_id": invocation_id,
        "details": redact_value(details, _REDACTIONS),
    }
    payload = (json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    with _LOCK:
        descriptor = os.open(path, flags, 0o600)
        try:
            os.write(descriptor, payload)
        finally:
            os.close(descriptor)


def _frame_matches(frame: FrameType, matcher: Mapping[str, Any]) -> bool:
    filename = frame.f_code.co_filename.replace("\\", "/")
    expected_file = str(matcher["file"]).replace("\\", "/")
    if not filename.endswith("/" + expected_file) and filename != expected_file:
        return False
    function = frame.f_code.co_name
    qualified = getattr(frame.f_code, "co_qualname", function)
    expected = str(matcher["function"])
    return (
        function == expected
        or qualified == expected
        or qualified.endswith("." + expected)
    )


def _nested_value(value: Any, path: list[str]) -> Any:
    current = value
    for key in path:
        if isinstance(current, Mapping):
            current = current.get(key)
        else:
            return None
    return current


def _trigger_match(raw: Any) -> tuple[bool, str | None]:
    if not isinstance(raw, str) or not raw:
        return False, None
    trigger = _ORACLE["trigger"]
    normalized = raw
    for transform in trigger["transforms"]:
        if transform == "expanduser":
            normalized = os.path.expanduser(normalized)
        elif transform == "normpath":
            normalized = os.path.normpath(normalized)
        else:
            return False, None
    if normalized not in trigger["targets"]:
        return False, normalized
    if trigger.get("require_changed", False) and normalized == raw:
        return False, normalized
    return True, normalized


def _contexts() -> list[dict[str, Any]]:
    value = getattr(_TLS, "contexts", None)
    if value is None:
        value = []
        _TLS.contexts = value
    return value


def _gate_frames() -> dict[int, dict[str, Any]]:
    value = getattr(_TLS, "gate_frames", None)
    if value is None:
        value = {}
        _TLS.gate_frames = value
    return value


def _active_context() -> dict[str, Any] | None:
    contexts = _contexts()
    return contexts[-1] if contexts else None


def _trace(frame: FrameType, event: str, arg: Any):
    try:
        if event == "call" and _frame_matches(frame, _ORACLE["handler"]):
            raw = _nested_value(
                frame.f_locals, list(_ORACLE["handler"]["argument_path"])
            )
            matches, normalized = _trigger_match(raw)
            if matches:
                invocation_id = _next_invocation_id()
                context = {
                    "frame_id": id(frame),
                    "invocation_id": invocation_id,
                    "raw_argument": raw,
                    "normalized_argument": normalized,
                    "gate_matched": False,
                }
                _contexts().append(context)
                _append_event(
                    "handler_argument_matched",
                    invocation_id=invocation_id,
                    function=_ORACLE["handler"]["function"],
                    raw_argument=raw,
                    normalized_argument=normalized,
                )
        elif event == "call" and _frame_matches(frame, _ORACLE["gate"]):
            context = _active_context()
            if context is not None:
                gate_raw = frame.f_locals.get(_ORACLE["gate"]["argument_name"])
                if gate_raw == context["raw_argument"]:
                    _gate_frames()[id(frame)] = context
        elif event == "return":
            gate_context = _gate_frames().pop(id(frame), None)
            if gate_context is not None:
                if (
                    arg is _ORACLE["gate"]["expected_return"]
                    or arg == _ORACLE["gate"]["expected_return"]
                ):
                    gate_context["gate_matched"] = True
                    _append_event(
                        "gate_returned_expected",
                        invocation_id=gate_context["invocation_id"],
                        function=_ORACLE["gate"]["function"],
                        return_value=arg,
                        raw_argument=gate_context["raw_argument"],
                    )
                else:
                    _append_event(
                        "gate_returned_other",
                        invocation_id=gate_context["invocation_id"],
                        function=_ORACLE["gate"]["function"],
                        return_value=arg,
                    )
            contexts = _contexts()
            if contexts and contexts[-1]["frame_id"] == id(frame):
                contexts.pop()
    except Exception as exc:
        try:
            _append_event("instrumentation_error", error=f"{type(exc).__name__}: {exc}")
        except Exception:
            pass
    return _trace


def _sink_stack_match() -> bool:
    sink = _ORACLE["sink"]
    for frame_info in inspect.stack(context=0):
        frame = frame_info.frame
        if not _frame_matches(frame, sink):
            continue
        expected_line = sink.get("line")
        if expected_line is None or frame_info.lineno == expected_line:
            return True
    return False


def _payload_text(args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> str:
    value: object
    if args:
        value = args[0]
    else:
        value = kwargs.get("args", kwargs)
    return repr(value)[:8000]


class _InstrumentedPopen(_ORIGINAL_POPEN):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        context = _active_context()
        if context is not None and context.get("gate_matched") and _sink_stack_match():
            payload = _payload_text(args, kwargs)
            raw = context["raw_argument"]
            if (
                _ORACLE["sink"]["payload_relation"] == "contains-raw-argument"
                and raw in payload
            ):
                invocation_id = context["invocation_id"]
                _append_event(
                    "sink_reached",
                    invocation_id=invocation_id,
                    primitive=_ORACLE["sink"]["primitive"],
                    raw_argument=raw,
                    payload=payload,
                )
                _append_event(
                    "effect_intercepted",
                    invocation_id=invocation_id,
                    primitive=_ORACLE["sink"]["primitive"],
                    policy="block-before-effect",
                )
                raise RuntimeEffectIntercepted(
                    "ClawGap runtime validation intercepted the matching sink"
                )
        super().__init__(*args, **kwargs)


def install(
    oracle: Mapping[str, Any], event_path: Path, redactions: tuple[str, ...] = ()
) -> None:
    global _EVENT_PATH, _INSTALLED, _ORACLE, _REDACTIONS
    if _INSTALLED:
        return
    _ORACLE = dict(oracle)
    _EVENT_PATH = event_path
    _REDACTIONS = tuple(value for value in redactions if value)
    event_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.Popen = _InstrumentedPopen
    sys.settrace(_trace)
    threading.settrace(_trace)
    _INSTALLED = True
    _append_event(
        "instrumentation_ready",
        oracle_schema=_ORACLE.get("schema_version"),
        report_name=_ORACLE.get("report_name"),
    )


def install_from_environment() -> None:
    oracle_path = os.getenv("CLAWGAP_RUNTIME_ORACLE_PATH", "").strip()
    event_path = os.getenv("CLAWGAP_RUNTIME_EVENTS_PATH", "").strip()
    if not oracle_path and not event_path:
        return
    if not oracle_path or not event_path:
        raise RuntimeError("both runtime oracle and event paths are required")
    owner_pid = os.getenv("CLAWGAP_RUNTIME_OWNER_PID", "").strip()
    if owner_pid and owner_pid != str(os.getpid()):
        return
    os.environ["CLAWGAP_RUNTIME_OWNER_PID"] = str(os.getpid())
    oracle = json.loads(Path(oracle_path).read_text(encoding="utf-8"))
    if not isinstance(oracle, dict):
        raise RuntimeError("runtime oracle must be an object")
    raw_redactions = os.getenv("CLAWGAP_RUNTIME_REDACT_VALUES", "[]")
    redactions = json.loads(raw_redactions)
    if not isinstance(redactions, list) or not all(
        isinstance(value, str) for value in redactions
    ):
        raise RuntimeError("runtime redaction values must be a JSON string array")
    install(oracle, Path(event_path), tuple(redactions))

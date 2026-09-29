"""Source-anchor tracer for isolated Python L2 entrypoints."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path


def _initialize() -> None:
    config_path = os.environ.get("CLAWGAP_L2_INSTRUMENTATION")
    if not config_path:
        return
    try:
        config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    output = Path(config["event_path"])
    output.parent.mkdir(parents=True, exist_ok=True)
    anchors = config["anchors"]
    lock = threading.Lock()
    sequence = 0
    emitted = set()

    def write_event(kind: str, anchor: str, details: dict | None = None) -> None:
        nonlocal sequence
        with lock:
            sequence += 1
            event = {
                "schema_version": "clawgap-l2-evidence-event/v1",
                "event_id": f"{config['case_id']}:{config['attempt']}:{sequence}",
                "case_id": config["case_id"],
                "correlation_id": config["correlation_id"],
                "attempt": config["attempt"],
                "role": config["role"],
                "kind": kind,
                "stage": kind,
                "project": config.get("project"),
                "environment_id": config.get("environment_id"),
                "probe_id": config.get("probe_id"),
                "candidate_id": config.get("candidate_id"),
                "ordinal": sequence,
                "source_anchor": anchor,
                "intercept_before_execution": kind == "pre-effect",
                "details": details or {},
            }
            with output.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, sort_keys=True) + "\n")

    def trace(frame, event, arg):
        if event not in {"call", "line"}:
            return trace
        filename = frame.f_code.co_filename.replace("\\", "/")
        for anchor in anchors:
            relative = anchor["anchor"].rsplit(":", 1)[0]
            line = int(anchor["anchor"].rsplit(":", 1)[1])
            identity = (anchor["kind"], anchor["anchor"])
            if (
                filename.endswith("/" + relative)
                and frame.f_lineno == line
                and identity not in emitted
            ):
                emitted.add(identity)
                write_event(anchor["kind"], anchor["anchor"])
        return trace

    if config.get("trace_enabled", True):
        sys.settrace(trace)
        threading.settrace(trace)

    if config.get("intercept_effects") and any(row["kind"] == "pre-effect" for row in anchors):
        class InterceptedPopen(subprocess.Popen):
            def __init__(self, *args, **kwargs):
                write_event(
                    "pre-effect",
                    next(row["anchor"] for row in anchors if row["kind"] == "pre-effect"),
                    {"primitive": "subprocess.Popen", "command": str(args[0]) if args else ""},
                )
                raise RuntimeError("ClawGap intercepted subprocess.Popen before execution")

        subprocess.Popen = InterceptedPopen


_initialize()

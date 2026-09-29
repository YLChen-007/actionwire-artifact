"""Convert structured runtime events into conservative attempt verdicts."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping, Sequence

from .contracts import INCONCLUSIVE, NOT_TRIGGERED, TRIGGERED


def evaluate_events(
    events: Sequence[Mapping[str, Any]],
    oracle: Mapping[str, Any],
    *,
    trace_errors: Sequence[str] = (),
    process_status: str,
    returncode: int | None,
) -> tuple[str, str, list[str]]:
    """Require the oracle event sequence within one invocation, in order."""

    if trace_errors:
        return INCONCLUSIVE, "; ".join(trace_errors), []
    if not any(row.get("event") == "instrumentation_ready" for row in events):
        return INCONCLUSIVE, "instrumentation did not report readiness", []
    instrumentation_errors = [
        str((row.get("details") or {}).get("error", "unknown instrumentation error"))
        for row in events
        if row.get("event") == "instrumentation_error"
    ]
    if instrumentation_errors:
        return INCONCLUSIVE, "; ".join(instrumentation_errors), []

    required = list(oracle["success_events"])
    by_invocation: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for event in events:
        invocation_id = event.get("invocation_id")
        if isinstance(invocation_id, str) and invocation_id:
            by_invocation[invocation_id].append(event)

    for invocation_id, rows in sorted(by_invocation.items()):
        ordered = sorted(rows, key=lambda row: int(row.get("sequence", 0)))
        cursor = 0
        matched_ids: list[str] = []
        for row in ordered:
            if cursor < len(required) and row.get("event") == required[cursor]:
                matched_ids.append(str(row.get("event_id", "")))
                cursor += 1
        if cursor == len(required):
            return (
                TRIGGERED,
                f"invocation {invocation_id} satisfied the complete runtime oracle",
                matched_ids,
            )

    if process_status == "timeout":
        return INCONCLUSIVE, "agent process timed out before a conclusive trace", []
    if process_status not in {"completed", "terminated-after-trigger"}:
        return INCONCLUSIVE, f"agent process failed with status {process_status}", []
    if returncode not in (0, None):
        return INCONCLUSIVE, f"agent process exited with return code {returncode}", []

    observed = {str(row.get("event")) for row in events}
    if "handler_argument_matched" not in observed:
        reason = "the agent completed without invoking the target handler with a matching argument"
    elif "gate_returned_expected" not in observed:
        reason = (
            "the target argument was observed but the vulnerable gate result was not"
        )
    elif "sink_reached" not in observed:
        reason = "the vulnerable gate result was observed but the matching sink was not reached"
    else:
        reason = "the trace did not contain the complete ordered interception sequence"
    return NOT_TRIGGERED, reason, []

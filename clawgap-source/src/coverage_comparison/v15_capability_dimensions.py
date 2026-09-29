"""Versioned capability boundary/effect registry for detector v15."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Mapping, Sequence

from .contracts import CoverageComparisonError


REGISTRY_VERSION = "coverage-capability-dimension-registry/v15"
REGISTRY_PATH = Path(__file__).with_name("capability-dimensions-v15.json")
TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def load_capability_dimensions(
    path: Path = REGISTRY_PATH,
) -> dict[str, tuple[str, str, str]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CoverageComparisonError(
            f"invalid capability dimension registry: {exc}"
        ) from exc
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "classes"}:
        raise CoverageComparisonError("capability dimension registry fields mismatch")
    if raw["schema_version"] != REGISTRY_VERSION or not isinstance(
        raw["classes"], dict
    ):
        raise CoverageComparisonError("unsupported capability dimension registry")
    output: dict[str, tuple[str, str, str]] = {}
    for capability_class, values in raw["classes"].items():
        if (
            not isinstance(capability_class, str)
            or not TOKEN_RE.fullmatch(capability_class)
            or not isinstance(values, list)
            or len(values) != 3
            or any(
                not isinstance(value, str) or not TOKEN_RE.fullmatch(value)
                for value in values
            )
        ):
            raise CoverageComparisonError("invalid capability dimension registry row")
        boundary, effect, predicate = values
        output[capability_class] = (boundary, effect, predicate)
    if not output:
        raise CoverageComparisonError("capability dimension registry is empty")
    return output


CAPABILITY_DIMENSIONS = load_capability_dimensions()
PRIMARY_SINK_ROLES = {
    "adb-shell-execution": "command",
    "agent-creation": "primary-input",
    "app-launch": "primary-input",
    "approval-persistence": "primary-input",
    "approval-presentation": "content",
    "browser-content-read": "destination-url",
    "browser-interaction": "primary-input",
    "browser-nav": "destination-url",
    "browser-navigation": "destination-url",
    "card-delivery": "content",
    "clipboard-paste": "content",
    "clipboard-write": "content",
    "code-eval": "code",
    "command-execution": "command",
    "content-search": "statement",
    "delivery": "content",
    "delivery-render": "content",
    "device-file-pull": "path",
    "device-file-push": "path",
    "device-keyevent": "primary-input",
    "device-long-press": "primary-input",
    "device-swipe": "primary-input",
    "device-tap": "primary-input",
    "device-text-input": "content",
    "email-compose": "content",
    "external-agent-execution": "command",
    "external-tool-boundary": "payload",
    "file-copy": "source-path",
    "file-delete": "path",
    "file-delivery": "path",
    "file-edit": "path",
    "file-enumeration": "path",
    "file-read": "path",
    "file-read-or-write": "path",
    "file-write": "path",
    "interactive-question": "content",
    "mcp-server-registration": "command",
    "message-delivery": "content",
    "message-edit": "content",
    "message-reaction": "primary-input",
    "network-egress": "destination-url",
    "package-installation": "primary-input",
    "process-spawn": "command",
    "resource-consumption": "primary-input",
    "rpc-boundary": "payload",
    "rpc-node-invoke": "payload",
    "runtime-config-mutation": "payload",
    "screen-capture": "primary-input",
    "settings-navigation": "primary-input",
    "sql-exec": "statement",
    "subagent-delegation": "content",
    "task-cancel": "primary-input",
    "task-pause": "primary-input",
    "task-read": "primary-input",
    "task-resume": "primary-input",
    "task-scheduling": "content",
    "task-update": "content",
    "tool-capability-exposure": "payload",
    "user-consent": "command",
}


def capability_dimensions(
    capability_class: str,
    *,
    registry: Mapping[str, Sequence[str]] = CAPABILITY_DIMENSIONS,
) -> tuple[str, str, str]:
    values = registry.get(capability_class)
    if values is None or len(values) != 3:
        raise CoverageComparisonError(
            f"unregistered capability class: {capability_class}"
        )
    return str(values[0]), str(values[1]), str(values[2])


def primary_sink_role(capability_classes: Sequence[str]) -> str:
    roles = {PRIMARY_SINK_ROLES.get(value) for value in capability_classes}
    if None in roles or len(roles) != 1:
        raise CoverageComparisonError(
            f"capability classes have no common primary sink role: {sorted(capability_classes)}"
        )
    return str(next(iter(roles)))

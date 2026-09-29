"""Public request/result contracts and shared artifact helpers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


REQUEST_SCHEMA_VERSION = "clawgap-runtime-validation-request/v1"
ATTEMPT_SCHEMA_VERSION = "clawgap-runtime-validation-attempt/v1"
RUN_SCHEMA_VERSION = "clawgap-runtime-validation-run/v1"
MANIFEST_SCHEMA_VERSION = "clawgap-runtime-validation-manifest/v1"
EVENT_SCHEMA_VERSION = "clawgap-runtime-validation-event/v1"
ORACLE_SCHEMA_VERSION = "clawgap-runtime-trigger-oracle/v1"

TRIGGERED = "triggered"
NOT_TRIGGERED = "not-triggered"
INCONCLUSIVE = "inconclusive"
VERDICTS = (TRIGGERED, NOT_TRIGGERED, INCONCLUSIVE)

_CREDENTIAL_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{8,}\b", re.IGNORECASE),
    re.compile(r"(?i)(authorization[ \t]*:[ \t]*bearer[ \t]+)\S+"),
    re.compile(r"(?i)((?:api[_-]?key|auth[_-]?token)[ \t]*[:=][ \t]*)\S+"),
)


class ValidationError(ValueError):
    """Raised when a validation request or artifact violates its contract."""


@dataclass(frozen=True)
class ValidationRequest:
    """One prompt and issue to validate against a registered benchmark project."""

    project_id: str
    report_name: str
    prompt: str
    attempts: int = 1
    timeout_seconds: int = 180
    model: str | None = None
    base_url: str | None = None
    api_key_env: str | None = None
    out_dir: Path | None = None

    def __post_init__(self) -> None:
        for field_name in ("project_id", "report_name", "prompt"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValidationError(f"{field_name} must be a non-empty string")
        if self.attempts < 1:
            raise ValidationError("attempts must be at least 1")
        if self.timeout_seconds < 1:
            raise ValidationError("timeout_seconds must be at least 1")
        if self.api_key_env is not None and not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*", self.api_key_env
        ):
            raise ValidationError("api_key_env must be an environment variable name")

    def record(self) -> dict[str, Any]:
        return {
            "schema_version": REQUEST_SCHEMA_VERSION,
            "project": self.project_id,
            "report_name": self.report_name,
            "prompt": self.prompt,
            "prompt_sha256": sha256_text(self.prompt),
            "attempts": self.attempts,
            "timeout_seconds": self.timeout_seconds,
            "model": self.model,
            "base_url": self.base_url,
            "api_key_env": self.api_key_env,
        }


@dataclass(frozen=True)
class ValidationRun:
    """Final aggregate verdict and the location of its reproducible evidence."""

    run_id: str
    project_id: str
    report_name: str
    verdict: str
    reason: str
    attempts: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    artifact_dir: Path | None = None
    source_binding: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise ValidationError(f"unsupported validation verdict: {self.verdict}")

    def record(self) -> dict[str, Any]:
        return {
            "schema_version": RUN_SCHEMA_VERSION,
            "run_id": self.run_id,
            "project": self.project_id,
            "report_name": self.report_name,
            "verdict": self.verdict,
            "reason": self.reason,
            "attempts": [dict(row) for row in self.attempts],
            "source_binding": dict(self.source_binding),
            "artifact_dir": str(self.artifact_dir) if self.artifact_dir else None,
        }


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def redact_text(value: str, secrets: Iterable[str] = ()) -> str:
    """Redact credential shapes plus exact runtime secrets before persistence."""

    result = value
    for secret in sorted({item for item in secrets if item}, key=len, reverse=True):
        result = result.replace(secret, "[REDACTED_CREDENTIAL]")
    for pattern in _CREDENTIAL_PATTERNS:
        if pattern.groups:
            result = pattern.sub(r"\1[REDACTED_CREDENTIAL]", result)
        else:
            result = pattern.sub("[REDACTED_CREDENTIAL]", result)
    return result


def redact_value(value: Any, secrets: Iterable[str] = ()) -> Any:
    """Recursively redact string values in a JSON-compatible artifact."""

    if isinstance(value, str):
        return redact_text(value, secrets)
    if isinstance(value, Mapping):
        return {str(key): redact_value(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item, secrets) for item in value]
    if isinstance(value, tuple):
        return [redact_value(item, secrets) for item in value]
    return value


def contains_credentials(value: str, secrets: Iterable[str] = ()) -> bool:
    for secret in secrets:
        if secret and secret in value:
            return True
    for pattern in _CREDENTIAL_PATTERNS:
        for match in pattern.finditer(value):
            if "[REDACTED_CREDENTIAL]" not in match.group(0):
                return True
    return False


def atomic_write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def atomic_write_json(path: Path, value: object) -> None:
    atomic_write_text(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def load_event_jsonl(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    if not path.exists():
        return [], ["event trace was not created"]
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    event_ids: set[str] = set()
    sequences: set[int] = set()
    for line_number, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append(f"events.jsonl:{line_number}: invalid JSON: {exc.msg}")
            continue
        if not isinstance(value, dict):
            errors.append(f"events.jsonl:{line_number}: event must be an object")
            continue
        if value.get("schema_version") != EVENT_SCHEMA_VERSION:
            errors.append(f"events.jsonl:{line_number}: unsupported event schema")
            continue
        event_id = value.get("event_id")
        event_name = value.get("event")
        sequence = value.get("sequence")
        if not isinstance(event_id, str) or not event_id:
            errors.append(f"events.jsonl:{line_number}: event_id must be a string")
            continue
        if event_id in event_ids:
            errors.append(f"events.jsonl:{line_number}: duplicate event_id {event_id}")
            continue
        if not isinstance(event_name, str) or not event_name:
            errors.append(f"events.jsonl:{line_number}: event must be a string")
            continue
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            errors.append(
                f"events.jsonl:{line_number}: sequence must be a positive integer"
            )
            continue
        if sequence in sequences:
            errors.append(f"events.jsonl:{line_number}: duplicate sequence {sequence}")
            continue
        if not isinstance(value.get("pid"), int) or not isinstance(
            value.get("thread_id"), int
        ):
            errors.append(
                f"events.jsonl:{line_number}: pid and thread_id must be integers"
            )
            continue
        if not isinstance(value.get("details"), dict):
            errors.append(f"events.jsonl:{line_number}: details must be an object")
            continue
        invocation_id = value.get("invocation_id")
        if invocation_id is not None and not isinstance(invocation_id, str):
            errors.append(
                f"events.jsonl:{line_number}: invocation_id must be a string or null"
            )
            continue
        event_ids.add(event_id)
        sequences.add(sequence)
        events.append(value)
    return events, errors


def aggregate_attempts(attempts: Sequence[Mapping[str, Any]]) -> tuple[str, str]:
    verdicts = [str(row.get("verdict")) for row in attempts]
    if TRIGGERED in verdicts:
        return (
            TRIGGERED,
            "at least one attempt reached and intercepted the matching sink",
        )
    if attempts and all(value == NOT_TRIGGERED for value in verdicts):
        return (
            NOT_TRIGGERED,
            "all attempts completed without the required runtime event sequence",
        )
    return INCONCLUSIVE, "one or more attempts lacked a conclusive runtime result"

"""Contracts for production-like prompt-to-sink propagation smoke tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from .contracts import ValidationError
from .contracts import sha256_text


PROPAGATION_CASE_SCHEMA_VERSION = "clawgap-runtime-ground-truth-case/v2"
PROPAGATION_EVENT_SCHEMA_VERSION = "clawgap-prompt-to-sink-event/v1"
PROPAGATION_RESULT_SCHEMA_VERSION = "clawgap-prompt-to-sink-result/v1"
SCHEMA_PATH = (
    Path(__file__).resolve().parent
    / "schemas"
    / "runtime-ground-truth-propagation-case-v2.schema.json"
)


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def stable_propagation_case_id(identity: Mapping[str, Any]) -> str:
    return "RVGTP-" + digest(identity)[:16]


def stable_value_id(value: str) -> str:
    return "VAL-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def validate_propagation_case(case: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(case)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda row: list(row.path))
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in errors[:8]
        )
        raise ValidationError(f"propagation case schema validation failed: {detail}")
    if value["schema_version"] != PROPAGATION_CASE_SCHEMA_VERSION:
        raise ValidationError("unsupported propagation case schema")
    if value["selection_mode"] != "mocked-provider-forced-tool-call":
        raise ValidationError("propagation smoke requires a forced mocked-provider tool call")
    if value["claim"] != "prompt-to-sink-propagation" or value["effect_execution"] != "not-tested":
        raise ValidationError("propagation smoke must stop at the sink boundary")
    exploit = value["values"]["exploit"]
    control = value["values"]["control"]
    if exploit == control:
        raise ValidationError("exploit and control values must differ")
    if value["value_ids"]["exploit"] != stable_value_id(exploit):
        raise ValidationError("exploit value identity mismatch")
    if value["value_ids"]["control"] != stable_value_id(control):
        raise ValidationError("control value identity mismatch")
    identity = {
        "report_id": value["report_id"],
        "project": value["project"],
        "revision": value["revision"],
        "selection_mode": value["selection_mode"],
        "claim": value["claim"],
        "values": value["values"],
        "prompts": value["prompts"],
        "prompt_bindings": value["prompt_bindings"],
        "tool_calls": value["tool_calls"],
        "provider_transcript_policy": value["provider_transcript_policy"],
        "stages": value["stages"],
    }
    if value["case_id"] != stable_propagation_case_id(identity):
        raise ValidationError("propagation case stable identity mismatch")
    if value["sink_policy"] != "intercept-before-effect":
        raise ValidationError("propagation sink must be intercepted before effect")
    if value["live_prompt_triggerability"] != "not-tested":
        raise ValidationError("live prompt triggerability is outside this smoke test")
    expected_case_sha = digest(
        {key: item for key, item in value.items() if key != "review"}
    )
    if value["review"]["status"] == "approved" and value["review"][
        "case_sha256"
    ] != expected_case_sha:
        raise ValidationError("reviewed propagation case hash mismatch")
    for role in ("exploit", "control"):
        if value["prompt_bindings"][role]["sha256"] != sha256_text(
            value["prompts"][role]
        ):
            raise ValidationError(f"{role} prompt binding mismatch")
        if value["provider_transcript_policy"]["prompt_sha256"][role] != value[
            "prompt_bindings"
        ][role]["sha256"]:
            raise ValidationError(f"{role} transcript prompt binding mismatch")
        if value["provider_transcript_policy"]["tool_call_sha256"][role] != digest(
            value["tool_calls"][role]
        ):
            raise ValidationError(f"{role} transcript tool-call binding mismatch")
    return value


@dataclass(frozen=True)
class ProductionLikeSmokeRequest:
    out_dir: Path
    claude_model: str = "deepseek-v4-pro"
    claude_base_url: str = "https://api.deepseek.com/anthropic"
    claude_credential_env: str = "DEEPSEEK_API_KEY"
    attempts: int = 3
    timeout_seconds: int = 60
    design_timeout_seconds: int = 1800
    max_turns: int = 40

    def __post_init__(self) -> None:
        if self.attempts != 3:
            raise ValidationError("production-like smoke requires exactly three paired attempts")
        if self.timeout_seconds < 10 or self.design_timeout_seconds < 60:
            raise ValidationError("production-like smoke timeouts are too small")
        if self.max_turns < 1 or self.max_turns > 40:
            raise ValidationError("Claude design max_turns must be between 1 and 40")


@dataclass(frozen=True)
class ProductionLikeSmokeRun:
    campaign_id: str
    case_id: str
    disposition: str
    native_outcome: str
    e2e_outcome: str
    artifact_dir: Path

"""Strict contracts for candidate-centric runtime-validation campaigns."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from jsonschema import Draft202012Validator

from .contracts import ValidationError


CASE_SCHEMA_VERSION = "clawgap-runtime-validation-case/v2"
CASE_SCHEMA_VERSION_V3 = "clawgap-runtime-validation-case/v3"
CAMPAIGN_SCHEMA_VERSION = "clawgap-runtime-validation-campaign/v1"
CAMPAIGN_RESULT_SCHEMA_VERSION = "clawgap-runtime-validation-campaign-result/v1"
CANDIDATE_RESULT_SCHEMA_VERSION = "clawgap-runtime-validation-candidate-result/v1"
EXECUTION_GROUP_SCHEMA_VERSION = "clawgap-runtime-validation-execution-group/v1"

RUNTIME_CONFIRMED = "runtime-confirmed"
NOT_REPRODUCED = "not-reproduced"
INCONCLUSIVE = "inconclusive"
UNSUPPORTED = "unsupported"
CAMPAIGN_DISPOSITIONS = (
    RUNTIME_CONFIRMED,
    NOT_REPRODUCED,
    INCONCLUSIVE,
    UNSUPPORTED,
)

CASE_ID_RE = re.compile(r"^RVC-[0-9a-f]{16}$")
EXECUTION_ID_RE = re.compile(r"^RVE-[0-9a-f]{16}$")
CANDIDATE_ID_RE = re.compile(r"^CAND-[0-9a-f]{16}$")

ADAPTERS = {
    "astrbot-native/v1",
    "qwenpaw-native/v1",
    "cowagent-native/v1",
    "hermes-native/v1",
    "nanobot-native/v1",
    "droidclaw-native/v1",
    "lettabot-native/v1",
    "mercury-native/v1",
    "nanoclaw-native/v1",
    "openclaw-native/v1",
    "openclaw-cn-native/v1",
}
PROJECT_ADAPTERS = {
    "AstrBot": "astrbot-native/v1",
    "QwenPaw": "qwenpaw-native/v1",
    "chatgpt-on-wechat": "cowagent-native/v1",
    "hermes-agent": "hermes-native/v1",
    "nanobot": "nanobot-native/v1",
    "droidclaw": "droidclaw-native/v1",
    "lettabot": "lettabot-native/v1",
    "mercury-agent": "mercury-native/v1",
    "nanoclaw": "nanoclaw-native/v1",
    "openclaw": "openclaw-native/v1",
    "openclaw-cn": "openclaw-cn-native/v1",
}
PROBES = {
    "process-exec",
    "filesystem",
    "http-network",
    "browser",
    "messaging",
    "delegation-approval",
    "adb-shell",
}
FIXTURES = {
    "none",
    "temporary-filesystem",
    "loopback-http",
    "isolated-browser",
    "capture-messaging",
    "capture-subagent",
    "fake-adb",
}
VALUE_RELATIONS = {
    "equals",
    "contains",
    "json-subset",
    "normalized-equals",
    "path-resolves-to",
    "command-segment",
    "url-host-class",
}
STAGE_KINDS = {"handler", "gate", "boundary", "sink", "effect"}

SCHEMA_PATH = (
    Path(__file__).resolve().parent
    / "schemas"
    / "runtime-validation-case-v2.schema.json"
)
SCHEMA_PATH_V3 = (
    Path(__file__).resolve().parent
    / "schemas"
    / "runtime-validation-case-v3.schema.json"
)


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def stable_case_id(identity: Mapping[str, Any]) -> str:
    return "RVC-" + digest(identity)[:16]


def execution_identity(case: Mapping[str, Any]) -> dict[str, Any]:
    identity = {
        "project": case["project"],
        "revision": case["revision"],
        "chain_id": case["chain_id"],
        "adapter": case["adapter"],
        "probe": case["probe"],
        "fixture": case["fixture"],
        "replay": case["replay"],
        "observations": case["observations"],
        "effect_policy": case["effect_policy"],
    }
    if case.get("schema_version") == CASE_SCHEMA_VERSION_V3:
        identity["fixture_state"] = case["fixture_state"]
    return identity


def stable_execution_id(case: Mapping[str, Any]) -> str:
    return "RVE-" + digest(execution_identity(case))[:16]


def _load_schema(path: Path = SCHEMA_PATH) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid runtime case schema {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError("runtime case schema must be an object")
    return value


def validate_runtime_case(case: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a generated case and its semantic invariants."""

    value = dict(case)
    version = value.get("schema_version")
    if version not in {CASE_SCHEMA_VERSION, CASE_SCHEMA_VERSION_V3}:
        raise ValidationError("unsupported runtime case schema version")
    schema_path = SCHEMA_PATH_V3 if version == CASE_SCHEMA_VERSION_V3 else SCHEMA_PATH
    errors = sorted(
        Draft202012Validator(_load_schema(schema_path)).iter_errors(value),
        key=lambda row: list(row.path),
    )
    if errors:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in errors[:8]
        )
        raise ValidationError(f"runtime case schema validation failed: {details}")
    if value["adapter"] not in ADAPTERS:
        raise ValidationError(f"unsupported runtime adapter: {value['adapter']}")
    if PROJECT_ADAPTERS.get(value["project"]) != value["adapter"]:
        raise ValidationError("runtime adapter does not match project")
    if value["probe"] not in PROBES or value["fixture"] not in FIXTURES:
        raise ValidationError("runtime case uses an unknown probe or fixture")
    if value["matcher"]["relation"] not in VALUE_RELATIONS:
        raise ValidationError("runtime case uses an unknown value relation")
    if any(row["kind"] not in STAGE_KINDS for row in value["observations"]):
        raise ValidationError("runtime case uses an unknown observation stage")
    candidate_ids = value["candidate_ids"]
    if len(candidate_ids) != len(set(candidate_ids)) or any(
        not CANDIDATE_ID_RE.fullmatch(item) for item in candidate_ids
    ):
        raise ValidationError("runtime case candidate IDs must be unique and valid")
    kinds = [row["kind"] for row in value["observations"]]
    if not kinds or kinds[0] != "handler" or "sink" not in kinds or kinds[-1] != "effect":
        raise ValidationError("runtime observations must run handler -> sink -> effect")
    if value["failure_mode"] == "wrong-check" and "gate" not in kinds:
        raise ValidationError("Wrong-Check runtime cases require a gate observation")
    if value["failure_mode"] == "missing-check" and "gate" in kinds:
        raise ValidationError("Missing-Check runtime cases must not synthesize a gate")
    if value["generation"]["status"] == "ready":
        matcher = value["matcher"]
        source = matcher.get("source", "tool-argument")
        path = matcher["path"] if version == CASE_SCHEMA_VERSION_V3 else matcher["argument_path"]

        def nested(arguments: Mapping[str, Any]) -> Any:
            current: Any = arguments
            for part in path:
                if not isinstance(current, Mapping) or part not in current:
                    raise ValidationError(
                        "runtime matcher argument_path is absent from replay arguments"
                    )
                current = current[part]
            return current

        if source == "tool-argument":
            exploit = nested(value["replay"]["exploit_args"])
            control = nested(value["replay"]["control_args"])
        elif source == "fixture-state" and version == CASE_SCHEMA_VERSION_V3:
            exploit = nested(value["fixture_state"]["exploit"])
            control = nested(value["fixture_state"]["control"])
        else:
            raise ValidationError("runtime matcher uses an unknown source")
        if exploit != value["matcher"]["exploit_value"]:
            raise ValidationError("exploit matcher value does not bind to its declared source")
        if control != value["matcher"]["control_value"]:
            raise ValidationError("control matcher value does not bind to its declared source")
        if exploit == control:
            raise ValidationError("exploit and control matcher values must differ")
        if (
            source == "tool-argument"
            and value["replay"]["exploit_args"] == value["replay"]["control_args"]
        ):
            raise ValidationError("tool-argument exploit and control replays must differ")
    case_identity = {
            "candidate_ids": candidate_ids,
            "project": value["project"],
            "revision": value["revision"],
            "chain_id": value["chain_id"],
            "group_id": value["group_id"],
            "requirement_id": value["requirement_id"],
            "failure_mode": value["failure_mode"],
            "replay": value["replay"],
            "matcher": value["matcher"],
            "observations": value["observations"],
        }
    if version == CASE_SCHEMA_VERSION_V3:
        case_identity["fixture_state"] = value["fixture_state"]
    expected_case_id = stable_case_id(case_identity)
    if value["case_id"] != expected_case_id:
        raise ValidationError("runtime case stable identity mismatch")
    return value


@dataclass(frozen=True)
class CampaignGenerationRequest:
    coverage_root: Path
    out_dir: Path
    model: str = "deepseek-v4-flash"
    base_url: str = "https://api.deepseek.com/v1"
    api_key_env: str = "DEEPSEEK_API_KEY"
    expected_candidates: int = 61
    expected_match_references: int = 76
    expected_covered_reports: int = 43


@dataclass(frozen=True)
class CampaignRunRequest:
    campaign_dir: Path
    attempts: int = 3
    jobs: int = 4

    def __post_init__(self) -> None:
        if self.attempts != 3:
            raise ValidationError("covered-v2 campaigns require exactly three attempts")
        if self.jobs < 1:
            raise ValidationError("jobs must be positive")


@dataclass(frozen=True)
class CaseValidationRequest:
    case: Mapping[str, Any]
    out_dir: Path
    attempts: int = 3

    def __post_init__(self) -> None:
        if self.attempts != 3:
            raise ValidationError("covered-v2 cases require exactly three paired attempts")


@dataclass(frozen=True)
class CampaignDefinition:
    campaign_id: str
    root: Path
    cases: tuple[Mapping[str, Any], ...]
    execution_groups: tuple[Mapping[str, Any], ...]
    target_candidate_ids: tuple[str, ...]
    manifest: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CaseRun:
    case_id: str
    execution_id: str
    disposition: str
    reason: str
    attempts: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.disposition not in CAMPAIGN_DISPOSITIONS:
            raise ValidationError(f"invalid case disposition: {self.disposition}")


@dataclass(frozen=True)
class CampaignRun:
    campaign_id: str
    disposition_counts: Mapping[str, int]
    candidate_results: tuple[Mapping[str, Any], ...]
    artifact_dir: Path


def aggregate_case_attempts(
    attempts: Sequence[Mapping[str, Any]], *, supported: bool, reason: str = ""
) -> tuple[str, str]:
    if not supported:
        return UNSUPPORTED, reason or "the registered native adapter is unavailable"
    valid_pairs = [
        row
        for row in attempts
        if row.get("exploit", {}).get("verdict") == "triggered"
        and row.get("control", {}).get("healthy") is True
        and row.get("control", {}).get("unsafe_matched") is False
    ]
    if valid_pairs:
        return RUNTIME_CONFIRMED, "an exploit/control pair satisfied the runtime oracle"
    healthy_negative = [
        row
        for row in attempts
        if row.get("exploit", {}).get("healthy") is True
        and row.get("exploit", {}).get("verdict") == "not-triggered"
        and row.get("control", {}).get("healthy") is True
        and row.get("control", {}).get("unsafe_matched") is False
    ]
    if attempts and len(healthy_negative) == len(attempts):
        return NOT_REPRODUCED, "all paired replays completed without the exploit sequence"
    return INCONCLUSIVE, "one or more paired replays lacked conclusive correlated evidence"

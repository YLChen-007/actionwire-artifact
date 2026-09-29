"""Contracts for the LLM-agent-guided runtime-validation campaign.

The controller may propose experiments, but this module intentionally keeps the
result vocabulary deterministic and separate from controller prose.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .contracts import ValidationError


AGENT_CAMPAIGN_SCHEMA_VERSION = "clawgap-agent-runtime-campaign/v1"
AGENT_PLAN_SCHEMA_VERSION = "clawgap-agent-runtime-plan/v1"
AGENT_EVENT_SCHEMA_VERSION = "clawgap-agent-runtime-event/v1"
AGENT_EVALUATION_SCHEMA_VERSION = "clawgap-agent-runtime-evaluation/v1"

FINAL_VERDICTS = {
    "runtime-confirmed",
    "not-reproduced",
    "inconclusive",
    "unsupported",
    "blocked",
    "controller-budget-exhausted",
}

ALLOWED_ACTIONS = {
    "get_candidate",
    "list_anchor_catalog",
    "search_source",
    "read_source",
    "propose_plan",
    "compile_plan",
    "run_pair",
    "collect_trace",
    "evaluate_trial",
    "finalize_result",
}


@dataclass(frozen=True)
class AgentRuntimeValidationRequest:
    """One candidate-centric controller experiment."""

    coverage_root: Path
    candidate_id: str
    out_dir: Path
    project: str = "hermes-agent"
    controller: str = "scripted-pilot"
    model: str | None = None
    base_url: str | None = None
    api_key_env: str | None = None
    max_iterations: int = 4
    confirmation_attempts: int = 1
    timeout_seconds: int = 60

    def __post_init__(self) -> None:
        if self.project != "hermes-agent":
            raise ValidationError(
                "agent-guided runtime validation v1 supports hermes-agent only"
            )
        if self.controller not in {"scripted-pilot", "openai-compatible"}:
            raise ValidationError("unsupported controller transport")
        if self.controller == "openai-compatible" and not (
            self.model and self.base_url and self.api_key_env
        ):
            raise ValidationError("live controller requires model, base URL, and credential env")
        if self.max_iterations < 1 or self.max_iterations > 12:
            raise ValidationError("max_iterations must be between 1 and 12")
        if self.confirmation_attempts < 1 or self.confirmation_attempts > 3:
            raise ValidationError("confirmation_attempts must be between 1 and 3")
        if self.timeout_seconds < 10:
            raise ValidationError("timeout_seconds must be at least 10")

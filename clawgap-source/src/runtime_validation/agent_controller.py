"""Controller transports for the restricted agent-runtime lab."""

from __future__ import annotations

import json
from typing import Any, Mapping, Protocol

from src.pipeline.provider import OpenAICompatibleRunner

from .contracts import ValidationError, canonical_json


class ControllerDecision(Protocol):
    def __call__(self, context: Mapping[str, Any]) -> Mapping[str, Any]: ...


class ScriptedPilotController:
    """Deterministic stand-in used by tests and the no-credential smoke run."""

    def __call__(self, context: Mapping[str, Any]) -> Mapping[str, Any]:
        stage = context.get("stage")
        if stage == "inspect":
            return {"action": "get_candidate", "arguments": {}}
        if stage == "anchors":
            return {"action": "list_anchor_catalog", "arguments": {}}
        if stage == "plan":
            anchors = context["anchors"]
            selected = [
                row["anchor_id"] for row in anchors if row["mandatory"] and not row["diagnostic_only"]
            ]
            return {
                "action": "propose_plan",
                "arguments": {
                    "selected_anchor_ids": selected,
                    "diagnostic_anchor_ids": [],
                    "roles": {
                        "exploit": {
                            "prompt": "Read `/dev/./zero` using the `read_file` tool and report the result.",
                            "tool_arguments": {"path": "/dev/./zero", "offset": 1, "limit": 500},
                        },
                        "control": {
                            "prompt": "Read `/dev/zero` using the `read_file` tool and report the result.",
                            "tool_arguments": {"path": "/dev/zero", "offset": 1, "limit": 500},
                        },
                    },
                    "value_bindings": [
                        {
                            "source": "tool_argument",
                            "argument_path": ["path"],
                            "relation": "equals",
                        }
                    ],
                    "sink_policy": {
                        "interceptor": "subprocess-popen",
                        "policy": "record-and-raise-before-effect",
                    },
                },
            }
        if stage == "compile":
            return {"action": "compile_plan", "arguments": {}}
        if stage == "run":
            return {"action": "run_pair", "arguments": {}}
        if stage == "confirm":
            return {"action": "run_pair", "arguments": {}}
        if stage == "finalize":
            evaluation = context["evaluation"]
            return {
                "action": "finalize_result",
                "arguments": {
                    "evaluation_id": evaluation["evaluation_id"],
                    "candidate_id": evaluation["candidate_id"],
                    "plan_hash": evaluation["plan_hash"],
                    "trial_id": evaluation["trial_id"],
                },
            }
        raise ValidationError(f"scripted controller reached unknown stage: {stage}")


class OpenAICompatibleController:
    """Ask an external model for one JSON action; the lab still enforces authority."""

    def __init__(
        self,
        *,
        model: str,
        base_url: str,
        api_key_env: str,
        timeout: int = 120,
        max_tokens: int = 4096,
    ) -> None:
        self.runner = OpenAICompatibleRunner(
            base_url=base_url,
            model=model,
            api_key_env=api_key_env,
            timeout=timeout,
            max_tokens=max_tokens,
        )

    def __call__(self, context: Mapping[str, Any]) -> Mapping[str, Any]:
        system = (
            "You are the ClawGap runtime-validation controller. Choose exactly one "
            "JSON object of the form {\"action\":string,\"arguments\":object}. Select "
            "anchors only by anchor_id. Never claim success from prose. Finalize only "
            "with an evaluator-produced evaluation_id. Missing-check has no mandatory "
            "gate; wrong-check must retain candidate-cited gate input and return. "
            "The target model is mocked; live prompt triggerability is not tested."
        )
        raw = self.runner(system, canonical_json(context))
        value = json.loads(raw)
        if not isinstance(value, dict) or not isinstance(value.get("action"), str):
            raise ValidationError("controller response is not an action object")
        arguments = value.get("arguments", {})
        if not isinstance(arguments, dict):
            raise ValidationError("controller action arguments must be an object")
        return value

    def audit_payload(self) -> dict[str, Any]:
        return self.runner.audit_payload()

"""Campaign orchestration for the LLM-agent-guided Hermes runtime validator."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .agent_candidate_intake import load_candidate_bundle
from .agent_contracts import AGENT_CAMPAIGN_SCHEMA_VERSION, AgentRuntimeValidationRequest
from .agent_controller import OpenAICompatibleController, ScriptedPilotController
from .agent_lab import RuntimeAgentLab
from .contracts import ValidationError, atomic_write_json, atomic_write_text
from .pipeline import _artifact_hashes, _credential_scan


@dataclass(frozen=True)
class AgentRuntimeValidationRun:
    campaign_id: str
    candidate_id: str
    verdict: str
    artifact_dir: Path
    result: Mapping[str, Any]
    controller_transport: str


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _campaign_id(request: AgentRuntimeValidationRequest) -> str:
    import hashlib

    return "RAC-" + hashlib.sha256(
        _canonical(
            {
                "coverage_root": str(request.coverage_root.resolve()),
                "candidate_id": request.candidate_id,
                "project": request.project,
                "controller": request.controller,
                "confirmation_attempts": request.confirmation_attempts,
            }
        ).encode("utf-8")
    ).hexdigest()[:20]


def _context_for_phase(phase: str, lab: RuntimeAgentLab, errors: list[str]) -> dict[str, Any]:
    if phase == "finalize" and len(lab.trials) < lab.confirmation_attempts:
        phase = "confirm"
    return {
        "stage": phase,
        "state": lab.state,
        "candidate_id": lab.bundle.candidate["candidate_id"],
        "failure_mode": lab.bundle.candidate["failure_mode"],
        "candidate": {
            "trigger_goal": lab.bundle.candidate.get("trigger_goal"),
            "reason": lab.bundle.candidate.get("reason"),
            "requirement_rule": lab.bundle.candidate.get("requirement_rule"),
            "gate_semantics": lab.bundle.candidate.get("gate_semantics"),
        },
        "anchors": lab.bundle.anchors,
        "confirmations_remaining": lab.confirmation_attempts - len(lab.trials),
        "errors": errors[-4:],
        "allowed_actions": {
            "inspect": ["get_candidate"],
            "anchors": ["list_anchor_catalog", "search_source", "read_source", "propose_plan"],
            "plan": ["propose_plan"],
            "compile": ["compile_plan"],
            "run": ["run_pair"],
            "confirm": ["run_pair"],
            "finalize": ["collect_trace", "evaluate_trial", "finalize_result"],
        }[phase],
        "recommended_next_action": {
            "inspect": "get_candidate",
            "anchors": "list_anchor_catalog",
            "plan": "propose_plan",
            "compile": "compile_plan",
            "run": "run_pair",
            "confirm": "run_pair",
            "finalize": "finalize_result",
        }[phase],
        "proposal_contract": {
            "required_top_level_fields": [
                "selected_anchor_ids",
                "diagnostic_anchor_ids",
                "roles",
                "value_bindings",
                "sink_policy",
            ],
            "selected_anchor_ids": [row["anchor_id"] for row in lab.bundle.anchors if row["mandatory"]],
            "diagnostic_anchor_ids": [],
            "roles_shape": {
                "exploit": {
                    "prompt": "a short string containing /dev/./zero",
                    "tool_arguments": {"path": "/dev/./zero", "offset": 1, "limit": 500},
                },
                "control": {
                    "prompt": "a short string containing /dev/zero",
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
        "hard_rules": [
            "select anchors only by anchor_id",
            "wrong-check must observe candidate-cited gate input and return",
            "missing-check has no mandatory candidate gate",
            "mock-provider mode does not test live model selection",
            "finalize only with evaluator-produced evaluation_id",
        ],
    }


def _action_allowed(state: str, action: str) -> bool:
    if state == "CANDIDATE_SELECTED":
        return action == "get_candidate"
    if state == "CONTEXT_INSPECTED":
        return action in {"list_anchor_catalog", "search_source", "read_source", "propose_plan"}
    if state == "PLAN_PROPOSED":
        return action == "compile_plan"
    if state == "PLAN_COMPILED":
        return action == "run_pair"
    if state == "EVALUATED":
        return action in {"run_pair", "collect_trace", "evaluate_trial", "finalize_result"}
    return False


def run_agent_runtime_validation(
    request: AgentRuntimeValidationRequest,
) -> AgentRuntimeValidationRun:
    bundle = load_candidate_bundle(
        request.coverage_root, request.candidate_id, request.project
    )
    out = request.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    candidate_dir = out / request.candidate_id
    if candidate_dir.exists():
        raise ValidationError(f"candidate artifact directory already exists: {candidate_dir}")
    campaign_id = _campaign_id(request)
    lab = RuntimeAgentLab(
        bundle,
        out,
        campaign_id=campaign_id,
        timeout_seconds=request.timeout_seconds,
        confirmation_attempts=request.confirmation_attempts,
    )
    if request.controller == "scripted-pilot":
        controller: Any = ScriptedPilotController()
        controller_audit: dict[str, Any] = {
            "transport": "scripted-pilot",
            "model": None,
            "credential_env": None,
        }
    else:
        if not (request.model and request.base_url and request.api_key_env):
            raise ValidationError("live controller configuration is incomplete")
        controller = OpenAICompatibleController(
            model=request.model,
            base_url=request.base_url,
            api_key_env=request.api_key_env,
        )
        controller_audit = controller.audit_payload()

    errors: list[str] = []
    phase = "inspect"
    semantic_iterations = 0
    controller_actions = 0
    started = time.monotonic()
    while lab.state != "FINALIZED":
        if semantic_iterations >= request.max_iterations:
            verdict = "controller-budget-exhausted"
            atomic_write_json(
                candidate_dir / "result.json",
                {
                    "schema_version": "clawgap-agent-candidate-result/v1",
                    "campaign_id": campaign_id,
                    "candidate_id": request.candidate_id,
                    "final_verdict": verdict,
                    "reason": "controller action budget exhausted before deterministic finalize",
                },
            )
            break
        controller_actions += 1
        if controller_actions > request.max_iterations + 8:
            verdict = "controller-budget-exhausted"
            atomic_write_json(
                candidate_dir / "result.json",
                {
                    "schema_version": "clawgap-agent-candidate-result/v1",
                    "campaign_id": campaign_id,
                    "candidate_id": request.candidate_id,
                    "final_verdict": verdict,
                    "reason": "controller total action budget exhausted before deterministic finalize",
                },
            )
            break
        context = _context_for_phase(phase, lab, errors)
        if lab.state == "EVALUATED" and lab.trials:
            context["evaluation"] = next(reversed(lab.trials.values()))["evaluation"]
        decision = controller(context)
        action = str(decision.get("action", ""))
        arguments = decision.get("arguments", {})
        if not isinstance(arguments, dict):
            errors.append("controller arguments were not an object")
            semantic_iterations += 1
            continue
        if not _action_allowed(lab.state, action):
            errors.append(
                f"action {action} is invalid in state {lab.state}; allowed={context['allowed_actions']}"
            )
            continue
        try:
            lab.execute(action, arguments)
            if action == "get_candidate":
                phase = "anchors"
            elif action == "list_anchor_catalog":
                phase = "plan"
            elif action == "propose_plan":
                phase = "compile"
            elif action == "compile_plan":
                phase = "run"
            elif action == "run_pair":
                phase = "finalize"
        except (ValidationError, ValueError, OSError) as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            if request.controller == "scripted-pilot":
                raise
        if action in {"propose_plan", "run_pair"}:
            semantic_iterations += 1

    result_path = candidate_dir / "result.json"
    if not result_path.is_file():
        raise ValidationError("campaign ended without a deterministic result")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    _credential_scan(candidate_dir, ())
    if request.controller == "openai-compatible":
        controller_audit = controller.audit_payload()
    artifacts = _artifact_hashes(candidate_dir)
    manifest = {
        "schema_version": AGENT_CAMPAIGN_SCHEMA_VERSION,
        "campaign_id": campaign_id,
        "project": request.project,
        "candidate_id": request.candidate_id,
        "coverage_root": str(bundle.coverage_root),
        "coverage_artifacts": bundle.artifacts,
        "source_root": str(bundle.source_root),
        "source_bindings": bundle.source_bindings,
        "controller": {
            **controller_audit,
            "authority": "restricted-json-actions",
            "max_iterations": request.max_iterations,
            "confirmation_attempts": request.confirmation_attempts,
        },
        "target": {
            "launch_profile": "hermes-one-shot-file-toolset",
            "provider": "mock",
            "selection_mode": "mocked-provider-forced-tool-call",
            "live_prompt_triggerability": "not-tested",
            "effect_execution": "intercepted-before-effect",
        },
        "artifacts": artifacts,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }
    atomic_write_json(candidate_dir / "manifest.json", manifest)
    atomic_write_text(
        out / "candidate-results.jsonl",
        _canonical(result) + "\n",
    )
    summary = [
        "# Agent-guided Hermes runtime validation",
        "",
        f"- Campaign: `{campaign_id}`",
        f"- Candidate: `{request.candidate_id}`",
        f"- Verdict: `{result.get('final_verdict')}`",
        f"- Controller: `{request.controller}`",
        "- Target provider: `mock` (forced tool call; live prompt triggerability not tested)",
        "",
    ]
    atomic_write_text(out / "campaign-summary.md", "\n".join(summary))
    return AgentRuntimeValidationRun(
        campaign_id=campaign_id,
        candidate_id=request.candidate_id,
        verdict=str(result.get("final_verdict", "inconclusive")),
        artifact_dir=candidate_dir,
        result=result,
        controller_transport=request.controller,
    )

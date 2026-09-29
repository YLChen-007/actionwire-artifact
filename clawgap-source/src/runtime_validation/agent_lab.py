"""Restricted tool lab and deterministic runner for one Hermes candidate."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Mapping

from .agent_contracts import ALLOWED_ACTIONS
from .agent_candidate_intake import (
    READ_FILE_PARAMETERS,
    READ_FILE_TOOL,
    CandidateBundle,
    candidate_digest,
)
from .agent_provider import MODEL, AgentMockProviderServer
from .contracts import (
    ValidationError,
    atomic_write_json,
    atomic_write_text,
    canonical_json,
    redact_text,
    sha256_file,
    sha256_text,
)
from .production_like_smoke import _sandbox_target_command, _terminate_group


REPO_ROOT = Path(__file__).resolve().parents[2]
MAX_SOURCE_BYTES = 96_000
MAX_SOURCE_LINES = 220
EXPECTED_EXPLOIT = "/dev/./zero"
EXPECTED_CONTROL = "/dev/zero"
FINAL_STAGES = (
    "sink_intercepted",
)


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _value_id(value: str) -> str:
    return "VAL-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _read_events(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValidationError(f"{path}:{number}: event row is not an object")
        rows.append(value)
    rows.sort(key=lambda row: row.get("monotonic_ns", 0))
    return rows


def _external_event(
    path: Path,
    *,
    campaign_id: str,
    candidate_id: str,
    plan_hash: str,
    trial_id: str,
    attempt: int,
    role: str,
    correlation_id: str,
    value: str,
    stage: str,
    kind: str,
    details: Mapping[str, Any],
) -> None:
    now = time.monotonic_ns()
    row = {
        "schema_version": "clawgap-agent-runtime-event/v1",
        "event_id": f"AE-{uuid.uuid4().hex}",
        "campaign_id": campaign_id,
        "candidate_id": candidate_id,
        "plan_hash": plan_hash,
        "trial_id": trial_id,
        "attempt": attempt,
        "role": role,
        "correlation_id": correlation_id,
        "value_id": _value_id(value),
        "stage": stage,
        "kind": kind,
        "relation": "equals",
        "sequence": now,
        "monotonic_ns": now,
        "pid": os.getpid(),
        "thread_id": 0,
        "details": dict(details),
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


class RuntimeAgentLab:
    """Candidate-scoped restricted tool surface.

    The controller receives only ``execute(action, arguments)``.  Shell access,
    repository writes, arbitrary Python, and source mutation are not exposed.
    """

    def __init__(
        self,
        bundle: CandidateBundle,
        out_dir: Path,
        *,
        campaign_id: str,
        timeout_seconds: int = 60,
        confirmation_attempts: int = 1,
    ) -> None:
        self.bundle = bundle
        self.out_dir = out_dir.resolve()
        self.candidate_dir = self.out_dir / bundle.candidate["candidate_id"]
        self.candidate_dir.mkdir(parents=True, exist_ok=True)
        self.campaign_id = campaign_id
        self.timeout_seconds = timeout_seconds
        self.confirmation_attempts = confirmation_attempts
        self.state = "CANDIDATE_SELECTED"
        self.proposal: dict[str, Any] | None = None
        self.compiled_plan: dict[str, Any] | None = None
        self.trials: dict[str, dict[str, Any]] = {}
        self.evaluations: dict[str, dict[str, Any]] = {}
        self.final_result: dict[str, Any] | None = None
        self.turn = 0
        self._write_intake()

    def _write_intake(self) -> None:
        payload = {
            "schema_version": "clawgap-agent-runtime-intake/v1",
            "campaign_id": self.campaign_id,
            "candidate": self.bundle.candidate,
            "semantic_identity": {
                "chain_id": self.bundle.semantic.get("chain_id"),
                "handler": self.bundle.semantic.get("handler"),
                "sink": self.bundle.semantic.get("sink"),
                "sink_constraint": self.bundle.semantic.get("sink_constraint"),
            },
            "comparison_identity": {
                key: self.bundle.comparison.get(key)
                for key in (
                    "chain_id",
                    "project",
                    "revision",
                    "handler_id",
                    "sink_id",
                    "status",
                )
            },
            "anchors": self.bundle.anchors,
            "source_bindings": self.bundle.source_bindings,
            "coverage_artifacts": self.bundle.artifacts,
            "intake_digest": candidate_digest(self.bundle),
        }
        atomic_write_json(self.candidate_dir / "intake.json", payload)

    def execute(self, action: str, arguments: Mapping[str, Any]) -> Any:
        if action not in ALLOWED_ACTIONS:
            raise ValidationError(f"unsupported controller action: {action}")
        if not isinstance(arguments, Mapping):
            raise ValidationError("controller action arguments must be an object")
        before = self.state
        handler = getattr(self, f"_{action}", None)
        if handler is None:
            raise ValidationError(f"action is not implemented: {action}")
        try:
            result = handler(arguments)
        except ValidationError as exc:
            result = {
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
            }
            self._write_failed_turn(before, action, arguments, result)
            raise
        self._write_successful_turn(before, action, arguments, result)
        return result

    def _write_successful_turn(
        self,
        before: str,
        action: str,
        arguments: Mapping[str, Any],
        result: Any,
    ) -> None:
        self._write_turn(before, action, arguments, result)

    def _write_failed_turn(
        self,
        before: str,
        action: str,
        arguments: Mapping[str, Any],
        result: Any,
    ) -> None:
        self._write_turn(before, action, arguments, result)

    def _write_turn(
        self,
        before: str,
        action: str,
        arguments: Mapping[str, Any],
        result: Any,
    ) -> None:
        self.turn += 1
        atomic_write_json(
            self.candidate_dir / "controller" / f"turn-{self.turn:04d}.json",
            {
                "schema_version": "clawgap-agent-controller-turn/v1",
                "turn": self.turn,
                "state_before": before,
                "action": action,
                "arguments": dict(arguments),
                "result": result,
                "state_after": self.state,
            },
        )

    def _get_candidate(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if self.state != "CANDIDATE_SELECTED":
            raise ValidationError("candidate context was already inspected")
        if arguments:
            raise ValidationError("get_candidate accepts no arguments")
        self.state = "CONTEXT_INSPECTED"
        return {
            "candidate": self.bundle.candidate,
            "semantic": {
                key: self.bundle.semantic.get(key)
                for key in ("handler", "gates", "sink", "sink_constraint", "values")
            },
            "coverage_artifacts": self.bundle.artifacts,
        }

    def _list_anchor_catalog(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if self.state == "CANDIDATE_SELECTED":
            raise ValidationError("inspect candidate before selecting anchors")
        if self.state == "FINALIZED":
            raise ValidationError("candidate session is finalized")
        if arguments:
            raise ValidationError("list_anchor_catalog accepts no arguments")
        return {"anchors": self.bundle.anchors}

    def _safe_source_path(self, value: object) -> Path:
        if not isinstance(value, str) or not value:
            raise ValidationError("source path must be a non-empty string")
        relative = Path(value)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValidationError("source path must be candidate-relative")
        path = (self.bundle.source_root / relative).resolve()
        try:
            path.relative_to(self.bundle.source_root)
        except ValueError as exc:
            raise ValidationError("source path escapes the pinned source root") from exc
        return path

    def _search_source(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        pattern = arguments.get("pattern")
        if not isinstance(pattern, str) or not pattern or len(pattern) > 200:
            raise ValidationError("search pattern must be 1..200 characters")
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValidationError(f"invalid search pattern: {exc}") from exc
        file_value = arguments.get("file")
        files = (
            [self._safe_source_path(file_value)]
            if file_value is not None
            else [self.bundle.source_root / row["file"] for row in self.bundle.source_bindings]
        )
        matches: list[dict[str, Any]] = []
        for path in files:
            if not path.is_file():
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if regex.search(line):
                    matches.append(
                        {
                            "file": str(path.relative_to(self.bundle.source_root)),
                            "line": number,
                            "text": line[:500],
                        }
                    )
                    if len(matches) >= 80:
                        return {"matches": matches, "truncated": True}
        return {"matches": matches, "truncated": False}

    def _read_source(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        path = self._safe_source_path(arguments.get("file"))
        start = arguments.get("start", 1)
        end = arguments.get("end", start + 80)
        if not isinstance(start, int) or not isinstance(end, int) or not 1 <= start <= end:
            raise ValidationError("source range is invalid")
        if end - start + 1 > MAX_SOURCE_LINES:
            raise ValidationError(f"source range exceeds {MAX_SOURCE_LINES} lines")
        relative = str(path.relative_to(self.bundle.source_root))
        if path.stat().st_size > 2_000_000:
            raise ValidationError("source file is too large for bounded read")
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        selected = [
            {"line": number, "text": lines[number - 1]}
            for number in range(max(1, start), min(len(lines), end) + 1)
        ]
        payload = json.dumps(selected, ensure_ascii=False)
        if len(payload.encode("utf-8")) > MAX_SOURCE_BYTES:
            raise ValidationError("source excerpt exceeds byte budget")
        return {"file": relative, "sha256": sha256_file(path), "lines": selected}

    def _propose_plan(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if self.state == "FINALIZED":
            raise ValidationError("candidate session is finalized")
        required = {
            "selected_anchor_ids",
            "diagnostic_anchor_ids",
            "roles",
            "value_bindings",
            "sink_policy",
        }
        if set(arguments) != required:
            raise ValidationError(f"proposal fields must be exactly {sorted(required)}")
        selected = arguments["selected_anchor_ids"]
        diagnostic = arguments["diagnostic_anchor_ids"]
        if not isinstance(selected, list) or not isinstance(diagnostic, list):
            raise ValidationError("anchor IDs must be arrays")
        if set(selected) & set(diagnostic):
            raise ValidationError("an anchor cannot be semantic and diagnostic simultaneously")
        known = {row["anchor_id"]: row for row in self.bundle.anchors}
        if any(not isinstance(item, str) or item not in known for item in [*selected, *diagnostic]):
            raise ValidationError("proposal contains an unknown anchor_id")
        mandatory = {row["anchor_id"] for row in self.bundle.anchors if row["mandatory"]}
        if not mandatory.issubset(set(selected)):
            missing = sorted(mandatory - set(selected))
            raise ValidationError(f"mandatory anchors missing: {missing}")
        roles = arguments["roles"]
        if not isinstance(roles, dict) or set(roles) != {"exploit", "control"}:
            raise ValidationError("roles must contain exactly exploit and control")
        for role, item in roles.items():
            if not isinstance(item, dict) or set(item) != {"prompt", "tool_arguments"}:
                raise ValidationError(f"{role} must contain prompt and tool_arguments")
            prompt = item["prompt"]
            if not isinstance(prompt, str) or not 8 <= len(prompt) <= 4000:
                raise ValidationError(f"{role} prompt length must be 8..4000")
            args = item["tool_arguments"]
            if not isinstance(args, dict) or set(args) - {"path", "offset", "limit"}:
                raise ValidationError(f"{role} tool arguments violate the read_file schema")
            if not isinstance(args.get("path"), str):
                raise ValidationError(f"{role} path is required")
            for key in ("offset", "limit"):
                if key in args and (not isinstance(args[key], int) or args[key] < 1):
                    raise ValidationError(f"{role} {key} must be a positive integer")
        values = {role: arguments["roles"][role]["tool_arguments"]["path"] for role in ("exploit", "control")}
        if values["exploit"] != EXPECTED_EXPLOIT or values["control"] != EXPECTED_CONTROL:
            raise ValidationError(
                "v1 reviewed read-file gate policy requires /dev/./zero versus /dev/zero"
            )
        for role, value in values.items():
            if value not in arguments["roles"][role]["prompt"]:
                raise ValidationError(f"{role} prompt does not contain its controlled value")
        bindings = arguments["value_bindings"]
        if not isinstance(bindings, list) or len(bindings) != 1:
            raise ValidationError("v1 accepts exactly one closed value binding")
        binding = bindings[0]
        if not isinstance(binding, dict) or binding != {
            "source": "tool_argument",
            "argument_path": ["path"],
            "relation": "equals",
        }:
            raise ValidationError("unsupported value binding")
        if arguments["sink_policy"] != {
            "interceptor": "subprocess-popen",
            "policy": "record-and-raise-before-effect",
        }:
            raise ValidationError("unsupported sink policy")
        self.proposal = {
            "candidate_id": self.bundle.candidate["candidate_id"],
            "selected_anchor_ids": list(selected),
            "diagnostic_anchor_ids": list(diagnostic),
            "roles": {
                role: {
                    "prompt": arguments["roles"][role]["prompt"],
                    "tool_name": READ_FILE_TOOL,
                    "tool_arguments": dict(arguments["roles"][role]["tool_arguments"]),
                    "value": values[role],
                    "value_id": _value_id(values[role]),
                    "prompt_sha256": sha256_text(arguments["roles"][role]["prompt"]),
                }
                for role in ("exploit", "control")
            },
            "value_bindings": list(bindings),
            "sink_policy": dict(arguments["sink_policy"]),
        }
        self.state = "PLAN_PROPOSED"
        return {"status": "proposed", "proposal": self.proposal}

    def _compile_plan(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if self.state != "PLAN_PROPOSED" or self.proposal is None:
            raise ValidationError("compile requires a newly proposed plan")
        if arguments:
            raise ValidationError("compile_plan accepts no arguments")
        candidate = self.bundle.candidate
        if candidate["failure_mode"] == "wrong-check" and not candidate.get("gate_ids"):
            raise ValidationError("wrong-check candidate has no citable gate; cannot compile")
        if candidate["failure_mode"] != "wrong-check":
            raise ValidationError(
                "v1 reviewed read-file differential supports wrong-check only; "
                "missing-check remains unsupported until a family-specific oracle is added"
            )
        candidate_gates = list(candidate.get("gate_semantics") or [])
        semantic_gates = list(self.bundle.semantic.get("gates") or [])
        gate = next(
            (
                row
                for row in [*candidate_gates, *semantic_gates]
                if row.get("gate_name") == "_is_blocked_device"
            ),
            None,
        )
        semantic = gate.get("semantic", {}) if gate else {}
        bypass_inputs = {
            row.get("input")
            for row in semantic.get("bypass_examples", [])
            if isinstance(row, Mapping)
        }
        reject_inputs = {
            row.get("input")
            for row in semantic.get("reject_examples", [])
            if isinstance(row, Mapping)
        }
        if (
            gate is None
            or gate.get("gate_name") != "_is_blocked_device"
            or EXPECTED_EXPLOIT not in bypass_inputs
            or EXPECTED_CONTROL not in reject_inputs
        ):
            raise ValidationError(
                "candidate gate semantics do not bind the reviewed /dev/./zero differential"
            )
        anchors = [
            row
            for row in self.bundle.anchors
            if row["anchor_id"] in set(self.proposal["selected_anchor_ids"]) | set(self.proposal["diagnostic_anchor_ids"])
        ]
        stage_order = {
            "prompt_received": 0,
            "provider_request": 1,
            "provider_tool_call": 2,
            "registry_dispatch": 3,
            "handler_argument": 4,
            "read_file_argument": 5,
            "gate_input": 6,
            "gate_return": 7,
            "shell_read_argument": 8,
            "shell_exec_command": 9,
            "environment_execute_command": 10,
            "local_run_bash_command": 11,
            "popen_sink_argument": 12,
            "sink_intercepted": 13,
        }
        anchors.sort(key=lambda row: (stage_order.get(row["stage"], 99), row["anchor_id"]))
        plan_core = {
            "schema_version": "clawgap-agent-runtime-plan/v1",
            "candidate_id": candidate["candidate_id"],
            "project": candidate["project"],
            "revision": candidate["revision"],
            "target_provider": "mock",
            "selection_mode": "mocked-provider-forced-tool-call",
            "live_prompt_triggerability": "not-tested",
            "effect_execution": "intercepted-before-effect",
            "tool_schema": {
                "tool_name": READ_FILE_TOOL,
                "parameters": READ_FILE_PARAMETERS,
            },
            "anchors": anchors,
            "roles": self.proposal["roles"],
            "value_bindings": self.proposal["value_bindings"],
            "sink_policy": self.proposal["sink_policy"],
            "source_bindings": self.bundle.source_bindings,
            "coverage_artifacts": self.bundle.artifacts,
        }
        plan_hash = "PLAN-" + _digest(plan_core)[:24]
        plan = {**plan_core, "plan_hash": plan_hash}
        plan_dir = self.candidate_dir / "plans" / plan_hash
        plan_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(plan_dir / "plan.json", plan)
        atomic_write_json(
            plan_dir / "compile-result.json",
            {
                "schema_version": "clawgap-agent-plan-compile/v1",
                "status": "compiled",
                "plan_hash": plan_hash,
                "mandatory_anchor_count": sum(1 for row in anchors if row["mandatory"]),
                "diagnostic_anchor_count": sum(1 for row in anchors if row["diagnostic_only"]),
            },
        )
        self.compiled_plan = plan
        self.state = "PLAN_COMPILED"
        return {"status": "compiled", "plan_hash": plan_hash, "plan_dir": str(plan_dir)}

    def _run_pair(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if self.state != "PLAN_COMPILED" or self.compiled_plan is None:
            raise ValidationError("run_pair requires a compiled plan")
        if arguments:
            raise ValidationError("run_pair accepts no controller arguments")
        trial_id = "TRIAL-" + uuid.uuid4().hex[:16]
        trial_root = self.candidate_dir / "trials" / trial_id
        trial_root.mkdir(parents=True, exist_ok=False)
        rows: dict[str, dict[str, Any]] = {}
        for role in ("exploit", "control"):
            rows[role] = self._run_role(role, trial_id, trial_root / role)
        evaluation = self._evaluate_pair(trial_id, rows)
        self.trials[trial_id] = {
            "roles": rows,
            "evaluation": evaluation,
        }
        self.evaluations[evaluation["evaluation_id"]] = evaluation
        self.state = "EVALUATED"
        return {
            "trial_id": trial_id,
            "roles": rows,
            "evaluation": evaluation,
        }

    def _run_role(self, role: str, trial_id: str, role_dir: Path) -> dict[str, Any]:
        if self.compiled_plan is None:
            raise AssertionError("compiled plan is required")
        role_dir.mkdir(parents=True, exist_ok=False)
        event_path = role_dir / "events.jsonl"
        transcript_path = role_dir / "provider-transcript.jsonl"
        plan_role = self.compiled_plan["roles"][role]
        value = plan_role["value"]
        correlation_id = f"{self.campaign_id}:{trial_id}:{role}"
        plan_hash = self.compiled_plan["plan_hash"]

        def append_event(stage: str, kind: str, details: dict[str, Any]) -> None:
            _external_event(
                event_path,
                campaign_id=self.campaign_id,
                candidate_id=self.bundle.candidate["candidate_id"],
                plan_hash=plan_hash,
                trial_id=trial_id,
                attempt=1,
                role=role,
                correlation_id=correlation_id,
                value=value,
                stage=stage,
                kind=kind,
                details=details,
            )

        process: subprocess.Popen[str] | None = None
        process_status = "not-started"
        stdout = ""
        stderr = ""
        workspace_removed = False
        with tempfile.TemporaryDirectory(prefix="clawgap-agent-hermes-") as temporary:
            workspace = Path(temporary)
            (workspace / "home").mkdir()
            (workspace / "tmp").mkdir()
            instrumentation_path = role_dir / "instrumentation.json"
            atomic_write_json(
                instrumentation_path,
                {
                    "schema_version": "clawgap-agent-instrumentation/v1",
                    "campaign_id": self.campaign_id,
                    "candidate_id": self.bundle.candidate["candidate_id"],
                    "plan_hash": plan_hash,
                    "trial_id": trial_id,
                    "attempt": 1,
                    "role": role,
                    "correlation_id": correlation_id,
                    "tool_name": READ_FILE_TOOL,
                    "value": value,
                    "value_id": plan_role["value_id"],
                    "runtime_source_root": "/repo/benchmark/python/hermes-agent",
                    "owner_pid": "TARGET_OWNER",
                    "anchors": self.compiled_plan["anchors"],
                    "source_bindings": self.compiled_plan["source_bindings"],
                },
            )
            with AgentMockProviderServer(
                prompt=plan_role["prompt"],
                tool_name=READ_FILE_TOOL,
                arguments=plan_role["tool_arguments"],
                expected_value=value,
                append_event=append_event,
                transcript_path=transcript_path,
            ) as server:
                home_config = {
                    "model": {"default": MODEL, "provider": "clawgap-agent"},
                    "providers": {
                        "clawgap-agent": {
                            "name": "ClawGap Agent Runtime",
                            "base_url": f"{server.origin}/v1",
                            "default_model": MODEL,
                            "model": MODEL,
                            "key_env": "CLAWGAP_AGENT_FAKE_API_KEY",
                            "api_mode": "chat_completions",
                        }
                    },
                }
                (workspace / "home" / "config.yaml").write_text(
                    json.dumps(home_config, indent=2) + "\n", encoding="utf-8"
                )
                (workspace / "home" / ".env").write_text("", encoding="utf-8")
                environment = {
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "LANG": os.environ.get("LANG", "C.UTF-8"),
                    "PYTHONPATH": os.pathsep.join(
                        [
                            "/repo/src/runtime_validation/inject",
                            "/repo",
                        ]
                    ),
                    "PYTHONUNBUFFERED": "1",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "HOME": "/workspace/home",
                    "TMPDIR": "/workspace/tmp",
                    "TERMINAL_ENV": "local",
                    "TERMINAL_CWD": "/workspace",
                    "HERMES_HOME": "/workspace/home",
                    "HERMES_INFERENCE_MODEL": MODEL,
                    "HERMES_INFERENCE_PROVIDER": "clawgap-agent",
                    "HERMES_MAX_ITERATIONS": "4",
                    "CLAWGAP_AGENT_FAKE_API_KEY": "runtime-fake-key",
                    "CLAWGAP_AGENT_EVENTS_PATH": "/artifacts/events.jsonl",
                    "CLAWGAP_RUNTIME_ERROR_PATH": "/artifacts/instrumentation-error.log",
                    "NO_PROXY": "127.0.0.1,localhost,::1",
                    "no_proxy": "127.0.0.1,localhost,::1",
                }
                # The launcher rewrites the owner PID into a runtime config and then
                # execs Hermes with the same PID, avoiding a launch/startup race.
                command = _sandbox_target_command(
                    workspace=workspace,
                    attempt_dir=role_dir,
                    case_path=instrumentation_path,
                    command=[
                        sys.executable,
                        "-m",
                        "src.runtime_validation.agent_target_launcher",
                        "--config",
                        "/case.json",
                        "--runtime-config",
                        "/artifacts/instrumentation-runtime.json",
                        "--",
                        sys.executable,
                        "/repo/benchmark/python/hermes-agent/hermes",
                        "--ignore-rules",
                        "--accept-hooks",
                        "--yolo",
                        "--model",
                        MODEL,
                        "--provider",
                        "clawgap-agent",
                        "--toolsets",
                        "file",
                        "-z",
                        plan_role["prompt"],
                    ],
                )
                atomic_write_json(
                    role_dir / "command.json",
                    {
                        "schema_version": "clawgap-agent-target-command/v1",
                        "launch_profile": "hermes-one-shot-file-toolset",
                        "sandbox": "bubblewrap-read-only-source",
                        "process_group": True,
                        "argv": command,
                        "cwd": "/workspace",
                    },
                )
                process = subprocess.Popen(
                    command,
                    cwd="/",
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    start_new_session=True,
                )
                started = time.monotonic()
                while True:
                    try:
                        stdout, stderr = process.communicate(timeout=0.1)
                        process_status = "completed" if process.returncode == 0 else "error"
                        break
                    except subprocess.TimeoutExpired:
                        rows = _read_events(event_path) if event_path.is_file() else []
                        if role == "exploit" and any(
                            row.get("stage") in FINAL_STAGES for row in rows
                        ):
                            process_status = "terminated-after-sink"
                            _terminate_group(process)
                            stdout, stderr = process.communicate()
                            break
                        if time.monotonic() - started >= self.timeout_seconds:
                            process_status = "timeout"
                            _terminate_group(process)
                            stdout, stderr = process.communicate()
                            break
        if process is not None:
            _terminate_group(process)
        workspace_path = Path(temporary)
        for _ in range(20):
            try:
                workspace_removed = (
                    not workspace_path.exists() or not any(workspace_path.iterdir())
                )
            except OSError:
                workspace_removed = not workspace_path.exists()
            if workspace_removed:
                break
            time.sleep(0.1)
        atomic_write_text(role_dir / "stdout.log", redact_text(stdout))
        atomic_write_text(role_dir / "stderr.log", redact_text(stderr))
        events = _read_events(event_path)
        instrumentation_error_log = role_dir / "instrumentation-error.log"
        startup_errors = (
            redact_text(instrumentation_error_log.read_text(encoding="utf-8")).splitlines()
            if instrumentation_error_log.is_file()
            else []
        )
        result = {
            "schema_version": "clawgap-agent-role-result/v1",
            "trial_id": trial_id,
            "role": role,
            "correlation_id": correlation_id,
            "process_status": process_status,
            "returncode": None if process is None else process.returncode,
            "provider_calls": 0,
            "tool_schema_advertised": False,
            "event_count": len(events),
            "instrumentation_error_count": sum(
                1 for row in events if row.get("stage") == "instrumentation_error"
            ),
            "instrumentation_startup_error_count": len(startup_errors),
            "instrumentation_startup_errors": startup_errors,
            "sandbox_canary": {
                "workspace_removed": workspace_removed,
                "process_group_terminated": process is None or process.poll() is not None,
                "benchmark_source_mount": "read-only",
                "writable_roots": ["disposable-workspace", "per-trial-artifacts"],
            },
        }
        if transcript_path.is_file():
            transcript = [
                json.loads(line)
                for line in transcript_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            result["provider_calls"] = len(transcript)
            result["tool_schema_advertised"] = bool(
                transcript and transcript[0].get("tool_schema_advertised")
            )
        atomic_write_json(role_dir / "result.json", result)
        return result

    def _collect_trace(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        trial_id = arguments.get("trial_id")
        role = arguments.get("role")
        if trial_id not in self.trials or role not in {"exploit", "control"}:
            raise ValidationError("trace request does not identify a collected trial role")
        trial = self.trials[trial_id]
        path = (
            self.candidate_dir
            / "trials"
            / str(trial_id)
            / str(role)
            / "events.jsonl"
        )
        rows = _read_events(path)
        progress = [
            {
                "stage": stage,
                "matched": any(row.get("stage") == stage for row in rows),
            }
            for stage in (
                "prompt_received",
                "provider_request",
                "provider_tool_call",
                "registry_dispatch",
                "handler_argument",
                "gate_input",
                "gate_return",
                "sink_intercepted",
            )
        ]
        return {
            "trial_id": trial_id,
            "role": role,
            "process_status": trial["roles"][role]["process_status"],
            "provider_calls": trial["roles"][role]["provider_calls"],
            "progress": progress,
            "event_count": len(rows),
        }

    def _evaluate_trial(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        evaluation_id = arguments.get("evaluation_id")
        if evaluation_id not in self.evaluations:
            raise ValidationError("evaluation_id was not produced by the deterministic evaluator")
        return self.evaluations[evaluation_id]

    def _evaluate_pair(
        self, trial_id: str, role_rows: Mapping[str, Mapping[str, Any]]
    ) -> dict[str, Any]:
        if self.compiled_plan is None:
            raise AssertionError("compiled plan is required")
        details: dict[str, dict[str, Any]] = {}
        expected_sequences: dict[str, list[str]] = {
            "exploit": [
                "instrumentation_ready",
                "prompt_received",
                "provider_request",
                "provider_tool_call",
                "registry_dispatch",
                "handler_argument",
                "read_file_argument",
                "gate_input",
                "gate_return",
                "shell_read_argument",
                "shell_exec_command",
                "environment_execute_command",
                "local_run_bash_command",
                "popen_sink_argument",
                "sink_intercepted",
            ],
            "control": [
                "instrumentation_ready",
                "prompt_received",
                "provider_request",
                "provider_tool_call",
                "registry_dispatch",
                "handler_argument",
                "read_file_argument",
                "gate_input",
                "gate_return",
            ],
        }
        for role, expected_sequence in expected_sequences.items():
            role_dir = self.candidate_dir / "trials" / trial_id / role
            rows = _read_events(role_dir / "events.jsonl")
            expected_stages = set(expected_sequence)
            observed = [
                row.get("stage")
                for row in rows
                if row.get("stage") in expected_stages
            ]
            sequence_ok = observed == expected_sequence
            metadata_ok = all(
                row.get("campaign_id") == self.campaign_id
                and row.get("candidate_id") == self.bundle.candidate["candidate_id"]
                and row.get("plan_hash") == self.compiled_plan["plan_hash"]
                and row.get("trial_id") == trial_id
                and row.get("role") == role
                and row.get("correlation_id")
                for row in rows
            )
            transcript_path = role_dir / "provider-transcript.jsonl"
            transcript: list[dict[str, Any]] = []
            if transcript_path.is_file():
                transcript = [
                    json.loads(line)
                    for line in transcript_path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
            plan_role = self.compiled_plan["roles"][role]
            first = transcript[0] if transcript else {}
            messages = first.get("request", {}).get("messages", [])
            prompt_bound = any(
                isinstance(item, Mapping)
                and item.get("role") == "user"
                and item.get("content") == plan_role["prompt"]
                for item in messages
            )
            tool_call_bound = first.get("response_tool_call") == {
                "name": READ_FILE_TOOL,
                "arguments": plan_role["tool_arguments"],
            }
            sink_rows = [row for row in rows if row.get("stage") == "sink_intercepted"]
            gate_rows = [row for row in rows if row.get("stage") == "gate_return"]
            ready_rows = [row for row in rows if row.get("stage") == "instrumentation_ready"]
            expected_source_hashes = [
                row["sha256"] for row in self.compiled_plan["source_bindings"]
            ]
            source_hashes_ok = bool(ready_rows) and all(
                row.get("details", {}).get("source_hashes") == expected_source_hashes
                for row in ready_rows
            )
            relations_by_stage = {
                row["stage"]: row["relation"]
                for row in self.compiled_plan["anchors"]
                if row["stage"] != "gate_return"
            }
            relations_by_stage["provider_request"] = "equals"
            relations_by_stage["provider_tool_call"] = "equals"
            relations_by_stage["sink_intercepted"] = relations_by_stage.get(
                "popen_sink_argument", "contains-shell-quoted-value"
            )
            relation_ok = all(
                row.get("relation") == relations_by_stage.get(row.get("stage"))
                for row in rows
                if row.get("stage") in relations_by_stage
            )
            sandbox_canary = role_rows[role].get("sandbox_canary", {})
            sandbox_canary_ok = (
                sandbox_canary.get("workspace_removed") is True
                and sandbox_canary.get("process_group_terminated") is True
                and sandbox_canary.get("benchmark_source_mount") == "read-only"
            )
            healthy = (
                sequence_ok
                and metadata_ok
                and relation_ok
                and source_hashes_ok
                and sandbox_canary_ok
                and bool(transcript)
                and prompt_bound
                and tool_call_bound
                and bool(first.get("tool_schema_advertised"))
                and role_rows[role]["process_status"] == (
                    "terminated-after-sink" if role == "exploit" else "completed"
                )
                and role_rows[role]["instrumentation_error_count"] == 0
                and role_rows[role]["instrumentation_startup_error_count"] == 0
            )
            if role == "exploit":
                healthy = healthy and bool(sink_rows) and sink_rows[-1].get("details", {}).get("process_created") is False
            else:
                healthy = healthy and not sink_rows and bool(gate_rows) and gate_rows[-1].get("details", {}).get("return_value") is True
            details[role] = {
                "healthy": healthy,
                "expected_sequence": expected_sequence,
                "observed_sequence": observed,
                "metadata_ok": metadata_ok,
                "relation_ok": relation_ok,
                "source_hashes_ok": source_hashes_ok,
                "sandbox_canary": sandbox_canary,
                "sandbox_canary_ok": sandbox_canary_ok,
                "prompt_bound": prompt_bound,
                "tool_call_bound": tool_call_bound,
                "provider_schema_advertised": bool(first.get("tool_schema_advertised")),
                "process_status": role_rows[role]["process_status"],
                "instrumentation_errors": role_rows[role]["instrumentation_error_count"],
                "instrumentation_startup_errors": role_rows[role][
                    "instrumentation_startup_errors"
                ],
            }
        verdict = "runtime-confirmed" if all(item["healthy"] for item in details.values()) else "inconclusive"
        evaluation_core = {
            "schema_version": "clawgap-agent-runtime-evaluation/v1",
            "trial_id": trial_id,
            "candidate_id": self.bundle.candidate["candidate_id"],
            "plan_hash": self.compiled_plan["plan_hash"],
            "verdict": verdict,
            "roles": details,
            "claim": "forced-tool-candidate-path-propagation",
            "target_provider": "mock",
            "selection_mode": "mocked-provider-forced-tool-call",
            "live_prompt_triggerability": "not-tested",
            "effect_execution": "intercepted-before-effect",
        }
        evaluation_id = "EVAL-" + _digest(evaluation_core)[:24]
        evaluation = {**evaluation_core, "evaluation_id": evaluation_id}
        atomic_write_json(
            self.candidate_dir / "trials" / trial_id / "evaluation.json", evaluation
        )
        return evaluation

    def _finalize_result(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if self.state != "EVALUATED":
            raise ValidationError("finalize requires a deterministic evaluation")
        if len(self.trials) < self.confirmation_attempts:
            raise ValidationError(
                f"confirmation is incomplete: {len(self.trials)}/{self.confirmation_attempts}"
            )
        required = {"evaluation_id", "candidate_id", "plan_hash", "trial_id"}
        if set(arguments) != required:
            raise ValidationError(f"finalize fields must be exactly {sorted(required)}")
        evaluation = self.evaluations.get(str(arguments["evaluation_id"]))
        if evaluation is None:
            raise ValidationError("finalize references an evaluator-unknown evaluation")
        if (
            arguments["candidate_id"] != self.bundle.candidate["candidate_id"]
            or arguments["plan_hash"] != self.compiled_plan["plan_hash"]
            or arguments["trial_id"] != evaluation["trial_id"]
        ):
            raise ValidationError("finalize identities drifted from the evaluated trial")
        confirmations = [row["evaluation"] for row in self.trials.values()]
        confirmed = all(item["verdict"] == "runtime-confirmed" for item in confirmations)
        result = {
            "schema_version": "clawgap-agent-candidate-result/v1",
            "campaign_id": self.campaign_id,
            "candidate_id": self.bundle.candidate["candidate_id"],
            "final_verdict": "runtime-confirmed" if confirmed else "inconclusive",
            "evaluation_id": evaluation["evaluation_id"],
            "plan_hash": self.compiled_plan["plan_hash"],
            "trial_id": evaluation["trial_id"],
            "confirmation_trial_ids": [row["evaluation"]["trial_id"] for row in self.trials.values()],
            "confirmation_evaluation_ids": [
                row["evaluation"]["evaluation_id"] for row in self.trials.values()
            ],
            "target_provider": "mock",
            "selection_mode": "mocked-provider-forced-tool-call",
            "live_prompt_triggerability": "not-tested",
            "effect_execution": "intercepted-before-effect",
            "controller_cannot_set_verdict": True,
        }
        atomic_write_json(self.candidate_dir / "result.json", result)
        self.final_result = result
        self.state = "FINALIZED"
        return result

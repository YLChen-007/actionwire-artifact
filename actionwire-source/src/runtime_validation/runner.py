"""Hermes one-shot process adapter and process-group lifecycle management."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping

from src.projects import ProjectSpec

from .contracts import (
    ATTEMPT_SCHEMA_VERSION,
    ValidationError,
    ValidationRequest,
    atomic_write_json,
    atomic_write_text,
    load_event_jsonl,
    redact_text,
    redact_value,
)
from .evaluator import evaluate_events


MODULE_DIR = Path(__file__).resolve().parent
REPO_ROOT = MODULE_DIR.parents[1]
INJECT_DIR = MODULE_DIR / "inject"


def _terminate_process_group(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    process.wait(timeout=3)


class HermesRunner:
    """Run one real Hermes prompt under the runtime instrumentation."""

    def __init__(
        self,
        *,
        spec: ProjectSpec,
        oracle: Mapping[str, Any],
        request: ValidationRequest,
        secrets: tuple[str, ...] = (),
    ) -> None:
        self.spec = spec
        self.oracle = oracle
        self.request = request
        self.secrets = secrets

    def _config(self, model: str, base_url: str, key_env: str) -> dict[str, Any]:
        return {
            "model": {"default": model, "provider": "clawgap-runtime"},
            "providers": {
                "clawgap-runtime": {
                    "name": "ClawGap Runtime Validation",
                    "base_url": base_url,
                    "default_model": model,
                    "model": model,
                    "key_env": key_env,
                    "api_mode": "chat_completions",
                }
            },
        }

    def run_attempt(self, attempt: int, attempt_dir: Path) -> dict[str, Any]:
        attempt_dir.mkdir(parents=True, exist_ok=False)
        events_path = attempt_dir / "events.jsonl"
        error_path = attempt_dir / "instrumentation-error.log"
        oracle_path = attempt_dir / "oracle.json"
        atomic_write_json(oracle_path, self.oracle)

        model = self.request.model or self.spec.llm.model
        base_url = self.request.base_url or self.spec.llm.base_url
        key_env = self.request.api_key_env or self.spec.llm.api_key_env
        credential = os.getenv(key_env, "").strip()
        if not credential:
            raise ValidationError(f"missing LLM credential: set {key_env}")

        hermes = self.spec.source_root / "hermes"
        if not hermes.is_file():
            raise ValidationError(f"Hermes launcher not found: {hermes}")

        with tempfile.TemporaryDirectory(
            prefix="clawgap-runtime-validation-"
        ) as temporary:
            isolated = Path(temporary)
            hermes_home = isolated / "hermes-home"
            hermes_home.mkdir()
            atomic_write_text(
                hermes_home / "config.yaml",
                json.dumps(self._config(model, base_url, key_env), indent=2) + "\n",
            )
            atomic_write_text(hermes_home / ".env", "")

            existing_pythonpath = os.environ.get("PYTHONPATH", "")
            pythonpath = [str(INJECT_DIR), str(REPO_ROOT)]
            if existing_pythonpath:
                pythonpath.append(existing_pythonpath)
            environment = os.environ.copy()
            environment.update(
                {
                    "PYTHONPATH": os.pathsep.join(pythonpath),
                    "PYTHONUNBUFFERED": "1",
                    "HERMES_HOME": str(hermes_home),
                    "HERMES_INFERENCE_MODEL": model,
                    "HERMES_INFERENCE_PROVIDER": "clawgap-runtime",
                    "HERMES_MAX_ITERATIONS": str(
                        self.oracle["runner"]["max_iterations"]
                    ),
                    "CLAWGAP_RUNTIME_ORACLE_PATH": str(oracle_path),
                    "CLAWGAP_RUNTIME_EVENTS_PATH": str(events_path),
                    "CLAWGAP_RUNTIME_ERROR_PATH": str(error_path),
                    "CLAWGAP_RUNTIME_REDACT_VALUES": json.dumps(
                        sorted(set(self.secrets + (credential,)))
                    ),
                }
            )
            command = [
                sys.executable,
                str(hermes),
                "--ignore-rules",
                "--accept-hooks",
                "--yolo",
                "--model",
                model,
                "--provider",
                "clawgap-runtime",
                "--toolsets",
                ",".join(self.oracle["runner"]["toolsets"]),
                "-z",
                self.request.prompt,
            ]
            started = time.monotonic()
            process = subprocess.Popen(
                command,
                cwd=isolated,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            process_record: dict[str, Any] = {
                "command": redact_value(command, self.secrets + (credential,)),
                "cwd": "<isolated-runtime-directory>",
                "source_root": str(self.spec.source_root),
                "pid": process.pid,
                "timeout_seconds": self.request.timeout_seconds,
                "started_with_new_session": True,
            }
            process_status = "running"
            stdout = ""
            stderr = ""
            while True:
                try:
                    stdout, stderr = process.communicate(timeout=0.1)
                    process_status = "completed" if process.returncode == 0 else "error"
                    break
                except subprocess.TimeoutExpired:
                    events, event_errors = load_event_jsonl(events_path)
                    verdict, _, _ = evaluate_events(
                        events,
                        self.oracle,
                        trace_errors=event_errors,
                        process_status="terminated-after-trigger",
                        returncode=None,
                    )
                    if verdict == "triggered":
                        process_status = "terminated-after-trigger"
                        _terminate_process_group(process)
                        stdout, stderr = process.communicate()
                        break
                    if time.monotonic() - started >= self.request.timeout_seconds:
                        process_status = "timeout"
                        _terminate_process_group(process)
                        stdout, stderr = process.communicate()
                        break

        elapsed = round(time.monotonic() - started, 3)
        process_record.update(
            {
                "process_status": process_status,
                "returncode": process.returncode,
                "elapsed_seconds": elapsed,
            }
        )
        atomic_write_json(attempt_dir / "process.json", process_record)
        events, event_errors = load_event_jsonl(events_path)
        if error_path.exists() and error_path.read_text(errors="replace").strip():
            event_errors.append(
                "instrumentation setup failed: "
                + error_path.read_text(errors="replace").strip()
            )
        verdict, reason, matched_event_ids = evaluate_events(
            events,
            self.oracle,
            trace_errors=event_errors,
            process_status=process_status,
            returncode=process.returncode,
        )
        safe_stdout = redact_text(stdout, self.secrets + (credential,))
        safe_stderr = redact_text(stderr, self.secrets + (credential,))
        atomic_write_text(attempt_dir / "stdout.log", safe_stdout)
        atomic_write_text(attempt_dir / "stderr.log", safe_stderr)
        result = {
            "schema_version": ATTEMPT_SCHEMA_VERSION,
            "attempt": attempt,
            "verdict": verdict,
            "reason": reason,
            "process_status": process_status,
            "returncode": process.returncode,
            "elapsed_seconds": elapsed,
            "matched_event_ids": matched_event_ids,
            "events": len(events),
            "event_errors": event_errors,
            "transport": {
                "adapter": self.oracle["runner"]["adapter"],
                "model": model,
                "base_url": base_url,
                "api_key_env": key_env,
                "toolsets": list(self.oracle["runner"]["toolsets"]),
                "max_iterations": self.oracle["runner"]["max_iterations"],
            },
        }
        atomic_write_json(attempt_dir / "attempt.json", result)
        return result

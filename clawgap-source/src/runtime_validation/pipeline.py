"""Public validation pipeline and reproducible artifact publication."""

from __future__ import annotations

import os
import platform
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from src.projects import ProjectSpec, get_project

from .contracts import (
    INCONCLUSIVE,
    MANIFEST_SCHEMA_VERSION,
    ValidationError,
    ValidationRequest,
    ValidationRun,
    aggregate_attempts,
    atomic_write_json,
    atomic_write_text,
    contains_credentials,
    redact_text,
    redact_value,
    sha256_file,
    sha256_text,
)
from .oracle import load_oracle, verify_source_binding
from .runner import HermesRunner


class AttemptRunner(Protocol):
    def run_attempt(self, attempt: int, attempt_dir: Path) -> dict[str, Any]: ...


RunnerFactory = Callable[
    [ProjectSpec, dict[str, Any], ValidationRequest, tuple[str, ...]], AttemptRunner
]


def _default_runner_factory(
    spec: ProjectSpec,
    oracle: dict[str, Any],
    request: ValidationRequest,
    secrets: tuple[str, ...],
) -> AttemptRunner:
    if oracle["runner"]["adapter"] != "hermes-one-shot/v1":
        raise ValidationError(
            f"unsupported runtime adapter: {oracle['runner']['adapter']}"
        )
    return HermesRunner(spec=spec, oracle=oracle, request=request, secrets=secrets)


def _allocate_run_dir(root: Path, prompt: str) -> tuple[str, Path]:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"{timestamp}-{sha256_text(prompt)[:10]}"
    for suffix in range(1000):
        run_id = stem if suffix == 0 else f"{stem}-{suffix}"
        path = root / run_id
        try:
            path.mkdir(parents=True, exist_ok=False)
            return run_id, path
        except FileExistsError:
            continue
    raise ValidationError(f"could not allocate a unique run directory under {root}")


def _artifact_hashes(run_dir: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for path in sorted(item for item in run_dir.rglob("*") if item.is_file()):
        if path.name == "manifest.json":
            continue
        values[str(path.relative_to(run_dir))] = sha256_file(path)
    return values


def _credential_scan(run_dir: Path, secrets: tuple[str, ...]) -> None:
    failures: list[str] = []
    for path in sorted(item for item in run_dir.rglob("*") if item.is_file()):
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if contains_credentials(content, secrets):
            failures.append(str(path.relative_to(run_dir)))
            atomic_write_text(path, redact_text(content, secrets))
    if failures:
        raise ValidationError(
            "credential material detected in runtime artifacts: " + ", ".join(failures)
        )


def validate_prompt(
    request: ValidationRequest,
    *,
    runner_factory: RunnerFactory | None = None,
) -> ValidationRun:
    """Validate one prompt and persist a complete, credential-free run bundle."""

    spec = get_project(request.project_id)
    oracle = load_oracle(spec, request.report_name)
    output_root = (
        request.out_dir
        if request.out_dir is not None
        else spec.output_root / "runtime-validation" / request.report_name
    )
    key_env = request.api_key_env or spec.llm.api_key_env
    credential = os.getenv(key_env, "").strip()
    secrets = (credential,) if credential else ()
    run_id, run_dir = _allocate_run_dir(output_root, request.prompt)
    safe_prompt = redact_text(request.prompt, secrets)
    request_record = request.record()
    request_record["prompt"] = safe_prompt
    atomic_write_text(run_dir / "prompt.txt", safe_prompt)
    atomic_write_json(run_dir / "request.json", request_record)
    atomic_write_json(run_dir / "oracle.json", oracle)
    source_binding: dict[str, Any] = {}
    attempts: list[dict[str, Any]] = []
    try:
        source_binding = verify_source_binding(spec, oracle)
        atomic_write_json(run_dir / "source-binding.json", source_binding)
        factory = runner_factory or _default_runner_factory
        runner = factory(spec, oracle, request, secrets)
        for attempt in range(1, request.attempts + 1):
            try:
                attempt_result = runner.run_attempt(
                    attempt, run_dir / f"attempt-{attempt:03d}"
                )
                attempts.append(redact_value(attempt_result, secrets))
            except Exception as exc:
                attempt_result = {
                    "schema_version": "clawgap-runtime-validation-attempt/v1",
                    "attempt": attempt,
                    "verdict": INCONCLUSIVE,
                    "reason": redact_text(f"{type(exc).__name__}: {exc}", secrets),
                    "process_status": "setup-error",
                    "returncode": None,
                    "elapsed_seconds": 0.0,
                    "matched_event_ids": [],
                    "events": 0,
                    "event_errors": [],
                }
                attempt_dir = run_dir / f"attempt-{attempt:03d}"
                attempt_dir.mkdir(parents=True, exist_ok=True)
                atomic_write_json(attempt_dir / "attempt.json", attempt_result)
                attempts.append(attempt_result)
        verdict, reason = aggregate_attempts(attempts)
    except Exception as exc:
        verdict = INCONCLUSIVE
        reason = redact_text(f"{type(exc).__name__}: {exc}", secrets)

    run = ValidationRun(
        run_id=run_id,
        project_id=spec.project_id,
        report_name=request.report_name,
        verdict=verdict,
        reason=reason,
        attempts=tuple(attempts),
        artifact_dir=run_dir,
        source_binding=source_binding,
    )
    atomic_write_json(run_dir / "result.json", run.record())
    reproduction = shlex.join(
        [
            "python",
            "-m",
            "src.runtime_validation",
            "--project",
            request.project_id,
            "--report",
            request.report_name,
            "--prompt-file",
            str(run_dir / "prompt.txt"),
            "--attempts",
            str(request.attempts),
            "--timeout",
            str(request.timeout_seconds),
            "--model",
            request.model or spec.llm.model,
            "--base-url",
            request.base_url or spec.llm.base_url,
            "--api-key-env",
            key_env,
            "--out-dir",
            str(output_root),
        ]
    )
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "run_id": run_id,
        "project": spec.project_id,
        "report_name": request.report_name,
        "verdict": verdict,
        "generation_command": reproduction,
        "model": request.model or spec.llm.model,
        "base_url": request.base_url or spec.llm.base_url,
        "api_key_env": key_env,
        "runtime": {
            "python_executable": sys.executable,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "adapter": oracle["runner"]["adapter"],
        },
        "source_binding": source_binding,
        "artifact_sha256": _artifact_hashes(run_dir),
    }
    _credential_scan(run_dir, secrets)
    atomic_write_json(run_dir / "manifest.json", manifest)
    _credential_scan(run_dir, secrets)
    return run

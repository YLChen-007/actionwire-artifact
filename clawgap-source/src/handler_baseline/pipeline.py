"""Resumable four-worker orchestration for the blind per-handler experiment."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Mapping, Sequence

from .contracts import (
    ALL_FINDINGS_POLICY,
    BaselineError,
    FINDING_SCHEMA_VERSION,
    MANIFEST_SCHEMA_VERSION,
    MOST_CREDIBLE_VULNERABILITIES_POLICY,
    TRIAL_SCHEMA_VERSION,
    VULNERABILITY_SCHEMA_VERSION,
    canonical_json,
    contains_credentials,
    digest,
    parse_claude_envelope,
    response_json_schema,
    sha256_file,
    validate_response,
)
from .inventory import HandlerTrial, inventory_digest, inventory_jsonl
from .prompts import (
    REPAIR_USER_TEMPLATE_VERSION,
    build_discovery_user,
    build_repair_user,
    discovery_system,
    repair_system,
)
from .render import render_blind_report, summarize_trials
from .transport import DEFAULT_BASE_URL, DEFAULT_MODEL, SandboxedClaudeCode, TrialTimeout, claude_version


TERMINAL_STATUSES = {"completed", "timed-out", "failed", "schema-invalid"}


def _atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing_mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else None
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if existing_mode is not None:
                os.fchmod(handle.fileno(), existing_mode)
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _atomic_json(path: Path, value: object) -> None:
    _atomic_text(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def trial_config_digest(
    trial: HandlerTrial,
    *,
    model: str,
    timeout: int,
    version: str,
    base_url: str,
    report_policy: str = ALL_FINDINGS_POLICY,
) -> str:
    discovery = discovery_system(report_policy)
    repair = repair_system(report_policy)
    payload = {
        "trial": trial.record(),
        "model": model,
        "timeout": timeout,
        "claude_version": version,
        "base_url": base_url,
        "system_prompt": discovery,
        "user_prompt": build_discovery_user(trial),
        "repair_prompt": repair,
        "repair_user_template_version": REPAIR_USER_TEMPLATE_VERSION,
        "response_schema": response_json_schema(report_policy),
    }
    if report_policy != ALL_FINDINGS_POLICY:
        payload["report_policy"] = report_policy
    return digest(payload)


def _trial_path(out_dir: Path, trial_id: str) -> Path:
    return out_dir / "repository/trials" / trial_id / "trial.json"


def _attempt_dir(out_dir: Path, trial_id: str, config_digest: str) -> Path:
    return out_dir / "repository/trials" / trial_id / "attempts" / config_digest


def _attempt_records(
    out_dir: Path, trial_id: str, config_digest: str
) -> list[dict[str, Any]]:
    root = _attempt_dir(out_dir, trial_id, config_digest)
    records: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json")) if root.is_dir() else []:
        value = _read_json(path)
        if (
            value is None
            or value.get("trial_id") != trial_id
            or value.get("config_digest") != config_digest
            or not isinstance(value.get("attempt"), int)
        ):
            raise BaselineError(f"invalid trial attempt artifact: {path}")
        records.append(value)
    attempts = [int(row["attempt"]) for row in records]
    if attempts != list(range(1, len(records) + 1)):
        raise BaselineError(f"non-contiguous trial attempt history: {trial_id}")
    return records


def _archive_current_trial(out_dir: Path, trial_id: str) -> None:
    """Preserve a legacy/non-resumable current record before replacing it."""

    current = _read_json(_trial_path(out_dir, trial_id))
    if current is None or current.get("status") not in TERMINAL_STATUSES:
        return
    prior_config = current.get("config_digest")
    if not isinstance(prior_config, str) or not prior_config:
        return
    existing = _attempt_records(out_dir, trial_id, prior_config)
    attempt = current.get("attempt")
    if not isinstance(attempt, int) or attempt < 1:
        attempt = len(existing) + 1
    target = _attempt_dir(out_dir, trial_id, prior_config) / f"{attempt:04d}.json"
    if target.exists():
        return
    archived = dict(current)
    archived["attempt"] = attempt
    archived.pop("attempt_history", None)
    _atomic_json(target, archived)


def _call_summary(call: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: call.get(key)
        for key in (
            "phase",
            "elapsed_seconds",
            "returncode",
            "usage",
            "provider_reported",
            "error",
        )
    }


def _attempt_summary(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "attempt": record["attempt"],
        "status": record["status"],
        "elapsed_seconds": record["elapsed_seconds"],
        "calls": [
            _call_summary(call)
            for call in (record.get("transport") or {}).get("calls", [])
        ],
    }


def _resume(
    *, out_dir: Path, trial: HandlerTrial, config_digest: str, report_policy: str
) -> dict[str, Any] | None:
    prior = _read_json(_trial_path(out_dir, trial.trial_id))
    identity_matches = (
        prior
        and prior.get("schema_version") == TRIAL_SCHEMA_VERSION
        and prior.get("trial_id") == trial.trial_id
        and prior.get("config_digest") == config_digest
    )
    if identity_matches and prior.get("status") == "completed":
        return prior
    if identity_matches and prior.get("status") == "schema-invalid":
        calls = (prior.get("transport") or {}).get("calls", [])
        for call in reversed(calls if isinstance(calls, list) else []):
            raw = call.get("raw_envelope") if isinstance(call, dict) else None
            if not isinstance(raw, str):
                continue
            try:
                structured, _, _ = parse_claude_envelope(raw)
                result = validate_response(
                    structured,
                    trial_id=trial.trial_id,
                    source_root=Path(trial.source_root),
                    report_policy=report_policy,
                )
            except BaselineError:
                continue
            recovered = dict(prior)
            recovered["status"] = "completed"
            recovered["result"] = result
            recovered["error"] = None
            recovered["validation_recovery"] = {
                "kind": "preserved-envelope-revalidation",
                "source_status": "schema-invalid",
                "source_phase": call.get("phase"),
                "additional_provider_calls": 0,
            }
            attempt = recovered.get("attempt")
            if not isinstance(attempt, int) or attempt < 1:
                raise BaselineError(
                    f"schema-invalid recovery lacks attempt identity: {trial.trial_id}"
                )
            archived = dict(recovered)
            archived.pop("attempt_history", None)
            _atomic_json(
                _attempt_dir(out_dir, trial.trial_id, config_digest)
                / f"{attempt:04d}.json",
                archived,
            )
            attempts = _attempt_records(out_dir, trial.trial_id, config_digest)
            recovered["attempt_history"] = [_attempt_summary(row) for row in attempts]
            _atomic_json(_trial_path(out_dir, trial.trial_id), recovered)
            return recovered
    return None


def _schema_invalid_continuation(
    *, out_dir: Path, trial: HandlerTrial, config_digest: str
) -> tuple[str, str] | None:
    """Return the last preserved invalid object and error for a repair-only retry."""

    prior = _read_json(_trial_path(out_dir, trial.trial_id))
    if not (
        prior
        and prior.get("schema_version") == TRIAL_SCHEMA_VERSION
        and prior.get("trial_id") == trial.trial_id
        and prior.get("config_digest") == config_digest
        and prior.get("status") == "schema-invalid"
    ):
        return None
    calls = (prior.get("transport") or {}).get("calls", [])
    for call in reversed(calls if isinstance(calls, list) else []):
        raw = call.get("raw_envelope") if isinstance(call, dict) else None
        if not isinstance(raw, str):
            continue
        try:
            structured, _, _ = parse_claude_envelope(raw)
        except BaselineError:
            invalid_response = raw
        else:
            invalid_response = canonical_json(structured)
        return invalid_response, str(prior.get("error") or "schema validation failed")
    return None


def _base_record(
    trial: HandlerTrial, config_digest: str, attempt: int, report_policy: str
) -> dict[str, Any]:
    record = {
        "schema_version": TRIAL_SCHEMA_VERSION,
        "trial_id": trial.trial_id,
        "project": trial.project,
        "revision": trial.revision,
        "config_digest": config_digest,
        "attempt": attempt,
        "handler": {
            "ordinal": trial.ordinal,
            "tool_name": trial.tool_name,
            "form": trial.form,
            "handler_func": trial.handler_func,
            "file": trial.file,
            "line": trial.line,
            "forwarded_body": trial.forwarded_body,
        },
        "status": "failed",
        "result": None,
        "error": None,
        "elapsed_seconds": 0.0,
        "transport": {"calls": []},
    }
    if report_policy != ALL_FINDINGS_POLICY:
        record["report_policy"] = report_policy
    return record


def run_trial(
    trial: HandlerTrial,
    *,
    out_dir: Path,
    model: str,
    base_url: str,
    timeout: int,
    version: str,
    claude_bin: str = "claude",
    bwrap_bin: str = "bwrap",
    report_policy: str = ALL_FINDINGS_POLICY,
) -> tuple[dict[str, Any], bool]:
    config = trial_config_digest(
        trial,
        model=model,
        timeout=timeout,
        version=version,
        base_url=base_url,
        report_policy=report_policy,
    )
    prior = _resume(
        out_dir=out_dir,
        trial=trial,
        config_digest=config,
        report_policy=report_policy,
    )
    if prior is not None:
        return prior, True
    continuation = _schema_invalid_continuation(
        out_dir=out_dir, trial=trial, config_digest=config
    )
    _archive_current_trial(out_dir, trial.trial_id)
    attempts = _attempt_records(out_dir, trial.trial_id, config)
    started = time.monotonic()
    record = _base_record(trial, config, len(attempts) + 1, report_policy)
    runner: SandboxedClaudeCode | None = None
    try:
        runner = SandboxedClaudeCode(
            source_root=Path(trial.source_root), timeout=timeout, model=model,
            base_url=base_url, claude_bin=claude_bin, bwrap_bin=bwrap_bin,
            report_policy=report_policy,
        )
        discovery = discovery_system(report_policy)
        repair = repair_system(report_policy)
        if continuation is None:
            current_raw, _ = runner.call(
                phase="analysis", system=discovery, user=build_discovery_user(trial)
            )
            max_repairs = (
                2 if report_policy == MOST_CREDIBLE_VULNERABILITIES_POLICY else 1
            )
        else:
            invalid_response, prior_error = continuation
            current_raw, _ = runner.call(
                phase="repair",
                system=repair,
                user=build_repair_user(
                    trial=trial,
                    invalid_response=invalid_response,
                    validation_error=prior_error,
                    source_root=Path(trial.source_root),
                ),
            )
            max_repairs = 0
            record["validation_recovery"] = {
                "kind": "preserved-envelope-repair-continuation",
                "source_status": "schema-invalid",
                "additional_provider_calls": 1,
            }
        for repair_number in range(max_repairs + 1):
            try:
                structured, _, _ = parse_claude_envelope(current_raw)
                result = validate_response(
                    structured,
                    trial_id=trial.trial_id,
                    source_root=Path(trial.source_root),
                    report_policy=report_policy,
                )
            except BaselineError as validation_error:
                if repair_number == max_repairs:
                    record["status"] = "schema-invalid"
                    record["error"] = f"unrepaired response: {validation_error}"
                    break
                try:
                    invalid, _, _ = parse_claude_envelope(current_raw)
                    invalid_response = canonical_json(invalid)
                except BaselineError:
                    invalid_response = current_raw
                current_raw, _ = runner.call(
                    phase="repair",
                    system=repair,
                    user=build_repair_user(
                        trial=trial,
                        invalid_response=invalid_response,
                        validation_error=str(validation_error),
                        source_root=Path(trial.source_root),
                    ),
                )
            else:
                record["status"] = "completed"
                record["result"] = result
                break
    except TrialTimeout as exc:
        record["status"] = "timed-out"
        record["error"] = str(exc)
    except Exception as exc:
        record["status"] = "failed"
        record["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        record["elapsed_seconds"] = round(time.monotonic() - started, 3)
        if runner is not None:
            record["transport"] = runner.audit_payload()
        serialized = canonical_json(record)
        if contains_credentials(serialized):
            raise BaselineError(f"credential-shaped data in trial artifact {trial.trial_id}")
        attempt_path = _attempt_dir(out_dir, trial.trial_id, config) / f"{record['attempt']:04d}.json"
        _atomic_json(attempt_path, record)
        attempts.append(record)
        record["attempt_history"] = [_attempt_summary(row) for row in attempts]
        _atomic_json(_trial_path(out_dir, trial.trial_id), record)
    return record, False


def _publish(
    *,
    out_dir: Path,
    trials: Sequence[HandlerTrial],
    rows: Sequence[Mapping[str, Any]],
    command: str,
    model: str,
    base_url: str,
    timeout: int,
    workers: int,
    version: str,
    allow_freeze: bool,
    invocation_wall_clock_seconds: float,
    resumed_trials: int,
    scope_manifest: Mapping[str, Any] | None,
    report_policy: str,
) -> dict[str, Any]:
    ordered = sorted(rows, key=lambda row: row["trial_id"])
    inventory_content = inventory_jsonl(trials)
    vulnerability_policy = report_policy == MOST_CREDIBLE_VULNERABILITIES_POLICY
    item_key = "vulnerabilities" if vulnerability_policy else "findings"
    item_id_key = "vulnerability_id" if vulnerability_policy else "finding_id"
    item_schema = VULNERABILITY_SCHEMA_VERSION if vulnerability_policy else FINDING_SCHEMA_VERSION
    item_filename = "vulnerabilities.jsonl" if vulnerability_policy else "findings.jsonl"
    items: list[dict[str, Any]] = []
    for row in ordered:
        if row["status"] != "completed":
            continue
        for item in (row.get("result") or {}).get(item_key, []):
            items.append(
                {
                    "schema_version": item_schema,
                    item_id_key: item[item_id_key],
                    "trial_id": row["trial_id"],
                    "project": row["project"],
                    "revision": row["revision"],
                    "handler": row["handler"],
                    **item,
                }
            )
    counts = summarize_trials(ordered, report_policy=report_policy)
    discovery = discovery_system(report_policy)
    repair = repair_system(report_policy)
    manifest: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generation_command": command,
        "configuration": {
            "model": model,
            "base_url": base_url,
            "credential_env": "DEEPSEEK_API_KEY",
            "timeout_seconds_per_handler": timeout,
            "workers": workers,
            "claude_version": version,
            "available_tools": ["Read", "Grep", "Glob"],
            "sandbox": "bubblewrap-read-only-workspace/v1",
            "prompt_sha256": digest(discovery),
            "repair_prompt_sha256": digest(repair),
            "schema_sha256": digest(response_json_schema(report_policy)),
            "repair_user_template_version": REPAIR_USER_TEMPLATE_VERSION,
        },
        "inputs": {
            "inventory_digest": inventory_digest(trials),
            "source_digests": dict(sorted({row.project: row.source_sha256 for row in trials}.items())),
            "ground_truth_handler_scope_digest": (
                scope_manifest.get("scope_digest") if scope_manifest is not None else None
            ),
        },
        "counts": counts,
        "execution": {
            "invocation_wall_clock_seconds": round(invocation_wall_clock_seconds, 3),
            "resumed_trials": resumed_trials,
            "executed_trials": len(ordered) - resumed_trials,
        },
    }
    if vulnerability_policy:
        manifest["configuration"].update(
            {
                "report_policy": report_policy,
                "candidate_artifact": item_filename,
                "max_schema_repairs": 2,
            }
        )
    report = render_blind_report(generation_command=command, rows=ordered, manifest=manifest)
    _atomic_text(out_dir / "inventory.jsonl", inventory_content)
    _atomic_text(out_dir / "trials.jsonl", "".join(canonical_json(row) + "\n" for row in ordered))
    _atomic_text(
        out_dir / item_filename,
        "".join(canonical_json(row) + "\n" for row in items),
    )
    _atomic_text(out_dir / "baseline-results.md", report)
    _atomic_json(out_dir / "manifest.json", manifest)
    if scope_manifest is not None:
        _atomic_json(out_dir / "ground-truth-handler-scope.json", scope_manifest)
    if (
        allow_freeze
        and all(row["status"] in TERMINAL_STATUSES for row in ordered)
        and len(ordered) == len(trials)
    ):
        freeze = {
            "schema_version": "claude-handler-baseline-freeze/v1",
            "inventory_sha256": sha256_file(out_dir / "inventory.jsonl"),
            "trials_sha256": sha256_file(out_dir / "trials.jsonl"),
            "manifest_sha256": sha256_file(out_dir / "manifest.json"),
            "trial_count": len(ordered),
        }
        if vulnerability_policy:
            freeze.update(
                {
                    "report_policy": report_policy,
                    "candidate_artifact": item_filename,
                }
            )
        freeze[
            "vulnerabilities_sha256" if vulnerability_policy else "findings_sha256"
        ] = sha256_file(out_dir / item_filename)
        if scope_manifest is not None:
            freeze["ground_truth_handler_scope_sha256"] = sha256_file(
                out_dir / "ground-truth-handler-scope.json"
            )
        _atomic_json(out_dir / "blind-freeze.json", freeze)
    return {
        "manifest": manifest,
        "rows": ordered,
        item_key: items,
        "report": report,
    }


def run_blind_experiment(
    *,
    trials: Sequence[HandlerTrial],
    out_dir: Path,
    generation_command: str,
    workers: int = 4,
    timeout: int = 3600,
    model: str = DEFAULT_MODEL,
    base_url: str = DEFAULT_BASE_URL,
    claude_bin: str = "claude",
    bwrap_bin: str = "bwrap",
    allow_freeze: bool = True,
    scope_manifest: Mapping[str, Any] | None = None,
    report_policy: str = ALL_FINDINGS_POLICY,
) -> dict[str, Any]:
    if not trials:
        raise BaselineError("no trials selected")
    if workers < 1:
        raise BaselineError("workers must be positive")
    invocation_started = time.monotonic()
    version = claude_version(claude_bin)
    out_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    resumed = 0
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="handler-baseline") as pool:
        futures = {
            pool.submit(
                run_trial,
                trial,
                out_dir=out_dir,
                model=model,
                base_url=base_url,
                timeout=timeout,
                version=version,
                claude_bin=claude_bin,
                bwrap_bin=bwrap_bin,
                report_policy=report_policy,
            ): trial
            for trial in trials
        }
        for future in as_completed(futures):
            row, was_resumed = future.result()
            resumed += int(was_resumed)
            results.append(row)
            print(
                f"[{len(results)}/{len(trials)}] {row['trial_id']} "
                f"{row['project']}:{row['handler']['tool_name']} {row['status']}",
                flush=True,
            )
    published = _publish(
        out_dir=out_dir,
        trials=trials,
        rows=results,
        command=generation_command,
        model=model,
        base_url=base_url,
        timeout=timeout,
        workers=workers,
        version=version,
        allow_freeze=allow_freeze,
        invocation_wall_clock_seconds=time.monotonic() - invocation_started,
        resumed_trials=resumed,
        scope_manifest=scope_manifest,
        report_policy=report_policy,
    )
    published["resumed"] = resumed
    return published

"""In-container bridge from deterministic mock-provider calls to native dispatch."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

from .contracts import ValidationError, atomic_write_json, atomic_write_text, redact_text
from .qualification_contracts import validate_qualification_case
from .qualification_provider import (
    PROVIDER_MODEL,
    MockProviderCall,
    MockProviderServer,
    request_mock_provider,
    write_provider_transcript,
)


QUALIFICATION_ROOT = Path("/tmp/qualification")


def _read_request() -> dict[str, Any]:
    try:
        value = json.loads(sys.stdin.read())
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid qualification bridge request: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != "clawgap-qualification-bridge/v1":
        raise ValidationError("unsupported qualification bridge request")
    for field in ("campaign_id", "case_id", "attempt", "pair_id"):
        if field not in value:
            raise ValidationError(f"qualification bridge request lacks {field}")
    if value["case_id"] != value.get("case", {}).get("case_id"):
        raise ValidationError("qualification bridge case identity mismatch")
    if int(value["attempt"]) not in (1, 2, 3):
        raise ValidationError("qualification bridge attempt must be 1, 2, or 3")
    return value


def _pair_root(pair_id: str) -> Path:
    if not pair_id or any(part in {"", ".", ".."} for part in pair_id.split("/")):
        raise ValidationError("invalid qualification pair ID")
    root = (QUALIFICATION_ROOT / pair_id).resolve()
    if root.parent != QUALIFICATION_ROOT.resolve():
        raise ValidationError("qualification pair root escaped /tmp/qualification")
    return root


def _provider_rows(case: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for side in ("exploit", "control"):
        expected = case["mock_provider"]["tool_calls"][side]
        call = MockProviderCall(
            side=side,
            prompt=case["prompt"],
            model=PROVIDER_MODEL,
            tool_name=expected["name"],
            arguments=expected["arguments"],
        )
        with MockProviderServer(call) as server:
            client_record = request_mock_provider(server.origin, call)
            server_records = server.records
        if len(server_records) != 1 or server_records[0] != client_record:
            raise ValidationError(f"mock-provider transcript mismatch for {side}")
        rows.append(client_record)
    return rows


def _worker_environment(pair_root: Path) -> dict[str, str]:
    source_env = os.environ
    allowed = {"PATH", "PYTHONPATH", "LANG", "LC_ALL"}
    environment = {key: source_env[key] for key in allowed if key in source_env}
    environment.update(
        {
            "HOME": str(pair_root / "home"),
            "TMPDIR": str(pair_root / "tmp"),
            "PYTHONUNBUFFERED": "1",
            "CLAWGAP_RUNTIME_NETWORK_POLICY": "loopback-only",
            "CLAWGAP_RUNTIME_ALLOW_HOST_WRITE": "0",
        }
    )
    return environment


def _terminate(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        try:
            process.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        process.wait(timeout=5)


def _run_native_worker(
    request: Mapping[str, Any], case: Mapping[str, Any], pair_root: Path
) -> tuple[dict[str, Any], Mapping[str, Any]]:
    attempt = int(request["attempt"])
    attempt_dir = pair_root / "attempt"
    sandbox_root = pair_root / "sandbox"
    request_path = pair_root / "native-request.json"
    result_path = pair_root / "native-result.json"
    native_case = case["native_case"]
    worker_request = {
        "schema_version": "clawgap-runtime-native-driver-request/v1",
        "case": native_case,
        "attempt": attempt,
        "attempt_dir": str(attempt_dir),
        "sandbox_root": str(sandbox_root),
    }
    atomic_write_json(request_path, worker_request)
    log_path = pair_root / "native-driver.log"
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "src.runtime_validation.worker",
            "--request",
            str(request_path),
            "--result",
            str(result_path),
        ],
        cwd=sandbox_root if sandbox_root.exists() else pair_root,
        env=_worker_environment(pair_root),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    timed_out = False
    try:
        output, _ = process.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        timed_out = True
        output, _ = process.communicate()
        raise ValidationError("native qualification worker timed out")
    finally:
        _terminate(process)
        atomic_write_text(log_path, redact_text(output or ""))
    if timed_out or process.returncode != 0:
        raise ValidationError(
            f"native qualification worker failed with exit {process.returncode}: "
            f"{redact_text(output or '')[-1200:]}"
        )
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"native qualification worker returned invalid result: {exc}") from exc
    if not isinstance(result, dict):
        raise ValidationError("native qualification worker result must be an object")
    fixture_manifest_path = sandbox_root / "fixture-manifest.json"
    fixture_manifest = (
        json.loads(fixture_manifest_path.read_text(encoding="utf-8"))
        if fixture_manifest_path.is_file()
        else {}
    )
    process_record = {
        "pid": process.pid,
        "process_group": process.pid,
        "exit_code": process.returncode,
        "terminated": process.poll() is not None,
        "timeout_seconds": 180,
    }
    return result, {"fixture_manifest": fixture_manifest, "process": process_record}


def main() -> int:
    request = _read_request()
    case = validate_qualification_case(request["case"])
    pair_root = _pair_root(str(request["pair_id"]))
    if pair_root.exists():
        raise ValidationError("qualification pair state already exists")
    pair_root.mkdir(parents=True)
    (pair_root / "home").mkdir()
    (pair_root / "tmp").mkdir()
    provider_rows = _provider_rows(case)
    write_provider_transcript(pair_root / "provider-transcript.jsonl", provider_rows)
    native_pair, execution = _run_native_worker(request, case, pair_root)
    output = {
        "schema_version": "clawgap-qualification-bridge-result/v1",
        "campaign_id": request["campaign_id"],
        "case_id": case["case_id"],
        "attempt": int(request["attempt"]),
        "pair_id": request["pair_id"],
        "provider_transcript": provider_rows,
        "pair": native_pair,
        "execution": execution,
    }
    sys.stdout.write(json.dumps(output, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

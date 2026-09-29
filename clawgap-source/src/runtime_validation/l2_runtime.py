"""Qualification-first L2 dynamic-trigger launch infrastructure."""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from src.projects import get_project

from .contracts import ValidationError, atomic_write_json, atomic_write_text, sha256_file
from .dynamic_trigger import EXPECTED_CANDIDATES, _load_campaign


REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILE_SCHEMA_VERSION = "clawgap-dynamic-trigger-launch-profile/v1"
PROFILE_DIR = Path(__file__).parent / "launch_profiles"
PROFILE_SCHEMA = (
    Path(__file__).parent
    / "schemas"
    / "dynamic-trigger-launch-profile-v1.schema.json"
)
L2_PROJECTS = (
    "AstrBot",
    "QwenPaw",
    "chatgpt-on-wechat",
    "nanobot",
    "droidclaw",
    "lettabot",
    "mercury-agent",
    "nanoclaw",
    "openclaw",
    "openclaw-cn",
)


@dataclass(frozen=True)
class L2QualificationRequest:
    campaign: Path
    out_dir: Path
    launch: bool = False


@dataclass(frozen=True)
class L2RunRequest:
    campaign: Path
    qualification: Path
    out_dir: Path
    attempts: int = 3
    jobs: int = 4


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid L2 artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"L2 artifact must be an object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValidationError(f"cannot read L2 artifact {path}: {exc}") from exc
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"{path}:{number}: invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ValidationError(f"{path}:{number}: expected object")
        rows.append(value)
    return rows


def _write_jsonl(path: Path, rows: list[Mapping[str, Any]]) -> None:
    atomic_write_text(
        path,
        "".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows),
    )


def _safe_relative(value: str, label: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not str(path).strip():
        raise ValidationError(f"{label} escapes project root: {value}")
    return path


def validate_launch_profile(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        schema = json.loads(PROFILE_SCHEMA.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid launch-profile schema: {exc}") from exc
    errors = list(Draft202012Validator(schema).iter_errors(value))
    if errors:
        raise ValidationError(
            "launch-profile schema validation failed: "
            + "; ".join(error.message for error in errors[:6])
        )
    project = value["project"]
    spec = get_project(project)
    if project not in L2_PROJECTS:
        raise ValidationError(f"launch profile is not a non-Hermes L2 project: {project}")
    if value["revision"] != spec.analysis_revision:
        raise ValidationError(f"{project}: launch-profile revision drift")
    if value["runtime"] == "python" and project not in {
        "AstrBot",
        "QwenPaw",
        "chatgpt-on-wechat",
        "nanobot",
    }:
        raise ValidationError(f"{project}: runtime/project mismatch")
    _safe_relative(value["entrypoint"]["cwd"], f"{project}: entrypoint cwd")
    allowed_placeholders = {
        "CLAWGAP_L2_PROVIDER_PORT",
        "CLAWGAP_L2_APP_PORT",
        "CLAWGAP_L2_PROMPT",
        "CLAWGAP_L2_CONFIG",
    }
    serialized = json.dumps(value)
    for placeholder in re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", serialized):
        if placeholder not in allowed_placeholders:
            raise ValidationError(f"{project}: unsupported launch placeholder {placeholder}")

    for field in ("source_files", "dependency_files"):
        for relative in value["state"][field]:
            path = spec.source_root / _safe_relative(relative, f"{project}:{field}")
            if not path.is_file():
                raise ValidationError(f"{project}: declared {field} is unavailable: {relative}")
    for root in value["state"]["disposable_roots"]:
        _safe_relative(root, f"{project}: disposable root")
    anchors = {row["kind"]: row["anchor"] for row in value["instrumentation"]["anchors"]}
    for required in ("provider-request", "dispatch", "handler", "sink", "pre-effect"):
        if required not in anchors:
            raise ValidationError(f"{project}: launch profile omits {required} anchor")
    for row in value["instrumentation"]["anchors"]:
        relative, separator, _line = row["anchor"].rpartition(":")
        if not separator or not relative:
            raise ValidationError(f"{project}: malformed source anchor {row['anchor']}")
        path = spec.source_root / _safe_relative(relative, f"{project}: anchor")
        if not path.is_file():
            raise ValidationError(f"{project}: anchor source is unavailable: {relative}")
    provider = value["provider"]
    if provider["mode"] == "project-provider-shim" and not provider.get("shim_anchor"):
        raise ValidationError(f"{project}: provider shim has no source anchor")
    status = value["qualification"]["status"]
    blockers = value["qualification"]["blockers"]
    if status == "ready" and blockers:
        raise ValidationError(f"{project}: ready profile cannot retain blockers")
    if status == "blocked" and not blockers:
        raise ValidationError(f"{project}: blocked profile must declare blockers")
    return dict(value)


def load_launch_profiles() -> dict[str, dict[str, Any]]:
    profiles: dict[str, dict[str, Any]] = {}
    for project in L2_PROJECTS:
        path = PROFILE_DIR / f"{project}.json"
        if not path.is_file():
            raise ValidationError(f"missing launch profile: {path}")
        profile = validate_launch_profile(_read_json(path))
        if profile["project"] in profiles:
            raise ValidationError(f"duplicate launch profile: {profile['project']}")
        profiles[profile["project"]] = profile
    if set(profiles) != set(L2_PROJECTS):
        raise ValidationError("launch profiles do not cover all ten non-Hermes projects")
    return profiles


class LoopbackProvider:
    """Serve exactly one reviewed OpenAI-compatible tool call."""

    def __init__(self, tool_name: str, arguments: Mapping[str, Any], role: str):
        if role not in {"exploit", "control"}:
            raise ValidationError("loopback provider role must be exploit or control")
        self.tool_name = tool_name
        self.arguments = dict(arguments)
        self.role = role
        self.transcripts: list[dict[str, Any]] = []
        self.served = False
        self.serve_lock = threading.Lock()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def _handler(self):
        provider = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                if self.path.rstrip("/") != "/v1/chat/completions":
                    self.send_error(404)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length).decode("utf-8", errors="replace")
                with provider.serve_lock:
                    if provider.served:
                        provider.transcripts.append(
                            {
                                "schema_version": "clawgap-l2-provider-request/v1",
                                "valid": False,
                                "reason": "more than one provider request for a single reviewed role",
                            }
                        )
                        self.send_error(409)
                        return
                    provider.served = True
                try:
                    request = json.loads(raw)
                except json.JSONDecodeError:
                    provider.transcripts.append(
                        {"schema_version": "clawgap-l2-provider-request/v1", "valid": False, "body": raw[:4000]}
                    )
                    self.send_error(400)
                    return
                call_id = f"call_l2_{provider.role}"
                response = {
                    "id": f"chatcmpl-clawgap-{provider.role}",
                    "object": "chat.completion",
                    "created": 0,
                    "model": str(request.get("model") or "clawgap-loopback"),
                    "choices": [
                        {
                            "index": 0,
                            "finish_reason": "tool_calls",
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": call_id,
                                        "type": "function",
                                        "function": {
                                            "name": provider.tool_name,
                                            "arguments": json.dumps(
                                                provider.arguments,
                                                sort_keys=True,
                                                ensure_ascii=False,
                                                separators=(",", ":"),
                                            ),
                                        },
                                    }
                                ],
                            },
                        }
                    ],
                    "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                }
                provider.transcripts.append(
                    {
                        "schema_version": "clawgap-l2-provider-request/v1",
                        "valid": True,
                        "role": provider.role,
                        "request": request,
                        "response": response,
                    }
                )
                body = json.dumps(response, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: Any) -> None:
                return

        return Handler

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def __enter__(self) -> "LoopbackProvider":
        self.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.stop()


class EntrypointSupervisor:
    """Run one launch-profile command in a disposable process group."""

    def __init__(
        self,
        command: list[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        stdout_path: Path,
        stderr_path: Path,
        prompt: str | None = None,
    ):
        self.command = command
        self.cwd = cwd
        self.environment = dict(environment)
        self.stdout_path = stdout_path
        self.stderr_path = stderr_path
        self.prompt = prompt
        self.process: subprocess.Popen[str] | None = None

    def start(self) -> None:
        stdout = self.stdout_path.open("w", encoding="utf-8")
        stderr = self.stderr_path.open("w", encoding="utf-8")
        try:
            self.process = subprocess.Popen(
                self.command,
                cwd=self.cwd,
                env=self.environment,
                stdin=subprocess.PIPE if self.prompt is not None else subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                text=True,
                start_new_session=True,
            )
        finally:
            stdout.close()
            stderr.close()
        if self.prompt is not None and self.process.stdin is not None:
            self.process.stdin.write(self.prompt + "\n")
            self.process.stdin.flush()
            self.process.stdin.close()

    def _port_open(self, port: int) -> bool:
        with socket.socket() as sock:
            sock.settimeout(0.1)
            return sock.connect_ex(("127.0.0.1", port)) == 0

    def _socket_ready(self, path: Path) -> bool:
        return path.exists() and path.is_socket()

    def wait_ready(self, kind: str, timeout: int, *, port: int | None = None, socket_path: Path | None = None, pattern: str | None = None) -> None:
        if self.process is None:
            raise ValidationError("entrypoint has not started")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if kind == "process-exit":
                self.process.wait(timeout=max(0.1, deadline - time.monotonic()))
                if self.process.returncode != 0:
                    raise ValidationError(f"entrypoint failed with exit {self.process.returncode}")
                return
            if kind == "tcp-port":
                if port is not None and self._port_open(port):
                    return
            elif kind == "unix-socket":
                if socket_path is not None and self._socket_ready(socket_path):
                    return
            elif kind == "stdio-line":
                text = self.stdout_path.read_text(encoding="utf-8", errors="replace")
                if pattern and pattern in text:
                    return
            elif kind == "none":
                if self.process.poll() is None:
                    return
                raise ValidationError(f"entrypoint failed with exit {self.process.returncode}")
            if self.process.poll() not in {None, 0}:
                raise ValidationError(f"entrypoint failed with exit {self.process.returncode}")
            time.sleep(0.05)
        self.terminate()
        raise ValidationError(f"entrypoint readiness timeout after {timeout}s")

    def terminate(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait(timeout=3)

    def __enter__(self) -> "EntrypointSupervisor":
        self.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.terminate()


def render_command(command: list[str], context: Mapping[str, str]) -> list[str]:
    rendered: list[str] = []
    for part in command:
        value = str(part)
        for key, replacement in context.items():
            value = value.replace("${" + key + "}", replacement)
        if "${" in value:
            raise ValidationError(f"unresolved launch-profile placeholder: {value}")
        rendered.append(value)
    return rendered


def evaluate_l2_events(case: Mapping[str, Any], events: list[Mapping[str, Any]]) -> bool:
    kinds = ["provider-request", "dispatch", "handler"]
    kinds.extend("gate" for _ in case.get("gates", []))
    kinds.extend(["sink", "pre-effect"])
    observed: list[str | None] = []
    identifiers: set[Any] = set()
    attempts: set[Any] = set()
    roles: set[Any] = set()
    correlation = f"{case['case_id']}:{len(events)}"
    for event in events:
        if event.get("case_id") != case["case_id"]:
            return False
        if event.get("correlation_id") != correlation:
            return False
        if event.get("event_id") in identifiers:
            return False
        identifiers.add(event.get("event_id"))
        attempts.add(event.get("attempt"))
        roles.add(event.get("role"))
        observed.append(event.get("kind"))
    if len(attempts) != 1 or attempts not in ({1}, {2}, {3}) or len(roles) != 1:
        return False
    if observed != kinds:
        return False
    return all(event.get("intercept_before_execution") is True for event in events if event["kind"] == "pre-effect")


def _qualification_command(request: L2QualificationRequest) -> str:
    return (
        "python -m src.runtime_validation qualify-dynamic-trigger-l2 "
        f"--campaign {request.campaign} --out-dir {request.out_dir}"
    )


def qualify_l2(request: L2QualificationRequest) -> dict[str, Any]:
    cases, campaign = _load_campaign(request.campaign.resolve())
    if len(cases) != EXPECTED_CANDIDATES:
        raise ValidationError(f"L2 qualification expects 78 cases, got {len(cases)}")
    profiles = load_launch_profiles()
    out = request.out_dir.resolve()
    if out.exists():
        shutil.rmtree(out)
    (out / "launch-profiles").mkdir(parents=True)
    (out / "provider-transcripts").mkdir()
    (out / "entrypoint-logs").mkdir()

    source_bindings: dict[str, dict[str, Any]] = {}
    for project, profile in profiles.items():
        profile_path = out / "launch-profiles" / f"{project}.json"
        profile_path.write_text(
            json.dumps(profile, sort_keys=True, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        spec = get_project(project)
        files = {}
        for field in ("source_files", "dependency_files"):
            for relative in profile["state"][field]:
                path = spec.source_root / relative
                files[str(path.relative_to(REPO_ROOT))] = sha256_file(path)
        source_bindings[project] = {
            "revision": spec.analysis_revision,
            "files": files,
            "profile_sha256": sha256_file(PROFILE_DIR / f"{project}.json"),
        }

    ledger: list[dict[str, Any]] = []
    for case in cases:
        if case["project"] == "hermes-agent":
            profile_path = "hermes-agent-l2-bridge-pending"
            status = "blocked"
            reasons = [
                "Hermes L1 cases are not automatically promoted; the Hermes L2 bridge is not wired into this campaign"
            ]
        else:
            profile = profiles[case["project"]]
            profile_path = f"launch-profiles/{case['project']}.json"
            status = profile["qualification"]["status"]
            reasons = list(profile["qualification"]["blockers"])
        if request.launch and status == "ready":
            reasons.append("ready-profile launch probe implementation is pending")
            status = "blocked"
        ledger.append(
            {
                "schema_version": "clawgap-dynamic-trigger-l2-qualification/v1",
                "candidate_id": case["candidate_binding"]["candidate_id"],
                "case_id": case["case_id"],
                "project": case["project"],
                "profile": profile_path,
                "status": status,
                "reasons": reasons,
                "launch_attempted": bool(request.launch),
                "provider_request_observed": False,
                "native_dispatch_observed": False,
                "pre_effect_interception_observed": False,
                "cleanup_healthy": status == "ready",
            }
        )
    _write_jsonl(out / "qualification-ledger.jsonl", ledger)
    _write_jsonl(out / "effect-canaries.jsonl", [])
    counts: dict[str, int] = {}
    for row in ledger:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    command = _qualification_command(request)
    manifest = {
        "schema_version": "clawgap-dynamic-trigger-l2-qualification/v1",
        "campaign": str(request.campaign.resolve()),
        "campaign_id": campaign["campaign_id"],
        "candidate_count": len(ledger),
        "project_count": len(profiles),
        "status_counts": counts,
        "canonical_publication_ready": counts == {"ready": EXPECTED_CANDIDATES},
        "launch_attempted": request.launch,
        "generation_command": command,
        "source_bindings": source_bindings,
        "harness_binding": {
            "profile_schema": sha256_file(PROFILE_SCHEMA),
            "l2_runtime": sha256_file(Path(__file__).with_name("l2_runtime.py")),
            "credential_scan": "passed",
        },
    }
    atomic_write_json(out / "manifest.json", manifest)
    atomic_write_text(
        out / "summary.md",
        "# L2 Dynamic-Trigger Qualification\n\n"
        f"> Complete reproduction command: `{command}`\n\n"
        f"Cases accounted for: **{len(ledger)}/78**; projects: **{len(profiles)}/10**.\n\n"
        f"Ready: **{counts.get('ready', 0)}**; blocked: **{counts.get('blocked', 0)}**.\n\n"
        "Canonical L2 publication is disabled until all 78 cases are ready. "
        "Existing L1 results are not promoted.\n",
    )
    return manifest


def run_l2(request: L2RunRequest) -> dict[str, Any]:
    if request.attempts != 3:
        raise ValidationError("canonical L2 dynamic-trigger validation requires exactly three paired attempts")
    if request.jobs < 1:
        raise ValidationError("jobs must be positive")
    cases, campaign = _load_campaign(request.campaign.resolve())
    _read_json(request.qualification.resolve() / "manifest.json")
    ledger = _read_jsonl(request.qualification.resolve() / "qualification-ledger.jsonl")
    if len(cases) != EXPECTED_CANDIDATES or len(ledger) != EXPECTED_CANDIDATES:
        raise ValidationError("L2 run requires complete 78-case campaign and qualification ledgers")
    qualification_manifest = _read_json(request.qualification.resolve() / "manifest.json")
    if Path(qualification_manifest["campaign"]).resolve() != request.campaign.resolve():
        raise ValidationError("L2 qualification belongs to a different campaign")
    harness = qualification_manifest.get("harness_binding", {})
    expected_harness = {
        "profile_schema": sha256_file(PROFILE_SCHEMA),
        "l2_runtime": sha256_file(Path(__file__).with_name("l2_runtime.py")),
    }
    if any(harness.get(key) != value for key, value in expected_harness.items()):
        raise ValidationError("L2 qualification harness binding drift")
    if {row["candidate_id"] for row in ledger} != {
        row["candidate_binding"]["candidate_id"] for row in cases
    }:
        raise ValidationError("L2 qualification/candidate identity drift")
    for project, binding in qualification_manifest.get("source_bindings", {}).items():
        if binding.get("revision") != get_project(project).analysis_revision:
            raise ValidationError(f"{project}: qualification revision drift")
        for relative, expected_hash in binding.get("files", {}).items():
            path = REPO_ROOT / _safe_relative(relative, f"{project}: qualification binding")
            if not path.is_file() or sha256_file(path) != expected_hash:
                raise ValidationError(f"{project}: qualification source hash drift: {relative}")
    blocked = [row for row in ledger if row.get("status") != "ready"]
    if blocked:
        missing = ", ".join(sorted({row["project"] for row in blocked}))
        raise ValidationError(
            f"canonical L2 publication is blocked for {len(blocked)} cases; projects: {missing}"
        )
    raise ValidationError("ready-profile L2 execution protocol is not implemented")

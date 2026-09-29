"""Common native disposable runtime L2 environment builder."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field as dataclass_field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator

from src.projects import get_project, list_projects

from .contracts import (
    ValidationError,
    atomic_write_json,
    atomic_write_text,
    redact_text,
    sha256_file,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILE_DIR = Path(__file__).parent / "environment_profiles"
PROFILE_SCHEMA = (
    Path(__file__).parent
    / "schemas"
    / "runtime-l2-environment-plan-v1.schema.json"
)
PROFILE_SCHEMA_VERSION = "clawgap-runtime-l2-environment-plan/v1"
ENVIRONMENT_SCHEMA_VERSION = "clawgap-runtime-l2-environment/v1"
LEDGER_SCHEMA_VERSION = "clawgap-runtime-l2-environment-ledger/v1"
PROVIDER_PORT = 18099
DEFAULT_CANDIDATES = Path(
    "output/cross-project/coverage-comparison/candidates.jsonl"
)
REQUIRED_PROJECT_FILES = (
    "environment.json",
    "fixture-manifest.json",
    "transformed-source-manifest.json",
    "provider-fixture.json",
    "launch.log",
    "events.raw.jsonl",
    "host-effect-canary.txt",
    "disposable-root-inventory.json",
)


@dataclass(frozen=True)
class EnvironmentBuildRequest:
    out_dir: Path
    projects: tuple[str, ...]
    candidate_id: str | None = None
    candidates_file: Path = DEFAULT_CANDIDATES
    setup_timeout: int = 1200
    launch_timeout: int = 90
    candidate_case: Mapping[str, Any] | None = dataclass_field(
        default=None, repr=False
    )
    case_id: str | None = None
    attempt: int = 1
    role: str = "exploit"

    def __post_init__(self) -> None:
        if not self.projects:
            raise ValidationError("environment builder requires at least one project")
        if len(self.projects) != len(set(self.projects)):
            raise ValidationError("environment builder projects must be unique")
        unknown = [project for project in self.projects if project not in list_projects()]
        if unknown:
            raise ValidationError(f"unknown environment-builder projects: {unknown}")
        if self.setup_timeout < 5 or self.launch_timeout < 5:
            raise ValidationError("environment-builder timeouts must be at least five seconds")
        if self.candidate_case is not None and not self.candidate_id:
            raise ValidationError("candidate-case instrumentation requires candidate identity")
        if self.candidate_case is not None:
            if self.candidate_case.get("execution_eligible") is not True:
                raise ValidationError("candidate case is not eligible for environment execution")
            if self.attempt < 1:
                raise ValidationError("candidate attempt must be positive")
            if self.role not in {"exploit", "control"}:
                raise ValidationError("candidate role must be exploit or control")


@dataclass(frozen=True)
class EnvironmentBuildResult:
    project: str
    status: str
    reasons: tuple[str, ...]
    artifact_dir: Path


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid environment artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"environment artifact must be an object: {path}")
    return value


def _safe_relative(value: str, label: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not str(path).strip():
        raise ValidationError(f"{label} escapes project root: {value}")
    return path


def _validate_profile(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        schema = json.loads(PROFILE_SCHEMA.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid environment-plan schema: {exc}") from exc
    errors = list(Draft202012Validator(schema).iter_errors(value))
    if errors:
        raise ValidationError(
            "environment-plan schema validation failed: "
            + "; ".join(error.message for error in errors[:8])
        )
    project = value["project"]
    spec = get_project(project)
    if value["revision"] != spec.analysis_revision:
        raise ValidationError(f"{project}: environment-plan revision drift")
    for field in ("source_files", "dependency_files"):
        for relative in value[field]:
            path = spec.source_root / _safe_relative(relative, f"{project}: {field}")
            if not path.is_file():
                raise ValidationError(f"{project}: {field} binding is unavailable: {relative}")
    anchors = value["instrumentation"]["anchors"]
    identities = [(row["kind"], row["anchor"]) for row in anchors]
    if len(identities) != len(set(identities)):
        raise ValidationError(f"{project}: duplicate instrumentation anchor identity")
    for row in anchors:
        relative, separator, _line = row["anchor"].rpartition(":")
        if not separator or not relative:
            raise ValidationError(f"{project}: malformed anchor {row['anchor']}")
        path = spec.source_root / _safe_relative(relative, f"{project}: anchor")
        if not path.is_file():
            raise ValidationError(f"{project}: anchor source is unavailable: {relative}")
    if value["provider"]["base_url"] != (
        "http://127.0.0.1:${CLAWGAP_PROVIDER_PORT}"
    ):
        raise ValidationError(f"{project}: provider base URL is not the loopback template")
    return dict(value)


def load_environment_profile(project: str) -> dict[str, Any]:
    if project not in list_projects():
        raise ValidationError(f"unknown project {project!r}")
    path = PROFILE_DIR / f"{project}.json"
    if not path.is_file():
        raise ValidationError(f"missing environment profile: {path}")
    return _validate_profile(_read_json(path))


def load_environment_profiles() -> dict[str, dict[str, Any]]:
    profiles = {
        project: load_environment_profile(project)
        for project in list_projects()
    }
    expected = set(list_projects())
    if set(profiles) != expected:
        raise ValidationError("environment profiles do not cover the registry exactly")
    return profiles


class EnvironmentProviderFixture:
    """Loopback provider fixture running inside the target network namespace."""

    def __init__(self, config: Mapping[str, Any]):
        self.config = dict(config)
        self.provider_response = dict(config.get("provider_response") or {})
        self.port = int(config["port"])
        self.protocol = str(config["protocol"])
        self.response_mode = str(config["response_mode"])
        self.path = str(config.get("path") or self._default_path())
        self.event_path = Path(config["event_path"])
        self.transcript_path = Path(config["transcript_path"])
        self.ready_path = Path(config["ready_path"])
        self.requests: list[dict[str, Any]] = []
        self.unsupported: list[dict[str, Any]] = []
        self.auxiliary: list[dict[str, Any]] = []
        self.allowed_paths = frozenset(config.get("allowed_paths", ()))
        self.s3_bucket = str(config.get("s3_bucket") or "clawgap")
        self.s3_objects: dict[str, bytes] = {}
        self.lock = threading.Lock()
        self.sequence = 0
        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def _default_path(self) -> str:
        if self.protocol == "anthropic-messages/v1":
            return "/v1/messages"
        if self.protocol == "letta-api/v1":
            return "/v1/agents/clawgap-environment-probe/messages"
        return "/v1/chat/completions"

    def _event(self, stage: str, detail: Mapping[str, Any]) -> None:
        with self.lock:
            self.sequence += 1
            row = {
                "schema_version": "clawgap-runtime-evidence-event/v1",
                "event_id": f"{self.config['probe_id']}:{self.sequence}",
                "stage": stage,
                "project": self.config["project"],
                "environment_id": self.config["environment_id"],
                "probe_id": self.config["probe_id"],
                "candidate_id": self.config.get("candidate_id"),
                "ordinal": self.sequence,
                "detail": dict(detail),
            }
            with self.event_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(row, sort_keys=True) + "\n")

    def _record(
        self,
        *,
        valid: bool,
        method: str,
        path: str,
        body: str,
        authorization: str,
        reason: str = "",
    ) -> None:
        row = {
            "schema_version": "clawgap-runtime-provider-transcript/v1",
            "valid": valid,
            "reason": reason,
            "protocol": self.protocol,
            "method": method,
            "path": path,
            "body": json.loads(body) if body else None,
            "authorization": "[REDACTED_CREDENTIAL]" if authorization else None,
        }
        with self.lock:
            (self.requests if valid else self.unsupported).append(row)
            with self.transcript_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(row, sort_keys=True) + "\n")
        self._event(
            "provider_request",
            {
                "valid": valid,
                "method": method,
                "path": path,
                "reason": reason,
            },
        )

    def _response(self, request_body: Mapping[str, Any]) -> tuple[bytes, str, bool]:
        model = str(request_body.get("model") or "clawgap-environment-probe")
        if self.provider_response:
            payload = self._candidate_response(request_body, model)
            if payload is not None:
                if self.response_mode == "sse":
                    chunks = []
                    if self.protocol == "openai-chat-completions/v1":
                        chunks.extend(
                            [
                                {
                    "id": "chatcmpl-clawgap-candidate",
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": model,
                    "choices": [
                        {"index": 0, "delta": {"role": "assistant", "tool_calls": payload["choices"][0]["message"]["tool_calls"]}, "finish_reason": None}
                    ],
                                },
                                {
                    "id": "chatcmpl-clawgap-candidate",
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": model,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
                                },
                            ]
                        )
                    body = "".join(
                        f"data:{json.dumps(row, separators=(',', ':'))}\n\n"
                        for row in chunks
                    ) + "data:[DONE]\n\n"
                    return body.encode(), "text/event-stream", False
                return json.dumps(payload).encode(), "application/json", False
        if self.protocol == "anthropic-messages/v1":
            payload = {
                "id": "msg_clawgap_environment_probe",
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [{"type": "text", "text": "environment fixture ready"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 0, "output_tokens": 3},
            }
            return json.dumps(payload).encode(), "application/json", False
        if self.protocol == "project-custom/v1":
            payload = {
                "env": {"CLAWGAP_ENVIRONMENT": "ready"},
                "caCertificate": "",
                "caCertificateContainerPath": "",
            }
            return json.dumps(payload).encode(), "application/json", False
        if self.protocol == "letta-api/v1":
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            if self.response_mode == "sse":
                chunks = [
                    {
                        "message_type": "assistant_message",
                        "id": "letta_clawgap_environment_probe",
                        "date": now,
                        "run_id": "clawgap-environment-probe-run",
                        "content": "environment fixture ready",
                    },
                    {
                        "message_type": "stop_reason",
                        "id": "letta_clawgap_environment_probe_stop",
                        "date": now,
                        "run_id": "clawgap-environment-probe-run",
                        "stop_reason": "end_turn",
                    },
                ]
                body = b"".join(
                    b"data: " + json.dumps(chunk).encode() + b"\n\n"
                    for chunk in chunks
                )
                return body, "text/event-stream", True
            payload = {
                "messages": [
                    {
                        "message_type": "assistant_message",
                        "id": "letta_clawgap_environment_probe",
                        "content": "environment fixture ready",
                    }
                ],
            }
            return json.dumps(payload).encode(), "application/json", False
        message = {"role": "assistant", "content": "environment fixture ready"}
        if self.response_mode == "sse":
            chunks = [
                {"id": "chatcmpl-clawgap", "object": "chat.completion.chunk", "created": 0, "model": model, "choices": [{"index": 0, "delta": {"role": "assistant", "content": "environment fixture ready"}, "finish_reason": None}]},
                {"id": "chatcmpl-clawgap", "object": "chat.completion.chunk", "created": 0, "model": model, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
            ]
            body = b"".join(
                b"data: " + json.dumps(chunk).encode() + b"\n\n" for chunk in chunks
            ) + b"data: [DONE]\n\n"
            return body, "text/event-stream", True
        payload = {
            "id": "chatcmpl-clawgap-environment-probe",
            "object": "chat.completion",
            "created": 0,
            "model": model,
            "choices": [{"index": 0, "finish_reason": "stop", "message": message}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 3, "total_tokens": 3},
        }
        return json.dumps(payload).encode(), "application/json", False

    def _candidate_response(
        self, request_body: Mapping[str, Any], model: str
    ) -> dict[str, Any] | None:
        name = str(self.provider_response.get("tool_name") or "")
        arguments = self.provider_response.get("arguments")
        if not name or arguments is None:
            return None
        call_id = str(self.provider_response.get("id") or "call-clawgap-candidate")
        if self.protocol == "openai-chat-completions/v1":
            return {
                "id": "chatcmpl-clawgap-candidate",
                "object": "chat.completion",
                "created": 0,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": call_id,
                                    "type": "function",
                                    "function": {
                                        "name": name,
                                        "arguments": json.dumps(
                                            arguments, separators=(",", ":"), sort_keys=True
                                        ),
                                    },
                                }
                            ],
                        },
                        "finish_reason": "tool_calls",
                    }
                ],
            }
        if self.protocol == "anthropic-messages/v1":
            return {
                "id": "msg_clawgap_candidate",
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [
                    {"type": "tool_use", "id": call_id, "name": name, "input": arguments}
                ],
                "stop_reason": "tool_use",
                "usage": {"input_tokens": 0, "output_tokens": 0},
            }
        if self.protocol == "letta-api/v1":
            return {
                "id": "run_clawgap_candidate",
                "run_id": "clawgap-candidate-run",
                "model": model,
                "messages": [
                    {
                        "id": "msg_clawgap_candidate",
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": call_id,
                                "type": "function",
                                "name": name,
                                "arguments": arguments,
                            }
                        ],
                    }
                ],
            }
        return None

    def _discovery_response(self, path: str) -> bytes | None:
        route_path = urlsplit(path).path
        if route_path not in self.allowed_paths:
            return None
        row = {
            "schema_version": "clawgap-runtime-provider-transcript/v1",
            "valid": True,
            "kind": "declared-discovery",
            "protocol": self.protocol,
            "method": "GET",
            "path": path,
        }
        with self.lock:
            self.auxiliary.append(row)
            with self.transcript_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(row, sort_keys=True) + "\n")
        if route_path in {"/api/tags", "/version", "/v1/props", "/props"}:
            payload: dict[str, Any] = {"version": "clawgap-environment-probe"}
        elif self.protocol == "letta-api/v1":
            if route_path == "/v1/health":
                payload = {"status": "ok"}
            elif route_path == "/v1/agents/":
                payload = [{"id": "clawgap-fake-agent", "name": "ClawGapEnvironmentProbe"}]
            elif route_path == "/v1/agents/clawgap-fake-agent":
                payload = {"id": "clawgap-fake-agent", "name": "ClawGapEnvironmentProbe"}
            elif route_path == "/v1/agents/clawgap-fake-agent/tools":
                payload = []
            elif route_path == "/v1/metadata/balance":
                payload = {"billing_tier": "standard"}
            elif route_path == "/v1/runs/":
                payload = []
            elif route_path.endswith("/messages"):
                payload = {"messages": []}
            else:
                payload = [{"id": "letta/auto", "name": "letta/auto"}]
        elif route_path == "/api/v1/models":
            payload = {"data": [{"id": "clawgap-environment-probe"}]}
        elif route_path == "/v1/models/clawgap-environment-probe":
            payload = {
                "id": "clawgap-environment-probe",
                "object": "model",
                "owned_by": "clawgap",
            }
        else:
            payload = {
                "object": "list",
                "data": [
                    {
                        "id": "clawgap-environment-probe",
                        "object": "model",
                        "owned_by": "clawgap",
                    }
                ],
            }
        return json.dumps(payload).encode()

    def _record_s3(self, method: str, path: str, status: int) -> None:
        row = {
            "schema_version": "clawgap-runtime-provider-transcript/v1",
            "valid": True,
            "kind": "declared-s3-fixture",
            "method": method,
            "path": path,
            "status": status,
        }
        with self.lock:
            self.auxiliary.append(row)
            with self.transcript_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(row, sort_keys=True) + "\n")

    def _s3_object_response(self, method: str, path: str, body: bytes) -> tuple[int, bytes, dict[str, str]] | None:
        from urllib.parse import urlsplit, parse_qs

        split = urlsplit(path)
        route = split.path
        prefix = f"/{self.s3_bucket}/"
        if not route.startswith(prefix) and route != f"/{self.s3_bucket}":
            return None
        if method == "PUT":
            self.s3_objects[route] = body
            self._record_s3(method, path, 200)
            return 200, b"", {"ETag": f'"{sha256_file(Path("/dev/null"))}"'}
        if method == "HEAD":
            exists = route in self.s3_objects
            self._record_s3(method, path, 200 if exists else 404)
            return (200 if exists else 404), b"", {"ETag": f'"{sha256_file(Path("/dev/null"))}"'}
        if method == "DELETE":
            self.s3_objects.pop(route, None)
            self._record_s3(method, path, 204)
            return 204, b"", {}
        if method == "POST" and route == f"/{self.s3_bucket}":
            self._record_s3(method, path, 200)
            return 200, b"", {"Content-Type": "application/xml"}
        if method not in {"GET", "POST"}:
            return None
        if route.startswith(prefix):
            value = self.s3_objects.get(route)
            self._record_s3(method, path, 200 if value is not None else 404)
            if value is None:
                return 404, b"", {}
            return 200, value, {"ETag": f'"{sha256_file(Path("/dev/null"))}"'}
        marker = (parse_qs(split.query).get("marker") or [""])[0]
        rows = [
            f"<Contents><Key>{key.removeprefix(prefix)}</Key></Contents>"
            for key in sorted(self.s3_objects)
            if key.startswith(prefix) and key.removeprefix(prefix) > marker
        ]
        payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<ListBucketResult Name="{self.s3_bucket}">' + "".join(rows) + "</ListBucketResult>"
        ).encode()
        self._record_s3(method, path, 200)
        return 200, payload, {"Content-Type": "application/xml"}

    def _handler(self):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def handle_expect_100(self) -> bool:
                self.send_response_only(100)
                self.end_headers()
                return True

            def do_GET(self) -> None:
                if self.path == "/__clawgap/health":
                    body = b'{"status":"ready"}\n'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if self._s3("GET"):
                    return
                if (
                    fixture.protocol == "project-custom/v1"
                    and urlsplit(self.path).path == fixture.path
                ):
                    fixture._record(
                        valid=True,
                        method="GET",
                        path=self.path,
                        body="",
                        authorization=self.headers.get("Authorization", ""),
                    )
                    response = fixture._response({})
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(response[0])))
                    self.end_headers()
                    self.wfile.write(response[0])
                    return
                discovery = fixture._discovery_response(self.path)
                if discovery is not None:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(discovery)))
                    self.end_headers()
                    self.wfile.write(discovery)
                    return
                fixture._record(
                    valid=False,
                    method="GET",
                    path=self.path,
                    body="",
                    authorization=self.headers.get("Authorization", ""),
                    reason="unsupported provider endpoint",
                )
                self.send_error(404)

            def do_POST(self) -> None:
                if self._s3("POST"):
                    return
                if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                    chunks: list[bytes] = []
                    while True:
                        size = int(self.rfile.readline().strip().split(b";", 1)[0], 16)
                        if size == 0:
                            while True:
                                trailer = self.rfile.readline().strip()
                                if not trailer:
                                    break
                            break
                        chunks.append(self.rfile.read(size))
                        self.rfile.read(2)
                    raw = b"".join(chunks).decode("utf-8", errors="replace")
                else:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw = self.rfile.read(length).decode("utf-8", errors="replace")
                if self.path.rstrip("/") != fixture.path.rstrip("/"):
                    fixture._record(
                        valid=False,
                        method="POST",
                        path=self.path,
                        body=raw,
                        authorization=self.headers.get("Authorization", ""),
                        reason="provider path does not match declared contract",
                    )
                    self.send_error(404)
                    return
                try:
                    request = json.loads(raw)
                    if not isinstance(request, dict):
                        raise ValueError("request body is not an object")
                except (json.JSONDecodeError, ValueError) as exc:
                    fixture._record(
                        valid=False,
                        method="POST",
                        path=self.path,
                        body=raw[:4000],
                        authorization=self.headers.get("Authorization", ""),
                        reason=f"malformed provider request: {exc}",
                    )
                    self.send_error(400)
                    return
                fixture._record(
                    valid=True,
                    method="POST",
                    path=self.path,
                    body=raw,
                    authorization=self.headers.get("Authorization", ""),
                )
                body, content_type, streaming = fixture._response(request)
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                if streaming:
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "keep-alive")
                else:
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_PATCH(self) -> None:
                discovery = fixture._discovery_response(self.path)
                if discovery is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(discovery)))
                self.end_headers()
                self.wfile.write(discovery)

            def _s3(self, method: str) -> bool:
                route = urlsplit(self.path).path
                prefix = f"/{fixture.s3_bucket}/"
                if not route.startswith(prefix) and route != f"/{fixture.s3_bucket}":
                    return False
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else b""
                result = fixture._s3_object_response(method, self.path, body)
                if result is None:
                    return False
                status, payload, headers = result
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                if method != "HEAD":
                    self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if method not in {"HEAD", "DELETE"}:
                    self.wfile.write(payload)
                return True

            def do_PUT(self) -> None:
                if self._s3("PUT"):
                    return
                self.send_error(501)

            def do_DELETE(self) -> None:
                if self._s3("DELETE"):
                    return
                self.send_error(501)

            def do_HEAD(self) -> None:
                if self._s3("HEAD"):
                    return
                self.send_error(501)

            def log_message(self, *_args: Any) -> None:
                return

        return Handler

    def start(self) -> None:
        self.event_path.parent.mkdir(parents=True, exist_ok=True)
        self.transcript_path.parent.mkdir(parents=True, exist_ok=True)
        self._event("fixture_prepared", {"protocol": self.protocol, "port": self.port})
        self.thread.start()
        atomic_write_text(self.ready_path, "ready\n")

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def __enter__(self) -> "EnvironmentProviderFixture":
        self.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.stop()


def _append_event(path: Path, row: Mapping[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, sort_keys=True) + "\n")


def _instrumentation_config(
    runtime_config: Mapping[str, Any],
    *,
    intercept_effects: bool,
) -> dict[str, Any]:
    value = dict(runtime_config)
    value["intercept_effects"] = intercept_effects
    return value


def _target_environment(
    config: Mapping[str, Any], *, intercept_effects: bool
) -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "HOME": str(config["home"]),
        "TMPDIR": str(config["temporary"]),
        "NO_COLOR": "1",
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "CLAWGAP_PROVIDER_PORT": str(PROVIDER_PORT),
        "CLAWGAP_STATE_ROOT": str(config["state_root"]),
        "CLAWGAP_FAKE_PROVIDER_KEY": "clawgap-loopback-mock",
        "NO_PROXY": "127.0.0.1,localhost,::1",
        "no_proxy": "127.0.0.1,localhost,::1",
    }
    loader = str(config["loader"])
    runtime = str(config["runtime"])
    if runtime == "python":
        environment["PYTHONPATH"] = os.pathsep.join(
            [str(REPO_ROOT / "src/runtime_validation/l2_instrumentation/python"), str(REPO_ROOT)]
        )
    elif runtime in {"node", "npm", "pnpm"}:
        environment["NODE_OPTIONS"] = f"--import={Path(loader).as_uri()}"
    elif runtime == "bun":
        environment["CLAWGAP_BUN_PRELOAD"] = loader
    else:
        raise ValidationError(f"unsupported environment runtime: {runtime}")
    environment["CLAWGAP_L2_INSTRUMENTATION"] = str(config["target_instrumentation"])
    if intercept_effects:
        environment["CLAWGAP_L2_INSTRUMENTATION"] = str(
            config["smoke_instrumentation"]
        )
    return environment


def _wait_for_file(path: Path, pattern: str | None, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            if pattern is None or pattern == "__any_output__" or pattern in text:
                return bool(text.strip())
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)
    return False


def _run_interceptor_smoke(config: Mapping[str, Any]) -> tuple[bool, str]:
    runtime = str(config["runtime"])
    environment = _target_environment(config, intercept_effects=True)
    if runtime == "python":
        command = [
            sys.executable,
            "-c",
            "import subprocess; subprocess.Popen(['true'])",
        ]
    elif runtime in {"node", "npm", "pnpm"}:
        command = [
            shutil.which("node") or "node",
            "--eval",
            "require('node:child_process').spawnSync('true')",
        ]
    else:
        command = [
            shutil.which("bun") or "bun",
            "--preload",
            str(config["loader"]),
            "-e",
            "require('node:child_process').spawnSync('true')",
        ]
    try:
        completed = subprocess.run(
            command,
            cwd=str(config["project_root"]),
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "interceptor smoke timed out"
    output = completed.stdout or ""
    event_path = Path(str(config["event_path"]))
    time.sleep(0.1)
    try:
        rows = [
            json.loads(line)
            for line in event_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, json.JSONDecodeError):
        rows = []
    intercepted = any(
        row.get("stage") == "pre-effect"
        and row.get("intercept_before_execution") is True
        for row in rows
    )
    return intercepted, output


def _launch_target(config: Mapping[str, Any]) -> dict[str, Any]:
    project_root = Path(str(config["project_root"]))
    launch_log = Path(str(config["launch_log"]))
    event_path = Path(str(config["event_path"]))
    environment = _target_environment(config, intercept_effects=False)
    launch_log.parent.mkdir(parents=True, exist_ok=True)
    event_path.parent.mkdir(parents=True, exist_ok=True)
    reasons: list[str] = []

    with EnvironmentProviderFixture(config) as provider:
        with launch_log.open("w", encoding="utf-8") as log_handle:
            process = subprocess.Popen(
                ["bash", "-lc", str(config["launch_command"])],
                cwd=project_root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            _append_event(
                event_path,
                {
                    "schema_version": "clawgap-runtime-evidence-event/v1",
                    "event_id": f"{config['probe_id']}:launch",
                    "stage": "launch_started",
                    "project": config["project"],
                    "environment_id": config["environment_id"],
                    "probe_id": config["probe_id"],
                    "candidate_id": config.get("candidate_id"),
                    "ordinal": 10_000,
                    "detail": {"pid": process.pid, "process_group": True},
                },
            )
            timeout = float(config["launch_timeout"])
            deadline = time.monotonic() + timeout
            ready = False
            while time.monotonic() < deadline:
                readiness_observed = (
                    provider.requests is not None
                    and str(config["readiness_pattern"]) == "__provider_request__"
                    and bool(provider.requests)
                ) or _wait_for_file(
                    launch_log, str(config["readiness_pattern"]), 0
                )
                if not ready and readiness_observed:
                    ready = True
                    _append_event(
                        event_path,
                        {
                            "schema_version": "clawgap-runtime-evidence-event/v1",
                            "event_id": f"{config['probe_id']}:input",
                            "stage": "input_delivered",
                            "project": config["project"],
                            "environment_id": config["environment_id"],
                            "probe_id": config["probe_id"],
                            "candidate_id": config.get("candidate_id"),
                            "ordinal": 10_001,
                            "detail": {"kind": config["input_kind"], "readiness": True},
                        },
                    )
                    if config.get("probe_command"):
                        probe = subprocess.run(
                            ["bash", "-lc", str(config["probe_command"])],
                            cwd=project_root,
                            env=environment,
                            text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            timeout=min(timeout, 180),
                            check=False,
                        )
                        log_handle.write(probe.stdout or "")
                        log_handle.flush()
                        if probe.returncode != 0:
                            reasons.append(
                                f"input/provider probe failed with exit {probe.returncode}"
                            )
                if provider.requests:
                    break
                if process.poll() not in {None, 0}:
                    reasons.append(f"entrypoint failed with exit {process.returncode}")
                    break
                time.sleep(0.1)
            if not ready:
                reasons.append("entrypoint readiness boundary was not observed")
            if not provider.requests:
                reasons.append("real target provider request was not observed")
            if provider.unsupported:
                reasons.append("provider fixture observed unsupported requests")

            interceptor_ok, interceptor_output = _run_interceptor_smoke(config)
            if interceptor_output:
                log_handle.write("\n[interceptor smoke]\n" + interceptor_output)
            if not interceptor_ok:
                reasons.append(
                    "terminal interceptor did not emit executed=false before effect: "
                    + (interceptor_output[-500:] or "no output")
                )

            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)

        provider_fixture = {
            "schema_version": "clawgap-runtime-provider-fixture/v1",
            "protocol": provider.protocol,
            "response_mode": provider.response_mode,
            "declared_path": provider.path,
            "base_url": f"http://127.0.0.1:{PROVIDER_PORT}",
            "credential": "clawgap-loopback-mock",
            "request_count": len(provider.requests),
            "unsupported_count": len(provider.unsupported),
            "auxiliary_request_count": len(provider.auxiliary),
            "requests": provider.requests,
            "unsupported_requests": provider.unsupported,
            "auxiliary_requests": provider.auxiliary,
        }
    return {
        "ready": not reasons,
        "reasons": reasons,
        "provider_fixture": provider_fixture,
    }


def _overlay_setup_script() -> str:
    return """#!/bin/bash
set -euo pipefail
root="$CLAWGAP_PROJECT_ROOT"
state="$CLAWGAP_STATE_ROOT"
mkdir -p "$state/lower" "$state/upper" "$state/work" "$state/merged" "$state/home"
mount --bind "$root" "$state/lower"
mount -t overlay overlay -o "lowerdir=$state/lower,upperdir=$state/upper,workdir=$state/work" "$state/merged"
mount --bind "$state/merged" "$root"
cd "$root"
export HOME="$state/home"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_DATA_HOME="$HOME/.local/share"
bash -lc "$CLAWGAP_SETUP_COMMAND" >> "$CLAWGAP_SETUP_LOG" 2>&1
"""


def _overlay_launch_script() -> str:
    return """#!/bin/bash
set -euo pipefail
root="$CLAWGAP_PROJECT_ROOT"
state="$CLAWGAP_STATE_ROOT"
mkdir -p "$state/lower" "$state/reuse" "$state/launch-upper" "$state/launch-work" \
  "$state/merged" "$state/launch-home" "$state/proc" "$state/temporary"
mount --bind "$root" "$state/lower"
mount --bind "$state/upper" "$state/reuse"
mount -t overlay overlay -o "lowerdir=$state/reuse:$state/lower,upperdir=$state/launch-upper,workdir=$state/launch-work" "$state/merged"
mount --bind "$state/merged" "$root"
mount -t proc proc "$state/proc"
ip link set lo up
cd "$root"
export HOME="$state/launch-home"
export TMPDIR="$state/temporary"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_DATA_HOME="$HOME/.local/share"
export NO_COLOR=1
exec python -m src.runtime_validation.environment_builder --launch-target "$CLAWGAP_LAUNCH_CONFIG"
"""


def _run_process(
    command: Sequence[str], environment: Mapping[str, str], timeout: int
) -> tuple[int | None, str]:
    try:
        completed = subprocess.run(
            [str(part) for part in command],
            env=dict(environment),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stdout
    except subprocess.TimeoutExpired as exc:
        value = exc.stdout or ""
        if not isinstance(value, str):
            value = value.decode("utf-8", errors="replace")
        return None, value


def _base_environment(network: bool) -> dict[str, str]:
    environment: dict[str, str] = {}
    if network:
        for name in ("PATH", "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "no_proxy"):
            if name in os.environ:
                environment[name] = os.environ[name]
    else:
        environment["PATH"] = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")
    environment.update(
        {
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "HOME": "/tmp",
            "PYTHONPATH": str(REPO_ROOT),
        }
    )
    return environment


def _runtime_secrets() -> tuple[str, ...]:
    keys = (
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "DEEPSEEK_API_KEY",
        "GROQ_API_KEY",
        "OPENROUTER_API_KEY",
        "MERCURY_API_KEY",
    )
    return tuple(value for key in keys if (value := os.environ.get(key)))


def _source_bindings(profile: Mapping[str, Any]) -> dict[str, str]:
    root = get_project(str(profile["project"])).source_root
    result: dict[str, str] = {}
    for field in ("source_files", "dependency_files"):
        for relative in profile[field]:
            result[str(relative)] = sha256_file(root / relative)
    for relative in profile["fixture_files"]:
        result[str(relative)] = sha256_file(REPO_ROOT / relative)
    return result


def _verify_candidate(request: EnvironmentBuildRequest, project: str) -> dict[str, Any]:
    path = REPO_ROOT / request.candidates_file
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                value = json.loads(line)
                if isinstance(value, dict):
                    rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid candidate artifact {path}: {exc}") from exc
    matches = [row for row in rows if row.get("candidate_id") == request.candidate_id]
    if len(matches) != 1:
        raise ValidationError(
            f"candidate {request.candidate_id} is not uniquely bound in {path}"
        )
    row = matches[0]
    if row.get("project") != project:
        raise ValidationError("candidate project does not match requested project")
    if row.get("revision") != get_project(project).analysis_revision:
        raise ValidationError("candidate revision does not match project registry")
    return row


def compile_candidate_environment_contract(
    request: EnvironmentBuildRequest, project: str
) -> dict[str, Any]:
    """Compile candidate-bound identity and anchors without inventing an adapter."""

    if request.candidate_case is None or request.candidate_id is None:
        raise ValidationError("candidate environment contract requires a bound case")
    candidate = _verify_candidate(request, project)
    case = request.candidate_case
    if case.get("project") != project or case.get("candidate_binding", {}).get("candidate_id") != request.candidate_id:
        raise ValidationError("candidate case identity does not match environment request")
    anchors = list(case.get("instrumentation_anchors") or [])
    if not anchors:
        raise ValidationError("candidate case has no instrumentation anchors")
    identities = [(row.get("kind"), row.get("anchor")) for row in anchors]
    if any(not kind or not anchor for kind, anchor in identities):
        raise ValidationError("candidate instrumentation anchor is incomplete")
    if len(identities) != len(set(identities)):
        raise ValidationError("candidate instrumentation anchors are not unique")
    if identities[-1][0] != "pre-effect":
        raise ValidationError("candidate instrumentation lacks terminal pre-effect anchor")
    case_id = request.case_id or str(case["case_id"])
    environment_id = f"{case_id}:{request.attempt}:{request.role}"
    role_call = next(
        row for row in case.get("forced_tool_calls", []) if row.get("role") == request.role
    )
    return {
        "schema_version": "clawgap-runtime-candidate-environment-contract/v1",
        "project": project,
        "revision": candidate["revision"],
        "candidate_id": request.candidate_id,
        "case_id": case_id,
        "attempt": request.attempt,
        "role": request.role,
        "correlation_id": environment_id,
        "environment_id": environment_id,
        "trace_enabled": True,
        "anchors": anchors,
        "provider_response": {
            "id": f"call-{request.candidate_id}",
            "tool_name": case.get("tool_or_action_name"),
            "arguments": role_call.get("arguments"),
        },
        "adapter_status": "unregistered",
    }


def _command(request: EnvironmentBuildRequest) -> str:
    from src.projects import list_projects

    all_projects = set(request.projects) == set(list_projects())
    options = "" if all_projects else "".join(
        f" --project {project}" for project in request.projects
    )
    if all_projects:
        options = " --all"
    candidate = f" --candidate-id {request.candidate_id}" if request.candidate_id else ""
    return (
        "python -m src.runtime_validation build-runtime-l2-environment"
        f"{options}{candidate} --out-dir {request.out_dir}"
        f" --setup-timeout {request.setup_timeout} --launch-timeout {request.launch_timeout}"
    )


def _build_project(
    profile: Mapping[str, Any], request: EnvironmentBuildRequest
) -> EnvironmentBuildResult:
    project = str(profile["project"])
    spec = get_project(project)
    out = request.out_dir.resolve() / project
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    status = "environment-blocked"
    reasons: list[str] = []
    launch_result: dict[str, Any] | None = None
    before = _source_bindings(profile)
    canary = out / "host-effect-canary.txt"
    atomic_write_text(canary, f"clawgap-host-canary:{project}\n")
    canary_before = sha256_file(canary)
    launch_log = out / "launch.log"
    events = out / "events.raw.jsonl"
    transcript = out / "provider-transcript.jsonl"

    try:
        if request.candidate_id:
            _verify_candidate(request, project)
        setup_log = out / "setup.log"
        with tempfile.TemporaryDirectory(prefix=f"clawgap-l2-{project}-") as temporary_name:
            temporary = Path(temporary_name)
            state = temporary / "state"
            state.mkdir()
            raw_setup_log = temporary / "setup.log"
            scripts: dict[str, Path] = {}
            for name, value in (
                ("setup.sh", _overlay_setup_script()),
                ("launch.sh", _overlay_launch_script()),
            ):
                path = temporary / name
                path.write_text(value, encoding="utf-8")
                path.chmod(0o700)
                scripts[name] = path
            setup_environment = _base_environment(network=True) | {
                "CLAWGAP_PROJECT_ROOT": str(spec.source_root),
                "CLAWGAP_STATE_ROOT": str(state),
                "CLAWGAP_SETUP_LOG": str(raw_setup_log),
                "CLAWGAP_PROVIDER_PORT": str(PROVIDER_PORT),
                "CLAWGAP_SETUP_COMMAND": str(profile["setup_command"]),
            }
            setup_exit, setup_output = _run_process(
                ("unshare", "--mount", "--propagation", "private", scripts["setup.sh"]),
                setup_environment,
                request.setup_timeout,
            )
            setup_text = raw_setup_log.read_text(errors="replace") if raw_setup_log.exists() else ""
            setup_text += setup_output
            atomic_write_text(setup_log, redact_text(setup_text, _runtime_secrets()))
            if setup_exit != 0:
                reasons.append(
                    "dependency/build phase timed out"
                    if setup_exit is None
                    else f"dependency/build phase failed with exit {setup_exit}"
                )
            else:
                for relative in profile["fixture_files"]:
                    source = REPO_ROOT / relative
                    destination = state / "upper" / Path(relative).name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, destination)

                if request.candidate_id:
                    contract = compile_candidate_environment_contract(request, project)
                    contract_path = out / "candidate-environment-contract.json"
                    atomic_write_json(contract_path, contract)
                    runtime = str(profile["runtime"])
                    loader = (
                        REPO_ROOT
                        / "src/runtime_validation/l2_instrumentation/python/sitecustomize.py"
                        if runtime == "python"
                        else REPO_ROOT
                        / "src/runtime_validation/l2_instrumentation/node/loader.mjs"
                    )
                    base_config = {
                        "schema_version": PROFILE_SCHEMA_VERSION,
                        "case_id": contract["case_id"],
                        "correlation_id": contract["correlation_id"],
                        "attempt": contract["attempt"],
                        "role": contract["role"],
                        "trace_enabled": True,
                        "project": project,
                        "environment_id": contract["environment_id"],
                        "probe_id": f"L2-{request.candidate_id}",
                        "candidate_id": request.candidate_id,
                        "anchors": contract["anchors"],
                        "event_path": str(events),
                        "provider_base_url": f"http://127.0.0.1:{PROVIDER_PORT}",
                    }
                    environment_id = str(contract["environment_id"])
                    probe_id = str(base_config["probe_id"])
                    provider_response = dict(contract["provider_response"])
                else:
                    probe_id = f"ENV-{project}-self-test-v1"
                    environment_id = f"{probe_id}:{spec.analysis_revision}"
                    runtime = str(profile["runtime"])
                    loader = (
                        REPO_ROOT
                        / "src/runtime_validation/l2_instrumentation/python/sitecustomize.py"
                        if runtime == "python"
                        else REPO_ROOT
                        / "src/runtime_validation/l2_instrumentation/node/loader.mjs"
                    )
                    base_config = {
                        "schema_version": PROFILE_SCHEMA_VERSION,
                        "case_id": probe_id,
                        "correlation_id": environment_id,
                        "attempt": 1,
                        "role": "self-test",
                        "trace_enabled": False,
                        "project": project,
                        "environment_id": environment_id,
                        "probe_id": probe_id,
                        "candidate_id": None,
                        "anchors": profile["instrumentation"]["anchors"],
                        "event_path": str(events),
                        "provider_base_url": f"http://127.0.0.1:{PROVIDER_PORT}",
                    }
                    provider_response = {}
                target_config_path = out / "target-instrumentation.json"
                smoke_config_path = out / "interceptor-smoke-instrumentation.json"
                atomic_write_json(
                    target_config_path,
                    _instrumentation_config(base_config, intercept_effects=False),
                )
                atomic_write_json(
                    smoke_config_path,
                    _instrumentation_config(base_config, intercept_effects=True),
                )
                launch_config = {
                    "project": project,
                    "environment_id": environment_id,
                    "probe_id": probe_id,
                    "candidate_id": request.candidate_id,
                    "runtime": runtime,
                    "project_root": spec.source_root,
                    "state_root": state,
                    "home": state / "launch-home",
                    "temporary": state / "temporary",
                    "launch_command": profile["launch_command"],
                    "probe_command": profile.get("probe_command"),
                    "readiness_pattern": profile["readiness_pattern"],
                    "launch_timeout": request.launch_timeout,
                    "launch_log": launch_log,
                    "event_path": events,
                    "transcript_path": transcript,
                    "ready_path": temporary / "provider.ready",
                    "port": PROVIDER_PORT,
                    "protocol": profile["provider"]["protocol"],
                    "response_mode": profile["provider"]["response_mode"],
                    "path": profile["provider"].get("path"),
                    "allowed_paths": profile["provider"].get("allowed_paths", []),
                    "provider_response": provider_response,
                    "s3_bucket": "clawgap",
                    "loader": loader,
                    "input_kind": profile["input"]["kind"],
                    "target_instrumentation": target_config_path,
                    "smoke_instrumentation": smoke_config_path,
                }
                launch_config_path = temporary / "launch-config.json"
                atomic_write_json(
                    launch_config_path,
                    json.loads(json.dumps(launch_config, default=str)),
                )
                launch_environment = _base_environment(network=False) | {
                    "CLAWGAP_PROJECT_ROOT": str(spec.source_root),
                    "CLAWGAP_STATE_ROOT": str(state),
                    "CLAWGAP_LAUNCH_CONFIG": str(launch_config_path),
                }
                launch_exit, launch_output = _run_process(
                    (
                        "unshare",
                        "--mount",
                        "--net",
                        "--pid",
                        "--fork",
                        "--propagation",
                        "private",
                        scripts["launch.sh"],
                    ),
                    launch_environment,
                    request.launch_timeout + 30,
                )
                if launch_exit != 0:
                    reasons.append(
                        f"isolated launch supervisor failed with exit {launch_exit}"
                    )
                if launch_log.exists():
                    launch_text = redact_text(
                        launch_log.read_text(errors="replace"), _runtime_secrets()
                    )
                    atomic_write_text(launch_log, launch_text)
                else:
                    atomic_write_text(launch_log, redact_text(launch_output, _runtime_secrets()))
                    reasons.append("isolated target did not create launch output")
                result_path = out / "launch-result.json"
                if result_path.is_file():
                    launch_result = _read_json(result_path)
                    reasons.extend(str(row) for row in launch_result.get("reasons", []))

            after = _source_bindings(profile)
            if before != after:
                reasons.append("source/dependency/fixture hash drift after build")
            disposable_inventory = {
                "schema_version": "clawgap-runtime-disposable-root-inventory/v1",
                "roots": [
                    str(state / "home"),
                    str(state / "launch-home"),
                    str(state / "temporary"),
                    str(state / "upper"),
                    str(state / "launch-upper"),
                ],
                "removed": not state.exists(),
                "process_cleanup": "terminate-process-group",
            }
        disposable_inventory["removed"] = not state.exists()
        atomic_write_json(out / "disposable-root-inventory.json", disposable_inventory)
        if not disposable_inventory["removed"]:
            reasons.append("disposable state remained after cleanup")
    except Exception as exc:
        reasons.append(f"{type(exc).__name__}: {exc}")

    if sha256_file(canary) != canary_before:
        reasons.append("host-effect canary changed")
    if not launch_log.is_file():
        atomic_write_text(launch_log, "")
    if not events.is_file():
        events.write_text("", encoding="utf-8")

    provider_fixture = (launch_result or {}).get("provider_fixture") or {
        "schema_version": "clawgap-runtime-provider-fixture/v1",
        "protocol": profile["provider"]["protocol"],
        "response_mode": profile["provider"]["response_mode"],
        "base_url": f"http://127.0.0.1:{PROVIDER_PORT}",
        "credential": "clawgap-loopback-mock",
        "request_count": 0,
        "unsupported_count": 0,
        "requests": [],
        "unsupported_requests": [],
    }
    atomic_write_json(out / "provider-fixture.json", provider_fixture)
    source_manifest = {
        "schema_version": "clawgap-runtime-transformed-source-manifest/v1",
        "mode": "disposable-overlay-copy",
        "revision": spec.analysis_revision,
        "profile_sha256": sha256_file(PROFILE_DIR / f"{project}.json"),
        "files": before,
    }
    atomic_write_json(out / "transformed-source-manifest.json", source_manifest)
    fixture_manifest = {
        "schema_version": "clawgap-runtime-fixture-manifest/v1",
        "provider": provider_fixture,
        "profile_path": str(PROFILE_DIR / f"{project}.json"),
        "profile_sha256": sha256_file(PROFILE_DIR / f"{project}.json"),
        "schema_sha256": sha256_file(PROFILE_SCHEMA),
        "instrumentation_config_sha256": {
            "target": sha256_file(out / "target-instrumentation.json")
            if (out / "target-instrumentation.json").is_file()
            else None,
            "interceptor_smoke": sha256_file(out / "interceptor-smoke-instrumentation.json")
            if (out / "interceptor-smoke-instrumentation.json").is_file()
            else None,
        },
        "fixture_files": {
            relative: sha256_file(REPO_ROOT / relative)
            for relative in profile["fixture_files"]
        },
    }
    atomic_write_json(out / "fixture-manifest.json", fixture_manifest)
    environment = {
        "schema_version": ENVIRONMENT_SCHEMA_VERSION,
        "identity_mode": "candidate" if request.candidate_id else "project-self-test",
        "project": project,
        "revision": spec.analysis_revision,
        "environment_id": (
            f"{request.case_id}:{request.attempt}:{request.role}"
            if request.candidate_id
            else f"ENV-{project}-self-test-v1:{spec.analysis_revision}"
        ),
        "candidate_id": request.candidate_id,
        "probe_id": None if request.candidate_id else f"ENV-{project}-self-test-v1",
        "status": "ready" if not reasons else "environment-blocked",
        "reasons": reasons,
        "isolation": {
            "mode": "native-disposable-overlay",
            "network": "loopback-only",
            "process_group": True,
            "host_write": "forbidden",
            "credential_policy": "fake-or-redacted-only",
        },
        "provider": provider_fixture,
        **(
            {"candidate_environment_contract": _read_json(out / "candidate-environment-contract.json")}
            if request.candidate_id
            and (out / "candidate-environment-contract.json").is_file()
            else {}
        ),
    }
    atomic_write_json(out / "environment.json", environment)
    status = environment["status"]
    return EnvironmentBuildResult(project, status, tuple(reasons), out)


def build_runtime_l2_environments(
    request: EnvironmentBuildRequest,
) -> dict[str, Any]:
    profiles = load_environment_profiles()
    request.out_dir.resolve().mkdir(parents=True, exist_ok=True)
    results = [
        _build_project(profiles[project], request)
        for project in request.projects
    ]
    records = [
        {
            "schema_version": LEDGER_SCHEMA_VERSION,
            "project": result.project,
            "status": result.status,
            "reasons": list(result.reasons),
            "artifact_dir": str(result.artifact_dir),
        }
        for result in results
    ]
    ledger_path = request.out_dir.resolve() / "environment-ledger.jsonl"
    atomic_write_text(
        ledger_path,
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in records),
    )
    counts: dict[str, int] = {}
    for row in records:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    command = _command(request)
    manifest = {
        "schema_version": "clawgap-runtime-l2-environment-builder-manifest/v1",
        "project_count": len(records),
        "status_counts": counts,
        "canonical_candidate_execution_ready": False,
        "generation_command": command,
        "profile_schema_sha256": sha256_file(PROFILE_SCHEMA),
        "harness_sha256": sha256_file(Path(__file__)),
        "projects": {
            row["project"]: {
                "status": row["status"],
                "artifact_dir": row["artifact_dir"],
                "artifact_sha256": {
                    name: sha256_file(path)
                    for name in REQUIRED_PROJECT_FILES
                    if (path := Path(row["artifact_dir"]) / name).is_file()
                }
                | (
                    {
                        "candidate-environment-contract.json": sha256_file(
                            Path(row["artifact_dir"]) / "candidate-environment-contract.json"
                        )
                    }
                    if request.candidate_id
                    and (Path(row["artifact_dir"]) / "candidate-environment-contract.json").is_file()
                    else {}
                ),
            }
            for row in records
        },
    }
    atomic_write_json(request.out_dir.resolve() / "manifest.json", manifest)
    atomic_write_text(
        request.out_dir.resolve() / "summary.md",
        "# Runtime L2 Environment Builder\n\n"
        f"> Complete reproduction command: `{command}`\n\n"
        f"Projects: **{len(records)}**; ready: **{counts.get('ready', 0)}**; "
        f"environment-blocked: **{counts.get('environment-blocked', 0)}**.\n\n"
        + (
            "Candidate-mode output is an environment handoff only; it does not assign "
            "a candidate verdict.\n"
            if request.candidate_id
            else "Project self-test readiness does not execute candidate verdicts or "
            "promote the canonical 78-row L2 campaign.\n"
        )
    )
    return manifest


def _write_launch_result(path: str, result: Mapping[str, Any]) -> None:
    atomic_write_json(Path(path), dict(result))


def _internal_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--launch-target", required=True)
    args = parser.parse_args(argv)
    config = _read_json(Path(args.launch_target))
    result_path = str(Path(str(config["event_path"])).parent / "launch-result.json")
    try:
        result = _launch_target(config)
    except Exception as exc:
        result = {"ready": False, "reasons": [f"{type(exc).__name__}: {exc}"], "provider_fixture": None}
    _write_launch_result(result_path, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(_internal_main(sys.argv[1:]))

"""Deterministic loopback mock provider used by adapter qualification."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping

from .campaign_contracts import digest
from .contracts import ValidationError, atomic_write_text, canonical_json


PROVIDER_SCHEMA_VERSION = "clawgap-runtime-mock-provider-transcript/v1"
PROVIDER_MODEL = "clawgap-mock-provider/v1"


@dataclass(frozen=True)
class MockProviderCall:
    side: str
    prompt: str
    model: str
    tool_name: str
    arguments: Mapping[str, Any]

    def response_id(self) -> str:
        return "chatcmpl-" + digest(
            {
                "side": self.side,
                "prompt": self.prompt,
                "model": self.model,
                "tool_name": self.tool_name,
                "arguments": self.arguments,
            }
        )[:24]


def provider_response(call: MockProviderCall) -> dict[str, Any]:
    return {
        "id": call.response_id(),
        "object": "chat.completion",
        "created": 0,
        "model": call.model,
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call-"
                            + digest({"response_id": call.response_id(), "side": call.side})[:24],
                            "type": "function",
                            "function": {
                                "name": call.tool_name,
                                "arguments": canonical_json(call.arguments),
                            },
                        }
                    ],
                },
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def validate_provider_exchange(
    prompt: str,
    model: str,
    tool_name: str,
    arguments: Mapping[str, Any],
    request_body: Mapping[str, Any],
    response_body: Mapping[str, Any],
) -> None:
    """Validate one request/response pair without trusting either side."""

    messages = request_body.get("messages")
    if not isinstance(messages, list):
        raise ValidationError("mock-provider request must contain messages")
    user_rows = [row for row in messages if isinstance(row, Mapping) and row.get("role") == "user"]
    if len(user_rows) != 1 or user_rows[0].get("content") != prompt:
        raise ValidationError("mock-provider request does not bind the reviewed prompt")
    if request_body.get("model") != model:
        raise ValidationError("mock-provider request model drifted")
    try:
        choice = response_body["choices"][0]
        tool_call = choice["message"]["tool_calls"][0]
        function = tool_call["function"]
        decoded_arguments = json.loads(function["arguments"])
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"malformed mock-provider response: {exc}") from exc
    if (
        response_body.get("model") != model
        or choice.get("finish_reason") != "tool_calls"
        or function.get("name") != tool_name
        or decoded_arguments != arguments
    ):
        raise ValidationError("mock-provider response does not bind the reviewed call")


class _MockProviderServer(ThreadingHTTPServer):
    def __init__(self, call: MockProviderCall):
        self.call = call
        self.records: list[dict[str, Any]] = []
        super().__init__(("127.0.0.1", 0), _ProviderHandler)


class _ProviderHandler(BaseHTTPRequestHandler):
    server_version = "ClawGapMockProvider/1"

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        server = self.server
        if not isinstance(server, _MockProviderServer) or self.path.rstrip("/") != "/v1/chat/completions":
            self._fail(404, "unsupported mock-provider path")
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
            if length < 1 or length > 1_048_576:
                raise ValueError("invalid request length")
            request_body = json.loads(self.rfile.read(length))
            if not isinstance(request_body, dict):
                raise TypeError("request body is not an object")
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._fail(400, f"invalid mock-provider request: {exc}")
            return
        response_body = provider_response(server.call)
        try:
            validate_provider_exchange(
                server.call.prompt,
                server.call.model,
                server.call.tool_name,
                server.call.arguments,
                request_body,
                response_body,
            )
        except ValidationError as exc:
            self._fail(400, str(exc))
            return
        server.records.append(
            transcript_record(server.call, request_body, response_body, 200)
        )
        value = json.dumps(response_body, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(value)))
        self.end_headers()
        self.wfile.write(value)

    def _fail(self, status: int, reason: str) -> None:
        value = json.dumps({"error": {"message": reason}}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(value)))
        self.end_headers()
        self.wfile.write(value)

    def log_message(self, _format: str, *args: Any) -> None:
        return


class MockProviderServer:
    """One request, one deterministic tool call, loopback only."""

    def __init__(self, call: MockProviderCall):
        self.call = call
        self._server = _MockProviderServer(call)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> "MockProviderServer":
        self._thread.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    @property
    def origin(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def records(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self._server.records)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def request_mock_provider(origin: str, call: MockProviderCall) -> dict[str, Any]:
    request_body = {
        "model": call.model,
        "messages": [{"role": "user", "content": call.prompt}],
        "tools": [
            {
                "type": "function",
                "function": {"name": call.tool_name, "parameters": {"type": "object"}},
            }
        ],
        "tool_choice": {"type": "function", "function": {"name": call.tool_name}},
    }
    request = urllib.request.Request(
        origin.rstrip("/") + "/v1/chat/completions",
        data=json.dumps(request_body, separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status = response.status
            raw_response = response.read()
    except urllib.error.HTTPError as exc:
        raise ValidationError(f"mock-provider HTTP error: {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise ValidationError(f"mock-provider transport failed: {exc}") from exc
    try:
        response_body = json.loads(raw_response)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"mock-provider returned invalid JSON: {exc}") from exc
    if not isinstance(response_body, dict):
        raise ValidationError("mock-provider response must be an object")
    validate_provider_exchange(
        call.prompt,
        call.model,
        call.tool_name,
        call.arguments,
        request_body,
        response_body,
    )
    return transcript_record(call, request_body, response_body, status)


def transcript_record(
    call: MockProviderCall,
    request_body: Mapping[str, Any],
    response_body: Mapping[str, Any],
    status: int,
) -> dict[str, Any]:
    return {
        "schema_version": PROVIDER_SCHEMA_VERSION,
        "side": call.side,
        "prompt": call.prompt,
        "prompt_sha256": digest(call.prompt),
        "model": call.model,
        "response_id": call.response_id(),
        "http_status": status,
        "request": dict(request_body),
        "response": dict(response_body),
        "request_sha256": digest(request_body),
        "response_sha256": digest(response_body),
    }


def write_provider_transcript(path: Path, rows: list[Mapping[str, Any]]) -> None:
    atomic_write_text(path, "".join(canonical_json(row) + "\n" for row in rows))

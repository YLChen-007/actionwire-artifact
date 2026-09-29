"""Loopback OpenAI-compatible provider for agent-guided Hermes trials."""

from __future__ import annotations

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping

from .contracts import ValidationError, canonical_json, sha256_text


MODEL = "clawgap-agent-mock-provider"


class AgentMockProviderServer:
    """Serve exactly one reviewed tool call, then a terminal text response."""

    def __init__(
        self,
        *,
        prompt: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        expected_value: str,
        append_event: Callable[[str, str, dict[str, Any]], None],
        transcript_path: Path,
    ) -> None:
        self.prompt = prompt
        self.tool_name = tool_name
        self.arguments = dict(arguments)
        self.expected_value = expected_value
        self.append_event = append_event
        self.transcript_path = transcript_path
        self.calls = 0
        self.tool_schema_advertised = False
        self.records: list[dict[str, Any]] = []
        self._server = _Server(self)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> "AgentMockProviderServer":
        self._thread.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    @property
    def origin(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def record(self, request: Mapping[str, Any]) -> bool:
        self.calls += 1
        tools = request.get("tools") or []
        self.tool_schema_advertised = any(
            isinstance(item, Mapping)
            and item.get("type") == "function"
            and item.get("function", {}).get("name") == self.tool_name
            for item in tools
        )
        first = self.calls == 1
        messages = request.get("messages") or []
        prompt_text = canonical_json(messages)
        row = {
            "schema_version": "clawgap-agent-provider-transcript/v1",
            "request_number": self.calls,
            "request": dict(request),
            "response_tool_call": (
                {"name": self.tool_name, "arguments": self.arguments} if first else None
            ),
            "prompt_sha256": sha256_text(self.prompt),
            "expected_value": self.expected_value,
            "tool_schema_advertised": self.tool_schema_advertised,
            "prompt_contains_value": self.expected_value in prompt_text,
        }
        self.records.append(row)
        with self.transcript_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
        if first:
            self.append_event(
                "provider_request",
                "provider-request",
                {
                    "value": self.expected_value,
                    "prompt_contains_value": row["prompt_contains_value"],
                    "tool_schema_advertised": self.tool_schema_advertised,
                },
            )
            self.append_event(
                "provider_tool_call",
                "provider-tool-call",
                {
                    "value": self.expected_value,
                    "tool_name": self.tool_name,
                    "arguments": self.arguments,
                },
            )
        return first


class _Server(ThreadingHTTPServer):
    def __init__(self, context: AgentMockProviderServer):
        self.context = context
        super().__init__(("127.0.0.1", 0), _Handler)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args: Any) -> None:
        return None

    @property
    def context(self) -> AgentMockProviderServer:
        return self.server.context  # type: ignore[attr-defined]

    def _json(self, status: int, value: Mapping[str, Any]) -> None:
        payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path.rstrip("/") == "/v1/models":
            self._json(200, {"object": "list", "data": [{"id": MODEL}]})
        else:
            self._json(404, {"error": {"message": "not found"}})

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path.rstrip("/") != "/v1/chat/completions":
            self._json(404, {"error": {"message": "not found"}})
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            request = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(request, dict):
                raise ValidationError("provider request is not an object")
        except (json.JSONDecodeError, ValidationError) as exc:
            self._json(400, {"error": {"message": str(exc)}})
            return
        tool_call = self.context.record(request)
        if not tool_call:
            self._send_chunks(
                [
                    _choice(
                        {"role": "assistant", "content": "done"},
                        "stop",
                    )
                ]
            )
            return
        function = {
            "name": self.context.tool_name,
            "arguments": json.dumps(
                self.context.arguments, separators=(",", ":"), ensure_ascii=False
            ),
        }
        self._send_chunks(
            [
                _choice(
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call-clawgap-agent-1",
                                "type": "function",
                                "function": function,
                            }
                        ],
                    },
                    None,
                ),
                _choice({}, "tool_calls"),
            ]
        )

    def _send_chunks(self, chunks: list[dict[str, Any]]) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        for chunk in chunks:
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode("utf-8"))
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        self.close_connection = True


def _choice(delta: dict[str, Any], finish_reason: str | None) -> dict[str, Any]:
    return {
        "id": f"chatcmpl-agent-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": MODEL,
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
    }

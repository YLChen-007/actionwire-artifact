"""OpenAI-compatible, non-agentic transport for gate semantic extraction."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any


MAX_TRANSPORT_ATTEMPTS = 5
TRANSIENT_HTTP_STATUS = {405, 429, 500, 502, 503, 504, 551}


def _decode_response(raw: bytes) -> tuple[str | None, dict[str, Any] | None]:
    """Decode either a normal chat completion or OpenAI-compatible SSE chunks."""

    text = raw.decode("utf-8")
    stripped = text.lstrip()
    if stripped.startswith("{"):
        payload = json.loads(stripped)
        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            content = None
        usage = payload.get("usage")
        return content, usage if isinstance(usage, dict) else None

    pieces: list[str] = []
    usage: dict[str, Any] | None = None
    saw_event = False
    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        value = line.removeprefix("data:").strip()
        if not value or value == "[DONE]":
            continue
        chunk = json.loads(value)
        saw_event = True
        choices = chunk.get("choices")
        if isinstance(choices, list) and choices:
            delta = choices[0].get("delta")
            if isinstance(delta, dict) and isinstance(delta.get("content"), str):
                pieces.append(delta["content"])
        if isinstance(chunk.get("usage"), dict):
            usage = chunk["usage"]
    if not saw_event:
        raise ValueError("OpenAI-compatible response was neither JSON nor SSE")
    return "".join(pieces), usage


class OpenAICompatibleRunner:
    """Callable runner accepted by ``src.gate_semantics.pipeline``.

    Source collection remains the slicer's responsibility. This transport sends
    only the sink-free GateSlice prompt and deliberately exposes no tools.
    """

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key_env: str = "DEEPSEEK_API_KEY",
        timeout: int = 900,
        max_tokens: int = 8192,
    ) -> None:
        if max_tokens < 1:
            raise ValueError("max_tokens must be positive")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key_env = api_key_env
        self.timeout = timeout
        self.max_tokens = max_tokens
        self._calls: list[dict[str, Any]] = []
        self._usage: list[dict[str, int]] = []

    def __call__(self, system: str, user: str) -> str:
        api_key = os.environ.get(self.api_key_env, "").strip()
        if not api_key:
            raise RuntimeError(
                f"missing LLM credential: set {self.api_key_env} in the environment"
            )
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system.strip()},
                {"role": "user", "content": user.strip()},
            ],
            "temperature": 0,
            "max_tokens": self.max_tokens,
            # Gate extraction needs schema fidelity, not hidden chain-of-thought.
            # Disabling provider reasoning avoids spending the output budget on
            # reasoning_content that is discarded by this contract.
            "thinking": {"type": "disabled"},
            # Long DeepSeek JSON responses can exceed an idle reverse-proxy window.
            # SSE keeps the connection active while preserving one non-agentic call.
            "stream": True,
            "stream_options": {"include_usage": True},
            "response_format": {"type": "json_object"},
        }
        request = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        call: dict[str, Any] = {
            "call": len(self._calls) + 1,
            "endpoint": self.base_url + "/chat/completions",
            "model": self.model,
            "max_tokens": self.max_tokens,
        }
        self._calls.append(call)
        transient_errors: list[str] = []

        def failure(message: str) -> RuntimeError:
            call["error"] = message
            if transient_errors:
                call["transient_errors"] = list(transient_errors)
            return RuntimeError(message)

        for attempt in range(MAX_TRANSPORT_ATTEMPTS):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    content, usage = _decode_response(response.read())
                if content is None:
                    message = "OpenAI-compatible response has no message content"
                    if attempt < MAX_TRANSPORT_ATTEMPTS - 1:
                        transient_errors.append(message)
                        time.sleep(2**attempt)
                        continue
                    raise failure(message)
                if not isinstance(content, str) or not content.strip():
                    message = "OpenAI-compatible response returned empty content"
                    if attempt < MAX_TRANSPORT_ATTEMPTS - 1:
                        transient_errors.append(message)
                        time.sleep(2**attempt)
                        continue
                    raise failure(message)
                break
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace")[-1500:]
                message = f"HTTP {exc.code}: {detail}"
                if (
                    exc.code in TRANSIENT_HTTP_STATUS
                    and attempt < MAX_TRANSPORT_ATTEMPTS - 1
                ):
                    transient_errors.append(message)
                    time.sleep(2**attempt)
                    continue
                raise failure(message) from exc
            except TimeoutError as exc:
                raise failure(f"TimeoutError: {exc}") from exc
            except OSError as exc:
                message = f"{type(exc).__name__}: {exc}"
                if attempt < MAX_TRANSPORT_ATTEMPTS - 1:
                    transient_errors.append(message)
                    time.sleep(2**attempt)
                    continue
                raise failure(message) from exc
            except ValueError as exc:
                raise failure(f"{type(exc).__name__}: {exc}") from exc
        else:
            raise AssertionError("unreachable")
        if transient_errors:
            call["transient_errors"] = transient_errors
        if isinstance(usage, dict):
            normalized = {
                "input_tokens": int(usage.get("prompt_tokens", 0) or 0),
                "output_tokens": int(usage.get("completion_tokens", 0) or 0),
            }
            normalized["total_tokens"] = int(
                usage.get(
                    "total_tokens",
                    normalized["input_tokens"] + normalized["output_tokens"],
                )
                or 0
            )
            self._usage.append(normalized)
            call["usage"] = normalized
        return content.strip()

    def audit_payload(self) -> dict[str, Any]:
        input_tokens = sum(row.get("input_tokens", 0) for row in self._usage)
        output_tokens = sum(row.get("output_tokens", 0) for row in self._usage)
        return {
            "transport": "openai-compatible/v1",
            "base_url": self.base_url,
            "model": self.model,
            "credential_env": self.api_key_env,
            "available_tools": [],
            "token_usage": {
                "provider_reported": bool(self._usage),
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
            },
            "calls": list(self._calls),
        }

    def chat_payload(self) -> dict[str, Any]:
        return {
            "schema_version": "openai-compatible-chat-audit/v1",
            "transport": "openai-compatible/v1",
            "calls": list(self._calls),
        }

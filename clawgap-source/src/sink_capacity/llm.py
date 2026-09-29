"""LEGACY — direct DeepSeek (OpenAI-compatible) chat client.

Superseded by `agent.py` (claude CLI driven against DeepSeek's Anthropic endpoint),
which is the default backend. Kept only as a fallback / reference; not imported by the
pipeline. Per project direction we do not call the DeepSeek HTTP API directly anymore.

Minimal DeepSeek (OpenAI-compatible) chat client.

Some DeepSeek models return `reasoning_content` alongside the real answer in
`message.content`. Reasoning tokens are drawn from the completion budget, so
`max_tokens` must be generous or `content` can come back empty.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
import urllib.error

DEFAULT_BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
DEFAULT_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
DEFAULT_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-flash")


class LLMError(RuntimeError):
    pass


def chat(
    system: str,
    user: str,
    *,
    model: str = DEFAULT_MODEL,
    base_url: str = DEFAULT_BASE_URL,
    api_key: str = DEFAULT_API_KEY,
    max_tokens: int = 8000,
    temperature: float = 0.2,
    timeout: int = 300,
    retries: int = 3,
) -> str:
    if not api_key.strip():
        raise LLMError("missing LLM credential: set DEEPSEEK_API_KEY")
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": False,
    }
    data = json.dumps(payload).encode("utf-8")
    url = base_url.rstrip("/") + "/chat/completions"
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(
                url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            content = (body["choices"][0]["message"].get("content") or "").strip()
            if not content:
                raise LLMError("empty content (reasoning may have exhausted max_tokens)")
            return content
        except (urllib.error.URLError, urllib.error.HTTPError, LLMError, KeyError, TimeoutError) as e:
            last_err = e
            if attempt < retries:
                time.sleep(3 * attempt)
    raise LLMError(f"chat failed after {retries} attempts: {last_err}")

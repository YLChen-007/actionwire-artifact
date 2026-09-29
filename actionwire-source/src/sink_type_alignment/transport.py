"""Non-semantic transport helpers for reproducible sink alignment."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

from .contracts import CHAT_SCHEMA_VERSION, SinkTypeAlignmentError


class ExactPromptReplayRunner:
    """Replay prior audited responses only for byte-identical prompt pairs."""

    def __init__(self, live_runner: Callable[[str, str], str], artifact_root: Path):
        self.live_runner = live_runner
        self.cache: dict[tuple[str, str], str] = {}
        self.calls = 0
        self.hits = 0
        self.misses = 0
        self.checkpoint_path = artifact_root.parent / (
            f".{artifact_root.name}.prompt-checkpoint.jsonl"
        )
        if self.checkpoint_path.is_file():
            self._load_checkpoint(self.checkpoint_path)
        repository = artifact_root / "repository"
        if not repository.is_dir():
            return
        for path in sorted(repository.glob("*/chat.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise SinkTypeAlignmentError(
                    f"invalid sink-alignment replay sidecar {path}: {exc}"
                ) from exc
            if payload.get("schema_version") != CHAT_SCHEMA_VERSION:
                raise SinkTypeAlignmentError(
                    f"unsupported sink-alignment replay sidecar: {path}"
                )
            exchanges = payload.get("exchanges")
            if not isinstance(exchanges, list):
                raise SinkTypeAlignmentError(
                    f"invalid sink-alignment replay exchanges: {path}"
                )
            for exchange in exchanges:
                if not isinstance(exchange, dict) or set(exchange) != {
                    "system",
                    "user",
                    "response",
                }:
                    raise SinkTypeAlignmentError(
                        f"invalid sink-alignment replay exchange: {path}"
                    )
                if any(not isinstance(exchange[field], str) for field in exchange):
                    raise SinkTypeAlignmentError(
                        f"non-string sink-alignment replay exchange: {path}"
                    )
                key = (exchange["system"], exchange["user"])
                prior = self.cache.setdefault(key, exchange["response"])
                if prior != exchange["response"]:
                    raise SinkTypeAlignmentError(
                        "conflicting responses for an identical audited sink-alignment prompt"
                    )

    def _load_checkpoint(self, path: Path) -> None:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SinkTypeAlignmentError(
                    f"invalid sink-alignment checkpoint {path}:{number}: {exc}"
                ) from exc
            if (
                not isinstance(row, dict)
                or set(row) != {"system", "user", "response"}
                or any(not isinstance(row[field], str) for field in row)
            ):
                raise SinkTypeAlignmentError("invalid sink-alignment checkpoint row")
            key = (row["system"], row["user"])
            prior = self.cache.setdefault(key, row["response"])
            if prior != row["response"]:
                raise SinkTypeAlignmentError(
                    "conflicting sink-alignment checkpoint responses"
                )

    def __call__(self, system: str, user: str) -> str:
        self.calls += 1
        cached = self.cache.get((system, user))
        if cached is not None:
            self.hits += 1
            return cached
        self.misses += 1
        response = self.live_runner(system, user)
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        with self.checkpoint_path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {"system": system, "user": user, "response": response},
                    sort_keys=True,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        self.cache[(system, user)] = response
        return response

    def invalidate_prompts(self, prompts: list[tuple[str, str]]) -> None:
        keys = set(prompts)
        for key in keys:
            self.cache.pop(key, None)
        if not self.checkpoint_path.is_file():
            return
        retained = []
        for line in self.checkpoint_path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if (row["system"], row["user"]) not in keys:
                retained.append(line)
        temporary = self.checkpoint_path.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            if retained:
                handle.write("\n".join(retained) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.checkpoint_path)

    def clear_checkpoint(self) -> None:
        if self.checkpoint_path.exists():
            self.checkpoint_path.unlink()

    def audit_payload(self) -> dict[str, Any]:
        replay = {
            "enabled": True,
            "exact_prompt_hits": self.hits,
            "exact_prompt_misses": self.misses,
        }
        if self.misses:
            if callable(getattr(self.live_runner, "audit_payload", None)):
                payload = dict(self.live_runner.audit_payload())
            else:
                payload = {"transport": "injected-runner", "available_tools": []}
            payload["prompt_replay"] = replay
            return payload
        return {
            "transport": "exact-prompt-replay/v1",
            "base_url": getattr(self.live_runner, "base_url", None),
            "model": getattr(self.live_runner, "model", None),
            "credential_env": getattr(self.live_runner, "api_key_env", None),
            "available_tools": [],
            "prompt_replay": replay,
            "token_usage": {
                "provider_reported": False,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
            },
            "calls": [
                {"call": number, "source": "exact-prompt-replay"}
                for number in range(1, self.calls + 1)
            ],
        }

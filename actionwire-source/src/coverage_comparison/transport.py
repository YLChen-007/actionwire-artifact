"""Exact audited prompt replay for coverage comparison."""

from __future__ import annotations

import json
import os
import sys
from copy import deepcopy
from pathlib import Path
from threading import Lock
from typing import Any, Callable

from .contracts import CHAT_SCHEMA_VERSION, CoverageComparisonError
from .prompts import contains_credentials, redact_credentials
from .versions import EXACT_REPLAY_TRANSPORT_VERSION, GT_CHAT_SCHEMA_VERSION


def reject_legacy_archive(path: Path) -> None:
    normalized = path.resolve(strict=False).parts
    marker = ("archive", "coverage-comparison-legacy")
    if any(normalized[index : index + 2] == marker for index in range(len(normalized) - 1)):
        raise CoverageComparisonError(
            "coverage legacy archive is audit-only and cannot be loaded"
        )


class ExactPromptReplayRunner:
    def __init__(
        self,
        live_runner: Callable[[str, str], str],
        artifact_root: Path,
        *,
        checkpoint_root: Path | None = None,
        replay_only: bool = False,
    ):
        reject_legacy_archive(artifact_root)
        if checkpoint_root is not None:
            reject_legacy_archive(checkpoint_root)
        self.live_runner = live_runner
        self.replay_only = replay_only
        self.cache: dict[tuple[str, str], str] = {}
        self.calls = 0
        self.hits = 0
        self.misses = 0
        self.prior_transport: dict[str, Any] | None = None
        self._lock = Lock()
        checkpoint_owner = checkpoint_root or artifact_root
        self.checkpoint_path = checkpoint_owner.parent / (
            f".{checkpoint_owner.name}.prompt-checkpoint.jsonl"
        )
        if self.checkpoint_path.is_file():
            for number, line in enumerate(
                self.checkpoint_path.read_text(encoding="utf-8").splitlines(), 1
            ):
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise CoverageComparisonError(
                        f"invalid prompt checkpoint {self.checkpoint_path}:{number}: {exc}"
                    ) from exc
                if (
                    not isinstance(row, dict)
                    or set(row) != {"system", "user", "response"}
                    or any(not isinstance(row[field], str) for field in row)
                ):
                    raise CoverageComparisonError(
                        "invalid coverage prompt checkpoint row"
                    )
                if any(contains_credentials(row[field]) for field in row):
                    raise CoverageComparisonError(
                        "unsafe data in coverage prompt checkpoint"
                    )
                key = (row["system"], row["user"])
                prior = self.cache.setdefault(key, row["response"])
                if prior != row["response"]:
                    raise CoverageComparisonError("conflicting checkpoint responses")
        manifest_path = artifact_root / "manifest.json"
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            transport = manifest.get("transport")
            if not isinstance(transport, dict):
                raise CoverageComparisonError("invalid coverage replay manifest")
            self.prior_transport = transport
        repository = artifact_root / "repository"
        if not repository.is_dir():
            return
        for path in sorted(repository.glob("*/*/chat.json")):
            stage = path.relative_to(repository).parts[0]
            if stage == "source-discover" or stage.startswith("source-validate"):
                # Tool-using discovery/validation sessions are reused through
                # their own source/content-bound caches, never as plain prompt
                # responses.
                continue
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("schema_version") not in {
                CHAT_SCHEMA_VERSION,
                GT_CHAT_SCHEMA_VERSION,
            }:
                raise CoverageComparisonError(f"unsupported replay sidecar: {path}")
            for exchange in payload.get("exchanges", []):
                if not isinstance(exchange, dict) or set(exchange) != {
                    "system",
                    "user",
                    "response",
                }:
                    raise CoverageComparisonError(f"invalid replay exchange: {path}")
                if any(contains_credentials(exchange[field]) for field in exchange):
                    raise CoverageComparisonError(f"unsafe replay exchange: {path}")
                key = (exchange["system"], exchange["user"])
                prior = self.cache.setdefault(key, exchange["response"])
                if prior != exchange["response"]:
                    raise CoverageComparisonError("conflicting exact-prompt responses")

    def __call__(self, system: str, user: str) -> str:
        system = redact_credentials(system)
        user = redact_credentials(user)
        with self._lock:
            self.calls += 1
            call_number = self.calls
            cached = self.cache.get((system, user))
            if cached is not None:
                self.hits += 1
            else:
                self.misses += 1
        if cached is not None:
            print(
                f"coverage-comparison LLM call {call_number}: exact replay",
                file=sys.stderr,
                flush=True,
            )
            return cached
        if self.replay_only:
            raise CoverageComparisonError(
                "exact-prompt replay-only cache miss; live transport is disabled"
            )
        print(
            f"coverage-comparison LLM call {call_number}: live request",
            file=sys.stderr,
            flush=True,
        )
        response = redact_credentials(self.live_runner(system, user))
        with self._lock:
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
            prior = self.cache.setdefault((system, user), response)
            if prior != response:
                raise CoverageComparisonError(
                    "concurrent identical prompts returned conflicting responses"
                )
        return response

    def clear_checkpoint(self) -> None:
        if self.checkpoint_path.exists():
            self.checkpoint_path.unlink()

    def invalidate_prompts(self, prompts: list[tuple[str, str]]) -> None:
        keys = set(prompts)
        for key in keys:
            self.cache.pop(key, None)
        if not self.checkpoint_path.exists():
            return
        retained: list[str] = []
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

    def audit_payload(self) -> dict[str, Any]:
        replay = {
            "enabled": True,
            "replay_only": self.replay_only,
            "exact_prompt_hits": self.hits,
            "exact_prompt_misses": self.misses,
        }
        if self.misses and callable(getattr(self.live_runner, "audit_payload", None)):
            payload = dict(self.live_runner.audit_payload())
            payload["prompt_replay"] = replay
            return payload
        if self.prior_transport is not None:
            payload = deepcopy(self.prior_transport)
            payload["prompt_replay"] = replay
            return payload
        return self._replay_only_payload(replay)

    def current_audit_payload(self) -> dict[str, Any]:
        replay = {
            "enabled": True,
            "replay_only": self.replay_only,
            "exact_prompt_hits": self.hits,
            "exact_prompt_misses": self.misses,
        }
        if self.misses and callable(getattr(self.live_runner, "audit_payload", None)):
            payload = dict(self.live_runner.audit_payload())
            payload["prompt_replay"] = replay
            return payload
        return self._replay_only_payload(replay)

    def _replay_only_payload(self, replay: dict[str, Any]) -> dict[str, Any]:
        return {
            "transport": EXACT_REPLAY_TRANSPORT_VERSION,
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
                {"call": number, "source": "coverage-exact-prompt-replay"}
                for number in range(1, self.calls + 1)
            ],
        }

"""Exact audited prompt replay for group-oracle construction."""

from __future__ import annotations

import json
import os
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

from .contracts import CHAT_SCHEMA_VERSION, GroupOracleError
from .prompts import contains_credentials, redact_credentials


class ExactPromptReplayRunner:
    def __init__(self, live_runner: Callable[[str, str], str], artifact_root: Path):
        self.live_runner = live_runner
        self.cache: dict[tuple[str, str], str] = {}
        self.calls = 0
        self.hits = 0
        self.misses = 0
        self.prior_transport: dict[str, Any] | None = None
        self.checkpoint_path = (
            artifact_root.parent / f".{artifact_root.name}.prompt-checkpoint.jsonl"
        )
        if self.checkpoint_path.is_file():
            for number, line in enumerate(
                self.checkpoint_path.read_text(encoding="utf-8").splitlines(), 1
            ):
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise GroupOracleError(
                        f"invalid prompt checkpoint {self.checkpoint_path}:{number}: {exc}"
                    ) from exc
                if not isinstance(row, dict) or set(row) != {
                    "system", "user", "response"
                } or any(not isinstance(row[field], str) for field in row):
                    raise GroupOracleError(
                        f"invalid prompt checkpoint row {self.checkpoint_path}:{number}"
                    )
                if any(contains_credentials(row[field]) for field in row):
                    raise GroupOracleError(
                        f"unsafe credential-shaped data in prompt checkpoint "
                        f"{self.checkpoint_path}:{number}"
                    )
                key = (row["system"], row["user"])
                prior = self.cache.setdefault(key, row["response"])
                if prior != row["response"]:
                    raise GroupOracleError(
                        "conflicting responses in the exact-prompt checkpoint"
                    )
        repository = artifact_root / "repository"
        manifest_path = artifact_root / "manifest.json"
        if manifest_path.is_file():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise GroupOracleError(
                    f"invalid group-oracle replay manifest {manifest_path}: {exc}"
                ) from exc
            transport = manifest.get("transport")
            if not isinstance(transport, dict):
                raise GroupOracleError(
                    f"invalid group-oracle replay transport: {manifest_path}"
                )
            self.prior_transport = transport
        if not repository.is_dir():
            return
        for path in sorted(repository.glob("*/*/chat.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise GroupOracleError(f"invalid group-oracle replay sidecar {path}: {exc}") from exc
            if payload.get("schema_version") != CHAT_SCHEMA_VERSION:
                raise GroupOracleError(f"unsupported group-oracle replay sidecar: {path}")
            for exchange in payload.get("exchanges", []):
                if not isinstance(exchange, dict) or set(exchange) != {"system", "user", "response"}:
                    raise GroupOracleError(f"invalid replay exchange: {path}")
                if any(contains_credentials(exchange[field]) for field in exchange):
                    raise GroupOracleError(
                        f"unsafe credential-shaped data in replay exchange: {path}"
                    )
                key = (exchange["system"], exchange["user"])
                prior = self.cache.setdefault(key, exchange["response"])
                if prior != exchange["response"]:
                    raise GroupOracleError("conflicting responses for an identical audited prompt")

    def __call__(self, system: str, user: str) -> str:
        system = redact_credentials(system)
        user = redact_credentials(user)
        self.calls += 1
        cached = self.cache.get((system, user))
        if cached is not None:
            self.hits += 1
            print(
                f"group-oracle LLM call {self.calls}: exact replay",
                file=sys.stderr,
                flush=True,
            )
            return cached
        self.misses += 1
        print(
            f"group-oracle LLM call {self.calls}: live request",
            file=sys.stderr,
            flush=True,
        )
        response = redact_credentials(self.live_runner(system, user))
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

    def clear_checkpoint(self) -> None:
        if self.checkpoint_path.exists():
            self.checkpoint_path.unlink()

    def invalidate_prompts(self, prompts: list[tuple[str, str]]) -> None:
        """Evict terminally invalid checkpoint responses without touching artifacts."""

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
            "exact_prompt_hits": self.hits,
            "exact_prompt_misses": self.misses,
        }
        if self.misses and callable(getattr(self.live_runner, "audit_payload", None)):
            payload = dict(self.live_runner.audit_payload())
            payload["prompt_replay"] = replay
            return payload
        if self.prior_transport is not None:
            # A byte-identical all-replay run is a deterministic rebuild of the same
            # experiment. Preserve its original transport/token observation rather than
            # replacing it with a misleading zero-token replay-only record.
            return deepcopy(self.prior_transport)
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

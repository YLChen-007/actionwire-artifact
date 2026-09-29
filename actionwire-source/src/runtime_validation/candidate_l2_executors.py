"""Project-native execution adapters for candidate-bound L2 validation.

This module deliberately contains only adapters that already execute a real
entrypoint, loopback provider, native dispatch, and pre-effect interceptor.
It is not a registry for launch smoke or native-dispatch-only drivers.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .contracts import ValidationError


@dataclass(frozen=True)
class CandidateL2ExecutionReceipt:
    """One candidate result and the targeted runner manifest that produced it."""

    project: str
    candidate_id: str
    executor_id: str
    result: Mapping[str, Any]
    manifest: Mapping[str, Any]


CandidateExecutor = Callable[
    [str, Path, Path, int], CandidateL2ExecutionReceipt | None
]


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValidationError(f"cannot read targeted candidate result {path}: {exc}") from exc
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"{path}:{number}: invalid JSON") from exc
        if not isinstance(value, dict):
            raise ValidationError(f"{path}:{number}: expected object")
        rows.append(value)
    return rows


def _receipt(
    *,
    project: str,
    candidate_id: str,
    executor_id: str,
    target_dir: Path,
    manifest: Mapping[str, Any],
) -> CandidateL2ExecutionReceipt:
    rows = _read_jsonl(target_dir / "candidate-results.jsonl")
    matching = [row for row in rows if row.get("candidate_id") == candidate_id]
    if len(matching) != 1:
        raise ValidationError(
            f"{executor_id}: expected one result for {candidate_id}, got {len(matching)}"
        )
    result = matching[0]
    if result.get("project") != project:
        raise ValidationError(f"{executor_id}: project identity drift for {candidate_id}")
    return CandidateL2ExecutionReceipt(
        project=project,
        candidate_id=candidate_id,
        executor_id=executor_id,
        result=result,
        manifest=manifest,
    )


def _run_mercury(
    candidate_id: str, source_campaign: Path, target_dir: Path, attempts: int
) -> CandidateL2ExecutionReceipt:
    from .mercury_l2 import MercuryL2RunRequest, run_mercury_l2

    manifest = run_mercury_l2(
        MercuryL2RunRequest(
            campaign=source_campaign,
            out_dir=target_dir,
            attempts=attempts,
            candidate_id=candidate_id,
        )
    )
    return _receipt(
        project="mercury-agent",
        candidate_id=candidate_id,
        executor_id="mercury-agent-targeted-l2/v1",
        target_dir=target_dir,
        manifest=manifest,
    )


def _run_droidclaw(
    candidate_id: str, source_campaign: Path, target_dir: Path, attempts: int
) -> CandidateL2ExecutionReceipt:
    from .droidclaw_l2 import DroidClawL2RunRequest, run_droidclaw_l2

    if candidate_id != "CAND-02629879756e5c81":
        raise ValidationError(
            "requested DroidClaw candidate is not the canonical targeted L2 candidate"
        )
    manifest = run_droidclaw_l2(
        DroidClawL2RunRequest(
            campaign=source_campaign,
            out_dir=target_dir,
            attempts=attempts,
        )
    )
    return _receipt(
        project="droidclaw",
        candidate_id=candidate_id,
        executor_id="droidclaw-targeted-l2/v1",
        target_dir=target_dir,
        manifest=manifest,
    )


def _run_lettabot(
    candidate_id: str, source_campaign: Path, target_dir: Path, attempts: int
) -> CandidateL2ExecutionReceipt:
    from .letta_l2 import LettaL2RunRequest, run_letta_l2

    manifest = run_letta_l2(
        LettaL2RunRequest(
            campaign=source_campaign,
            out_dir=target_dir,
            attempts=attempts,
            candidate_id=candidate_id,
        )
    )
    return _receipt(
        project="lettabot",
        candidate_id=candidate_id,
        executor_id="lettabot-targeted-l2/v1",
        target_dir=target_dir,
        manifest=manifest,
    )


def _run_openclaw(
    candidate_id: str, source_campaign: Path, target_dir: Path, attempts: int
) -> CandidateL2ExecutionReceipt | None:
    from .openclaw_l2 import (
        TARGET_CANDIDATES,
        OpenClawL2RunRequest,
        run_openclaw_l2,
    )

    if candidate_id not in TARGET_CANDIDATES:
        return None
    campaign_root = target_dir.resolve()
    while (
        not campaign_root.name.startswith("runtime-auto-l2")
        and campaign_root.parent != campaign_root
    ):
        campaign_root = campaign_root.parent
    shared_build = campaign_root / "openclaw-build"
    build_dir = (
        shared_build
        if campaign_root.name.startswith("runtime-auto-l2")
        and shared_build.parent.is_dir()
        else None
    )
    manifest = run_openclaw_l2(
        OpenClawL2RunRequest(
            campaign=source_campaign,
            out_dir=target_dir,
            attempts=attempts,
            candidate_id=candidate_id,
            build_dir=build_dir,
        )
    )
    return _receipt(
        project="openclaw",
        candidate_id=candidate_id,
        executor_id="openclaw-targeted-l2/v1",
        target_dir=target_dir,
        manifest=manifest,
    )


def _run_openclaw_cn(
    candidate_id: str, source_campaign: Path, target_dir: Path, attempts: int
) -> CandidateL2ExecutionReceipt | None:
    from .openclaw_cn_l2 import (
        TARGET_CANDIDATES,
        OpenClawCNL2RunRequest,
        run_openclaw_cn_l2,
    )

    if candidate_id not in TARGET_CANDIDATES:
        return None
    campaign_root = target_dir.resolve()
    while (
        not campaign_root.name.startswith("runtime-auto-l2")
        and campaign_root.parent != campaign_root
    ):
        campaign_root = campaign_root.parent
    shared_build = campaign_root / "openclaw-cn-build"
    build_dir = (
        shared_build
        if campaign_root.name.startswith("runtime-auto-l2")
        and shared_build.parent.is_dir()
        else None
    )
    manifest = run_openclaw_cn_l2(
        OpenClawCNL2RunRequest(
            campaign=source_campaign,
            out_dir=target_dir,
            attempts=attempts,
            candidate_id=candidate_id,
            build_dir=build_dir,
        )
    )
    return _receipt(
        project="openclaw-cn",
        candidate_id=candidate_id,
        executor_id="openclaw-cn-targeted-l2/v1",
        target_dir=target_dir,
        manifest=manifest,
    )


def _run_nanoclaw(
    candidate_id: str, source_campaign: Path, target_dir: Path, attempts: int
) -> CandidateL2ExecutionReceipt | None:
    from .nanoclaw_l2 import (
        TARGET_CANDIDATES,
        NanoClawL2RunRequest,
        run_nanoclaw_l2,
    )

    if candidate_id not in TARGET_CANDIDATES:
        return None
    campaign_root = target_dir.resolve()
    while (
        not campaign_root.name.startswith("runtime-auto-l2")
        and campaign_root.parent != campaign_root
    ):
        campaign_root = campaign_root.parent
    shared_build = campaign_root / "nanoclaw-build"
    build_dir = (
        shared_build
        if campaign_root.name.startswith("runtime-auto-l2")
        and shared_build.parent.is_dir()
        else None
    )
    manifest = run_nanoclaw_l2(
        NanoClawL2RunRequest(
            campaign=source_campaign,
            out_dir=target_dir,
            attempts=attempts,
            candidate_id=candidate_id,
            build_dir=build_dir,
        )
    )
    return _receipt(
        project="nanoclaw",
        candidate_id=candidate_id,
        executor_id="nanoclaw-targeted-l2/v1",
        target_dir=target_dir,
        manifest=manifest,
    )


def _run_chatgpt_on_wechat(
    candidate_id: str, source_campaign: Path, target_dir: Path, attempts: int
) -> CandidateL2ExecutionReceipt | None:
    from .chatgpt_on_wechat_l2 import (
        HISTORICAL_TARGET_CANDIDATES,
        TARGET_CANDIDATES,
        ChatGPTOnWeChatL2RunRequest,
        run_chatgpt_on_wechat_l2,
    )

    if candidate_id not in {*TARGET_CANDIDATES, *HISTORICAL_TARGET_CANDIDATES}:
        return None
    campaign_root = target_dir.resolve()
    while (
        campaign_root.name
        not in {
            "runtime-auto-l2",
            "runtime-auto-l2-expanded-v2",
            "runtime-auto-l2-expanded-v3",
        }
        and campaign_root.parent != campaign_root
    ):
        campaign_root = campaign_root.parent
    shared_build = campaign_root / "chatgpt-on-wechat-build"
    build_dir = (
        shared_build
        if campaign_root.name in {
            "runtime-auto-l2",
            "runtime-auto-l2-expanded-v2",
            "runtime-auto-l2-expanded-v3",
        }
        and shared_build.parent.is_dir()
        else None
    )
    manifest = run_chatgpt_on_wechat_l2(
        ChatGPTOnWeChatL2RunRequest(
            campaign=source_campaign,
            out_dir=target_dir,
            attempts=attempts,
            candidate_id=candidate_id,
            build_dir=build_dir,
        )
    )
    return _receipt(
        project="chatgpt-on-wechat",
        candidate_id=candidate_id,
        executor_id="chatgpt-on-wechat-targeted-l2/v1",
        target_dir=target_dir,
        manifest=manifest,
    )


def _run_astrbot(
    candidate_id: str, source_campaign: Path, target_dir: Path, attempts: int
) -> CandidateL2ExecutionReceipt | None:
    from .astrbot_l2 import (
        TARGET_CANDIDATES,
        AstrBotL2RunRequest,
        run_astrbot_l2,
    )

    if candidate_id not in TARGET_CANDIDATES:
        return None
    campaign_root = target_dir.resolve()
    while (
        campaign_root.name
        not in {
            "runtime-auto-l2",
            "runtime-auto-l2-expanded-v2",
            "runtime-auto-l2-expanded-v3",
        }
        and campaign_root.parent != campaign_root
    ):
        campaign_root = campaign_root.parent
    shared_build = campaign_root / "astrbot-build"
    build_dir = (
        shared_build
        if campaign_root.name in {
            "runtime-auto-l2",
            "runtime-auto-l2-expanded-v2",
            "runtime-auto-l2-expanded-v3",
        }
        and shared_build.parent.is_dir()
        else None
    )
    manifest = run_astrbot_l2(
        AstrBotL2RunRequest(
            campaign=source_campaign,
            out_dir=target_dir,
            attempts=attempts,
            candidate_id=candidate_id,
            build_dir=build_dir,
        )
    )
    return _receipt(
        project="AstrBot",
        candidate_id=candidate_id,
        executor_id="astrbot-targeted-l2/v1",
        target_dir=target_dir,
        manifest=manifest,
    )


def _run_qwenpaw(
    candidate_id: str, source_campaign: Path, target_dir: Path, attempts: int
) -> CandidateL2ExecutionReceipt | None:
    from .qwenpaw_l2 import (
        TARGET_CANDIDATES,
        QwenPawL2RunRequest,
        run_qwenpaw_l2,
    )

    if candidate_id not in TARGET_CANDIDATES:
        return None
    campaign_root = target_dir.resolve()
    while (
        campaign_root.name
        not in {
            "runtime-auto-l2",
            "runtime-auto-l2-expanded-v2",
            "runtime-auto-l2-expanded-v3",
        }
        and campaign_root.parent != campaign_root
    ):
        campaign_root = campaign_root.parent
    shared_build = campaign_root / "qwenpaw-build"
    build_dir = (
        shared_build
        if campaign_root.name in {
            "runtime-auto-l2",
            "runtime-auto-l2-expanded-v2",
            "runtime-auto-l2-expanded-v3",
        }
        and shared_build.parent.is_dir()
        else None
    )
    manifest = run_qwenpaw_l2(
        QwenPawL2RunRequest(
            campaign=source_campaign,
            out_dir=target_dir,
            attempts=attempts,
            candidate_id=candidate_id,
            build_dir=build_dir,
        )
    )
    return _receipt(
        project="QwenPaw",
        candidate_id=candidate_id,
        executor_id="qwenpaw-targeted-l2/v1",
        target_dir=target_dir,
        manifest=manifest,
    )


def _run_hermes_agent(
    candidate_id: str, source_campaign: Path, target_dir: Path, attempts: int
) -> CandidateL2ExecutionReceipt | None:
    from .hermes_agent_l2 import (
        TARGET_CANDIDATES,
        HermesAgentL2RunRequest,
        run_hermes_agent_l2,
    )

    if candidate_id not in TARGET_CANDIDATES:
        return None
    campaign_root = target_dir.resolve()
    while (
        campaign_root.name
        not in {
            "runtime-auto-l2",
            "runtime-auto-l2-expanded-v2",
            "runtime-auto-l2-expanded-v3",
        }
        and campaign_root.parent != campaign_root
    ):
        campaign_root = campaign_root.parent
    shared_build = campaign_root / "hermes-agent-build"
    build_dir = (
        shared_build
        if campaign_root.name
        in {
            "runtime-auto-l2",
            "runtime-auto-l2-expanded-v2",
            "runtime-auto-l2-expanded-v3",
        }
        and shared_build.parent.is_dir()
        else None
    )
    manifest = run_hermes_agent_l2(
        HermesAgentL2RunRequest(
            campaign=source_campaign,
            out_dir=target_dir,
            attempts=attempts,
            candidate_id=candidate_id,
            build_dir=build_dir,
        )
    )
    return _receipt(
        project="hermes-agent",
        candidate_id=candidate_id,
        executor_id="hermes-agent-targeted-l2/v1",
        target_dir=target_dir,
        manifest=manifest,
    )


def _run_nanobot(
    candidate_id: str, source_campaign: Path, target_dir: Path, attempts: int
) -> CandidateL2ExecutionReceipt | None:
    from .nanobot_l2 import (
        TARGET_CANDIDATES,
        NanobotL2RunRequest,
        run_nanobot_l2,
    )

    if candidate_id not in TARGET_CANDIDATES:
        return None
    campaign_root = target_dir.resolve()
    while (
        campaign_root.name
        not in {
            "runtime-auto-l2",
            "runtime-auto-l2-expanded-v2",
            "runtime-auto-l2-expanded-v3",
        }
        and campaign_root.parent != campaign_root
    ):
        campaign_root = campaign_root.parent
    shared_build = campaign_root / "nanobot-build"
    build_dir = (
        shared_build
        if campaign_root.name
        in {
            "runtime-auto-l2",
            "runtime-auto-l2-expanded-v2",
            "runtime-auto-l2-expanded-v3",
        }
        and shared_build.parent.is_dir()
        else None
    )
    manifest = run_nanobot_l2(
        NanobotL2RunRequest(
            campaign=source_campaign,
            out_dir=target_dir,
            attempts=attempts,
            candidate_id=candidate_id,
            build_dir=build_dir,
        )
    )
    return _receipt(
        project="nanobot",
        candidate_id=candidate_id,
        executor_id="nanobot-targeted-l2/v1",
        target_dir=target_dir,
        manifest=manifest,
    )


_EXECUTORS: dict[str, CandidateExecutor] = {
    "mercury-agent": _run_mercury,
    "droidclaw": _run_droidclaw,
    "lettabot": _run_lettabot,
    "openclaw": _run_openclaw,
    "openclaw-cn": _run_openclaw_cn,
    "nanoclaw": _run_nanoclaw,
    "chatgpt-on-wechat": _run_chatgpt_on_wechat,
    "AstrBot": _run_astrbot,
    "QwenPaw": _run_qwenpaw,
    "hermes-agent": _run_hermes_agent,
    "nanobot": _run_nanobot,
}


def registered_candidate_l2_projects() -> tuple[str, ...]:
    """Return projects with real-entrypoint candidate L2 executors."""

    return tuple(sorted(_EXECUTORS))


def execute_registered_candidate_l2(
    *,
    project: str,
    candidate_id: str,
    source_campaign: Path,
    target_dir: Path,
    attempts: int,
) -> CandidateL2ExecutionReceipt | None:
    """Execute one registered project-native candidate runner, if one exists."""

    executor = _EXECUTORS.get(project)
    if executor is None:
        return None
    return executor(candidate_id, source_campaign, target_dir, attempts)

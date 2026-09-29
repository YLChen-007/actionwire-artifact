"""Deterministically upgrade the frozen corrected-v2 campaign to executable v3 cases."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from src.projects import get_project

from .campaign import load_campaign_definition
from .campaign_contracts import (
    CAMPAIGN_SCHEMA_VERSION,
    CASE_SCHEMA_VERSION_V3,
    EXECUTION_GROUP_SCHEMA_VERSION,
    CampaignDefinition,
    canonical_json,
    digest,
    execution_identity,
    stable_case_id,
    stable_execution_id,
    validate_runtime_case,
)
from .contracts import ValidationError, atomic_write_json, atomic_write_text, sha256_file
from .pipeline import _credential_scan


FROZEN_V2_CAMPAIGN_ID = "RVCAMP-d26ce0942aa6d47d"
REPAIRED_CANDIDATES = frozenset(
    {
        "CAND-1fa5be6c49abcf39",
        "CAND-371f371f008098b7",
        "CAND-419c430f8cec2cba",
        "CAND-516d232a79a7e834",
        "CAND-5625ea642cacc3cd",
        "CAND-5a22fba9d06f5a2c",
        "CAND-71a03074d533924d",
        "CAND-948bb3e0d2be4eb5",
        "CAND-a993ec3d8fd93302",
        "CAND-e20b81276e8e6255",
    }
)

TOOL_ALIASES: dict[tuple[str, str], str] = {
    ("hermes-agent", "read_file_tool"): "read_file",
    ("hermes-agent", "terminal_tool"): "terminal",
    ("openclaw-cn", "browserAct"): "browser",
    ("openclaw-cn", "browser_act"): "browser",
}

PYTHON_ANCHOR_REPAIRS: dict[tuple[str, str], dict[str, tuple[str, int, str]]] = {
    ("chatgpt-on-wechat", "web_fetch"): {
        "handler": ("agent/tools/web_fetch/web_fetch.py", 101, "WebFetch.execute"),
        "sink": ("agent/tools/web_fetch/web_fetch.py", 121, "requests.get"),
        "effect": ("agent/tools/web_fetch/web_fetch.py", 121, "requests.get"),
    },
    ("chatgpt-on-wechat", "vision"): {
        "handler": ("agent/tools/vision/vision.py", 150, "Vision.execute source-bearing entry"),
        "sink": ("agent/tools/vision/vision.py", 600, "requests.get"),
        "effect": ("agent/tools/vision/vision.py", 600, "requests.get"),
    },
    ("hermes-agent", "read_file"): {
        "handler": ("tools/file_tools.py", 1093, "_handle_read_file"),
        "sink": ("tools/environments/local.py", 413, "LocalEnvironment subprocess.Popen"),
        "effect": ("tools/environments/local.py", 413, "LocalEnvironment subprocess.Popen"),
    },
    ("hermes-agent", "skill_view"): {
        "handler": ("tools/skills_tool.py", 1500, "_skill_view_with_bump"),
        "sink": ("tools/skills_tool.py", 1017, "skill_md.read_text"),
        "effect": ("tools/skills_tool.py", 1017, "skill_md.read_text"),
    },
    ("hermes-agent", "terminal"): {
        "handler": ("tools/terminal_tool.py", 2321, "_handle_terminal"),
    },
    ("nanobot", "exec"): {
        "handler": ("nanobot/agent/tools/shell.py", 78, "ExecTool.execute"),
        "sink": ("nanobot/agent/tools/shell.py", 94, "asyncio.create_subprocess_shell"),
        "effect": ("nanobot/agent/tools/shell.py", 94, "asyncio.create_subprocess_shell"),
    },
}


@dataclass(frozen=True)
class CampaignUpgradeRequest:
    source_campaign: Path
    out_dir: Path
    expected_candidates: int = 100
    expected_repaired: int = 10


def _matcher(
    path: list[str], exploit: Any, control: Any, *, relation: str, source: str = "tool-argument"
) -> dict[str, Any]:
    return {
        "source": source,
        "relation": relation,
        "path": path,
        "exploit_value": exploit,
        "control_value": control,
    }


def _repair_case(case: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    """Convert one v2 case and apply the audited, candidate-specific repair."""

    value = json.loads(canonical_json(case))
    source_case_id = value["case_id"]
    candidate_id = value["candidate_ids"][0]
    value["schema_version"] = CASE_SCHEMA_VERSION_V3
    value["fixture_state"] = {"exploit": {}, "control": {}}
    old_matcher = value["matcher"]
    value["matcher"] = _matcher(
        list(old_matcher["argument_path"]),
        old_matcher["exploit_value"],
        old_matcher["control_value"],
        relation=old_matcher["relation"],
    )
    repair_kind = "none"

    if candidate_id in {"CAND-1fa5be6c49abcf39", "CAND-5a22fba9d06f5a2c"}:
        exploit = {
            "action": "send",
            "target": "matrix:!runtime:fixture",
            "message": "<img src=x onerror=alert(1)>",
        }
        control = {
            "action": "send",
            "target": "matrix:!runtime:fixture",
            "message": "safe message",
        }
        value["replay"]["exploit_args"] = exploit
        value["replay"]["control_args"] = control
        value["matcher"] = _matcher(
            ["message"], exploit["message"], control["message"], relation="contains"
        )
        repair_kind = "safe-control"
    elif candidate_id == "CAND-371f371f008098b7":
        exploit = {
            "action": "send",
            "target": "matrix:!runtime:fixture",
            "message": "<img src=x onerror=alert(1)>",
        }
        control = {
            "action": "send",
            "target": "matrix:!runtime:fixture",
            "message": "Hello world",
        }
        value["replay"]["exploit_args"] = exploit
        value["replay"]["control_args"] = control
        value["matcher"] = _matcher(
            ["message"], exploit["message"], control["message"], relation="contains"
        )
        repair_kind = "argument-path"
    elif candidate_id == "CAND-419c430f8cec2cba":
        exploit = "*** Begin Patch\n*** Add File: link/escape.txt\ncontent\n*** End Patch"
        control = "*** Begin Patch\n*** Add File: safe.txt\ncontent\n*** End Patch"
        value["replay"]["exploit_args"] = {"input": exploit}
        value["replay"]["control_args"] = {"input": control}
        value["matcher"] = _matcher(
            ["input"], exploit, control, relation="path-resolves-to"
        )
        repair_kind = "argument-path"
    elif candidate_id in {"CAND-516d232a79a7e834", "CAND-948bb3e0d2be4eb5"}:
        exploit = "() => { location.href = 'http://169.254.169.254/latest/meta-data/'; }"
        control = "() => { return document.title; }"
        value["replay"]["exploit_args"] = {
            "action": "act",
            "request": {"kind": "evaluate", "fn": exploit},
        }
        value["replay"]["control_args"] = {
            "action": "act",
            "request": {"kind": "evaluate", "fn": control},
        }
        value["matcher"] = _matcher(
            ["request", "fn"], exploit, control, relation="url-host-class"
        )
        repair_kind = "argument-path"
    elif candidate_id == "CAND-5625ea642cacc3cd":
        value["replay"]["exploit_args"] = {"command": "id"}
        value["replay"]["control_args"] = {"command": "echo safe"}
        value["matcher"] = _matcher(
            ["command"], "id", "echo safe", relation="command-segment"
        )
        repair_kind = "argument-path"
    elif candidate_id in {"CAND-71a03074d533924d", "CAND-a993ec3d8fd93302"}:
        args = {"action": "act", "request": {"kind": "click", "ref": "e12"}}
        value["replay"]["exploit_args"] = args
        value["replay"]["control_args"] = args
        value["fixture_state"] = {
            "exploit": {"browser_page": {"destination_class": "private-network"}},
            "control": {"browser_page": {"destination_class": "public-loopback"}},
        }
        value["matcher"] = _matcher(
            ["browser_page", "destination_class"],
            "private-network",
            "public-loopback",
            relation="url-host-class",
            source="fixture-state",
        )
        repair_kind = "fixture-state"
    elif candidate_id == "CAND-e20b81276e8e6255":
        args = {"to": "victim-agent", "filename": "payload.txt"}
        value["replay"]["exploit_args"] = args
        value["replay"]["control_args"] = args
        value["fixture_state"] = {
            "exploit": {"target_inbox": {"kind": "symlink"}},
            "control": {"target_inbox": {"kind": "directory"}},
        }
        value["matcher"] = _matcher(
            ["target_inbox", "kind"],
            "symlink",
            "directory",
            relation="path-resolves-to",
            source="fixture-state",
        )
        repair_kind = "fixture-state"

    tool = value["replay"]["tool_name"]
    canonical = TOOL_ALIASES.get((value["project"], tool))
    if canonical is not None:
        handler_symbol = value["observations"][0]["symbol"]
        if handler_symbol != canonical:
            raise ValidationError(
                f"alias {value['project']}:{tool} is not proved by the handler binding"
            )
        value["replay"]["tool_name"] = canonical
        if repair_kind == "none":
            repair_kind = "registered-alias"

    # The frozen v2 OpenClaw case names a split runtime file that is absent
    # from the revision-bound checkout. The same native spawn boundary is in
    # process/spawn-utils.ts at this revision; bind that exact source instead.
    if candidate_id == "CAND-22aaceea2b7af96b":
        sink_path = "src/process/spawn-utils.ts"
        sink_file = get_project("openclaw").source_root / sink_path
        for observation in value["observations"]:
            if observation["kind"] in {"sink", "effect"}:
                observation.update(
                    {
                        "file": sink_path,
                        "line": 67,
                        "symbol": "child_process.spawn via spawnWithFallback",
                    }
                )
        binding = {"path": sink_path, "sha256": sha256_file(sink_file)}
        if binding not in value["source_binding"]["files"]:
            value["source_binding"]["files"].append(binding)
            value["source_binding"]["files"].sort(key=lambda row: row["path"])
        repair_kind = "source-anchor"

    anchor_repair = PYTHON_ANCHOR_REPAIRS.get(
        (value["project"], value["replay"]["tool_name"])
    )
    if anchor_repair:
        changed = False
        for observation in value["observations"]:
            replacement = anchor_repair.get(observation["kind"])
            if replacement is None:
                continue
            file_name, line, symbol = replacement
            prior = (observation["file"], observation["line"], observation["symbol"])
            observation.update({"file": file_name, "line": line, "symbol": symbol})
            changed = changed or prior != replacement
        if changed and repair_kind == "none":
            repair_kind = "source-anchor"

    source_root = get_project(value["project"]).source_root
    bound_paths = {row["path"] for row in value["source_binding"]["files"]}
    for observation in value["observations"]:
        relative = Path(observation["file"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValidationError("observation source anchor escapes project root")
        if observation["file"] not in bound_paths:
            raise ValidationError(
                f"observation source is not hash-bound: {value['project']}:{observation['file']}"
            )
        source_file = source_root / relative
        if not source_file.is_file():
            raise ValidationError(
                f"observation source is unavailable: {value['project']}:{observation['file']}"
            )
        if observation["line"] is not None:
            line_count = len(source_file.read_text(encoding="utf-8", errors="replace").splitlines())
            if observation["line"] > line_count:
                raise ValidationError(
                    f"observation line is outside source: {value['project']}:{observation['file']}:{observation['line']}"
                )

    value["generation"] = {
        "status": "ready",
        "reason": value["generation"]["reason"]
        + ("; deterministically repaired from the audited v2 exchange" if candidate_id in REPAIRED_CANDIDATES else ""),
        "model_generated": value["generation"]["model_generated"],
        "repair": {"kind": repair_kind, "source_case_id": source_case_id},
    }
    identity = {
        "candidate_ids": value["candidate_ids"],
        "project": value["project"],
        "revision": value["revision"],
        "chain_id": value["chain_id"],
        "group_id": value["group_id"],
        "requirement_id": value["requirement_id"],
        "failure_mode": value["failure_mode"],
        "replay": value["replay"],
        "matcher": value["matcher"],
        "observations": value["observations"],
        "fixture_state": value["fixture_state"],
    }
    value["case_id"] = stable_case_id(identity)
    return validate_runtime_case(value), source_case_id


def _execution_groups(cases: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for case in cases:
        execution_id = stable_execution_id(case)
        group = groups.setdefault(
            execution_id,
            {
                "schema_version": EXECUTION_GROUP_SCHEMA_VERSION,
                "execution_id": execution_id,
                "case_ids": [],
                "candidate_ids": [],
                "project": case["project"],
                "revision": case["revision"],
                "execution_identity_sha256": digest(execution_identity(case)),
            },
        )
        group["case_ids"].append(case["case_id"])
        group["candidate_ids"].extend(case["candidate_ids"])
    for group in groups.values():
        group["case_ids"] = sorted(set(group["case_ids"]))
        group["candidate_ids"] = sorted(set(group["candidate_ids"]))
    return sorted(groups.values(), key=lambda row: row["execution_id"])


def _write_jsonl(path: Path, rows: list[Mapping[str, Any]]) -> None:
    atomic_write_text(path, "".join(canonical_json(row) + "\n" for row in rows))


def upgrade_covered_campaign(request: CampaignUpgradeRequest) -> CampaignDefinition:
    """Publish v3 from the immutable v2 cases without invoking a model."""

    source = load_campaign_definition(request.source_campaign)
    if source.campaign_id != FROZEN_V2_CAMPAIGN_ID:
        raise ValidationError(
            f"v2 campaign identity drift: expected {FROZEN_V2_CAMPAIGN_ID}, got {source.campaign_id}"
        )
    if len(source.target_candidate_ids) != request.expected_candidates:
        raise ValidationError("v2 campaign candidate denominator drift")
    repaired: list[dict[str, Any]] = []
    ledger: list[dict[str, Any]] = []
    repaired_ids: set[str] = set()
    for case in source.cases:
        upgraded, source_case_id = _repair_case(case)
        repaired.append(upgraded)
        candidate_id = upgraded["candidate_ids"][0]
        if candidate_id in REPAIRED_CANDIDATES:
            repaired_ids.add(candidate_id)
        ledger.append(
            {
                "candidate_id": candidate_id,
                "source_case_id": source_case_id,
                "case_id": upgraded["case_id"],
                "repair": upgraded["generation"]["repair"]["kind"],
                "tool_name": upgraded["replay"]["tool_name"],
            }
        )
    if repaired_ids != REPAIRED_CANDIDATES or len(repaired_ids) != request.expected_repaired:
        raise ValidationError("deterministic repair set drift")
    if any(case["generation"]["status"] != "ready" for case in repaired):
        raise ValidationError("v3 contains a non-ready generated case")
    groups = _execution_groups(repaired)
    source_hashes = {
        name: sha256_file(source.root / name)
        for name in ("campaign.json", "cases.jsonl", "execution-groups.jsonl", "generation-manifest.json")
    }
    campaign_id = "RVCAMP-" + digest(
        {
            "source_campaign": source.campaign_id,
            "source_hashes": source_hashes,
            "case_ids": sorted(case["case_id"] for case in repaired),
        }
    )[:16]
    campaign = {
        "schema_version": CAMPAIGN_SCHEMA_VERSION,
        "campaign_id": campaign_id,
        "analysis_mode": "post-hoc-ground-truth-informed-corrected-v3",
        "execution_mode": "native-tool-replay-only",
        "coverage_root": source.manifest["coverage_root"],
        "source_campaign": {
            "campaign_id": source.campaign_id,
            "path": str(source.root),
            "artifact_sha256": source_hashes,
        },
        "target": source.manifest["target"],
        "artifact_sha256": source.manifest["artifact_sha256"],
        "attempts": 3,
        "paired_controls": True,
        "canonical_policy": {"unsupported": 0, "infrastructure_inconclusive": 0},
    }
    out = request.out_dir.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{out.name}.staging-", dir=out.parent))
    backup = out.parent / f".{out.name}.backup-{os.getpid()}"
    try:
        _write_jsonl(staging / "cases.jsonl", repaired)
        _write_jsonl(staging / "execution-groups.jsonl", groups)
        _write_jsonl(staging / "repair-ledger.jsonl", ledger)
        atomic_write_json(staging / "campaign.json", campaign)
        generation_manifest = {
            "schema_version": "clawgap-runtime-validation-generation-manifest/v2",
            "campaign_id": campaign_id,
            "generation_command": (
                "python -m src.runtime_validation upgrade-covered-v3 "
                f"--source-campaign {request.source_campaign} --out-dir {request.out_dir}"
            ),
            "model_calls": 0,
            "source_campaign": source.campaign_id,
            "counts": {
                "candidate_ids": len(repaired),
                "ready_cases": len(repaired),
                "unsupported_cases": 0,
                "deterministic_repairs": len(repaired_ids),
                "execution_groups": len(groups),
            },
            "outputs": {
                name: sha256_file(staging / name)
                for name in ("campaign.json", "cases.jsonl", "execution-groups.jsonl", "repair-ledger.jsonl")
            },
        }
        atomic_write_json(staging / "generation-manifest.json", generation_manifest)
        _credential_scan(staging, ())
        if backup.exists():
            raise ValidationError(f"stale v3 generation backup blocks publication: {backup}")
        if out.exists():
            os.replace(out, backup)
        try:
            os.replace(staging, out)
        except Exception:
            if backup.exists() and not out.exists():
                os.replace(backup, out)
            raise
        if backup.exists():
            shutil.rmtree(backup)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return CampaignDefinition(
        campaign_id=campaign_id,
        root=out,
        cases=tuple(repaired),
        execution_groups=tuple(groups),
        target_candidate_ids=source.target_candidate_ids,
        manifest=campaign,
    )

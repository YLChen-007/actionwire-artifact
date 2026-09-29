"""Select and publish one reviewed ground-truth case per runtime adapter family."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

from .campaign_contracts import digest
from .contracts import ValidationError, atomic_write_json, atomic_write_text, sha256_file
from .qualification_contracts import (
    QUALIFICATION_CAMPAIGN_SCHEMA_VERSION,
    QualificationCampaign,
    QualificationGenerationRequest,
    QualificationExpansionRequest,
    canonical_jsonl,
    stable_qualification_case_id,
    validate_qualification_case,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_FAMILIES = 23


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid qualification input {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"qualification input must be an object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValidationError(f"cannot read qualification input {path}: {exc}") from exc
    for line_number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ValidationError(f"{path}:{line_number}: expected object")
        rows.append(value)
    return rows


def _family_key(case: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(case["project"]),
        str(case["adapter"]),
        str(case["replay"]["tool_name"]),
        str(case["probe"]),
    )


def _eligible(case: Mapping[str, Any]) -> bool:
    return (
        case.get("boundary_status") == "eligible"
        and case.get("support_status") == "ready"
        and case.get("review", {}).get("status") == "approved"
    )


def _qualification_case(
    source: Mapping[str, Any], source_digest: str
) -> dict[str, Any]:
    family = {
        "project": source["project"],
        "adapter": source["adapter"],
        "tool_name": source["replay"]["tool_name"],
        "probe": source["probe"],
    }
    replay = {
        "tool_name": source["replay"]["tool_name"],
        "exploit_args": source["replay"]["exploit_args"],
        "control_args": source["replay"]["control_args"],
    }
    value = {
        "schema_version": "clawgap-runtime-qualification-case/v1",
        "case_id": "",
        "family": family,
        "origin": {
            "report_id": source["report_id"],
            "ground_truth_case_id": source["case_id"],
            "source_campaign_sha256": source_digest,
        },
        "revision": source["revision"],
        "source_binding": source["source_binding"],
        "dependency_binding": source["dependency_binding"],
        "native_case": source,
        "replay": replay,
        "prompt": source["replay"]["reproduction_prompt"],
        "mock_provider": {
            "protocol": "clawgap-forced-tool-call/v1",
            "tool_calls": {
                side: {"name": replay["tool_name"], "arguments": replay[f"{side}_args"]}
                for side in ("exploit", "control")
            },
        },
        "observations": source["observations"],
        "effect_policy": source["effect_policy"],
        "selection": {
            "rule": "lexicographically-smallest-ready-reviewed-report-id",
            "family_key": list(_family_key(source)),
        },
    }
    identity = {
        key: item
        for key, item in value.items()
        if key not in {"case_id", "selection"}
    }
    value["case_id"] = stable_qualification_case_id(identity)
    return validate_qualification_case(value)


def _publish_atomically(out: Path, writer) -> None:
    out = out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{out.name}.staging-", dir=out.parent))
    backup = out.parent / f".{out.name}.backup-{os.getpid()}"
    try:
        writer(staging)
        if backup.exists():
            raise ValidationError(f"stale qualification backup blocks publication: {backup}")
        if out.exists():
            os.replace(out, backup)
        os.replace(staging, out)
        if backup.exists():
            shutil.rmtree(backup)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        if backup.exists() and not out.exists():
            os.replace(backup, out)
        raise


def generate_adapter_qualification(
    request: QualificationGenerationRequest,
) -> QualificationCampaign:
    source_root = request.source_campaign.resolve()
    source_manifest = _read_json(source_root / "manifest.json")
    source_cases_path = source_root / "cases.jsonl"
    source_cases = _read_jsonl(source_cases_path)
    source_digest = sha256_file(source_cases_path)
    groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for case in source_cases:
        if _eligible(case):
            groups[_family_key(case)].append(case)
    selected = {
        key: sorted(values, key=lambda item: (item["report_id"], item["case_id"]))[0]
        for key, values in groups.items()
    }
    expected = request.expected_families
    if len(selected) != expected:
        raise ValidationError(
            f"qualification family denominator drift: expected {expected}, found {len(selected)}"
        )
    cases = [_qualification_case(case, source_digest) for _, case in sorted(selected.items())]
    if len({case["case_id"] for case in cases}) != expected:
        raise ValidationError("qualification case identities are not unique")
    ledger: list[dict[str, Any]] = []
    for key, members in sorted(groups.items()):
        winner = selected[key]["case_id"]
        for member in sorted(members, key=lambda item: (item["report_id"], item["case_id"])):
            ledger.append(
                {
                    "schema_version": "clawgap-runtime-qualification-selection/v1",
                    "family": list(key),
                    "report_id": member["report_id"],
                    "ground_truth_case_id": member["case_id"],
                    "selected": member["case_id"] == winner,
                    "reason": (
                        "lexicographically-smallest-ready-reviewed-report-id"
                        if member["case_id"] == winner
                        else "same-project-adapter-tool-probe family has selected representative"
                    ),
                }
            )
    campaign_id = "RVQCAMP-" + digest(
        {
            "source_campaign": source_manifest.get("campaign_id"),
            "source_cases_sha256": source_digest,
            "case_ids": [case["case_id"] for case in cases],
        }
    )[:16]

    def write(staging: Path) -> None:
        campaign = {
            "schema_version": QUALIFICATION_CAMPAIGN_SCHEMA_VERSION,
            "campaign_id": campaign_id,
            "purpose": "adapter-qualification-only",
            "source_campaign": {
                "path": str(source_root),
                "campaign_id": source_manifest.get("campaign_id"),
                "cases_sha256": source_digest,
            },
            "target": {"families": expected, "case_ids": [case["case_id"] for case in cases]},
            "selection_rule": "lexicographically-smallest-ready-reviewed-report-id",
            "live_triggerability": "exploratory-only",
        }
        atomic_write_json(staging / "campaign.json", campaign)
        atomic_write_text(staging / "cases.jsonl", canonical_jsonl(cases))
        atomic_write_text(staging / "selection-ledger.jsonl", canonical_jsonl(ledger))
        atomic_write_json(
            staging / "generation-manifest.json",
            {
                "schema_version": "clawgap-runtime-qualification-generation/v1",
                "reproduction_command": (
                    "python -m src.runtime_validation generate-adapter-qualification "
                    f"--source-campaign {request.source_campaign} --out-dir {request.out_dir}"
                ),
                "source_manifest_sha256": sha256_file(source_root / "manifest.json"),
                "source_cases_sha256": source_digest,
            },
        )

    _publish_atomically(request.out_dir, write)
    return QualificationCampaign(campaign_id, request.out_dir.resolve(), tuple(cases), tuple(ledger))


def generate_adapter_qualification_expansion(
    request: QualificationExpansionRequest,
) -> QualificationCampaign:
    """Publish all reviewed cases only after the 23-family gate passes."""

    source_root = request.source_campaign.resolve()
    qualification_root = request.qualification_campaign.resolve()
    source_manifest = _read_json(source_root / "manifest.json")
    qualification_campaign = _read_json(qualification_root / "campaign.json")
    qualification_results = _read_jsonl(qualification_root / "qualification-results.jsonl")
    if len(qualification_results) != request.expected_families:
        raise ValidationError("adapter-family qualification gate has the wrong denominator")
    if any(
        row.get("qualification") != "qualified" or row.get("forced_path") != "confirmed"
        for row in qualification_results
    ):
        raise ValidationError("the all-42 expansion requires all 23 adapter families to qualify first")

    source_cases = _read_jsonl(source_root / "cases.jsonl")
    eligible = [case for case in source_cases if _eligible(case)]
    families = {_family_key(case) for case in eligible}
    if len(eligible) != request.expected_cases or len(families) != request.expected_families:
        raise ValidationError(
            "expanded ground-truth denominator drift: "
            f"expected {request.expected_cases} cases across {request.expected_families} families, "
            f"found {len(eligible)} across {len(families)}"
        )
    source_digest = sha256_file(source_root / "cases.jsonl")
    cases = [_qualification_case(case, source_digest) for case in eligible]
    if len({case["case_id"] for case in cases}) != request.expected_cases:
        raise ValidationError("expanded qualification case identities are not unique")
    ledger = [
        {
            "schema_version": "clawgap-runtime-qualification-selection/v1",
            "family": case["selection"]["family_key"],
            "report_id": case["origin"]["report_id"],
            "ground_truth_case_id": case["origin"]["ground_truth_case_id"],
            "selected": True,
            "reason": "all-ground-truth-expansion-after-23-family-gate",
        }
        for case in cases
    ]
    campaign_id = "RVQEXPCAMP-" + digest(
        {
            "gate_campaign_id": qualification_campaign.get("campaign_id"),
            "source_campaign": source_manifest.get("campaign_id"),
            "source_cases_sha256": source_digest,
            "case_ids": [case["case_id"] for case in cases],
        }
    )[:16]

    def write(staging: Path) -> None:
        campaign = {
            "schema_version": QUALIFICATION_CAMPAIGN_SCHEMA_VERSION,
            "campaign_id": campaign_id,
            "purpose": "adapter-qualification-all-ground-truths",
            "source_campaign": {
                "path": str(source_root),
                "campaign_id": source_manifest.get("campaign_id"),
                "cases_sha256": source_digest,
            },
            "qualification_gate": {
                "path": str(qualification_root),
                "campaign_id": qualification_campaign.get("campaign_id"),
                "qualification_results_sha256": sha256_file(
                    qualification_root / "qualification-results.jsonl"
                ),
                "status": "23-of-23-qualified",
            },
            "target": {
                "families": request.expected_families,
                "cases": request.expected_cases,
                "case_ids": [case["case_id"] for case in cases],
            },
            "selection_rule": "all-ready-reviewed-ground-truths-after-family-gate",
            "live_triggerability": "exploratory-only",
        }
        atomic_write_json(staging / "campaign.json", campaign)
        atomic_write_text(staging / "cases.jsonl", canonical_jsonl(cases))
        atomic_write_text(staging / "selection-ledger.jsonl", canonical_jsonl(ledger))
        atomic_write_json(
            staging / "generation-manifest.json",
            {
                "schema_version": "clawgap-runtime-qualification-generation/v1",
                "reproduction_command": (
                    "python -m src.runtime_validation expand-adapter-qualification "
                    f"--source-campaign {request.source_campaign} "
                    f"--qualification-campaign {request.qualification_campaign} "
                    f"--out-dir {request.out_dir}"
                ),
                "source_manifest_sha256": sha256_file(source_root / "manifest.json"),
                "source_cases_sha256": source_digest,
                "gate_results_sha256": sha256_file(
                    qualification_root / "qualification-results.jsonl"
                ),
            },
        )

    _publish_atomically(request.out_dir, write)
    return QualificationCampaign(campaign_id, request.out_dir.resolve(), tuple(cases), tuple(ledger))

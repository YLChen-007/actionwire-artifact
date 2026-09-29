"""Unified source-revised native-tool L2 campaign for four excluded reports."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .contracts import (
    ValidationError,
    atomic_write_json,
    atomic_write_text,
    contains_credentials,
    sha256_file,
)
from .nanobot_login_shell_l2 import (
    NanobotLoginShellL2RunRequest,
    run_nanobot_login_shell_l2,
)
from .openclaw_source_revised_l2 import (
    OpenClawSourceRevisedL2RunRequest,
    run_openclaw_source_revised_l2,
)
from .chatgpt_on_wechat_file_native_l2 import (
    ChatGPTOnWeChatFileNativeL2RunRequest,
    run_chatgpt_on_wechat_file_native_l2,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
CAMPAIGN_ID = "runtime-dynamic-trigger-source-revised-native-l2-v1"
EVIDENCE_SCOPE = "source-revised-native-tool"
EVIDENCE_TIER = "L2-forced-provider-E2E-source-revised"
RESULT_SCHEMA_VERSION = (
    "clawgap-dynamic-trigger-source-revised-native-l2-result/v1"
)

PROJECT_REPORTS = {
    "nanobot": {"GT-0d6ed4cec085773c"},
    "openclaw": {
        "GT-c6a9e97a28acf193",
        "GT-f1647abba5c44969",
    },
    "chatgpt-on-wechat": {"GT-e03e7f2d88091689"},
}
EXPECTED_REPORTS = set().union(*PROJECT_REPORTS.values())


@dataclass(frozen=True)
class SourceRevisedNativeL2RunRequest:
    out_dir: Path
    attempts: int = 3
    timeout: int = 180
    build_timeout: int = 1800
    build_dir: Path | None = None
    all_reports: bool = False
    project: str | None = None
    report_id: str | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
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


def _write_jsonl(path: Path, rows: list[Mapping[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _selected_projects(request: SourceRevisedNativeL2RunRequest) -> list[str]:
    if request.all_reports:
        if request.project is not None or request.report_id is not None:
            raise ValidationError("--all cannot be combined with --project or --report-id")
        return list(PROJECT_REPORTS)
    if request.project is not None:
        if request.project not in PROJECT_REPORTS:
            raise ValidationError("unsupported source-revised native project")
        if request.report_id is not None:
            if request.report_id not in PROJECT_REPORTS[request.project]:
                raise ValidationError("report is not bound to the selected project")
        return [request.project]
    if request.report_id is None:
        raise ValidationError("select --all, --project, or --report-id")
    return [
        project
        for project, reports in PROJECT_REPORTS.items()
        if request.report_id in reports
    ]


def _artifact_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): sha256_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "manifest.json"
    }


def _credential_scan(root: Path) -> str:
    text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix in {".json", ".jsonl", ".md", ".txt", ".log"}
    )
    return "failed" if contains_credentials(text) else "passed"


def _run_project(
    project: str,
    request: SourceRevisedNativeL2RunRequest,
) -> dict[str, Any]:
    out_dir = request.out_dir / project
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    build_dir = (
        request.build_dir / f"{project}-build"
        if request.build_dir is not None
        else out_dir / "build"
    )
    if project == "nanobot":
        return run_nanobot_login_shell_l2(
            NanobotLoginShellL2RunRequest(
                out_dir=out_dir,
                attempts=request.attempts,
                timeout=min(request.timeout, 150),
                build_timeout=min(request.build_timeout, 1200),
                build_dir=build_dir,
            )
        )
    if project == "openclaw":
        return run_openclaw_source_revised_l2(
            OpenClawSourceRevisedL2RunRequest(
                out_dir=out_dir,
                attempts=request.attempts,
                timeout=min(request.timeout, 150),
                build_timeout=request.build_timeout,
                build_dir=build_dir,
                report_id=request.report_id
                if request.project is not None
                else None,
            )
        )
    return run_chatgpt_on_wechat_file_native_l2(
        ChatGPTOnWeChatFileNativeL2RunRequest(
            out_dir=out_dir,
            attempts=request.attempts,
            timeout=request.timeout,
            build_timeout=request.build_timeout,
            build_dir=build_dir,
        )
    )


def run_source_revised_native_l2(
    request: SourceRevisedNativeL2RunRequest,
) -> dict[str, Any]:
    started = datetime.now(timezone.utc).timestamp()
    if request.attempts < 1 or request.timeout < 5 or request.build_timeout < 5:
        raise ValidationError("source-revised native L2 parameters must be positive")
    request.out_dir.resolve().mkdir(parents=True, exist_ok=True)
    projects = _selected_projects(request)

    manifests: dict[str, Any] = {}
    for project in projects:
        manifests[project] = _run_project(project, request)

    results: list[dict[str, Any]] = []
    for project in projects:
        results.extend(
            _read_jsonl(request.out_dir / project / "report-results.jsonl")
        )
    selected_ids = (
        EXPECTED_REPORTS
        if request.all_reports
        else {
            report_id
            for report_id in EXPECTED_REPORTS
            if request.report_id is None
            or report_id == request.report_id
        }
        if request.project is None
        else {
            report_id
            for report_id in PROJECT_REPORTS[request.project]
            if request.report_id is None or report_id == request.report_id
        }
    )
    actual_ids = {str(row.get("report_id")) for row in results}
    if actual_ids != selected_ids:
        raise ValidationError(
            f"source-revised report selection drift: expected {sorted(selected_ids)}, "
            f"got {sorted(actual_ids)}"
        )
    if any(row.get("evidence_scope") != EVIDENCE_SCOPE for row in results):
        raise ValidationError("source-revised evidence-scope drift")
    if any(row.get("canonical_accounting_affected") is not False for row in results):
        raise ValidationError("source-revised canonical-accounting drift")

    for row in results:
        row["schema_version"] = RESULT_SCHEMA_VERSION
        row["campaign_id"] = CAMPAIGN_ID
        row["evidence_tier"] = EVIDENCE_TIER
        row["native_interface"] = {
            "GT-0d6ed4cec085773c": "exec",
            "GT-c6a9e97a28acf193": "browser(action=act)",
            "GT-f1647abba5c44969": "message(action=send)",
            "GT-e03e7f2d88091689": "browser(action=navigate)",
        }[str(row["report_id"])]
    _write_jsonl(request.out_dir / "report-results.jsonl", results)
    _write_jsonl(request.out_dir / "candidate-results.jsonl", results)
    _write_jsonl(
        request.out_dir / "qualification.jsonl",
        [
            {
                "report_id": row["report_id"],
                "project": row["project"],
                "candidate_id": row.get("candidate_id")
                or row.get("additive_candidate_id"),
                "status": row["disposition"],
                "evidence_scope": EVIDENCE_SCOPE,
                "evidence_tier": EVIDENCE_TIER,
            }
            for row in results
        ],
    )

    counts: dict[str, int] = {}
    for row in results:
        counts[str(row["disposition"])] = counts.get(str(row["disposition"]), 0) + 1
    expected_traces = request.attempts * 2 * len(results)
    valid_traces = sum(
        int(row.get("trace_accounting", {}).get("valid", 0)) for row in results
    )
    credential_scan = _credential_scan(request.out_dir.resolve())
    summary = (
        "# Source-Revised Native Runtime Validation\n\n"
        f"Campaign: `{CAMPAIGN_ID}`\n\n"
        f"Reports accounted for: **{len(results)}**.\n\n"
        f"Runtime-confirmed: **{counts.get('runtime-confirmed', 0)}**.\n\n"
        f"Trace accounting: **{valid_traces}/{expected_traces} valid**.\n\n"
        "All provider calls use project-native tool interfaces: `exec`, `browser`, "
        "or `message`. This campaign is outside the frozen v3 canonical accounting "
        "and does not alter the canonical 81-candidate denominator, 43-report "
        "boundary, or `41/43` result.\n"
    )
    atomic_write_text(request.out_dir / "summary.md", summary)
    manifest = {
        "schema_version": (
            "clawgap-dynamic-trigger-source-revised-native-l2-manifest/v1"
        ),
        "campaign_id": CAMPAIGN_ID,
        "report_count": len(results),
        "attempt_pairs_per_report": request.attempts,
        "status_counts": counts,
        "evidence_scope": EVIDENCE_SCOPE,
        "evidence_tier": EVIDENCE_TIER,
        "canonical_accounting_affected": False,
        "selected_projects": projects,
        "project_manifests": manifests,
        "credential_scan": credential_scan,
        "trace_accounting": {
            "expected": expected_traces,
            "valid": valid_traces,
            "blocked": sum(
                int(row.get("trace_accounting", {}).get("blocked", 0))
                for row in results
            ),
            "not_launched": sum(
                int(row.get("trace_accounting", {}).get("not_launched", 0))
                for row in results
            ),
        },
        "artifact_sha256": _artifact_hashes(request.out_dir.resolve()),
        "reproduction_command": (
            "python -m src.runtime_validation "
            "run-dynamic-trigger-source-revised-native-l2 "
            f"--out-dir {request.out_dir} --attempts {request.attempts}"
        ),
        "started_at": datetime.fromtimestamp(started, timezone.utc).isoformat(),
        "completed_at": _utc_now(),
    }
    atomic_write_json(request.out_dir.resolve() / "manifest.json", manifest)
    return manifest

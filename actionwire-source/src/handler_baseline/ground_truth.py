"""Post-freeze strict ground-truth audit for blind handler findings."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.pipeline.provider import OpenAICompatibleRunner
from src.projects import ProjectSpec

from .contracts import (
    ALL_FINDINGS_POLICY,
    BaselineError,
    GROUND_TRUTH_MANIFEST_VERSION,
    GROUND_TRUTH_SCHEMA_VERSION,
    MOST_CREDIBLE_VULNERABILITIES_POLICY,
    aggregate_calls,
    canonical_json,
    contains_credentials,
    digest,
    normalize_token_usage,
    redact_credentials,
    sha256_file,
)
from .pipeline import _atomic_json, _atomic_text
from .prompts import MATCH_SYSTEM, build_match_user
from .render import render_ground_truth_report


REPORT_SUFFIX_RE = re.compile(r"(?:[-_]?issue[-_]?report(?:[-_]?fixed)?)$", re.I)
MATCH_FACETS = (
    "source_revision_compatible",
    "exact_handler_root",
    "same_controlled_input",
    "same_handler_rooted_path",
    "same_sink_capability_argument_effect",
    "same_security_requirement",
    "same_gate_defect",
    "compatible_failure_mode",
    "same_trigger_mechanism",
)


@dataclass(frozen=True)
class CuratedReport:
    report_id: str
    project: str
    report_name: str
    source_files: tuple[str, ...]
    source_sha256: tuple[str, ...]
    handlers: tuple[str, ...]
    invariant: dict[str, Any]


def _normalize_name(value: str) -> str:
    stem = Path(value).stem
    return REPORT_SUFFIX_RE.sub("", stem).strip("-_").casefold()


def _ground_truth_root(spec: ProjectSpec) -> Path | None:
    preferred = spec.design_root / "groundtruth/new-vuls"
    if preferred.is_dir():
        return preferred
    direct = spec.design_root / "groundtruth"
    return direct if direct.is_dir() else None


def _repo_path(path: Path) -> str:
    repo_root = Path(__file__).resolve().parents[2]
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        # The design entries are symlinks outside the repository. Preserve the logical path.
        for project in repo_root.glob("design/*"):
            ground = project / "groundtruth"
            try:
                relative = path.resolve().relative_to(ground.resolve())
            except (OSError, ValueError):
                continue
            return str(ground.relative_to(repo_root) / relative)
        return str(path)


def _json_invariant(raw: Mapping[str, Any]) -> tuple[tuple[str, ...], dict[str, Any]]:
    handlers = tuple(
        sorted(
            {
                str(row.get("name")).strip()
                for row in raw.get("d5_tool_handler_entry", [])
                if isinstance(row, dict) and str(row.get("name", "")).strip()
            }
        )
    )
    invariant = {
        "report_name": raw.get("report_name"),
        "verdict_reason": raw.get("verdict_reason"),
        "gate_type": raw.get("d5_gate_type"),
        "failure_mode": raw.get("d5_failure_mode"),
        "parameter_extraction": raw.get("d5_param_extraction"),
        "missing_check": raw.get("d5_gate_missing_check"),
        "defect_locations": raw.get("d5_defect_location"),
        "handler_entries": raw.get("d5_tool_handler_entry"),
        "gate_points": [
            {
                "name": row.get("name"),
                "location": row.get("location"),
                "policy": row.get("policy"),
                "is_defect_site": row.get("is_defect_site"),
            }
            for row in raw.get("d5_gate_points", [])
            if isinstance(row, dict)
        ],
        "sink_points": [
            {
                "name": row.get("name"),
                "location": row.get("location"),
                "problematic_parameter": row.get("problematic_parameter"),
            }
            for row in raw.get("d5_sink_points", [])
            if isinstance(row, dict)
        ],
        "justification": raw.get("d5_gate_structure_justification"),
    }
    return handlers, invariant


def _markdown_invariant(path: Path, tool_names: Sequence[str]) -> tuple[tuple[str, ...], dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    handlers = tuple(
        sorted(
            name
            for name in tool_names
            if re.search(
                rf"`{re.escape(name)}`\s+(?:tool|handler)|"
                rf"(?<![A-Za-z0-9_]){re.escape(name)}\s+(?:tool|handler)",
                text,
                re.I,
            )
        )
    )
    title_match = re.search(r"\*\*Title\*\*:\s*(.+)", text)
    summary_match = re.search(
        r"### Summary\s*(.+?)(?=\n### |\Z)", text, re.S | re.I
    )
    details_match = re.search(
        r"### Details\s*(.+?)(?=\n### |\Z)", text, re.S | re.I
    )
    return handlers, {
        "title": title_match.group(1).strip() if title_match else path.stem,
        "summary": (summary_match.group(1).strip() if summary_match else "")[:12000],
        "details": (details_match.group(1).strip() if details_match else "")[:24000],
        "handler_names_in_report": list(handlers),
    }


def discover_reports(specs: Sequence[ProjectSpec]) -> list[CuratedReport]:
    reports: list[CuratedReport] = []
    for spec in sorted((row.resolved() for row in specs), key=lambda row: row.project_id):
        root = _ground_truth_root(spec)
        if root is None:
            continue
        inventory = spec.design_root / "handler-entry/debug/tool-handler-entries.csv"
        tool_names: list[str] = []
        if inventory.is_file():
            import csv

            with inventory.open(newline="", encoding="utf-8-sig") as handle:
                tool_names = [row["tool_name"] for row in csv.DictReader(handle)]
        json_by_key: dict[str, tuple[Path, dict[str, Any]]] = {}
        for path in sorted(root.glob("*.json")):
            if not path.is_file():
                continue
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise BaselineError(f"invalid ground-truth JSON {path}: {exc}") from exc
            if not isinstance(raw, dict):
                raise BaselineError(f"ground-truth JSON is not an object: {path}")
            report_name = raw.get("report_name")
            if not isinstance(report_name, str) or not report_name.strip():
                report_name = path.stem
            key = _normalize_name(path.name)
            handlers, invariant = _json_invariant(raw)
            rel = _repo_path(path)
            reports.append(
                CuratedReport(
                    report_id="GT-" + digest([spec.project_id, report_name])[:16],
                    project=spec.project_id,
                    report_name=report_name,
                    source_files=(rel,),
                    source_sha256=(sha256_file(path),),
                    handlers=handlers,
                    invariant=invariant,
                )
            )
            json_by_key[key] = (path, raw)
            json_by_key[_normalize_name(report_name)] = (path, raw)
        for path in sorted(root.glob("*.md")):
            if not path.is_file() or _normalize_name(path.name) in json_by_key:
                continue
            handlers, invariant = _markdown_invariant(path, tool_names)
            report_name = path.stem
            rel = _repo_path(path)
            reports.append(
                CuratedReport(
                    report_id="GT-" + digest([spec.project_id, report_name])[:16],
                    project=spec.project_id,
                    report_name=report_name,
                    source_files=(rel,),
                    source_sha256=(sha256_file(path),),
                    handlers=handlers,
                    invariant=invariant,
                )
            )
    identities = {(row.project, _normalize_name(row.report_name)) for row in reports}
    if len(identities) != len(reports):
        raise BaselineError("ground-truth discovery contains duplicate report identities")
    return sorted(reports, key=lambda row: (row.project, row.report_name))


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise BaselineError(f"missing required artifact: {path}")
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise BaselineError(f"invalid JSONL {path}:{number}: {exc}") from exc
        if not isinstance(value, dict):
            raise BaselineError(f"invalid JSONL object {path}:{number}")
        rows.append(value)
    return rows


def _verify_freeze(out_dir: Path) -> dict[str, Any]:
    freeze_path = out_dir / "blind-freeze.json"
    if not freeze_path.is_file():
        raise BaselineError("ground-truth audit requires a complete blind-freeze.json")
    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    candidate_artifact = freeze.get("candidate_artifact", "findings.jsonl")
    if candidate_artifact not in {"findings.jsonl", "vulnerabilities.jsonl"}:
        raise BaselineError("blind freeze contains an invalid candidate artifact")
    candidate_hash = (
        "vulnerabilities_sha256"
        if candidate_artifact == "vulnerabilities.jsonl"
        else "findings_sha256"
    )
    checks = {
        "inventory_sha256": out_dir / "inventory.jsonl",
        "trials_sha256": out_dir / "trials.jsonl",
        candidate_hash: out_dir / candidate_artifact,
        "manifest_sha256": out_dir / "manifest.json",
    }
    for field, path in checks.items():
        if freeze.get(field) != sha256_file(path):
            raise BaselineError(f"blind artifact changed after freeze: {path}")
    scope_hash = freeze.get("ground_truth_handler_scope_sha256")
    if scope_hash is not None:
        scope_path = out_dir / "ground-truth-handler-scope.json"
        if scope_hash != sha256_file(scope_path):
            raise BaselineError(f"blind artifact changed after freeze: {scope_path}")
    return freeze


def _validate_match(value: Mapping[str, Any], report_id: str, finding_id: str) -> dict[str, Any]:
    expected = {"report_id", "finding_id", "verdict", "facets", "reason"}
    if set(value) != expected or value.get("report_id") != report_id or value.get("finding_id") != finding_id:
        raise BaselineError("ground-truth match identity or fields mismatch")
    facets = value.get("facets")
    if not isinstance(facets, dict) or set(facets) != set(MATCH_FACETS):
        raise BaselineError("ground-truth match facets mismatch")
    if any(not isinstance(facets[name], bool) for name in MATCH_FACETS):
        raise BaselineError("ground-truth match facets must be booleans")
    flag = all(facets[name] for name in MATCH_FACETS)
    verdict = value.get("verdict")
    if verdict not in {"match", "no-match"} or (verdict == "match") != flag:
        raise BaselineError("ground-truth match verdict invariant failed")
    reason = value.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise BaselineError("ground-truth match reason is empty")
    return {
        "report_id": report_id,
        "finding_id": finding_id,
        "verdict": verdict,
        "facets": {name: facets[name] for name in MATCH_FACETS},
        "reason": " ".join(reason.split()),
    }


def _parse_json_response(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[-1].strip() == "```":
            text = "\n".join(lines[1:-1])
            if text.lstrip().startswith("json"):
                text = text.lstrip()[4:].lstrip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"ground-truth response is not JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise BaselineError("ground-truth response root must be an object")
    return value


def _manual_reviews(path: Path) -> dict[tuple[str, str], dict[str, Any]]:
    if not path.is_file():
        return {}
    reviews: dict[tuple[str, str], dict[str, Any]] = {}
    for row in _load_jsonl(path):
        if set(row) != {"report_id", "finding_id", "verdict", "facets", "reason"}:
            raise BaselineError("manual-review row has unexpected fields")
        if row["verdict"] not in {"confirm", "reject"}:
            raise BaselineError("manual-review verdict must be confirm or reject")
        if (
            not isinstance(row["reason"], str)
            or not row["reason"].strip()
            or "REPLACE" in row["reason"]
        ):
            raise BaselineError("manual-review reason must contain completed source-backed review")
        facets = row.get("facets")
        if not isinstance(facets, dict) or set(facets) != set(MATCH_FACETS):
            raise BaselineError("manual-review facets mismatch")
        for name in MATCH_FACETS:
            facet = facets[name]
            if not isinstance(facet, dict) or set(facet) != {"verified", "evidence"}:
                raise BaselineError(f"manual-review facet {name} has unexpected fields")
            if not isinstance(facet["verified"], bool):
                raise BaselineError(f"manual-review facet {name}.verified must be boolean")
            if (
                not isinstance(facet["evidence"], str)
                or not facet["evidence"].strip()
                or "REPLACE" in facet["evidence"]
            ):
                raise BaselineError(
                    f"manual-review facet {name} needs completed source-backed evidence"
                )
        all_verified = all(facets[name]["verified"] for name in MATCH_FACETS)
        if (row["verdict"] == "confirm") != all_verified:
            raise BaselineError("manual-review verdict must agree with all facet verdicts")
        key = (row["report_id"], row["finding_id"])
        if key in reviews:
            raise BaselineError("duplicate manual-review identity")
        reviews[key] = row
    return reviews


def _vulnerability_validity_reviews(
    path: Path, *, expected_ids: set[str]
) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    reviews: dict[str, dict[str, Any]] = {}
    expected = {
        "schema_version",
        "vulnerability_id",
        "disposition",
        "duplicate_of",
        "recurs_prior_false_positive_ids",
        "reason",
        "source_anchors",
    }
    for row in _load_jsonl(path):
        if set(row) != expected:
            raise BaselineError("vulnerability validity-review row has unexpected fields")
        vulnerability_id = row.get("vulnerability_id")
        if vulnerability_id not in expected_ids:
            raise BaselineError("vulnerability validity review references an unknown identity")
        if vulnerability_id in reviews:
            raise BaselineError("duplicate vulnerability validity-review identity")
        disposition = row.get("disposition")
        if disposition not in {"tp", "fp", "duplicate", "unknown"}:
            raise BaselineError("invalid vulnerability validity disposition")
        duplicate_of = row.get("duplicate_of")
        if disposition == "duplicate":
            if duplicate_of not in expected_ids or duplicate_of == vulnerability_id:
                raise BaselineError("duplicate validity review needs another vulnerability_id")
        elif duplicate_of is not None:
            raise BaselineError("only duplicate validity reviews may set duplicate_of")
        reason = row.get("reason")
        if not isinstance(reason, str) or not reason.strip() or "REPLACE" in reason:
            raise BaselineError("vulnerability validity review needs a completed reason")
        anchors = row.get("source_anchors")
        if (
            not isinstance(anchors, list)
            or not anchors
            or any(not isinstance(anchor, str) or not anchor.strip() for anchor in anchors)
        ):
            raise BaselineError("vulnerability validity review needs source anchors")
        recurrence = row.get("recurs_prior_false_positive_ids")
        if not isinstance(recurrence, list) or any(
            not isinstance(item, str) or not item.strip() for item in recurrence
        ):
            raise BaselineError("invalid prior false-positive recurrence list")
        reviews[vulnerability_id] = row
    return reviews


def _legacy_baseline_comparison(out_dir: Path) -> dict[str, Any] | None:
    legacy = out_dir.parent / "claude-handler-baseline-ground-truth-handlers"
    manifest_path = legacy / "manifest.json"
    adjudication_path = legacy / "manual-finding-adjudication.jsonl"
    if not manifest_path.is_file() or not adjudication_path.is_file():
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        reviews = _load_jsonl(adjudication_path)
    except (OSError, json.JSONDecodeError, BaselineError):
        return None
    dispositions = {
        disposition: sum(row.get("disposition") == disposition for row in reviews)
        for disposition in ("tp", "fp", "duplicate")
    }
    denominator = dispositions["tp"] + dispositions["fp"]
    return {
        "source_directory": str(legacy),
        "raw_findings": manifest.get("counts", {}).get("findings"),
        "dispositions": dispositions,
        "conditioned_validity_rate": (
            dispositions["tp"] / denominator if denominator else None
        ),
    }


def _match_cache_path(
    out_dir: Path, report_id: str, finding_id: str, config_digest: str
) -> Path:
    return (
        out_dir
        / "repository/ground-truth"
        / report_id
        / finding_id
        / f"{config_digest}.json"
    )


def _match_config_digest(
    *,
    freeze: Mapping[str, Any],
    report: CuratedReport,
    finding: Mapping[str, Any],
    model: str,
    base_url: str,
    timeout: int,
    max_output_tokens: int,
    user_prompt: str,
) -> str:
    return digest(
        {
            "freeze": freeze,
            "report_id": report.report_id,
            "report_source_sha256": report.source_sha256,
            "finding": finding,
            "model": model,
            "base_url": base_url,
            "timeout": timeout,
            "max_output_tokens": max_output_tokens,
            "system_prompt": MATCH_SYSTEM,
            "user_prompt": user_prompt,
        }
    )


def _ground_truth_call_record(call: Mapping[str, Any] | None) -> dict[str, Any]:
    raw_usage = call.get("usage") if isinstance(call, Mapping) else None
    usage = normalize_token_usage(raw_usage)
    return {
        "phase": "ground-truth-adjudication",
        "provider_reported": bool(usage["provider_reported"]),
        "usage": usage,
        "error": call.get("error") if isinstance(call, Mapping) else "no call record",
    }


def _frozen_report_trial_bindings(
    out_dir: Path, freeze: Mapping[str, Any]
) -> dict[str, set[str]] | None:
    """Load exact report/trial candidates for a conditioned handler run."""

    if freeze.get("ground_truth_handler_scope_sha256") is None:
        return None
    path = out_dir / "ground-truth-handler-scope.json"
    try:
        scope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"invalid frozen ground-truth handler scope: {path}") from exc
    raw = scope.get("report_trial_bindings") if isinstance(scope, dict) else None
    if not isinstance(raw, dict):
        raise BaselineError("frozen ground-truth handler scope lacks report_trial_bindings")
    output: dict[str, set[str]] = {}
    for report_id, trial_ids in raw.items():
        if (
            not isinstance(report_id, str)
            or not isinstance(trial_ids, list)
            or any(not isinstance(trial_id, str) for trial_id in trial_ids)
        ):
            raise BaselineError("invalid report/trial binding in frozen scope")
        output[report_id] = set(trial_ids)
    return output


def _maximum_unique_matches(edges: Mapping[str, Sequence[str]]) -> dict[str, str]:
    """Deterministically assign at most one report per finding and vice versa."""

    finding_to_report: dict[str, str] = {}

    def assign(report_id: str, seen: set[str]) -> bool:
        for finding_id in sorted(set(edges.get(report_id, []))):
            if finding_id in seen:
                continue
            seen.add(finding_id)
            prior = finding_to_report.get(finding_id)
            if prior is None or assign(prior, seen):
                finding_to_report[finding_id] = report_id
                return True
        return False

    for report_id in sorted(edges):
        assign(report_id, set())
    return {report_id: finding_id for finding_id, report_id in finding_to_report.items()}


def _maximum_report_capacity(
    bindings: Mapping[str, set[str]], *, per_trial_capacity: int
) -> int:
    """Maximum report coverage when each handler trial may emit a bounded number."""

    slot_to_report: dict[tuple[str, int], str] = {}

    def assign(report_id: str, seen: set[tuple[str, int]]) -> bool:
        for trial_id in sorted(bindings.get(report_id, set())):
            for slot_number in range(per_trial_capacity):
                slot = (trial_id, slot_number)
                if slot in seen:
                    continue
                seen.add(slot)
                prior = slot_to_report.get(slot)
                if prior is None or assign(prior, seen):
                    slot_to_report[slot] = report_id
                    return True
        return False

    return sum(assign(report_id, set()) for report_id in sorted(bindings))


def run_ground_truth_audit(
    *,
    specs: Sequence[ProjectSpec],
    out_dir: Path,
    generation_command: str,
    model: str,
    base_url: str,
    timeout: int,
    max_output_tokens: int = 4096,
) -> dict[str, Any]:
    freeze = _verify_freeze(out_dir)
    manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    report_policy = manifest.get("configuration", {}).get(
        "report_policy", ALL_FINDINGS_POLICY
    )
    vulnerability_policy = report_policy == MOST_CREDIBLE_VULNERABILITIES_POLICY
    candidate_artifact = (
        "vulnerabilities.jsonl" if vulnerability_policy else "findings.jsonl"
    )
    findings = _load_jsonl(out_dir / candidate_artifact)
    if vulnerability_policy:
        findings = [
            {**row, "finding_id": row["vulnerability_id"]}
            for row in findings
        ]
    validity_review_path = out_dir / "vulnerability-manual-reviews.jsonl"
    validity_reviews = (
        _vulnerability_validity_reviews(
            validity_review_path,
            expected_ids={finding["vulnerability_id"] for finding in findings},
        )
        if vulnerability_policy
        else {}
    )
    reports = discover_reports(specs)
    frozen_bindings = _frozen_report_trial_bindings(out_dir, freeze)
    by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        by_project[finding["project"]].append(finding)
    manual_path = out_dir / "ground-truth-manual-reviews.jsonl"
    manual = _manual_reviews(manual_path)
    runner = OpenAICompatibleRunner(
        base_url=base_url.removesuffix("/anthropic") + "/v1"
        if base_url.endswith("/anthropic")
        else base_url,
        model=model,
        timeout=timeout,
        max_tokens=max_output_tokens,
    )
    rows: list[dict[str, Any]] = []
    pending_template: list[dict[str, Any]] = []
    call_records: list[dict[str, Any]] = []
    for report in reports:
        candidates = by_project.get(report.project, [])
        if frozen_bindings is not None:
            allowed_trials = frozen_bindings.get(report.report_id, set())
            candidates = [
                finding for finding in candidates if finding.get("trial_id") in allowed_trials
            ]
        elif report.handlers:
            names = {name.casefold() for name in report.handlers}
            candidates = [
                finding
                for finding in candidates
                if str(finding.get("handler", {}).get("tool_name", "")).casefold() in names
            ]
        assessments: list[dict[str, Any]] = []
        for finding in sorted(candidates, key=lambda row: row["finding_id"]):
            user = build_match_user(
                report_id=report.report_id,
                project=report.project,
                report=report.invariant,
                finding=finding,
            )
            match_config = _match_config_digest(
                freeze=freeze,
                report=report,
                finding=finding,
                model=model,
                base_url=base_url,
                timeout=timeout,
                max_output_tokens=max_output_tokens,
                user_prompt=user,
            )
            cache_path = _match_cache_path(
                out_dir, report.report_id, finding["finding_id"], match_config
            )
            cached = None
            if cache_path.is_file():
                try:
                    candidate = json.loads(cache_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    candidate = None
                if (
                    isinstance(candidate, dict)
                    and candidate.get("config_digest") == match_config
                    and isinstance(candidate.get("assessment"), dict)
                    and isinstance(candidate.get("call"), dict)
                ):
                    cached = candidate
            if cached is not None:
                assessment = cached["assessment"]
                call_record = cached["call"]
            else:
                before = len(runner.chat_payload()["calls"])
                raw = ""
                try:
                    raw = runner(MATCH_SYSTEM, user)
                    assessment = _validate_match(
                        _parse_json_response(raw), report.report_id, finding["finding_id"]
                    )
                except Exception as exc:
                    assessment = {
                        "report_id": report.report_id,
                        "finding_id": finding["finding_id"],
                        "verdict": "error",
                        "facets": {name: False for name in MATCH_FACETS},
                        "reason": f"{type(exc).__name__}: {exc}",
                    }
                calls = runner.chat_payload()["calls"]
                call = calls[-1] if len(calls) > before else None
                call_record = _ground_truth_call_record(call)
                cache = {
                    "schema_version": "claude-handler-baseline-ground-truth-call/v1",
                    "config_digest": match_config,
                    "report_id": report.report_id,
                    "finding_id": finding["finding_id"],
                    "assessment": assessment,
                    "call": call_record,
                    "raw_response": redact_credentials(raw),
                }
                if contains_credentials(canonical_json(cache)):
                    raise BaselineError("credential-shaped data in ground-truth call artifact")
                _atomic_json(cache_path, cache)
            call_records.append(call_record)
            assessments.append(assessment)
            if assessment["verdict"] == "match":
                key = (report.report_id, finding["finding_id"])
                if key not in manual:
                    pending_template.append(
                        {
                            "report_id": report.report_id,
                            "finding_id": finding["finding_id"],
                            "verdict": "confirm",
                            "facets": {
                                name: {
                                    "verified": True,
                                    "evidence": "REPLACE with source-backed facet evidence",
                                }
                                for name in MATCH_FACETS
                            },
                            "reason": "REPLACE with independent source-backed manual verification",
                        }
                    )
        manually_confirmed = sorted(
            assessment["finding_id"]
            for assessment in assessments
            if assessment["verdict"] == "match"
            and manual.get((report.report_id, assessment["finding_id"]), {}).get("verdict") == "confirm"
        )
        model_matches = [row for row in assessments if row["verdict"] == "match"]
        pending_matches = [
            assessment
            for assessment in model_matches
            if (report.report_id, assessment["finding_id"]) not in manual
        ]
        if pending_matches:
            status = "pending-manual-review"
            reason = "model match exists but strict recall requires independent confirmation"
        elif manually_confirmed:
            status = "pending-cardinality-assignment"
            reason = "manual match awaits one-finding-to-one-report assignment"
        elif model_matches:
            status = "missed"
            reason = "all model-proposed matches were independently rejected"
        else:
            status = "missed"
            reason = "no same-invariant finding among the handler-scoped blind candidates"
        rows.append(
            {
                "schema_version": GROUND_TRUTH_SCHEMA_VERSION,
                "report_id": report.report_id,
                "project": report.project,
                "report_name": report.report_name,
                "source_files": list(report.source_files),
                "source_sha256": list(report.source_sha256),
                "handlers": list(report.handlers),
                "assessments": assessments,
                "manually_confirmed_finding_ids": manually_confirmed,
                "matched_finding_ids": [],
                "status": status,
                "reason": reason,
            }
        )
    unique_assignments = _maximum_unique_matches(
        {
            row["report_id"]: row["manually_confirmed_finding_ids"]
            for row in rows
            if row["manually_confirmed_finding_ids"]
        }
    )
    for row in rows:
        assigned = unique_assignments.get(row["report_id"])
        if assigned is not None:
            row["matched_finding_ids"] = [assigned]
            row["status"] = "matched"
            row["reason"] = (
                "facet-by-facet manual verification confirmed a unique report/finding match"
            )
        elif row["status"] == "pending-cardinality-assignment":
            row["status"] = "missed"
            row["reason"] = (
                "confirmed candidate was assigned to another report under one-finding-to-one-report cardinality"
            )
    token_usage = aggregate_calls(call_records)
    detection_usage = manifest["counts"]["observed_token_subtotal"]
    detection_tokens = detection_usage["total_tokens"]
    matched = sum(row["status"] == "matched" for row in rows)
    confirmed_findings = {
        finding_id for row in rows for finding_id in row["matched_finding_ids"]
    }
    combined_usage = aggregate_calls(
        [
            {"provider_reported": True, "usage": detection_usage},
            {"provider_reported": True, "usage": token_usage},
        ]
    )
    counts = {
        "reports": len(rows),
        "matched_reports": matched,
        "strict_missed_reports": len(rows) - matched,
        "missed_reports": sum(row["status"] == "missed" for row in rows),
        "pending_manual_reports": sum(row["status"] == "pending-manual-review" for row in rows),
        "candidate_pair_assessments": sum(len(row["assessments"]) for row in rows),
        "raw_findings": len(findings),
        "strictly_matched_findings": len(confirmed_findings),
        "unmatched_findings": len(findings) - len(confirmed_findings),
        "missing_usage_calls": sum(not call["provider_reported"] for call in call_records),
        "detection_tokens_per_matched_issue": detection_tokens / matched if matched else None,
        "adjudication_tokens_per_matched_issue": (
            int(token_usage["total_tokens"]) / matched if matched else None
        ),
        "combined_tokens_per_matched_issue": (
            int(combined_usage["total_tokens"]) / matched if matched else None
        ),
        "combined_observed_tokens": int(combined_usage["total_tokens"]),
    }
    if vulnerability_policy:
        coverage_ceiling = (
            _maximum_report_capacity(frozen_bindings, per_trial_capacity=2)
            if frozen_bindings is not None
            else min(len(rows), int(manifest["counts"]["trials"]) * 2)
        )
        validity_dispositions: dict[str, int] = {
            disposition: sum(
                review["disposition"] == disposition
                for review in validity_reviews.values()
            )
            for disposition in ("tp", "fp", "duplicate", "unknown")
        }
        validity_denominator = validity_dispositions["tp"] + validity_dispositions["fp"]
        recurring_prior_ids = sorted(
            {
                prior_id
                for review in validity_reviews.values()
                for prior_id in review["recurs_prior_false_positive_ids"]
            }
        )
        counts.update(
            {
                "raw_vulnerabilities": len(findings),
                "strictly_matched_vulnerabilities": len(confirmed_findings),
                "unmatched_vulnerabilities": len(findings) - len(confirmed_findings),
                "maximum_strict_report_coverage": coverage_ceiling,
                "maximum_strict_recall": coverage_ceiling / len(rows) if rows else None,
                "validity_reviewed_vulnerabilities": len(validity_reviews),
                "pending_vulnerability_validity_reviews": len(findings)
                - len(validity_reviews),
                "validity_dispositions": validity_dispositions,
                "conditioned_validity_rate": (
                    validity_dispositions["tp"] / validity_denominator
                    if validity_denominator
                    else None
                ),
                "recurring_prior_false_positive_ids": recurring_prior_ids,
            }
        )
    validity_template = (
        [
            {
                "schema_version": "claude-handler-baseline-vulnerability-manual-review/v1",
                "vulnerability_id": finding["vulnerability_id"],
                "disposition": "REPLACE with tp|fp|duplicate|unknown",
                "duplicate_of": None,
                "recurs_prior_false_positive_ids": [],
                "reason": "REPLACE with independent source-backed validity review",
                "source_anchors": [],
            }
            for finding in sorted(findings, key=lambda row: row["finding_id"])
            if finding["vulnerability_id"] not in validity_reviews
        ]
        if vulnerability_policy
        else []
    )
    legacy_comparison = _legacy_baseline_comparison(out_dir) if vulnerability_policy else None
    gt_manifest = {
        "schema_version": GROUND_TRUTH_MANIFEST_VERSION,
        "generation_command": generation_command,
        "blind_freeze": freeze,
        "ground_truth_inputs": {
            path: digest_value
            for report in reports
            for path, digest_value in zip(report.source_files, report.source_sha256)
        },
        "manual_review_input": sha256_file(manual_path) if manual_path.is_file() else None,
        "counts": counts,
        "blind_detection": {
            "status": manifest["counts"]["status"],
            "finding_modes": manifest["counts"].get(
                "vulnerability_modes", manifest["counts"].get("finding_modes", {})
            ),
            "wall_clock_seconds": manifest.get("execution", {}).get(
                "invocation_wall_clock_seconds"
            ),
            "missing_usage_trials": manifest["counts"]["token_statistics_per_handler"][
                "missing_usage_trials"
            ],
        },
        "detection_token_usage": detection_usage,
        "token_usage": token_usage,
        "combined_token_usage": combined_usage,
    }
    if vulnerability_policy:
        gt_manifest.update(
            {
                "report_policy": report_policy,
                "candidate_label": "vulnerability",
                "legacy_baseline_comparison": legacy_comparison,
                "vulnerability_validity_review_input": (
                    sha256_file(validity_review_path)
                    if validity_review_path.is_file()
                    else None
                ),
            }
        )
    report_md = render_ground_truth_report(
        generation_command=generation_command, rows=rows, manifest=gt_manifest
    )
    for value in (rows, gt_manifest, pending_template, validity_template):
        if contains_credentials(canonical_json(value)):
            raise BaselineError("credential-shaped data in ground-truth artifact")
    _atomic_text(
        out_dir / "ground-truth-coverage.jsonl",
        "".join(canonical_json(row) + "\n" for row in rows),
    )
    _atomic_json(out_dir / "ground-truth-manifest.json", gt_manifest)
    _atomic_text(out_dir / "ground-truth-results.md", report_md)
    _atomic_text(
        out_dir / "ground-truth-manual-review-template.jsonl",
        "".join(canonical_json(row) + "\n" for row in pending_template),
    )
    if vulnerability_policy:
        _atomic_text(
            out_dir / "vulnerability-manual-review-template.jsonl",
            "".join(canonical_json(row) + "\n" for row in validity_template),
        )
    return {
        "rows": rows,
        "manifest": gt_manifest,
        "report": report_md,
        "pending": pending_template,
        "validity_pending": validity_template,
    }

"""Paired native-replay campaign orchestration and complete candidate accounting."""

from __future__ import annotations

import json
import shutil
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Mapping

from src.projects import get_project

from .adapters import (
    AdapterSpec,
    CapabilitySandbox,
    get_adapter,
    prepare_temporary_sandbox,
)
from .campaign_contracts import (
    CAMPAIGN_RESULT_SCHEMA_VERSION,
    CANDIDATE_RESULT_SCHEMA_VERSION,
    INCONCLUSIVE,
    CampaignDefinition,
    CampaignRun,
    CampaignRunRequest,
    CaseRun,
    CaseValidationRequest,
    aggregate_case_attempts,
    canonical_json,
    stable_execution_id,
    validate_runtime_case,
)
from .contracts import (
    ValidationError,
    atomic_write_json,
    atomic_write_text,
    sha256_file,
)
from .pipeline import _artifact_hashes, _credential_scan


PairRunnerFactory = Callable[
    [Mapping[str, Any], AdapterSpec, int, Path, CapabilitySandbox], Mapping[str, Any]
]
EVIDENCE_CONTRACT = "ordered-correlated-stages/v7"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid campaign artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"campaign artifact must be an object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValidationError(f"cannot read campaign artifact {path}: {exc}") from exc
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"{path}:{number}: invalid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise ValidationError(f"{path}:{number}: expected object")
        rows.append(row)
    return rows


def _write_jsonl(path: Path, rows: list[Mapping[str, Any]]) -> None:
    atomic_write_text(path, "".join(canonical_json(row) + "\n" for row in rows))


def load_campaign_definition(root: Path) -> CampaignDefinition:
    directory = root.resolve()
    campaign = _read_json(directory / "campaign.json")
    cases = tuple(
        validate_runtime_case(row) for row in _read_jsonl(directory / "cases.jsonl")
    )
    execution_groups = tuple(_read_jsonl(directory / "execution-groups.jsonl"))
    case_ids = [row["case_id"] for row in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValidationError("campaign contains duplicate case IDs")
    candidate_ids = [item for row in cases for item in row["candidate_ids"]]
    expected = campaign.get("target", {}).get("candidate_ids", [])
    if len(candidate_ids) != len(set(candidate_ids)) or sorted(candidate_ids) != sorted(
        expected
    ):
        raise ValidationError(
            "campaign cases do not exactly partition target candidates"
        )
    group_case_ids = [item for row in execution_groups for item in row["case_ids"]]
    if sorted(group_case_ids) != sorted(case_ids):
        raise ValidationError(
            "execution groups do not exactly partition campaign cases"
        )
    for row in execution_groups:
        matching = [case for case in cases if case["case_id"] in row["case_ids"]]
        if not matching or any(
            stable_execution_id(case) != row["execution_id"] for case in matching
        ):
            raise ValidationError("execution group stable identity mismatch")
    return CampaignDefinition(
        campaign_id=campaign["campaign_id"],
        root=directory,
        cases=cases,
        execution_groups=execution_groups,
        target_candidate_ids=tuple(expected),
        manifest=campaign,
    )


def _verify_case_bindings(case: Mapping[str, Any], campaign_root: Path) -> None:
    spec = get_project(case["project"])
    if case["revision"] != spec.analysis_revision:
        raise ValidationError("case revision does not match project registry")
    bound_paths: set[str] = set()
    for binding in case["source_binding"]["files"]:
        relative = Path(binding["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValidationError("case source binding escapes project root")
        path = spec.source_root / relative
        if not path.is_file() or sha256_file(path) != binding["sha256"]:
            raise ValidationError(f"source binding drift: {case['project']}:{relative}")
        bound_paths.add(binding["path"])
    if case["schema_version"].endswith("/v3"):
        for observation in case["observations"]:
            relative = Path(observation["file"])
            if relative.is_absolute() or ".." in relative.parts:
                raise ValidationError("observation source anchor escapes project root")
            if observation["file"] not in bound_paths:
                raise ValidationError(
                    f"observation source is not hash-bound: {case['project']}:{relative}"
                )
            path = spec.source_root / relative
            if not path.is_file():
                raise ValidationError(
                    f"observation source is unavailable: {case['project']}:{relative}"
                )
            line = observation.get("line")
            if line is not None:
                line_count = len(
                    path.read_text(encoding="utf-8", errors="replace").splitlines()
                )
                if line > line_count:
                    raise ValidationError(
                        f"observation line is outside source: {case['project']}:{relative}:{line}"
                    )
    campaign = _read_json(campaign_root / "campaign.json")
    coverage_root = Path(campaign["coverage_root"])
    if not coverage_root.is_absolute():
        coverage_root = Path(__file__).resolve().parents[2] / coverage_root
    coverage_manifest = _read_json(coverage_root / "manifest.json")
    candidate_artifact = (
        "training-regression-candidates.jsonl"
        if coverage_manifest.get("analysis_mode") == "canonical-trained-detector/v15"
        else "candidates.jsonl"
    )
    names = {
        "coverage_manifest": "manifest.json",
        "ground_truth_manifest": "ground-truth-manifest.json",
        "candidates": candidate_artifact,
        "comparisons": "comparisons.jsonl",
        "ground_truth_coverage": "ground-truth-coverage.jsonl",
    }
    frozen_bindings: Mapping[str, Any] | None = None
    for field, name in names.items():
        path = coverage_root / name
        if path.is_file() and sha256_file(path) == case["artifact_binding"][field]:
            continue
        if frozen_bindings is None:
            frozen_cases = (
                Path(__file__).resolve().parents[2]
                / "output/cross-project/runtime-validation-covered-v2/cases.jsonl"
            )
            first = json.loads(frozen_cases.read_text(encoding="utf-8").splitlines()[0])
            frozen_bindings = first["artifact_binding"]
        if frozen_bindings.get(field) != case["artifact_binding"][field]:
            raise ValidationError(f"corrected-v2 artifact drift: {name}")


def _default_pair_runner(
    case: Mapping[str, Any],
    adapter: AdapterSpec,
    attempt: int,
    attempt_dir: Path,
    sandbox: CapabilitySandbox,
) -> Mapping[str, Any]:
    if adapter.driver is None:
        raise ValidationError("native dispatcher driver is unavailable")
    return adapter.driver(case, attempt, attempt_dir, sandbox)


def _normalize_pair(
    value: Mapping[str, Any], attempt: int, case: Mapping[str, Any]
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationError("paired replay driver must return an object")
    exploit = value.get("exploit")
    control = value.get("control")
    if not isinstance(exploit, Mapping) or not isinstance(control, Mapping):
        raise ValidationError(
            "paired replay result requires exploit and control objects"
        )
    normalized = {
        "attempt": attempt,
        "exploit": dict(exploit),
        "control": dict(control),
        "sandbox": dict(value.get("sandbox", {}))
        if isinstance(value.get("sandbox", {}), Mapping)
        else {},
    }
    if normalized["exploit"].get("verdict") == "triggered":
        required = [row["stage_id"] for row in case["observations"]]
        if normalized["exploit"].get("observed_stages") != required or not isinstance(
            normalized["exploit"].get("correlation_id"), str
        ):
            normalized["exploit"].update(
                {
                    "healthy": False,
                    "verdict": "inconclusive",
                    "reason": "driver did not prove the exact ordered correlated stage sequence",
                }
            )
    return normalized


def validate_case(
    request: CaseValidationRequest,
    *,
    runner_factory: PairRunnerFactory | None = None,
    adapter_override: AdapterSpec | None = None,
) -> CaseRun:
    case = validate_runtime_case(request.case)
    execution_id = stable_execution_id(case)
    adapter = adapter_override or get_adapter(case["adapter"])
    if case["generation"]["status"] != "ready":
        disposition, reason = aggregate_case_attempts(
            (), supported=False, reason=case["generation"]["reason"]
        )
        result = CaseRun(case["case_id"], execution_id, disposition, reason)
        request.out_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(
            request.out_dir / "result.json",
            {
                "schema_version": "clawgap-runtime-validation-case-result/v1",
                "case_id": result.case_id,
                "execution_id": result.execution_id,
                "disposition": result.disposition,
                "reason": result.reason,
                "attempts": [],
                "evidence_contract": EVIDENCE_CONTRACT,
            },
        )
        return result
    supported, support_reason = adapter.preflight(case)
    if not supported:
        disposition, reason = aggregate_case_attempts(
            (), supported=False, reason=support_reason
        )
        result = CaseRun(case["case_id"], execution_id, disposition, reason)
        request.out_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(
            request.out_dir / "result.json",
            {
                "schema_version": "clawgap-runtime-validation-case-result/v1",
                "case_id": result.case_id,
                "execution_id": result.execution_id,
                "disposition": result.disposition,
                "reason": result.reason,
                "attempts": [],
                "evidence_contract": EVIDENCE_CONTRACT,
            },
        )
        return result

    request.out_dir.mkdir(parents=True, exist_ok=True)
    attempts: list[dict[str, Any]] = []
    driver = runner_factory or _default_pair_runner
    for attempt in range(1, request.attempts + 1):
        attempt_dir = request.out_dir / f"attempt-{attempt:03d}"
        if attempt_dir.exists():
            shutil.rmtree(attempt_dir)
        attempt_dir.mkdir(parents=True, exist_ok=True)
        temporary, sandbox = prepare_temporary_sandbox(case)
        try:
            pair = _normalize_pair(
                driver(case, adapter, attempt, attempt_dir, sandbox), attempt, case
            )
            fixture = sandbox.root / "fixture-manifest.json"
            if fixture.is_file():
                shutil.copy2(fixture, attempt_dir / "fixture-manifest.json")
        except Exception as exc:
            pair = {
                "attempt": attempt,
                "exploit": {
                    "healthy": False,
                    "verdict": "inconclusive",
                    "reason": f"{type(exc).__name__}: {exc}",
                },
                "control": {
                    "healthy": False,
                    "unsafe_matched": False,
                    "reason": "paired replay did not complete",
                },
                "sandbox": {},
            }
        finally:
            temporary.cleanup()
        atomic_write_json(attempt_dir / "pair.json", pair)
        attempts.append(pair)
    disposition, reason = aggregate_case_attempts(
        attempts, supported=True, reason=support_reason
    )
    result = CaseRun(
        case_id=case["case_id"],
        execution_id=execution_id,
        disposition=disposition,
        reason=reason,
        attempts=tuple(attempts),
    )
    atomic_write_json(
        request.out_dir / "result.json",
        {
            "schema_version": "clawgap-runtime-validation-case-result/v1",
            "case_id": result.case_id,
            "execution_id": result.execution_id,
            "disposition": result.disposition,
            "reason": result.reason,
            "attempts": list(result.attempts),
            "evidence_contract": EVIDENCE_CONTRACT,
        },
    )
    return result


def _summary_markdown(
    campaign: CampaignDefinition,
    results: list[Mapping[str, Any]],
    generation_command: str,
    ground_truth: Mapping[str, Any] | None = None,
    delta: Mapping[str, Any] | None = None,
) -> str:
    counts = Counter(row["disposition"] for row in results)
    if campaign.manifest.get("analysis_mode", "").endswith("v3"):
        generated = _read_json(campaign.root / "generation-manifest.json")
        reproduction = (
            f"{generated['generation_command']} && "
            "python -m src.runtime_validation provision-drivers "
            f"--campaign {campaign.root} && {generation_command}"
        )
    else:
        reproduction = generation_command
    lines = [
        "# Corrected-v3 Runtime Validation Campaign"
        if campaign.manifest.get("analysis_mode", "").endswith("v3")
        else "# Corrected-v2 Runtime Validation Campaign",
        "",
        f"> Complete reproduction command: `{reproduction}`",
        "",
        "## Results",
        "",
        f"Target candidates: **{len(campaign.target_candidate_ids)}**; "
        f"runtime-confirmed: **{counts.get('runtime-confirmed', 0)}**; "
        f"not-reproduced: **{counts.get('not-reproduced', 0)}**; "
        f"inconclusive: **{counts.get('inconclusive', 0)}**; "
        f"unsupported: **{counts.get('unsupported', 0)}**.",
        "",
        "This is deterministic native tool replay. It does not measure whether a live LLM prompt selects the tool.",
        "The target set is post-hoc and ground-truth-informed and does not replace the blind 18/42 result.",
        "",
        "| Candidate | Project | Case | Disposition | Reason |",
        "|---|---|---|---|---|",
    ]
    if ground_truth:
        gt_counts = ground_truth.get("disposition_counts", {})
        lines[10:10] = [
            "## Ground-truth projection",
            "",
            f"Target reports: **{ground_truth.get('target_reports', 0)}**; "
            f"runtime-confirmed: **{gt_counts.get('runtime-confirmed', 0)}**; "
            f"not-reproduced: **{gt_counts.get('not-reproduced', 0)}**; "
            f"inconclusive: **{gt_counts.get('inconclusive', 0)}**; "
            f"unsupported: **{gt_counts.get('unsupported', 0)}**.",
            "",
        ]
    if delta:
        lines[10:10] = [
            "## v2 to v3 delta",
            "",
            f"Formerly unsupported candidates now conclusive: **{delta.get('candidates_now_conclusive', 0)}"
            f"/{delta.get('formerly_unsupported_candidates', 0)}**; formerly unsupported-only reports now "
            f"conclusive: **{delta.get('reports_now_conclusive', 0)}"
            f"/{delta.get('formerly_unsupported_reports', 0)}**.",
            "",
        ]
    case_by_id = {case["case_id"]: case for case in campaign.cases}
    for row in sorted(results, key=lambda item: item["candidate_id"]):
        case = case_by_id[row["case_id"]]
        reason = str(row["reason"]).replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| `{row['candidate_id']}` | `{case['project']}` | `{row['case_id']}` | "
            f"`{row['disposition']}` | {reason} |"
        )
    return "\n".join(lines) + "\n"


def _project_ground_truth(
    campaign: CampaignDefinition, results: list[Mapping[str, Any]]
) -> dict[str, Any]:
    result_by_candidate = {row["candidate_id"]: row for row in results}
    reports: dict[str, dict[str, Any]] = {}
    priority = {
        "runtime-confirmed": 4,
        "not-reproduced": 3,
        "inconclusive": 2,
        "unsupported": 1,
    }
    for case in campaign.cases:
        disposition = result_by_candidate[case["candidate_ids"][0]]["disposition"]
        for binding in case["report_bindings"]:
            report = reports.setdefault(
                binding["report_id"],
                {
                    "report_id": binding["report_id"],
                    "report_name": binding["report_name"],
                    "candidate_ids": set(),
                    "dispositions": set(),
                },
            )
            report["candidate_ids"].update(case["candidate_ids"])
            report["dispositions"].add(disposition)
    rows = []
    for report in reports.values():
        disposition = max(report["dispositions"], key=priority.__getitem__)
        rows.append(
            {
                "report_id": report["report_id"],
                "report_name": report["report_name"],
                "candidate_ids": sorted(report["candidate_ids"]),
                "candidate_dispositions": sorted(report["dispositions"]),
                "disposition": disposition,
            }
        )
    rows.sort(key=lambda row: row["report_id"])
    return {
        "schema_version": "clawgap-runtime-validation-ground-truth-projection/v1",
        "campaign_id": campaign.campaign_id,
        "target_reports": len(rows),
        "disposition_counts": dict(
            sorted(Counter(row["disposition"] for row in rows).items())
        ),
        "reports": rows,
    }


def _v2_delta(
    campaign: CampaignDefinition, results: list[Mapping[str, Any]]
) -> dict[str, Any] | None:
    source_info = campaign.manifest.get("source_campaign")
    if not isinstance(source_info, Mapping):
        return None
    source_root = Path(str(source_info["path"]))
    source_results = _read_jsonl(source_root / "candidate-results.jsonl")
    source_campaign = load_campaign_definition(source_root)
    unsupported_ids = {
        row["candidate_id"]
        for row in source_results
        if row["disposition"] == "unsupported"
    }
    source_by_candidate = {row["candidate_id"]: row for row in source_results}
    source_reports: dict[str, set[str]] = {}
    for case in source_campaign.cases:
        dispositions = {
            source_by_candidate[candidate]["disposition"]
            for candidate in case["candidate_ids"]
        }
        for binding in case["report_bindings"]:
            source_reports.setdefault(binding["report_id"], set()).update(dispositions)
    unsupported_reports = {
        report
        for report, dispositions in source_reports.items()
        if dispositions == {"unsupported"}
    }
    result_by_candidate = {row["candidate_id"]: row for row in results}
    projection = _project_ground_truth(campaign, results)
    projected = {row["report_id"]: row["disposition"] for row in projection["reports"]}
    conclusive = {"runtime-confirmed", "not-reproduced"}
    return {
        "schema_version": "clawgap-runtime-validation-v2-v3-delta/v1",
        "source_campaign_id": source_campaign.campaign_id,
        "campaign_id": campaign.campaign_id,
        "formerly_unsupported_candidates": len(unsupported_ids),
        "candidates_now_conclusive": sum(
            result_by_candidate[candidate]["disposition"] in conclusive
            for candidate in unsupported_ids
        ),
        "formerly_unsupported_reports": len(unsupported_reports),
        "reports_now_conclusive": sum(
            projected.get(report) in conclusive for report in unsupported_reports
        ),
        "candidate_ids": sorted(unsupported_ids),
        "report_ids": sorted(unsupported_reports),
    }


def run_campaign(
    request: CampaignRunRequest,
    *,
    runner_factory: PairRunnerFactory | None = None,
    adapter_overrides: Mapping[str, AdapterSpec] | None = None,
) -> CampaignRun:
    campaign = load_campaign_definition(request.campaign_dir)
    is_v3 = campaign.manifest.get("analysis_mode", "").endswith("v3")
    if is_v3:
        provisioning_path = campaign.root / "driver-provisioning.json"
        if (
            not provisioning_path.is_file()
            or _read_json(provisioning_path).get("ready") is not True
        ):
            raise ValidationError(
                "v3 canonical replay requires a successful provision-drivers preflight"
            )
    cases_by_id = {case["case_id"]: case for case in campaign.cases}
    case_runs: dict[str, CaseRun] = {}

    def run_group(group: Mapping[str, Any]) -> tuple[Mapping[str, Any], CaseRun]:
        representative = cases_by_id[group["case_ids"][0]]
        execution_id = group["execution_id"]
        run_dir = campaign.root / "runs" / execution_id
        prior_path = run_dir / "result.json"
        reuse_prior = prior_path.is_file()
        if reuse_prior:
            prior_probe = _read_json(prior_path)
            adapter = (adapter_overrides or {}).get(
                representative["adapter"], get_adapter(representative["adapter"])
            )
            supported_now, _ = adapter.preflight(representative)
            if prior_probe.get("evidence_contract") != EVIDENCE_CONTRACT:
                reuse_prior = not supported_now
            elif prior_probe.get("disposition") in {"unsupported", "inconclusive"}:
                reuse_prior = not supported_now
        if reuse_prior:
            prior = _read_json(prior_path)
            case_run = CaseRun(
                case_id=representative["case_id"],
                execution_id=execution_id,
                disposition=prior["disposition"],
                reason=prior["reason"],
                attempts=tuple(prior.get("attempts", [])),
            )
        else:
            try:
                for case_id in group["case_ids"]:
                    _verify_case_bindings(cases_by_id[case_id], campaign.root)
                override = (adapter_overrides or {}).get(representative["adapter"])
                case_run = validate_case(
                    CaseValidationRequest(representative, run_dir, request.attempts),
                    runner_factory=runner_factory,
                    adapter_override=override,
                )
            except Exception as exc:
                run_dir.mkdir(parents=True, exist_ok=True)
                case_run = CaseRun(
                    case_id=representative["case_id"],
                    execution_id=execution_id,
                    disposition=INCONCLUSIVE,
                    reason=f"{type(exc).__name__}: {exc}",
                )
                atomic_write_json(
                    run_dir / "result.json",
                    {
                        "schema_version": "clawgap-runtime-validation-case-result/v1",
                        "case_id": case_run.case_id,
                        "execution_id": case_run.execution_id,
                        "disposition": case_run.disposition,
                        "reason": case_run.reason,
                        "attempts": [],
                        "evidence_contract": EVIDENCE_CONTRACT,
                    },
                )
        return group, case_run

    with ThreadPoolExecutor(
        max_workers=request.jobs, thread_name_prefix="runtime-campaign"
    ) as pool:
        futures = [pool.submit(run_group, group) for group in campaign.execution_groups]
        for future in as_completed(futures):
            group, case_run = future.result()
            for case_id in group["case_ids"]:
                case_runs[case_id] = CaseRun(
                    case_id=case_id,
                    execution_id=case_run.execution_id,
                    disposition=case_run.disposition,
                    reason=case_run.reason,
                    attempts=case_run.attempts,
                )

    candidate_results: list[dict[str, Any]] = []
    for case in campaign.cases:
        run = case_runs[case["case_id"]]
        for candidate_id in case["candidate_ids"]:
            candidate_results.append(
                {
                    "schema_version": CANDIDATE_RESULT_SCHEMA_VERSION,
                    "campaign_id": campaign.campaign_id,
                    "candidate_id": candidate_id,
                    "case_id": case["case_id"],
                    "execution_id": run.execution_id,
                    "disposition": run.disposition,
                    "reason": run.reason,
                    "attempts": len(run.attempts),
                    "project": case["project"],
                    "report_ids": sorted(
                        {row["report_id"] for row in case["report_bindings"]}
                    ),
                }
            )
    result_ids = [row["candidate_id"] for row in candidate_results]
    if len(result_ids) != len(set(result_ids)) or sorted(result_ids) != sorted(
        campaign.target_candidate_ids
    ):
        raise ValidationError(
            "candidate results do not exactly cover the campaign denominator"
        )
    counts = Counter(row["disposition"] for row in candidate_results)
    if is_v3 and (counts.get("unsupported", 0) or counts.get("inconclusive", 0)):
        raise ValidationError(
            "v3 canonical publication blocked: unsupported and inconclusive dispositions must both be zero"
        )
    projection = _project_ground_truth(campaign, candidate_results)
    delta = _v2_delta(campaign, candidate_results)
    if is_v3:
        if delta is None or delta["formerly_unsupported_candidates"] != 58:
            raise ValidationError(
                "v3 source delta does not bind the 58 formerly unsupported candidates"
            )
        if delta["formerly_unsupported_reports"] != 24:
            raise ValidationError(
                "v3 source delta does not bind the 24 unsupported-only reports"
            )
        if (
            delta["candidates_now_conclusive"] != 58
            or delta["reports_now_conclusive"] != 24
        ):
            raise ValidationError(
                "v3 did not make every formerly unsupported candidate/report conclusive"
            )
    _write_jsonl(campaign.root / "candidate-results.jsonl", candidate_results)
    atomic_write_json(campaign.root / "ground-truth-projection.json", projection)
    if delta is not None:
        atomic_write_json(campaign.root / "v2-v3-delta.json", delta)
    command = (
        "python -m src.runtime_validation run-campaign "
        f"--campaign {request.campaign_dir} --attempts {request.attempts} --jobs {request.jobs}"
    )
    atomic_write_text(
        campaign.root / "campaign-summary.md",
        _summary_markdown(campaign, candidate_results, command, projection, delta),
    )
    effect_canaries = {
        "schema_version": "clawgap-runtime-validation-effect-canaries/v1",
        "campaign_id": campaign.campaign_id,
        "host_process_effect": False,
        "physical_adb_effect": False,
        "host_filesystem_escape": False,
        "external_network_effect": False,
        "real_message_effect": False,
        "real_subagent_effect": False,
        "policy": "all candidate effects intercepted or confined before host effect",
    }
    atomic_write_json(campaign.root / "effect-canary-results.json", effect_canaries)
    result = {
        "schema_version": CAMPAIGN_RESULT_SCHEMA_VERSION,
        "campaign_id": campaign.campaign_id,
        "generation_command": command,
        "target_candidates": len(campaign.target_candidate_ids),
        "jobs_requested": request.jobs,
        "jobs_effective": request.jobs,
        "jobs_note": "per-attempt subprocess isolation permits bounded parallel native replay",
        "disposition_counts": dict(sorted(counts.items())),
        "ground_truth_disposition_counts": projection["disposition_counts"],
        "effect_canaries_sha256": sha256_file(
            campaign.root / "effect-canary-results.json"
        ),
        "dependency_provisioning_sha256": sha256_file(
            campaign.root / "driver-provisioning.json"
        )
        if (campaign.root / "driver-provisioning.json").is_file()
        else None,
        "candidate_results_sha256": sha256_file(
            campaign.root / "candidate-results.jsonl"
        ),
        "summary_sha256": sha256_file(campaign.root / "campaign-summary.md"),
    }
    atomic_write_json(campaign.root / "campaign-result.json", result)
    manifest = {
        **result,
        "schema_version": "clawgap-runtime-validation-campaign-manifest/v1",
        "artifact_sha256": _artifact_hashes(campaign.root),
    }
    atomic_write_json(campaign.root / "manifest.json", manifest)
    _credential_scan(campaign.root, ())
    return CampaignRun(
        campaign_id=campaign.campaign_id,
        disposition_counts=dict(sorted(counts.items())),
        candidate_results=tuple(candidate_results),
        artifact_dir=campaign.root,
    )

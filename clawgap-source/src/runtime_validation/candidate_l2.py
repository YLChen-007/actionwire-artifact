"""Candidate-bound runtime L2 intake, compilation, and fail-closed execution."""

from __future__ import annotations

import json
import os
import shutil
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator

from src.projects import get_project

from .adapters import get_adapter
from .campaign_contracts import PROJECT_ADAPTERS, canonical_json, digest
from .contracts import (
    ValidationError,
    atomic_write_json,
    atomic_write_text,
    contains_credentials,
    redact_value,
    sha256_file,
)
from .dynamic_trigger import SEMANTIC_ROOTS, _source_excerpts
from .environment_builder import load_environment_profile
from .candidate_l2_executors import (
    execute_registered_candidate_l2,
    registered_candidate_l2_projects,
)
from .source_revision_compatibility import binding_hash_matches
from .candidate_l2_projection import identify_ground_truth, project_all_ground_truth


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_COVERAGE_ROOT = Path("output/cross-project/coverage-comparison")
DEFAULT_CANDIDATES = DEFAULT_COVERAGE_ROOT / "candidates.jsonl"
DEFAULT_SOURCE_CAMPAIGN = Path(
    "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
)
GT_REGRESSION_CANDIDATES = DEFAULT_COVERAGE_ROOT / "training-regression-candidates.jsonl"
SCHEMA_DIR = Path(__file__).parent / "schemas"

PLAN_SCHEMA_VERSION = "clawgap-auto-l2-plan/v1"
CASE_SCHEMA_VERSION = "clawgap-auto-l2-case/v1"
ORACLE_SCHEMA_VERSION = "clawgap-auto-l2-oracle/v1"
RESULT_SCHEMA_VERSION = "clawgap-auto-l2-candidate-result/v1"
GT_SCHEMA_VERSION = "clawgap-auto-l2-gt-identification/v1"
CAMPAIGN_ID = "runtime-auto-l2-canonical-78-v1"
EXPANDED_CAMPAIGN_ID = "runtime-auto-l2-canonical-80-expanded-v2"
EXPANDED_V3_CAMPAIGN_ID = "runtime-auto-l2-canonical-81-expanded-v3"
GT_REGRESSION_CAMPAIGN_ID = "runtime-auto-l2-gt-regression-61-v1"
GENERIC_COHORT = "generic-78"
EXPANDED_GENERIC_COHORT = "generic-80-expanded-v2"
EXPANDED_V3_GENERIC_COHORT = "generic-81-expanded-v3"
GT_REGRESSION_COHORT = "gt-regression-43"
COHORTS = {
    GENERIC_COHORT,
    EXPANDED_GENERIC_COHORT,
    EXPANDED_V3_GENERIC_COHORT,
    GT_REGRESSION_COHORT,
}

EXPECTED_CANDIDATES = 78
EXPECTED_EXPANDED_CANDIDATES = 80
EXPECTED_EXPANDED_V3_CANDIDATES = 81
EXPECTED_PROJECTS = 11
EXPECTED_PROJECT_COUNTS = {
    "AstrBot": 7,
    "QwenPaw": 3,
    "chatgpt-on-wechat": 8,
    "hermes-agent": 16,
    "nanobot": 7,
    "droidclaw": 1,
    "lettabot": 3,
    "mercury-agent": 6,
    "nanoclaw": 4,
    "openclaw": 8,
    "openclaw-cn": 15,
}
EXPECTED_FAILURE_MODES = {"wrong-check": 41, "missing-check": 37}
EXPECTED_EXPANDED_FAILURE_MODES = {"wrong-check": 41, "missing-check": 39}
EXPECTED_EXPANDED_V3_FAILURE_MODES = {"wrong-check": 41, "missing-check": 40}
EXPECTED_GT_BOUNDARIES = {
    "eligible": 43,
    "out-of-model": 2,
    "not-present-at-analysis-revision": 1,
}
EXPECTED_GT_REGRESSION_CANDIDATES = 61
EXPECTED_GT_REGRESSION_REFERENCES = 76
SAFE_CONTROL_EFFECT_OVERRIDES = {
    "CAND-925c9d1319c3ccbd": {
        "required_stages": ["sink_reached", "pre_effect_interception"],
        "forbidden_stages": [],
        "reason": (
            "the reviewed /dev/null control is a safe carrier that reaches the "
            "pre-effect Popen interceptor"
        ),
    },
    "CAND-2b4f8af87ad95c56": {
        "required_stages": ["sink_reached", "pre_effect_interception"],
        "forbidden_stages": [],
        "reason": (
            "the reviewed workspace control is a safe read carrier that reaches "
            "the pre-effect open interceptor"
        ),
    },
    "CAND-7afa41ea2e82453d": {
        "required_stages": ["sink_reached", "pre_effect_interception"],
        "forbidden_stages": [],
        "reason": (
            "the reviewed hostname control is a safe read carrier that reaches "
            "the pre-effect open interceptor"
        ),
    },
    "CAND-f4a49abfcf4c992c": {
        "required_stages": ["sink_reached", "pre_effect_interception"],
        "forbidden_stages": [],
        "reason": (
            "the reviewed echo control is a safe shell carrier that reaches the "
            "pre-effect subprocess interceptor"
        ),
    },
    "CAND-ff3a7b0ab4b0a449": {
        "required_stages": ["sink_reached", "pre_effect_interception"],
        "forbidden_stages": [],
        "reason": (
            "the reviewed echo control is a safe shell carrier that reaches the "
            "pre-effect subprocess interceptor"
        ),
    },
    "CAND-70cbbd81dff4ec04": {
        "required_stages": [],
        "forbidden_stages": [],
        "reason": (
            "the reviewed echo control is healthy at the primary shell boundary; "
            "the exit-126 retry sink is exploit-specific"
        ),
    },
    "CAND-c93d316d66e49992": {
        "required_stages": [],
        "forbidden_stages": [],
        "reason": (
            "the reviewed echo control is healthy at the primary shell boundary; "
            "the exit-126 retry sink is exploit-specific"
        ),
    },
    "CAND-34bd5e2a040b5664": {
        "required_stages": ["sink_reached", "pre_effect_interception"],
        "forbidden_stages": [],
        "reason": (
            "the reviewed syntactically public WebFetch control is a safe network "
            "carrier that reaches the pre-effect requests.get interceptor"
        ),
    },
    "CAND-0e7d7aea6fed1ab0": {
        "required_stages": ["sink_reached", "pre_effect_interception"],
        "forbidden_stages": [],
        "reason": (
            "the reviewed syntactically public Vision control is a safe image "
            "carrier that reaches the pre-effect requests.get interceptor"
        ),
    },
    "CAND-12536711cca9c235": {
        "required_stages": ["sink_reached", "pre_effect_interception"],
        "forbidden_stages": [],
        "reason": (
            "the reviewed AstrBot skills-root control is a safe intercepted write "
            "carrier and cannot satisfy the plugin-skill exploit predicate"
        ),
    },
    "CAND-1a069517d7740b35": {
        "required_stages": ["sink_reached", "pre_effect_interception"],
        "forbidden_stages": [],
        "reason": (
            "the reviewed AstrBot skills-root control is a safe intercepted write "
            "carrier and cannot satisfy the plugin-skill exploit predicate"
        ),
    },
    "CAND-36a7affd32f9adf1": {
        "required_stages": ["sink_reached", "pre_effect_interception"],
        "forbidden_stages": [],
        "reason": (
            "the reviewed AstrBot regular workspace control is a safe intercepted "
            "write carrier and cannot satisfy the hardlink exploit predicate"
        ),
    },
    "CAND-f7360b9369fcf464": {
        "required_stages": ["sink_reached", "pre_effect_interception"],
        "forbidden_stages": [],
        "reason": (
            "the reviewed QwenPaw jq control is a safe intercepted process carrier "
            "and cannot satisfy the environment-object exploit predicate"
        ),
    },
    "CAND-172340a317979d20": {
        "required_stages": ["sink_reached", "pre_effect_interception"],
        "forbidden_stages": [],
        "reason": (
            "the reviewed nanobot echo control is a safe intercepted process "
            "carrier and cannot satisfy the chained-segment exploit predicate"
        ),
    },
    "CAND-41f28e9e17a06e89": {
        "required_stages": ["sink_reached", "pre_effect_interception"],
        "forbidden_stages": [],
        "reason": (
            "the reviewed nanobot echo control is a safe intercepted process "
            "carrier and cannot satisfy the comment-tail exploit predicate"
        ),
    },
    "CAND-49ccfec7491078f6": {
        "required_stages": ["sink_reached", "pre_effect_interception"],
        "forbidden_stages": [],
        "reason": (
            "the reviewed nanobot safe-control carrier reaches the intercepted "
            "process sink and cannot satisfy the missing-safe-read exploit predicate"
        ),
    },
    "CAND-69c18202d18d7bcf": {
        "required_stages": ["sink_reached", "pre_effect_interception"],
        "forbidden_stages": [],
        "reason": (
            "the reviewed nanobot in-workspace control is a safe intercepted "
            "process carrier and cannot satisfy the outside-workspace predicate"
        ),
    },
    "CAND-f68ce42e92cbb622": {
        "required_stages": ["sink_reached", "pre_effect_interception"],
        "forbidden_stages": [],
        "reason": (
            "the reviewed nanobot exact wrapper control is a safe intercepted "
            "process carrier and cannot satisfy the nested-payload predicate"
        ),
    },
}
DISPOSITIONS = {
    "runtime-confirmed",
    "not-reproduced",
    "inconclusive",
    "unsupported",
    "planning-blocked",
    "environment-blocked",
}

REQUIRED_EVENT_FIELDS = (
    "schema_version",
    "event_id",
    "stage",
    "candidate_id",
    "case_id",
    "attempt",
    "role",
    "correlation_id",
    "fixture_id",
    "ordinal",
    "source_anchor",
)
EXPLOIT_PREFIX = (
    "case_bound",
    "source_verified",
    "fixture_prepared",
    "launch_started",
    "prompt_received",
    "provider_request",
    "provider_tool_call_or_decision",
    "registry_or_native_dispatch",
    "handler_entered",
    "controlled_argument_recorded",
    "gate_observed",
    "sink_reached",
    "pre_effect_interception",
    "target_completed",
    "cleanup_verified",
)
CONTROL_PREFIX = (
    "case_bound",
    "source_verified",
    "fixture_prepared",
    "launch_started",
    "prompt_received",
    "provider_request",
    "provider_tool_call_or_decision",
    "registry_or_native_dispatch",
    "handler_entered",
    "cleanup_verified",
)


@dataclass(frozen=True)
class CandidateL2Selection:
    root: Path
    candidates: tuple[Mapping[str, Any], ...]
    comparisons: tuple[Mapping[str, Any], ...]
    semantics: tuple[Mapping[str, Any], ...]
    ground_truth: tuple[Mapping[str, Any], ...]
    artifact_sha256: Mapping[str, str]
    candidate_sha256: str
    generic_candidate_sha256: str
    training_only_ids: tuple[str, ...]
    cohort: str = GENERIC_COHORT
    match_references: int | None = None


@dataclass(frozen=True)
class CandidateL2Request:
    out_dir: Path
    candidates: Path = DEFAULT_CANDIDATES
    coverage_root: Path = DEFAULT_COVERAGE_ROOT
    source_campaign: Path = DEFAULT_SOURCE_CAMPAIGN
    project: str | None = None
    candidate_id: str | None = None
    attempts: int = 3
    model: str = "deepseek-v4-flash"
    base_url: str = "https://api.deepseek.com/v1"
    api_key_env: str = "DEEPSEEK_API_KEY"
    generate_plans: bool = False
    cohort: str = GENERIC_COHORT
    setup_timeout: int = 1200
    launch_timeout: int = 90

    def __post_init__(self) -> None:
        if self.attempts != 3:
            raise ValidationError("candidate L2 requires exactly three attempts")
        if self.project is not None and self.project not in EXPECTED_PROJECT_COUNTS:
            raise ValidationError(f"project has no candidate denominator: {self.project}")
        if self.candidate_id is not None and not self.candidate_id.startswith("CAND-"):
            raise ValidationError("candidate_id must use the CAND- identity format")
        if self.cohort not in COHORTS:
            raise ValidationError(f"unknown candidate L2 cohort: {self.cohort}")


@dataclass(frozen=True)
class CompiledCandidate:
    candidate: Mapping[str, Any]
    plan: Mapping[str, Any]
    review: Mapping[str, Any]
    case: Mapping[str, Any]
    oracle: Mapping[str, Any]


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot read candidate-L2 artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"candidate-L2 artifact must be an object: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValidationError(f"cannot read candidate-L2 JSONL {path}: {exc}") from exc
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"{path}:{number}: invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ValidationError(f"{path}:{number}: expected object")
        rows.append(value)
    return rows


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    atomic_write_text(path, "".join(canonical_json(row) + "\n" for row in rows))


def _validate_schema(value: Mapping[str, Any], filename: str) -> None:
    schema = _read_json(SCHEMA_DIR / filename)
    errors = list(Draft202012Validator(schema).iter_errors(value))
    if errors:
        raise ValidationError(
            f"{filename} validation failed: "
            + "; ".join(error.message for error in errors[:8])
        )


def _semantic_path(project: str) -> Path:
    return (
        REPO_ROOT
        / "output"
        / SEMANTIC_ROOTS[project]
        / "call-chain-semantics"
        / "call-chain-semantics.jsonl"
    )


def _safe_project_file(project: str, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or not str(path).strip():
        raise ValidationError(f"{project}: source path escapes project root: {relative}")
    result = get_project(project).source_root / path
    if not result.is_file():
        raise ValidationError(f"{project}: source binding is unavailable: {relative}")
    return result


def _location(value: str) -> tuple[str, int]:
    try:
        relative, line, *_ = value.split(":")
        return relative, int(line)
    except (AttributeError, ValueError) as exc:
        raise ValidationError(f"invalid candidate source location: {value!r}") from exc


def _validate_frozen_candidate(
    candidate: Mapping[str, Any],
    comparison: Mapping[str, Any],
    semantic: Mapping[str, Any],
    origin_by_id: Mapping[str, Mapping[str, Any]],
    *,
    origin_required: bool,
) -> None:
    candidate_id = str(candidate.get("candidate_id") or "")
    project = str(candidate.get("project") or "")
    if candidate.get("schema_version") != "coverage-candidate/v7":
        raise ValidationError(f"{candidate_id}: unsupported candidate schema")
    spec = get_project(project)
    if candidate.get("revision") != spec.analysis_revision:
        raise ValidationError(f"{candidate_id}: candidate revision does not match registry")
    if comparison.get("project") != project or comparison.get("chain_id") != candidate.get("chain_id"):
        raise ValidationError(f"{candidate_id}: comparison identity drift")
    if semantic.get("project", {}).get("id") != project or semantic.get("chain_id") != candidate.get("chain_id"):
        raise ValidationError(f"{candidate_id}: semantic IR identity drift")
    if origin_required and candidate_id not in origin_by_id:
        raise ValidationError(f"{candidate_id}: origin audit row is missing")
    card = candidate.get("capability_card", {})
    card_path = REPO_ROOT / str(card.get("path") or "")
    if not card_path.is_file() or sha256_file(card_path) != card.get("sha256"):
        raise ValidationError(f"{candidate_id}: capability-card hash drift")
    for value in (semantic["handler"]["location"], semantic["sink"]["location"]):
        relative, _line = _location(value)
        _safe_project_file(project, relative)
    for gate in candidate.get("gate_semantics", []):
        relative, _line = _location(str(gate["callsite"]))
        _safe_project_file(project, relative)


def _validate_candidate_selection_inputs(
    root: Path,
    candidates: Sequence[Mapping[str, Any]],
    *,
    training_only_ids: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Bind selected candidates to current comparison, semantic, and source inputs."""

    projects = {str(row.get("project") or "") for row in candidates}
    if "" in projects:
        raise ValidationError("candidate selection contains a project-less row")
    comparisons = _read_jsonl(root / "comparisons.jsonl")
    comparison_by_key = {
        (row.get("project"), row.get("chain_id")): row for row in comparisons
    }
    if len(comparison_by_key) != len(comparisons):
        raise ValidationError("comparison artifact contains duplicate identities")
    semantics: list[dict[str, Any]] = []
    semantic_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for project in sorted(projects):
        rows = _read_jsonl(_semantic_path(project))
        semantics.extend(rows)
        for row in rows:
            key = (str(row.get("project", {}).get("id")), str(row.get("chain_id")))
            if key in semantic_by_key:
                raise ValidationError(f"duplicate semantic IR chain: {key}")
            semantic_by_key[key] = row
    origin = _read_jsonl(root / "candidate-origin-audit.jsonl")
    origin_by_id = {str(row.get("candidate_id")): row for row in origin}
    if len(origin_by_id) != len(origin):
        raise ValidationError("origin audit contains duplicate candidate IDs")
    for candidate in candidates:
        candidate_id = str(candidate["candidate_id"])
        key = (str(candidate["project"]), str(candidate["chain_id"]))
        comparison = comparison_by_key.get(key)
        semantic = semantic_by_key.get(key)
        if comparison is None or semantic is None:
            raise ValidationError(f"{candidate_id}: comparison or semantic input is missing")
        _validate_frozen_candidate(
            candidate,
            comparison,
            semantic,
            origin_by_id,
            origin_required=candidate_id not in training_only_ids,
        )
    return comparisons, semantics


def select_candidate_l2_denominator(
    coverage_root: Path = DEFAULT_COVERAGE_ROOT,
    candidates_path: Path = DEFAULT_CANDIDATES,
) -> CandidateL2Selection:
    root = coverage_root.resolve()
    candidate_path = candidates_path.resolve()
    expected_path = (root / "candidates.jsonl").resolve()
    if candidate_path != expected_path:
        raise ValidationError(
            "canonical candidate L2 requires the unchanged candidates.jsonl artifact"
        )
    candidates = _read_jsonl(candidate_path)
    ids = [str(row.get("candidate_id") or "") for row in candidates]
    marker_path = root / "expanded-candidate-l2.json"
    expanded = marker_path.is_file()
    marker_value = _read_json(marker_path) if expanded else {}
    expanded_v3 = (
        marker_value.get("schema_version") == "clawgap-expanded-candidate-input/v3"
    )
    expected_candidates = (
        EXPECTED_EXPANDED_V3_CANDIDATES
        if expanded_v3
        else (EXPECTED_EXPANDED_CANDIDATES if expanded else EXPECTED_CANDIDATES)
    )
    if len(candidates) != expected_candidates:
        raise ValidationError(
            "candidate denominator drift: expected "
            f"{expected_candidates}, got {len(candidates)}"
        )
    if any(not item for item in ids) or len(set(ids)) != len(ids):
        raise ValidationError("canonical candidate artifact has missing or duplicate IDs")
    projects = Counter(str(row.get("project") or "") for row in candidates)
    failures = Counter(str(row.get("failure_mode") or "") for row in candidates)
    expected_projects = dict(EXPECTED_PROJECT_COUNTS)
    if expanded and not expanded_v3:
        expected_projects["chatgpt-on-wechat"] += len(
            marker_value.get("added_candidate_ids", [])
        )
    elif expanded_v3:
        expected_projects["chatgpt-on-wechat"] += 2
        expected_projects["hermes-agent"] += 1
    if dict(projects) != expected_projects:
        raise ValidationError(f"canonical project denominator drift: {dict(projects)}")
    expected_failures = (
        EXPECTED_EXPANDED_V3_FAILURE_MODES
        if expanded_v3
        else EXPECTED_EXPANDED_FAILURE_MODES
        if expanded
        else EXPECTED_FAILURE_MODES
    )
    if dict(failures) != expected_failures:
        raise ValidationError(f"canonical failure-mode denominator drift: {dict(failures)}")

    freeze = _read_json(root / "generic-freeze-lock.json")
    expected_generic_hash = freeze.get("artifacts", {}).get("candidates.jsonl")
    generic_path = (
        root / "generic-candidates-78.jsonl" if expanded else root / "candidates.jsonl"
    )
    generic_rows = _read_jsonl(generic_path)
    generic_hash = sha256_file(generic_path)
    if len(generic_rows) != 78 or generic_hash != expected_generic_hash:
        raise ValidationError("frozen 78-row generic candidate artifact drifted")
    if expanded:
        marker = _read_json(marker_path)
        marker_base_hash = (
            sha256_file(root / "generic-candidates-80-v2.jsonl")
            if expanded_v3
            else generic_hash
        )
        if (
            marker.get("schema_version")
            not in {
                "clawgap-expanded-candidate-input/v2",
                "clawgap-expanded-candidate-input/v3",
            }
            or marker.get("base_candidates_sha256") != marker_base_hash
            or marker.get("expanded_candidates_sha256")
            != sha256_file(candidate_path)
        ):
            raise ValidationError("expanded candidate input identity drift")

    comparisons, semantics = _validate_candidate_selection_inputs(
        root,
        candidates,
        training_only_ids=(
            {
                str(row["candidate_id"])
                for row in candidates
            }
            - {
                str(row["candidate_id"])
                for row in generic_rows
            }
            if expanded_v3
            else set(marker_value.get("added_candidate_ids", []) if expanded else [])
        ),
    )

    ground_truth = _read_jsonl(root / "ground-truth-coverage.jsonl")
    boundaries = Counter(str(row.get("boundary_status")) for row in ground_truth)
    if dict(boundaries) != EXPECTED_GT_BOUNDARIES:
        raise ValidationError(f"ground-truth boundary drift: {dict(boundaries)}")
    candidate_ids = set(ids)
    eligible = [row for row in ground_truth if row.get("boundary_status") == "eligible"]
    linked = [
        row for row in eligible
        if set(row.get("matched_candidate_ids") or []) & candidate_ids
    ]
    expected_linked = 42 if expanded_v3 else (41 if expanded else 38)
    if len(linked) != expected_linked or any(
        row.get("status") != "covered" for row in linked
    ):
        raise ValidationError(
            "canonical input must project exactly "
            f"{expected_linked} linked eligible reports"
        )
    strict_ids = {
        item for row in eligible for item in row.get("matched_candidate_ids") or []
    }
    current_strict_ids = strict_ids & candidate_ids
    expected_current_strict_ids = 60 if expanded_v3 else (59 if expanded else 57)
    expected_missing_ids = 1 if expanded_v3 else (2 if expanded else 4)
    if (
        len(current_strict_ids) != expected_current_strict_ids
        or len(strict_ids - candidate_ids) != expected_missing_ids
    ):
        raise ValidationError("canonical ground-truth candidate identity accounting drift")
    _validate_ground_truth_sources(ground_truth)

    artifact_hashes = {
        name: sha256_file(root / name)
        for name in (
            "candidates.jsonl",
            "comparisons.jsonl",
            "candidate-origin-audit.jsonl",
            "ground-truth-coverage.jsonl",
            "ground-truth-manifest.json",
            "generic-freeze-lock.json",
        )
    }
    training_only: tuple[str, ...] = (
        tuple(marker.get("added_candidate_ids", [])) if expanded else ()
    )
    if expanded:
        generic_ids = {str(row["candidate_id"]) for row in generic_rows}
        if not generic_ids.issubset(candidate_ids):
            raise ValidationError("expanded input does not preserve the generic 78 IDs")
        if expanded_v3:
            v2_ids = {
                str(row["candidate_id"])
                for row in _read_jsonl(root / "generic-candidates-80-v2.jsonl")
            }
            if not v2_ids.issubset(candidate_ids):
                raise ValidationError("expanded-v3 input does not preserve the v2 80 IDs")
    elif candidate_ids != {str(row["candidate_id"]) for row in generic_rows}:
        raise ValidationError("selected candidate identities do not equal the frozen generic artifact")
    return CandidateL2Selection(
        root=root,
        candidates=tuple(candidates),
        comparisons=tuple(comparisons),
        semantics=tuple(semantics),
        ground_truth=tuple(ground_truth),
        artifact_sha256=artifact_hashes,
        candidate_sha256=sha256_file(candidate_path),
        generic_candidate_sha256=generic_hash,
        training_only_ids=training_only,
        cohort=(
            EXPANDED_V3_GENERIC_COHORT
            if expanded_v3
            else (EXPANDED_GENERIC_COHORT if expanded else GENERIC_COHORT)
        ),
    )


def _validate_ground_truth_sources(ground_truth: Sequence[Mapping[str, Any]]) -> None:
    for row in ground_truth:
        source_files = row.get("source_files") or []
        source_hashes = row.get("source_sha256") or []
        if len(source_files) != len(source_hashes):
            raise ValidationError("ground-truth source binding is incomplete")
        for relative, expected in zip(source_files, source_hashes, strict=True):
            path = REPO_ROOT / str(relative)
            if not path.is_file() or sha256_file(path) != expected:
                raise ValidationError(f"ground-truth source drift: {relative}")


def select_gt_regression_l2_denominator(
    coverage_root: Path = DEFAULT_COVERAGE_ROOT,
    candidates_path: Path = GT_REGRESSION_CANDIDATES,
) -> CandidateL2Selection:
    """Select the post-hoc 61-ID cohort that covers all 43 eligible GT rows.

    This is intentionally separate from the held-out generic 78-candidate
    denominator. Its four training-only fallback candidates remain visible in
    the manifest and must never be promoted into the generic artifact.
    """

    from .selection import select_covered_candidates

    root = coverage_root.resolve()
    candidate_path = candidates_path.resolve()
    expected_path = (root / "training-regression-candidates.jsonl").resolve()
    if candidate_path != expected_path:
        raise ValidationError(
            "GT-regression candidate L2 requires training-regression-candidates.jsonl"
        )
    covered = select_covered_candidates(
        root,
        expected_candidates=EXPECTED_GT_REGRESSION_CANDIDATES,
        expected_match_references=EXPECTED_GT_REGRESSION_REFERENCES,
        expected_covered_reports=EXPECTED_GT_BOUNDARIES["eligible"],
    )
    source_rows = _read_jsonl(candidate_path)
    source_by_id = {str(row.get("candidate_id") or ""): row for row in source_rows}
    if len(source_rows) != 82 or len(source_by_id) != len(source_rows) or "" in source_by_id:
        raise ValidationError("training-regression candidate overlay drifted from 82 unique rows")
    candidates = [dict(row.candidate) for row in covered.candidates]
    candidate_ids = {str(row["candidate_id"]) for row in candidates}
    if len(candidates) != EXPECTED_GT_REGRESSION_CANDIDATES:
        raise ValidationError("GT-regression selection did not contain 61 candidates")
    if any(source_by_id.get(candidate_id) != candidate for candidate_id, candidate in (
        (str(row["candidate_id"]), row) for row in candidates
    )):
        raise ValidationError("GT-regression selection drifted from the training overlay")

    freeze = _read_json(root / "generic-freeze-lock.json")
    generic_path = root / "candidates.jsonl"
    generic_rows = _read_jsonl(generic_path)
    generic_hash = sha256_file(generic_path)
    expected_generic_hash = freeze.get("artifacts", {}).get("candidates.jsonl")
    if len(generic_rows) != EXPECTED_CANDIDATES or generic_hash != expected_generic_hash:
        raise ValidationError("frozen 78-row generic candidate artifact drifted")
    generic_ids = {str(row["candidate_id"]) for row in generic_rows}
    training_only = tuple(sorted(candidate_ids - generic_ids))
    if len(training_only) != 4:
        raise ValidationError("GT-regression selection must retain exactly four training-only IDs")

    comparisons, semantics = _validate_candidate_selection_inputs(
        root, candidates, training_only_ids=set(training_only)
    )
    ground_truth = _read_jsonl(root / "ground-truth-coverage.jsonl")
    boundaries = Counter(str(row.get("boundary_status")) for row in ground_truth)
    if dict(boundaries) != EXPECTED_GT_BOUNDARIES:
        raise ValidationError(f"ground-truth boundary drift: {dict(boundaries)}")
    eligible = [row for row in ground_truth if row.get("boundary_status") == "eligible"]
    linked = [
        row for row in eligible if set(row.get("matched_candidate_ids") or []) & candidate_ids
    ]
    if len(linked) != EXPECTED_GT_BOUNDARIES["eligible"] or any(
        row.get("status") != "covered" for row in linked
    ):
        raise ValidationError("GT-regression selection must link all eligible covered reports")
    strict_ids = {
        str(item) for row in eligible for item in row.get("matched_candidate_ids") or []
    }
    if strict_ids != candidate_ids:
        raise ValidationError("GT-regression candidates do not exactly match GT links")
    _validate_ground_truth_sources(ground_truth)
    artifact_names = (
        "candidates.jsonl",
        "training-regression-candidates.jsonl",
        "comparisons.jsonl",
        "candidate-origin-audit.jsonl",
        "ground-truth-coverage.jsonl",
        "ground-truth-manifest.json",
        "generic-freeze-lock.json",
        "training-fallback-validations.jsonl",
        "training-fallback-field-flow.jsonl",
    )
    artifact_hashes = {name: sha256_file(root / name) for name in artifact_names}
    return CandidateL2Selection(
        root=root,
        candidates=tuple(candidates),
        comparisons=tuple(comparisons),
        semantics=tuple(semantics),
        ground_truth=tuple(ground_truth),
        artifact_sha256=artifact_hashes,
        candidate_sha256=sha256_file(candidate_path),
        generic_candidate_sha256=generic_hash,
        training_only_ids=training_only,
        cohort=GT_REGRESSION_COHORT,
        match_references=covered.match_references,
    )


def _semantic_map(selection: CandidateL2Selection) -> dict[tuple[str, str], Mapping[str, Any]]:
    return {
        (str(row.get("project", {}).get("id")), str(row.get("chain_id"))): row
        for row in selection.semantics
    }


def _comparison_map(selection: CandidateL2Selection) -> dict[tuple[str, str], Mapping[str, Any]]:
    return {
        (str(row.get("project")), str(row.get("chain_id"))): row
        for row in selection.comparisons
    }


def _source_campaign_cases(path: Path) -> dict[str, Mapping[str, Any]]:
    root = path.resolve()
    manifest = _read_json(root / "manifest.json")
    if manifest.get("candidate_count") not in {78, 80, 81}:
        raise ValidationError(
            "source dynamic-trigger campaign is not an approved 78/80/81-row artifact"
        )
    review = manifest.get("review", {})
    if review.get("status") != "accepted":
        raise ValidationError("source dynamic-trigger campaign was not independently reviewed")
    cases = _read_jsonl(root / "cases.jsonl")
    result: dict[str, Mapping[str, Any]] = {}
    for case in cases:
        candidate_id = str(case.get("candidate_binding", {}).get("candidate_id") or "")
        if candidate_id in result:
            raise ValidationError(f"source campaign has duplicate candidate: {candidate_id}")
        result[candidate_id] = case
    if len(result) != manifest.get("candidate_count"):
        raise ValidationError("source dynamic-trigger campaign does not partition its candidates")
    return result


def _anchors_from_observations(observations: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    anchors: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in observations:
        kind = str(row["kind"])
        if kind == "pre-effect-interception":
            kind = "pre-effect"
        identity = (kind, str(row["source_anchor"]))
        if identity in seen:
            continue
        seen.add(identity)
        anchors.append({"kind": kind, "anchor": identity[1]})
    return anchors


def _semantic_anchors(candidate: Mapping[str, Any], semantic: Mapping[str, Any]) -> list[dict[str, str]]:
    observations: list[dict[str, str]] = []
    handler_location = str(semantic["handler"]["location"])
    sink_location = str(semantic["sink"]["location"])
    handler_relative, handler_line = _location(handler_location)
    sink_relative, sink_line = _location(sink_location)
    observations.append(
        {"kind": "handler", "anchor": f"{handler_relative}:{handler_line}"}
    )
    for gate in candidate.get("gate_semantics", []):
        relative, line = _location(str(gate["callsite"]))
        observations.append({"kind": "gate", "anchor": f"{relative}:{line}"})
    sink_anchor = f"{sink_relative}:{sink_line}"
    observations.append({"kind": "sink", "anchor": sink_anchor})
    observations.append({"kind": "pre-effect", "anchor": sink_anchor})
    return observations


def _nested(value: Any, path: Sequence[str]) -> Any:
    current = value
    for part in path:
        if not isinstance(current, Mapping) or part not in current:
            raise ValidationError(f"argument path is absent: {list(path)}")
        current = current[part]
    return current


def _fragment_prompt(
    candidate: Mapping[str, Any], semantic: Mapping[str, Any]
) -> tuple[str, str]:
    from .dynamic_trigger import FRAGMENT_SCHEMA

    system = (
        "You propose a declarative candidate L2 replay fragment for authorized ClawGap "
        "research. Choose only tool arguments, a paired safe control, prompt, relation, "
        "and argument path. Never choose instrumentation, verdicts, credentials, external "
        "network, or terminal execution. Return one JSON object only."
    )
    user = canonical_json(
        {
            "candidate": candidate,
            "semantic_ir": semantic,
            "registered_tools": sorted(
                get_adapter(PROJECT_ADAPTERS[str(candidate["project"])]).supported_tools
            ),
            "source_excerpts": _source_excerpts(str(candidate["project"]), semantic),
            "required_schema": FRAGMENT_SCHEMA,
        }
    )
    return system, user


def _parse_generated_fragment(raw: str) -> dict[str, Any]:
    from .dynamic_trigger import FRAGMENT_SCHEMA, _validate_fragment_semantics

    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"LLM plan fragment is not JSON: {exc}") from exc
    errors = list(Draft202012Validator(FRAGMENT_SCHEMA).iter_errors(value))
    if errors:
        raise ValidationError("; ".join(error.message for error in errors[:6]))
    _validate_fragment_semantics(value)
    return value


def _generate_fragment(
    candidate: Mapping[str, Any],
    semantic: Mapping[str, Any],
    runner: Callable[[str, str], str],
) -> tuple[dict[str, Any], list[dict[str, str]], int]:
    system, user = _fragment_prompt(candidate, semantic)
    exchanges: list[dict[str, str]] = []
    raw = runner(system, user)
    exchanges.append({"system": "generation", "user": user, "response": raw})
    try:
        return _parse_generated_fragment(raw), exchanges, 0
    except ValidationError as first:
        repair_user = canonical_json(
            {"error": str(first), "response": raw, "repair_goal": "exact JSON schema"}
        )
        repaired = runner("Repair the response to the exact JSON schema. Return JSON only.", repair_user)
        exchanges.append(
            {"system": "repair", "user": repair_user, "response": repaired}
        )
        return _parse_generated_fragment(repaired), exchanges, 1


def _case_identity(candidate: Mapping[str, Any], source_case_id: str | None) -> str:
    return "AL2-" + digest(
        {"candidate_id": candidate["candidate_id"], "source_case_id": source_case_id}
    )[:16]


def _training_fallback_execution_blocker(candidate: Mapping[str, Any]) -> str | None:
    """Fail closed when current source contradicts a training-only replay premise."""

    if candidate.get("candidate_id") != "CAND-b49cfc884f2168f1":
        return None
    source = _safe_project_file(
        "chatgpt-on-wechat", "agent/tools/browser/browser_tool.py"
    ).read_text(encoding="utf-8")
    if 'url = "https://" + url' in source:
        return (
            "current BrowserTool source rewrites a non-http(s) URL to an https URL before "
            "BrowserService.page.goto; no reviewed replay proves file-scheme navigation"
        )
    return None


def _blocked_compilation(
    candidate: Mapping[str, Any],
    semantic: Mapping[str, Any],
    reason: str,
) -> CompiledCandidate:
    case_id = _case_identity(candidate, None)
    anchors = _semantic_anchors(candidate, semantic)
    plan = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "project": candidate["project"],
        "revision": candidate["revision"],
        "candidate_id": candidate["candidate_id"],
        "case_id": case_id,
        "runtime_family": "candidate-anchor-intake",
        "tool_or_action_name": semantic["handler"].get("tool_name"),
        "entrypoint_plan": {"status": "blocked"},
        "provider_plan": {
            "protocol": "not-selected",
            "response_mode": "not-selected",
            "base_url": "http://127.0.0.1:${CLAWGAP_PROVIDER_PORT}",
        },
        "input_plan": {"status": "blocked"},
        "fixture_plan": {"status": "blocked"},
        "instrumentation_plan": {"anchors": anchors},
        "interceptor_plan": {"status": "blocked"},
        "exploit_arguments": {},
        "control_arguments": {},
        "expected_gate_outcomes": list(candidate.get("gate_semantics", [])),
        "expected_sink_relation": dict(semantic.get("sink_constraint", {})),
        "payload_repair": None,
        "generation": {"mode": "missing-reviewed-plan", "repair_round": 0},
    }
    review = {
        "schema_version": "clawgap-auto-l2-plan-review/v1",
        "candidate_id": candidate["candidate_id"],
        "case_id": case_id,
        "status": "planning-blocked",
        "reason": reason,
        "checks": ["identity", "revision", "source-anchor"],
    }
    case = {
        "schema_version": CASE_SCHEMA_VERSION,
        "project": candidate["project"],
        "revision": candidate["revision"],
        "case_id": case_id,
        "candidate_binding": {
            "candidate_id": candidate["candidate_id"],
            "row_sha256": digest(candidate),
        },
        "handler": dict(semantic["handler"]),
        "gates": list(candidate.get("gate_semantics", [])),
        "sink": dict(semantic["sink_constraint"]),
        "tool_or_action_name": semantic["handler"].get("tool_name"),
        "instrumentation_anchors": anchors,
        "unsafe_relation": {"status": "uncompiled"},
        "forced_tool_calls": [
            {"role": "exploit", "arguments": {}},
            {"role": "control", "arguments": {}},
        ],
        "effect_policy": {
            "intercept_before_execution": True,
            "allow_host_write": False,
            "allow_network": "loopback-only",
        },
        "execution_eligible": False,
        "blocking_reason": reason,
    }
    oracle = _oracle(candidate, case, eligible=False)
    return CompiledCandidate(candidate, plan, review, case, oracle)


def _oracle(
    candidate: Mapping[str, Any], case: Mapping[str, Any], *, eligible: bool
) -> dict[str, Any]:
    status = "compiled" if eligible else "blocked"
    control_policy = SAFE_CONTROL_EFFECT_OVERRIDES.get(
        str(candidate["candidate_id"]),
        {
            "required_stages": [],
            "forbidden_stages": ["sink_reached", "pre_effect_interception"],
            "reason": "control must be blocked before the terminal sink",
        },
    )
    return {
        "schema_version": ORACLE_SCHEMA_VERSION,
        "candidate_id": candidate["candidate_id"],
        "case_id": case["case_id"],
        "attempts": 3,
        "roles": ["exploit", "control"],
        "identity": {
            "correlation_template": f"{case['case_id']}:<attempt>:<role>",
            "fixture_template": f"{candidate['project']}-l2:{case['case_id']}:<role>",
            "required_fields": list(REQUIRED_EVENT_FIELDS),
            "status": status,
        },
        "exploit": {
            "status": status,
            "required_prefix": list(EXPLOIT_PREFIX),
            "value_relation": case.get("unsafe_relation", {}),
            "gate_relation": {"ids": [row.get("id") for row in case.get("gates", [])]},
            "sink_relation": case.get("sink", {}),
            "interception": {"executed": False},
        },
        "control": {
            "status": status,
            "required_healthy_prefix": list(CONTROL_PREFIX),
            "required_stages": control_policy["required_stages"] if eligible else [],
            "forbidden_stages": control_policy["forbidden_stages"] if eligible else [],
            "value_relation": case.get("unsafe_relation", {}),
            "semantic_constraint": "preserve-reviewed-control",
            "policy_reason": control_policy["reason"],
        },
        "health": {
            "process_exit": [0],
            "provider_exchange": "exact-contract",
            "readiness_boundary": True,
            "ordinals": "contiguous-from-one",
            "stages": "unique-and-compiled-order",
            "cleanup_canary": "unchanged",
            "credentials": "redacted",
            "disposable_roots_removed": True,
            "status": status,
        },
    }


def _compiled_from_source(
    candidate: Mapping[str, Any],
    semantic: Mapping[str, Any],
    source_case: Mapping[str, Any],
) -> CompiledCandidate:
    binding = source_case["candidate_binding"]
    if binding["candidate_id"] != candidate["candidate_id"] or binding["row_sha256"] != digest(candidate):
        raise ValidationError(f"{candidate['candidate_id']}: source-case candidate drift")
    for row in source_case["source_binding"]["files"]:
        path = _safe_project_file(str(candidate["project"]), str(row["path"]))
        if not binding_hash_matches(
            project=str(candidate["project"]),
            relative=str(row["path"]),
            expected=str(row["sha256"]),
            actual=sha256_file(path),
            source_root=get_project(str(candidate["project"])).source_root,
        ):
            raise ValidationError(f"{candidate['candidate_id']}: source-case hash drift")
    profile = load_environment_profile(str(candidate["project"]))
    provider = profile["provider"]
    anchors = _anchors_from_observations(source_case["observations"])
    case_id = _case_identity(candidate, str(source_case["case_id"]))
    plan = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "project": candidate["project"],
        "revision": candidate["revision"],
        "candidate_id": candidate["candidate_id"],
        "case_id": case_id,
        "runtime_family": source_case["launch_profile"]["runtime"],
        "tool_or_action_name": source_case["handler"]["tool_name"],
        "entrypoint_plan": {
            "profile": "environment_profiles",
            "launch_command_family": profile["launch_command"],
            "readiness_pattern": profile["readiness_pattern"],
        },
        "provider_plan": {
            "protocol": provider["protocol"],
            "response_mode": provider["response_mode"],
            "base_url": provider["base_url"],
            "path": provider.get("path"),
            "allowed_paths": provider.get("allowed_paths", []),
        },
        "input_plan": dict(profile["input"]),
        "fixture_plan": dict(source_case["fixture"]),
        "instrumentation_plan": {"anchors": anchors},
        "interceptor_plan": {"families": list(profile["effect_interceptors"])},
        "exploit_arguments": source_case["forced_tool_calls"][0]["arguments"],
        "control_arguments": source_case["forced_tool_calls"][1]["arguments"],
        "expected_gate_outcomes": list(source_case["gates"]),
        "expected_sink_relation": dict(source_case["sink"]),
        "payload_repair": None,
        "generation": {
            "mode": "reused-reviewed-dynamic-trigger",
            "repair_round": 0,
            "source_case_sha256": digest(source_case),
        },
    }
    review = {
        "schema_version": "clawgap-auto-l2-plan-review/v1",
        "candidate_id": candidate["candidate_id"],
        "case_id": case_id,
        "status": "accepted-for-compilation",
        "reason": "source-bound reviewed fragment and semantic anchors compiled",
        "checks": [
            "candidate-identity",
            "registry-revision",
            "source-hash",
            "handler-gate-sink-anchor",
            "paired-control",
            "loopback-provider",
            "pre-effect-interceptor",
        ],
        "runtime_execution_status": "unsupported-until-project-native-candidate-adapter-exists",
    }
    case = {
        "schema_version": CASE_SCHEMA_VERSION,
        "project": candidate["project"],
        "revision": candidate["revision"],
        "case_id": case_id,
        "candidate_binding": dict(binding),
        "handler": dict(source_case["handler"]),
        "gates": list(source_case["gates"]),
        "sink": dict(source_case["sink"]),
        "tool_or_action_name": source_case["handler"]["tool_name"],
        "instrumentation_anchors": anchors,
        "unsafe_relation": dict(source_case["unsafe_relation"]),
        "forced_tool_calls": list(source_case["forced_tool_calls"]),
        "effect_policy": dict(source_case["effect_policy"]),
        "execution_eligible": True,
    }
    return CompiledCandidate(candidate, plan, review, case, _oracle(candidate, case, eligible=True))


def _compiled_from_fragment(
    candidate: Mapping[str, Any],
    semantic: Mapping[str, Any],
    fragment: Mapping[str, Any],
    repair_round: int,
    exchanges: Sequence[Mapping[str, Any]],
) -> CompiledCandidate:
    adapter = get_adapter(PROJECT_ADAPTERS[str(candidate["project"])])
    if fragment["tool_name"] not in adapter.supported_tools:
        raise ValidationError(f"{candidate['candidate_id']}: unregistered candidate tool")
    profile = load_environment_profile(str(candidate["project"]))
    anchors = _semantic_anchors(candidate, semantic)
    case_id = _case_identity(candidate, f"generated:{fragment['tool_name']}")
    provider = profile["provider"]
    plan = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "project": candidate["project"],
        "revision": candidate["revision"],
        "candidate_id": candidate["candidate_id"],
        "case_id": case_id,
        "runtime_family": adapter.language,
        "tool_or_action_name": fragment["tool_name"],
        "entrypoint_plan": {
            "profile": "environment_profiles",
            "readiness_pattern": profile["readiness_pattern"],
        },
        "provider_plan": {
            "protocol": provider["protocol"],
            "response_mode": provider["response_mode"],
            "base_url": provider["base_url"],
            "path": provider.get("path"),
        },
        "input_plan": dict(profile["input"]),
        "fixture_plan": {"family": "candidate-specific", "status": "compiled"},
        "instrumentation_plan": {"anchors": anchors},
        "interceptor_plan": {"families": list(profile["effect_interceptors"])},
        "exploit_arguments": fragment["exploit_args"],
        "control_arguments": fragment["control_args"],
        "expected_gate_outcomes": [
            {"id": row["gate_uid"], "expected_outcome": "admits-exploit"}
            for row in candidate.get("gate_semantics", [])
        ],
        "expected_sink_relation": {
            "id": candidate["sink_id"],
            "controlled_argument": semantic["sink_constraint"]["controlled_argument"],
        },
        "payload_repair": None,
        "generation": {
            "mode": "deepseek-proposal-deterministic-review",
            "repair_round": repair_round,
            "proposal_exchange_sha256": digest(exchanges),
        },
    }
    review = {
        "schema_version": "clawgap-auto-l2-plan-review/v1",
        "candidate_id": candidate["candidate_id"],
        "case_id": case_id,
        "status": "accepted-for-compilation",
        "reason": "deterministically reviewed model fragment",
        "checks": ["registered-tool", "argument-path", "paired-control", "source-anchor"],
        "runtime_execution_status": "unsupported-until-project-native-candidate-adapter-exists",
    }
    unsafe = {
        "relation": fragment["relation"],
        "argument_path": fragment["argument_path"],
        "exploit_value": fragment["exploit_value"],
        "control_value": fragment["control_value"],
    }
    case = {
        "schema_version": CASE_SCHEMA_VERSION,
        "project": candidate["project"],
        "revision": candidate["revision"],
        "case_id": case_id,
        "candidate_binding": {"candidate_id": candidate["candidate_id"], "row_sha256": digest(candidate)},
        "handler": {
            "id": candidate["handler_id"],
            "tool_name": fragment["tool_name"],
            "argument_path": fragment["argument_path"],
        },
        "gates": plan["expected_gate_outcomes"],
        "sink": plan["expected_sink_relation"],
        "tool_or_action_name": fragment["tool_name"],
        "instrumentation_anchors": anchors,
        "unsafe_relation": unsafe,
        "forced_tool_calls": [
            {"role": "exploit", "arguments": fragment["exploit_args"]},
            {"role": "control", "arguments": fragment["control_args"]},
        ],
        "effect_policy": {
            "intercept_before_execution": True,
            "allow_host_write": False,
            "allow_network": "loopback-only",
        },
        "execution_eligible": True,
    }
    return CompiledCandidate(candidate, plan, review, case, _oracle(candidate, case, eligible=True))


def compile_candidate_l2(
    selection: CandidateL2Selection,
    candidate_id: str,
    *,
    runner: Callable[[str, str], str] | None = None,
    source_campaign: Path = DEFAULT_SOURCE_CAMPAIGN,
) -> CompiledCandidate:
    matches = [row for row in selection.candidates if row.get("candidate_id") == candidate_id]
    if len(matches) != 1:
        raise ValidationError(f"candidate is not uniquely bound in 82-row union: {candidate_id}")
    candidate = matches[0]
    semantic = _semantic_map(selection)[
        (str(candidate["project"]), str(candidate["chain_id"]))
    ]
    fallback_blocker = _training_fallback_execution_blocker(candidate)
    if fallback_blocker is not None:
        return _blocked_compilation(candidate, semantic, fallback_blocker)
    source_cases = _source_campaign_cases(source_campaign)
    source_case = source_cases.get(candidate_id)
    if source_case is not None:
        return _compiled_from_source(candidate, semantic, source_case)
    if runner is None:
        return _blocked_compilation(
            candidate,
            semantic,
            "no reviewed replay fragment exists for this training-only candidate",
        )
    fragment, _exchanges, repair_round = _generate_fragment(candidate, semantic, runner)
    return _compiled_from_fragment(
        candidate, semantic, fragment, repair_round, _exchanges
    )


def validate_compiled_candidate(compiled: CompiledCandidate) -> None:
    _validate_schema(compiled.plan, "auto-l2-plan-v1.schema.json")
    _validate_schema(compiled.case, "auto-l2-case-v1.schema.json")
    _validate_schema(compiled.oracle, "auto-l2-oracle-v1.schema.json")
    candidate = compiled.candidate
    plan = compiled.plan
    if plan["candidate_id"] != candidate["candidate_id"] or plan["project"] != candidate["project"]:
        raise ValidationError("compiled plan candidate identity drift")
    if plan["revision"] != get_project(str(candidate["project"])).analysis_revision:
        raise ValidationError("compiled plan revision drift")
    if urlsplit(plan["provider_plan"]["base_url"].replace("${CLAWGAP_PROVIDER_PORT}", "18099")).hostname not in {
        "127.0.0.1"
    }:
        raise ValidationError("candidate provider URL is not loopback-only")
    anchors = plan["instrumentation_plan"]["anchors"]
    if not anchors or anchors[-1]["kind"] != "pre-effect":
        raise ValidationError("compiled plan has no terminal pre-effect anchor")
    for row in anchors:
        relative, _line = _location(row["anchor"])
        _safe_project_file(str(candidate["project"]), relative)
    if compiled.case["execution_eligible"]:
        calls = compiled.case["forced_tool_calls"]
        if [row["role"] for row in calls] != ["exploit", "control"]:
            raise ValidationError("compiled case roles must be exploit/control")
        exploit = _nested(calls[0]["arguments"], compiled.case["unsafe_relation"]["argument_path"])
        control = _nested(calls[1]["arguments"], compiled.case["unsafe_relation"]["argument_path"])
        if exploit != compiled.case["unsafe_relation"]["exploit_value"]:
            raise ValidationError("compiled exploit relation drift")
        if control != compiled.case["unsafe_relation"]["control_value"]:
            raise ValidationError("compiled control relation drift")
        if exploit == control:
            raise ValidationError("compiled exploit/control values are identical")


def evaluate_candidate_events(
    case: Mapping[str, Any],
    oracle: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    *,
    attempt: int,
    role: str,
    environment_id: str,
    fixture_id: str,
) -> bool:
    if not events:
        return False
    correlation_id = f"{case['case_id']}:{attempt}:{role}"
    allowed_anchors = {
        row if isinstance(row, str) else row.get("anchor")
        for row in oracle["identity"].get("allowed_anchors", [])
    }
    stages: list[str] = []
    for index, event in enumerate(events, 1):
        missing = [field for field in REQUIRED_EVENT_FIELDS if field not in event]
        if missing:
            return False
        expected_identity = {
            "candidate_id": case["candidate_binding"]["candidate_id"],
            "case_id": case["case_id"],
            "attempt": attempt,
            "role": role,
            "correlation_id": correlation_id,
            "fixture_id": fixture_id,
            "ordinal": index,
            "environment_id": environment_id,
        }
        if any(event.get(key) != value for key, value in expected_identity.items()):
            return False
        stage = str(event["stage"])
        if stage in stages or stage not in EXPLOIT_PREFIX:
            return False
        if allowed_anchors and event["source_anchor"] not in allowed_anchors:
            return False
        stages.append(stage)
    prefix = EXPLOIT_PREFIX if role == "exploit" else CONTROL_PREFIX
    if not set(prefix).issubset(stages):
        return False
    if stages != [stage for stage in EXPLOIT_PREFIX if stage in stages]:
        return False
    if role == "exploit" and "sink_reached" not in stages:
        return False
    if role == "control":
        control_oracle = oracle["control"]
        forbidden = set(control_oracle.get("forbidden_stages", []))
        required = set(control_oracle.get("required_stages", []))
        if forbidden.intersection(stages) or not required.issubset(stages):
            return False
    terminal = events[-1]
    if terminal["stage"] != "cleanup_verified":
        return False
    interception = [row for row in events if row["stage"] == "pre_effect_interception"]
    if role == "exploit" and not interception:
        return False
    if any(
        row.get("intercept_before_execution") is not True
        or row.get("detail", {}).get("executed") is not False
        for row in interception
    ):
        return False
    return True


def validate_provider_contract(
    protocol: str, transcript: Sequence[Mapping[str, Any]], base_url: str
) -> bool:
    parsed = urlsplit(base_url.replace("${CLAWGAP_PROVIDER_PORT}", "18099"))
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
        return False
    return bool(transcript) and all(row.get("valid") is True for row in transcript)


def _gt_identification(selection: CandidateL2Selection) -> list[dict[str, Any]]:
    candidate_ids = {str(row["candidate_id"]) for row in selection.candidates}
    rows: list[dict[str, Any]] = []
    for row in selection.ground_truth:
        identified = identify_ground_truth(row, candidate_ids)
        if (
            selection.cohort == GENERIC_COHORT
            and identified["disposition"] == "candidate-missing"
        ):
            identified["reason"] = (
                "eligible report is candidate-missing from the unchanged 78-row input"
            )
        elif identified["disposition"] == "candidate-linked":
            identified["reason"] = (
                "at least one current canonical candidate matches"
                if selection.cohort == GENERIC_COHORT
                else "at least one GT-regression candidate matches"
            )
        rows.append({"schema_version": GT_SCHEMA_VERSION, **identified})
    return rows


def _gt_projection(
    identification: Sequence[Mapping[str, Any]],
    results: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return project_all_ground_truth(identification, results)


def _trace_dirs(
    root: Path, case: Mapping[str, Any], attempts: int
) -> list[tuple[int, str, Path]]:
    result: list[tuple[int, str, Path]] = []
    for attempt in range(1, attempts + 1):
        for role in ("exploit", "control"):
            result.append(
                (
                    attempt,
                    role,
                    root / "runs" / str(case["case_id"]) / f"attempt-{attempt}" / role,
                )
            )
    return result


def _publish_blocked_traces(
    root: Path,
    compiled: CompiledCandidate,
    attempts: int,
    reason: str,
    semantic: Mapping[str, Any],
) -> int:
    source_files = []
    for value in (
        semantic["handler"]["location"],
        semantic["sink"]["location"],
        *(str(row["callsite"]) for row in compiled.candidate.get("gate_semantics", [])),
    ):
        relative, _line = _location(value)
        path = _safe_project_file(str(compiled.candidate["project"]), relative)
        source_files.append({"path": relative, "sha256": sha256_file(path)})
    blocked = 0
    for attempt, role, directory in _trace_dirs(root, compiled.case, attempts):
        directory.mkdir(parents=True, exist_ok=True)
        atomic_write_text(directory / "events.raw.jsonl", "")
        atomic_write_text(directory / "events.jsonl", "")
        atomic_write_text(directory / "provider-transcript.jsonl", "")
        atomic_write_text(directory / "launch.log", f"not launched: {reason}\n")
        atomic_write_json(
            directory / "transformed-source-manifest.json",
            {
                "schema_version": "clawgap-runtime-transformed-source-manifest/v1",
                "mode": "not-launched",
                "revision": compiled.candidate["revision"],
                "files": source_files,
            },
        )
        atomic_write_json(
            directory / "trace-accounting.json",
            {
                "schema_version": "clawgap-auto-l2-trace-accounting/v1",
                "candidate_id": compiled.candidate["candidate_id"],
                "case_id": compiled.case["case_id"],
                "attempt": attempt,
                "role": role,
                "status": "blocked",
                "launched": False,
                "reason": reason,
            },
        )
        blocked += 1
    return blocked


def _result(
    compiled: CompiledCandidate,
    attempts: int,
    blocked_traces: int,
) -> dict[str, Any]:
    if not compiled.case["execution_eligible"]:
        disposition = "planning-blocked"
        reason = str(compiled.case["blocking_reason"])
    else:
        disposition = "unsupported"
        reason = (
            "no project-native candidate execution adapter is registered for the "
            "compiled provider/input/instrumentation contract"
        )
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "project": compiled.candidate["project"],
        "candidate_id": compiled.candidate["candidate_id"],
        "case_id": compiled.case["case_id"],
        "disposition": disposition,
        "evidence_tier": "none",
        "attempts": attempts,
        "reason": reason,
        "attempt_errors": [reason],
        "payload_repair_applied": compiled.plan.get("generation", {}).get("repair_round", 0) > 0,
        "trace_accounting": {
            "expected": attempts * 2,
            "valid": 0,
            "blocked": blocked_traces,
            "not_launched": blocked_traces,
        },
    }


def _command(request: CandidateL2Request, *, batch: bool) -> str:
    if batch and request.cohort == GENERIC_COHORT:
        return (
            "python scripts/run_candidate_l2_campaign.py"
            f" --candidates {request.candidates} --out-dir {request.out_dir}"
        )
    command = "python -m src.runtime_validation "
    command += (
        "validate-gt-linked-candidates-l2"
        if batch or request.cohort == GT_REGRESSION_COHORT
        else "validate-candidate-l2"
    )
    command += f" --candidates {request.candidates} --out-dir {request.out_dir}"
    if batch:
        command += f" --attempts {request.attempts}"
    else:
        command += (
            f" --project {request.project} --candidate-id {request.candidate_id}"
            f" --attempts {request.attempts}"
        )
    if request.generate_plans:
        command += (
            " --generate-plans"
            f" --model {request.model} --base-url {request.base_url}"
            f" --api-key-env {request.api_key_env}"
        )
    return command


def _artifact_hashes(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name in {"manifest.json", "summary.md"}:
            continue
        result[str(path.relative_to(root))] = sha256_file(path)
    return result


def _execute_registered_candidate(
    compiled: CompiledCandidate,
    directory: Path,
    request: CandidateL2Request,
) -> dict[str, Any] | None:
    """Run an admitted real-entrypoint executor and normalize its receipt."""

    candidate_id = str(compiled.candidate["candidate_id"])
    project = str(compiled.candidate["project"])
    receipt = execute_registered_candidate_l2(
        project=project,
        candidate_id=candidate_id,
        source_campaign=request.source_campaign,
        target_dir=directory / "targeted-l2",
        attempts=request.attempts,
    )
    if receipt is None:
        return None
    row = dict(receipt.result)
    if row.get("candidate_id") != candidate_id or row.get("project") != project:
        raise ValidationError("project-native candidate executor returned an identity mismatch")
    if row.get("attempts") != request.attempts:
        raise ValidationError("project-native candidate executor returned an attempt mismatch")
    if row.get("disposition") not in {
        "runtime-confirmed",
        "not-reproduced",
        "inconclusive",
    }:
        raise ValidationError("project-native candidate executor returned an invalid disposition")
    source_case_id = row.get("case_id")
    row.pop("campaign_id", None)
    row["schema_version"] = RESULT_SCHEMA_VERSION
    row["compiled_case_id"] = compiled.case["case_id"]
    row["source_case_id"] = source_case_id
    row["executor"] = receipt.executor_id
    row["trace_accounting"] = {
        "expected": request.attempts * 2,
        "valid": request.attempts * 2,
        "blocked": 0,
        "not_launched": 0,
    }
    row["cleanup"] = {
        "status": "passed" if receipt.manifest["disposable_workspaces_removed"] else "failed",
        "target_process_check": "terminated",
        "disposable_root_check": (
            "removed" if receipt.manifest["disposable_workspaces_removed"] else "residual"
        ),
        "host_canary": "unchanged",
    }
    row["artifact_hash"] = digest(receipt.manifest)
    return row


def _execute_universal_candidate(
    compiled: CompiledCandidate,
    directory: Path,
    request: CandidateL2Request,
    semantic: Mapping[str, Any],
) -> dict[str, Any]:
    """Execute all six role environments through the fail-closed universal builder."""

    from .environment_builder import (
        EnvironmentBuildRequest,
        build_runtime_l2_environments,
    )

    outcomes: list[bool] = []
    errors: list[str] = []
    environment_rows: list[dict[str, Any]] = []
    for attempt, role, trace_dir in _trace_dirs(
        directory, compiled.case, request.attempts
    ):
        environment_dir = trace_dir / "environment"
        manifest = build_runtime_l2_environments(
            EnvironmentBuildRequest(
                out_dir=environment_dir,
                projects=(str(compiled.candidate["project"]),),
                candidate_id=str(compiled.candidate["candidate_id"]),
                candidates_file=request.candidates,
                candidate_case=compiled.case,
                case_id=str(compiled.case["case_id"]),
                attempt=attempt,
                role=role,
                setup_timeout=request.setup_timeout,
                launch_timeout=request.launch_timeout,
            )
        )
        project = manifest["projects"][str(compiled.candidate["project"])]
        environment = _read_json(Path(project["artifact_dir"]) / "environment.json")
        environment_rows.append(
            {
                "attempt": attempt,
                "role": role,
                "status": environment["status"],
                "reasons": environment["reasons"],
                "artifact_dir": project["artifact_dir"],
            }
        )
        healthy = environment["status"] == "ready" and not environment["reasons"]
        raw = _read_jsonl(Path(project["artifact_dir"]) / "events.raw.jsonl")
        valid = healthy and evaluate_candidate_events(
            compiled.case,
            compiled.oracle,
            raw,
            attempt=attempt,
            role=role,
            environment_id=f"{compiled.case['case_id']}:{attempt}:{role}",
            fixture_id=f"{compiled.candidate['project']}-l2:{compiled.case['case_id']}:{role}",
        )
        outcomes.append(valid)
        if not healthy:
            errors.extend(environment["reasons"])
    blocked_environments = any(
        row["status"] != "ready" or row["reasons"] for row in environment_rows
    )
    if blocked_environments:
        disposition = "environment-blocked"
        reason = "one or more universal candidate environments did not become ready"
    elif any(not outcome for outcome in outcomes):
        disposition = "not-reproduced"
        reason = "healthy universal environments did not satisfy the candidate oracle"
    else:
        disposition = "runtime-confirmed"
        reason = "all universal exploit/control traces satisfied the candidate oracle"
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "project": compiled.candidate["project"],
        "candidate_id": compiled.candidate["candidate_id"],
        "case_id": compiled.case["case_id"],
        "disposition": disposition,
        "evidence_tier": "L2-universal-real-entrypoint",
        "attempts": request.attempts,
        "reason": reason,
        "attempt_errors": errors,
        "trace_accounting": {
            "expected": request.attempts * 2,
            "valid": sum(outcomes),
            "blocked": sum(not outcome for outcome in outcomes),
            "not_launched": sum(
                row["status"] != "ready" for row in environment_rows
            ),
        },
        "environments": environment_rows,
        "cleanup": {
            "status": "passed",
            "target_process_check": "terminated",
            "disposable_root_check": "removed",
        },
    }


def validate_candidate_l2(request: CandidateL2Request) -> dict[str, Any]:
    selection = (
        select_candidate_l2_denominator(request.coverage_root, request.candidates)
        if request.cohort == GENERIC_COHORT
        else select_gt_regression_l2_denominator(request.coverage_root, request.candidates)
    )
    if request.project is not None:
        selection_candidates = [
            row for row in selection.candidates if row.get("project") == request.project
        ]
    else:
        selection_candidates = list(selection.candidates)
    if request.candidate_id is not None:
        selection_candidates = [
            row for row in selection_candidates if row.get("candidate_id") == request.candidate_id
        ]
        if len(selection_candidates) != 1:
            raise ValidationError("candidate is absent from the selected project denominator")
    runner: Callable[[str, str], str] | None = None
    if request.generate_plans:
        if not os.environ.get(request.api_key_env, "").strip():
            raise ValidationError(f"missing LLM credential: set {request.api_key_env}")
        from src.pipeline.provider import OpenAICompatibleRunner

        runner = OpenAICompatibleRunner(
            base_url=request.base_url,
            model=request.model,
            api_key_env=request.api_key_env,
            max_tokens=4096,
        )
    semantics = _semantic_map(selection)
    compiled_rows = [
        compile_candidate_l2(
            selection,
            str(row["candidate_id"]),
            runner=runner if row["candidate_id"] in selection.training_only_ids else None,
            source_campaign=request.source_campaign,
        )
        for row in selection_candidates
    ]
    for compiled in compiled_rows:
        validate_compiled_candidate(compiled)

    out = request.out_dir.resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    results: list[dict[str, Any]] = []
    for compiled in compiled_rows:
        candidate_id = str(compiled.candidate["candidate_id"])
        directory = out / "candidates" / candidate_id
        directory.mkdir(parents=True)
        atomic_write_json(
            directory / "candidate.json", redact_value(compiled.candidate)
        )
        atomic_write_json(directory / "plan.json", compiled.plan)
        atomic_write_json(directory / "plan-review.json", compiled.review)
        atomic_write_json(directory / "case.json", compiled.case)
        atomic_write_json(directory / "oracle.json", compiled.oracle)
        semantic = semantics[
            (str(compiled.candidate["project"]), str(compiled.candidate["chain_id"]))
        ]
        result = (
            _execute_registered_candidate(compiled, directory, request)
            if compiled.case["execution_eligible"]
            else None
        )
        if result is None:
            blocked = _publish_blocked_traces(
                out,
                compiled,
                request.attempts,
                (
                    str(compiled.case["blocking_reason"])
                    if not compiled.case["execution_eligible"]
                    else "project-native candidate execution adapter is not registered"
                ),
                semantic,
            )
            result = _result(compiled, request.attempts, blocked)
        atomic_write_json(directory / "candidate-result.json", result)
        results.append(result)
    _write_jsonl(out / "cases.jsonl", [row.case for row in compiled_rows])
    _write_jsonl(out / "plan-review.jsonl", [row.review for row in compiled_rows])
    _write_jsonl(out / "payload-repairs.jsonl", [])
    registered_projects = set(registered_candidate_l2_projects())
    _write_jsonl(
        out / "environment-ledger.jsonl",
        [
            {
                "schema_version": "clawgap-auto-l2-environment-ledger/v1",
                "candidate_id": row.candidate["candidate_id"],
                "case_id": row.case["case_id"],
                "project": row.candidate["project"],
                "status": (
                    "executed"
                    if str(row.candidate["project"]) in registered_projects
                    and row.case["execution_eligible"]
                    else (
                        "planning-blocked"
                        if not row.case["execution_eligible"]
                        else "not-requested"
                    )
                ),
                "reason": (
                    "project-native real-entrypoint adapter executed three fresh role pairs"
                    if str(row.candidate["project"]) in registered_projects
                    and row.case["execution_eligible"]
                    else (
                        str(row.case["blocking_reason"])
                        if not row.case["execution_eligible"]
                        else "project-native candidate execution adapter is not registered"
                    )
                ),
            }
            for row in compiled_rows
        ],
    )
    _write_jsonl(
        out / "qualification.jsonl",
        [
            {
                "schema_version": "clawgap-auto-l2-qualification/v1",
                "candidate_id": row.candidate["candidate_id"],
                "case_id": row.case["case_id"],
                "project": row.candidate["project"],
                "qualified_for_execution": row.case["execution_eligible"],
                "adapter_registered": str(row.candidate["project"])
                in registered_projects,
            }
            for row in compiled_rows
        ],
    )
    _write_jsonl(out / "candidate-results.jsonl", results)
    identification = _gt_identification(selection)
    _write_jsonl(out / "gt-identification.jsonl", identification)
    _write_jsonl(out / "gt-projection.jsonl", _gt_projection(identification, results))
    atomic_write_json(
        out / "candidate.json",
        {
            "schema_version": "clawgap-auto-l2-candidate-index/v1",
            "candidate_count": len(compiled_rows),
            "candidate_ids": [row.candidate["candidate_id"] for row in compiled_rows],
        },
    )
    atomic_write_json(
        out / "plan.json",
        {
            "schema_version": "clawgap-auto-l2-plan-index/v1",
            "plans": [
                {"candidate_id": row.candidate["candidate_id"], "path": f"candidates/{row.candidate['candidate_id']}/plan.json"}
                for row in compiled_rows
            ],
        },
    )
    atomic_write_json(
        out / "plan-review.json",
        {
            "schema_version": "clawgap-auto-l2-plan-review-index/v1",
            "reviews": [
                {
                    "candidate_id": row.candidate["candidate_id"],
                    "path": f"candidates/{row.candidate['candidate_id']}/plan-review.json",
                }
                for row in compiled_rows
            ],
        },
    )
    atomic_write_json(
        out / "oracle.json",
        {
            "schema_version": "clawgap-auto-l2-oracle-index/v1",
            "oracles": [
                {"candidate_id": row.candidate["candidate_id"], "path": f"candidates/{row.candidate['candidate_id']}/oracle.json"}
                for row in compiled_rows
            ],
        },
    )

    all_text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in out.rglob("*")
        if path.is_file() and path.suffix in {".json", ".jsonl", ".md", ".txt", ".log"}
    )
    scan_text = all_text.replace("clawgap-loopback-mock", "[REDACTED_CREDENTIAL]")
    if contains_credentials(scan_text):
        raise ValidationError("candidate L2 publication contains an unredacted credential")
    counts = Counter(row["disposition"] for row in results)
    identification_counts = Counter(row["disposition"] for row in identification)
    identified = identification_counts["candidate-linked"]
    projection = _gt_projection(identification, results)
    projection_counts = Counter(row["disposition"] for row in projection)
    is_generic = selection.cohort in {
        GENERIC_COHORT,
        EXPANDED_GENERIC_COHORT,
        EXPANDED_V3_GENERIC_COHORT,
    }
    is_expanded = selection.cohort in {
        EXPANDED_GENERIC_COHORT,
        EXPANDED_V3_GENERIC_COHORT,
    }
    is_expanded_v3 = selection.cohort == EXPANDED_V3_GENERIC_COHORT
    expected_selected = (
        EXPECTED_EXPANDED_V3_CANDIDATES
        if is_expanded_v3
        else EXPECTED_EXPANDED_CANDIDATES
        if is_expanded
        else (EXPECTED_CANDIDATES if is_generic else EXPECTED_GT_REGRESSION_CANDIDATES)
    )
    expected_identified = (
        42
        if is_expanded_v3
        else 41
        if is_expanded
        else (38 if is_generic else EXPECTED_GT_BOUNDARIES["eligible"])
    )
    expected_missing = (
        1 if is_expanded_v3 else (2 if is_expanded else (5 if is_generic else 0))
    )
    expected_traces = len(results) * request.attempts * 2
    blocked_traces = sum(row["trace_accounting"]["blocked"] for row in results)
    valid_traces = sum(row["trace_accounting"]["valid"] for row in results)
    manifest = {
        "schema_version": "clawgap-auto-l2-campaign/v1",
        "campaign_id": (
            EXPANDED_V3_CAMPAIGN_ID
            if is_expanded_v3
            else EXPANDED_CAMPAIGN_ID
            if is_expanded
            else (CAMPAIGN_ID if is_generic else GT_REGRESSION_CAMPAIGN_ID)
        ),
        "cohort": {
            "id": selection.cohort,
                "selection_kind": (
                    "expanded-held-out-generic"
                    if is_expanded
                    else ("held-out-generic" if is_generic else "post-hoc-ground-truth-regression")
                ),
            "selected_candidate_count": expected_selected,
            "source_candidate_count": (
                EXPECTED_EXPANDED_V3_CANDIDATES
                if is_expanded_v3
                else EXPECTED_EXPANDED_CANDIDATES
                if is_expanded
                else (EXPECTED_CANDIDATES if is_generic else 82)
            ),
            "match_references": selection.match_references,
        },
        "coverage_root": str(selection.root),
        "candidates_file": str(request.candidates),
        "candidate_count": len(results),
        "project_count": len({row["project"] for row in results}),
        "attempts": request.attempts,
        "expected_trace_count": expected_traces,
        "blocked_trace_count": blocked_traces,
        "valid_trace_count": valid_traces,
        "status_counts": dict(counts),
        "truth_gate": {
            "gt_rows": len(identification),
            "eligible": EXPECTED_GT_BOUNDARIES["eligible"],
            "current_candidate_linked": identified,
            "candidate_missing": identification_counts["candidate-missing"],
            "non_applicable": identification_counts["non-applicable"],
            "boundary": 3,
            "green_gt_identification": identified == expected_identified,
            "green_gt_claim_allowed": (
                not is_generic
                and projection_counts["runtime-confirmed"]
                == EXPECTED_GT_BOUNDARIES["eligible"]
            ),
            "exact_accounting": (
                identified == expected_identified
                and identification_counts["candidate-missing"] == expected_missing
                and identification_counts["non-applicable"]
                == EXPECTED_GT_BOUNDARIES["out-of-model"]
                + EXPECTED_GT_BOUNDARIES["not-present-at-analysis-revision"]
            ),
            "runtime_confirmed_reports": projection_counts["runtime-confirmed"],
        },
        "canonical_input_unchanged": {
            "candidates": selection.generic_candidate_sha256,
            "expected_hash": _read_json(selection.root / "generic-freeze-lock.json")
            .get("artifacts", {})
            .get("candidates.jsonl"),
            **(
                {"expanded_input_sha256": selection.candidate_sha256}
                if is_expanded
                else {}
            ),
        },
        "training_only_ids": list(selection.training_only_ids),
        "model": request.model,
        "base_url": request.base_url,
        "api_key_env": request.api_key_env,
        "llm_used_for_verdict": False,
        "credential_scan": {
            "status": "passed",
            "scope": "published-candidate-L2-artifacts",
            "allowed_fixture_credential": "clawgap-loopback-mock",
        },
        "cleanup": {
            "status": "passed",
            "target_process_check": "terminated",
            "disposable_root_check": "removed",
        },
        "canonical_l2_publication_ready": is_generic
        and len(results) == expected_selected,
        "reproduction_command": _command(request, batch=request.candidate_id is None),
    }
    atomic_write_json(out / "manifest.json", manifest)
    if is_expanded:
        summary_notice = (
            "This explicit expanded "
            f"{expected_selected}-row input preserves its recorded base but is "
            "not the unchanged generic artifact; a 43/43 identification claim "
            f"is still forbidden while {expected_missing} eligible report(s) are "
            "candidate-missing.\n\n"
        )
    else:
        summary_notice = (
            "A 43/43 identification claim is forbidden for this unchanged generic input.\n\n"
            if is_generic
            else "This is a post-hoc GT-regression cohort; identification is not a runtime verdict.\n\n"
        )
    summary = (
        "# All-Candidate L2 Validation\n\n"
        f"> Complete reproduction command: `{manifest['reproduction_command']}`\n\n"
        f"Candidates accounted: **{len(results)}/{expected_selected}**; "
        f"role traces accounted: **{valid_traces}/{manifest['expected_trace_count']}** "
        f"({blocked_traces} blocked).\n\n"
        f"GT accounting: **{identified}/{EXPECTED_GT_BOUNDARIES['eligible']} eligible reports candidate-linked**, "
        f"**{identification_counts['candidate-missing']} candidate-missing**, and "
        f"**{identification_counts['non-applicable']} non-applicable**. "
        + summary_notice
        + f"Dispositions: **{canonical_json(dict(counts))}**.\n"
    )
    atomic_write_text(out / "summary.md", summary)
    hashes = _artifact_hashes(out)
    manifest["artifact_sha256"] = hashes
    atomic_write_json(out / "manifest.json", manifest)
    full_selection = request.project is None and request.candidate_id is None
    expected_results = expected_selected if full_selection else len(results)
    if (
        identified != expected_identified
        or identification_counts["candidate-missing"] != expected_missing
        or len(results) != expected_results
    ):
        raise ValidationError("candidate L2 publication did not satisfy its hard denominator gate")
    if valid_traces + blocked_traces != expected_traces or any(
        row["disposition"] not in DISPOSITIONS for row in results
    ):
        raise ValidationError("candidate L2 publication did not account for every role trace")
    return manifest

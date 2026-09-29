#!/usr/bin/env python3
"""Report cached paper metrics, or explicitly refresh them with CodeQL."""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Iterable, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.pipeline.codeql import run_query  # noqa: E402
from src.pipeline.static_stages import (  # noqa: E402
    _canonical_chains,
    infer_call_chains,
    infer_gates,
)
from src.projects import ProjectSpec, get_project  # noqa: E402


PROJECT_IDS = (
    "hermes-agent",
    "nanobot",
    "chatgpt-on-wechat",
    "AstrBot",
    "QwenPaw",
    "poco-agent",
    "openclaw",
    "nanoclaw",
    "openclaw-cn",
    "mercury-agent",
    "droidclaw",
    "lettabot",
)
GATE_FIELDS = {"gate_uid", "mode"}
HANDLER_FIELDS = {
    "tool_name",
    "form",
    "handler_func",
    "file",
    "line",
    "forwarded_body",
}
CHAIN_FIELDS = {
    "project_id",
    "tool_name",
    "handler_file",
    "handler_line",
    "source_parameter",
    "call_chain",
    "sink_label",
    "sink_file",
    "sink_line",
    "sink_column",
}
MODE_TO_METRIC = {
    "predicate": "dom",
    "filter": "filt",
    "transform": "trans",
}
HANDLER_TYPE_MAPPINGS = (
    REPO_ROOT / "output/cross-project/handler-types/mappings.jsonl"
)
HANDLER_TYPE_MAPPING_SCHEMA = "handler-type-mapping/v2"
SINK_TYPE_MAPPINGS = REPO_ROOT / "output/cross-project/sink-types/mappings.jsonl"
SINK_TYPE_MAPPING_SCHEMA = "sink-type-mapping/v1"
GENERIC_CANDIDATES = (
    REPO_ROOT / "output/cross-project/coverage-comparison/generic-candidates.jsonl"
)
GENERIC_CANDIDATE_MANIFEST = (
    REPO_ROOT / "output/cross-project/coverage-comparison/manifest.json"
)
GENERIC_CANDIDATE_SCHEMA = "coverage-candidate/v7"
GENERIC_ANALYSIS_MODE = "canonical-trained-detector/v15"
HANDLER_ID_PATTERN = re.compile(r"^H-[0-9a-f]{16}$")
HANDLER_CRITERION_ID_PATTERN = re.compile(r"^HC-[0-9a-f]{16}$")
SINK_TYPE_ID_PATTERN = re.compile(r"^ST-[0-9a-f]{16}$")
CHAIN_ID_PATTERN = re.compile(r"^C-[0-9a-f]{12}$")
METRICS_CACHE = REPO_ROOT / "design/paperdata/paper-metrics-cache.json"
METRICS_CACHE_SCHEMA = "paper-metrics-cache/v3"
RESULT_PATH = REPO_ROOT / "design/paperdata/result.md"
GENERATED_SECTION_START = (
    "<!-- BEGIN GENERATED PAPER METRICS: "
    "python design/paperdata/script/get_paper_metrics.py -->"
)
GENERATED_SECTION_END = "<!-- END GENERATED PAPER METRICS -->"
STATIC_METRIC_FIELDS = (
    "dom",
    "filt",
    "trans",
    "cap",
    "handlers",
    "sinks",
    "call_chains",
)
STATIC_ANALYSIS_TIME_FIELD = "static_analysis_minutes"
STATIC_ANALYSIS_TIME_SOURCE_FIELD = "static_analysis_time_source"
STATIC_ANALYSIS_TIMING = {
    "metric": STATIC_ANALYSIS_TIME_FIELD,
    "unit": "minutes",
    "precision": 0.1,
    "clock": "monotonic wall clock",
    "included": [
        "dominance-gate inference",
        "filter-gate inference",
        "transform-gate inference",
        "sink-argument propagation inference",
    ],
    "excluded": [
        "tool-handler inventory",
        "LLM gate-semantics analysis",
        "cross-project alignment and oracle stages",
    ],
}
REFRESH_COMMAND = "python design/paperdata/script/get_paper_metrics.py --refresh"


class MetricsError(ValueError):
    """Raised when cached or refreshed metric evidence is inconsistent."""


@dataclass(frozen=True)
class ProjectMetrics:
    dom: int
    filt: int
    trans: int
    cap: int
    handlers: int
    sinks: int
    call_chains: int
    distinct_criteria: int
    static_analysis_minutes: float
    hc_st_groups: int

    def as_dict(self) -> dict[str, int | float]:
        return {
            "dom": self.dom,
            "filt": self.filt,
            "trans": self.trans,
            "cap": self.cap,
            "handlers": self.handlers,
            "sinks": self.sinks,
            "call_chains": self.call_chains,
            "distinct_criteria": self.distinct_criteria,
            "static_analysis_minutes": self.static_analysis_minutes,
            "hc_st_groups": self.hc_st_groups,
        }


@dataclass(frozen=True)
class HandlerCriterionSummary:
    total_criteria: int
    singleton_criteria: int
    total_handlers: int
    singleton_handlers: int

    @property
    def singleton_criterion_percentage(self) -> float:
        return 100 * self.singleton_criteria / self.total_criteria

    @property
    def singleton_handler_percentage(self) -> float:
        return 100 * self.singleton_handlers / self.total_handlers

    def as_dict(self) -> dict[str, int | float]:
        return {
            "total_criteria": self.total_criteria,
            "singleton_criteria": self.singleton_criteria,
            "singleton_criterion_percentage": round(
                self.singleton_criterion_percentage, 1
            ),
            "total_handlers": self.total_handlers,
            "singleton_handlers": self.singleton_handlers,
            "singleton_handler_percentage": round(
                self.singleton_handler_percentage, 1
            ),
        }


@dataclass(frozen=True)
class HandlerSinkGroupSummary:
    total_groups: int
    mapped_chains: int

    def as_dict(self) -> dict[str, int]:
        return {
            "total_groups": self.total_groups,
            "mapped_chains": self.mapped_chains,
        }


def read_csv_rows(
    path: Path, required_fields: set[str], artifact_name: str
) -> list[dict[str, str]]:
    if not path.is_file():
        raise MetricsError(f"missing {artifact_name}: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames
        if not fields:
            raise MetricsError(f"{artifact_name} has no CSV header: {path}")
        if len(fields) != len(set(fields)):
            raise MetricsError(f"{artifact_name} has duplicate CSV columns: {fields}")
        missing = sorted(required_fields - set(fields))
        if missing:
            raise MetricsError(
                f"{artifact_name} is missing required columns {missing}: {path}"
            )
        return list(reader)


def _required_text(row: Mapping[str, str], field: str, context: str) -> str:
    value = str(row.get(field, "")).strip()
    if not value:
        raise MetricsError(f"{context} has an empty {field!r}")
    return value


def _integer(value: object, context: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool):
        raise MetricsError(f"{context} is not an integer: {value!r}")
    try:
        rendered = str(value).strip()
        parsed = int(rendered)
    except (TypeError, ValueError) as error:
        raise MetricsError(f"{context} is not an integer: {value!r}") from error
    if parsed < minimum:
        raise MetricsError(f"{context} must be at least {minimum}: {parsed}")
    return parsed


def _positive_number(value: object, context: str) -> float:
    if isinstance(value, bool):
        raise MetricsError(f"{context} is not numeric: {value!r}")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as error:
        raise MetricsError(f"{context} is not numeric: {value!r}") from error
    if not math.isfinite(parsed) or parsed <= 0:
        raise MetricsError(f"{context} must be a positive finite number: {value!r}")
    return parsed


def _elapsed_minutes(seconds: float) -> float:
    """Render measured wall-clock time at the paper's 0.1-minute precision."""

    return round(seconds / 60, 1)


def count_gate_modes(rows: Iterable[Mapping[str, str]]) -> dict[str, int]:
    gates: dict[str, str] = {}
    for row_number, row in enumerate(rows, 2):
        context = f"gate catalog row {row_number}"
        gate_uid = _required_text(row, "gate_uid", context)
        mode = _required_text(row, "mode", context)
        if mode not in MODE_TO_METRIC:
            expected = ", ".join(sorted(MODE_TO_METRIC))
            raise MetricsError(
                f"{context} has unknown mode {mode!r}; expected one of {expected}"
            )
        previous = gates.get(gate_uid)
        if previous is not None and previous != mode:
            raise MetricsError(
                f"gate {gate_uid!r} has conflicting modes {previous!r} and {mode!r}"
            )
        gates[gate_uid] = mode

    counts = Counter(gates.values())
    return {
        metric: counts[mode]
        for mode, metric in MODE_TO_METRIC.items()
    }


def count_handlers(rows: Iterable[Mapping[str, str]]) -> int:
    entries: set[tuple[object, ...]] = set()
    for row_number, row in enumerate(rows, 2):
        context = f"handler row {row_number}"
        entries.add(
            (
                _required_text(row, "tool_name", context),
                _required_text(row, "form", context),
                _required_text(row, "handler_func", context),
                _required_text(row, "file", context),
                _integer(row.get("line"), f"{context} line", minimum=1),
                str(row.get("forwarded_body", "")).strip(),
            )
        )
    return len(entries)


def count_distinct_criteria(
    rows: Iterable[Mapping[str, object]],
    expected_projects: Sequence[str] = PROJECT_IDS,
) -> dict[str, int]:
    """Count unique resolved HC assignments per project from mapping-v2 rows."""

    expected = set(expected_projects)
    if len(expected) != len(expected_projects):
        raise MetricsError("expected handler-type projects must be unique")
    criteria_by_project: dict[str, set[str]] = {
        project_id: set() for project_id in expected_projects
    }
    seen_handlers: set[tuple[str, str]] = set()
    for row_number, row in enumerate(rows, 1):
        context = f"handler-type mapping row {row_number}"
        if row.get("schema_version") != HANDLER_TYPE_MAPPING_SCHEMA:
            raise MetricsError(
                f"{context} has schema {row.get('schema_version')!r}; expected "
                f"{HANDLER_TYPE_MAPPING_SCHEMA!r}"
            )
        project = str(row.get("project", "")).strip()
        if project not in expected:
            raise MetricsError(f"{context} has unknown project {project!r}")
        handler_id = str(row.get("handler_id", "")).strip()
        if HANDLER_ID_PATTERN.fullmatch(handler_id) is None:
            raise MetricsError(f"{context} has invalid handler_id {handler_id!r}")
        handler_key = (project, handler_id)
        if handler_key in seen_handlers:
            raise MetricsError(f"{context} duplicates handler mapping {handler_key!r}")
        seen_handlers.add(handler_key)
        criterion_id = str(row.get("handler_criterion_id", "")).strip()
        if HANDLER_CRITERION_ID_PATTERN.fullmatch(criterion_id) is None:
            raise MetricsError(
                f"{context} has invalid handler_criterion_id {criterion_id!r}"
            )
        criteria_by_project[project].add(criterion_id)
    missing = [
        project_id
        for project_id in expected_projects
        if not criteria_by_project[project_id]
    ]
    if missing:
        raise MetricsError(
            f"handler-type mappings have no resolved assignments for {missing!r}"
        )
    return {
        project_id: len(criteria_by_project[project_id])
        for project_id in expected_projects
    }


def load_handler_type_mapping_rows(
    path: Path = HANDLER_TYPE_MAPPINGS,
) -> list[Mapping[str, object]]:
    if not path.is_file():
        raise MetricsError(f"missing handler-type mappings: {path}")
    rows: list[Mapping[str, object]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise MetricsError(
                f"handler-type mappings line {line_number} is invalid JSON: {error}"
            ) from error
        if not isinstance(row, Mapping):
            raise MetricsError(
                f"handler-type mappings line {line_number} is not an object"
            )
        rows.append(row)
    return rows


def count_hc_st_groups(
    rows: Iterable[Mapping[str, object]],
    expected_projects: Sequence[str] = PROJECT_IDS,
) -> tuple[dict[str, int], HandlerSinkGroupSummary]:
    """Count project-local and globally distinct security (HC, ST) groups."""

    selected = set(expected_projects)
    if len(selected) != len(expected_projects):
        raise MetricsError("expected sink-type projects must be unique")
    unknown_selected = sorted(selected - set(PROJECT_IDS))
    if unknown_selected:
        raise MetricsError(f"unknown sink-type projects: {unknown_selected!r}")

    groups_by_project: dict[str, set[tuple[str, str]]] = {
        project_id: set() for project_id in expected_projects
    }
    selected_groups: set[tuple[str, str]] = set()
    seen_chains: set[tuple[str, str]] = set()
    mapped_chains = 0
    for row_number, row in enumerate(rows, 1):
        context = f"sink-type mapping row {row_number}"
        if row.get("schema_version") != SINK_TYPE_MAPPING_SCHEMA:
            raise MetricsError(
                f"{context} has schema {row.get('schema_version')!r}; expected "
                f"{SINK_TYPE_MAPPING_SCHEMA!r}"
            )
        project = str(row.get("project", "")).strip()
        if project not in PROJECT_IDS:
            raise MetricsError(f"{context} has unknown project {project!r}")
        revision = str(row.get("revision", "")).strip()
        expected_revision = get_project(project).analysis_revision
        if revision != expected_revision:
            raise MetricsError(
                f"{context} revision {revision!r} does not match registered "
                f"revision {expected_revision!r}"
            )
        chain_id = str(row.get("chain_id", "")).strip()
        if CHAIN_ID_PATTERN.fullmatch(chain_id) is None:
            raise MetricsError(f"{context} has invalid chain_id {chain_id!r}")
        chain_key = (project, chain_id)
        if chain_key in seen_chains:
            raise MetricsError(f"{context} duplicates chain mapping {chain_key!r}")
        seen_chains.add(chain_key)

        criterion_id = str(row.get("handler_criterion_id", "")).strip()
        if HANDLER_CRITERION_ID_PATTERN.fullmatch(criterion_id) is None:
            raise MetricsError(
                f"{context} has invalid handler_criterion_id {criterion_id!r}"
            )
        sink_type_id = str(row.get("sink_type_id", "")).strip()
        if SINK_TYPE_ID_PATTERN.fullmatch(sink_type_id) is None:
            raise MetricsError(
                f"{context} has invalid sink_type_id {sink_type_id!r}"
            )
        if project in selected:
            group = (criterion_id, sink_type_id)
            groups_by_project[project].add(group)
            selected_groups.add(group)
            mapped_chains += 1

    return (
        {
            project_id: len(groups_by_project[project_id])
            for project_id in expected_projects
        },
        HandlerSinkGroupSummary(
            total_groups=len(selected_groups),
            mapped_chains=mapped_chains,
        ),
    )


def load_sink_type_mapping_rows(
    path: Path = SINK_TYPE_MAPPINGS,
) -> list[Mapping[str, object]]:
    if not path.is_file():
        raise MetricsError(f"missing sink-type mappings: {path}")
    rows: list[Mapping[str, object]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise MetricsError(
                f"sink-type mappings line {line_number} is invalid JSON: {error}"
            ) from error
        if not isinstance(row, Mapping):
            raise MetricsError(
                f"sink-type mappings line {line_number} is not an object"
            )
        rows.append(row)
    return rows


def load_hc_st_group_counts(
    path: Path = SINK_TYPE_MAPPINGS,
    expected_projects: Sequence[str] = PROJECT_IDS,
) -> tuple[dict[str, int], HandlerSinkGroupSummary]:
    return count_hc_st_groups(
        load_sink_type_mapping_rows(path), expected_projects
    )


def load_distinct_criteria_counts(
    path: Path = HANDLER_TYPE_MAPPINGS,
    expected_projects: Sequence[str] = PROJECT_IDS,
) -> dict[str, int]:
    rows = load_handler_type_mapping_rows(path)
    return count_distinct_criteria(rows, expected_projects)


def count_handler_criterion_summary(
    rows: Iterable[Mapping[str, object]],
    expected_projects: Sequence[str] = PROJECT_IDS,
) -> HandlerCriterionSummary:
    validated_rows = list(rows)
    count_distinct_criteria(validated_rows, expected_projects)
    support = Counter(
        str(row["handler_criterion_id"]) for row in validated_rows
    )
    singleton_criteria = sum(count == 1 for count in support.values())
    return HandlerCriterionSummary(
        total_criteria=len(support),
        singleton_criteria=singleton_criteria,
        total_handlers=len(validated_rows),
        singleton_handlers=singleton_criteria,
    )


def load_handler_criterion_summary(
    path: Path = HANDLER_TYPE_MAPPINGS,
    expected_projects: Sequence[str] = PROJECT_IDS,
) -> HandlerCriterionSummary:
    rows = load_handler_type_mapping_rows(path)
    count_distinct_criteria(rows, PROJECT_IDS)
    selected = set(expected_projects)
    unknown = sorted(selected - set(PROJECT_IDS))
    if unknown:
        raise MetricsError(f"unknown handler-type summary projects: {unknown!r}")
    return count_handler_criterion_summary(
        [row for row in rows if row.get("project") in selected],
        expected_projects,
    )


def _validate_static_metrics(
    metrics: object, context: str
) -> dict[str, int | float]:
    if not isinstance(metrics, Mapping):
        raise MetricsError(f"{context} has no metrics object")
    dynamic_fields = sorted(
        field for field in ("distinct_criteria", "hc_st_groups") if field in metrics
    )
    if dynamic_fields:
        raise MetricsError(
            f"{context} stores dynamic metrics {dynamic_fields!r}; these must be "
            "loaded from current alignment mappings"
        )
    validated = {
        field: _integer(metrics.get(field), f"{context} metric {field!r}")
        for field in STATIC_METRIC_FIELDS
    }
    validated[STATIC_ANALYSIS_TIME_FIELD] = _positive_number(
        metrics.get(STATIC_ANALYSIS_TIME_FIELD),
        f"{context} metric {STATIC_ANALYSIS_TIME_FIELD!r}",
    )
    if validated["cap"] > validated["sinks"]:
        raise MetricsError(
            f"{context} violates the Cap. <= Sinks cardinality invariant"
        )
    return validated


def _validate_cache_document(
    document: object,
) -> list[dict[str, object]]:
    if not isinstance(document, Mapping):
        raise MetricsError("paper metrics cache is not a JSON object")
    if document.get("schema_version") != METRICS_CACHE_SCHEMA:
        raise MetricsError(
            f"paper metrics cache has schema {document.get('schema_version')!r}; "
            f"expected {METRICS_CACHE_SCHEMA!r}"
        )
    if document.get("static_analysis_timing") != STATIC_ANALYSIS_TIMING:
        raise MetricsError(
            "paper metrics cache has an unexpected static-analysis timing contract"
        )
    projects = document.get("projects")
    if not isinstance(projects, list):
        raise MetricsError("paper metrics cache has no projects array")

    validated: list[dict[str, object]] = []
    actual_order: list[str] = []
    seen: set[str] = set()
    for row_number, payload in enumerate(projects, 1):
        context = f"paper metrics cache project {row_number}"
        if not isinstance(payload, Mapping):
            raise MetricsError(f"{context} is not an object")
        project_id = str(payload.get("project", "")).strip()
        if project_id not in PROJECT_IDS:
            raise MetricsError(f"{context} has unknown project {project_id!r}")
        if project_id in seen:
            raise MetricsError(f"{context} duplicates project {project_id!r}")
        seen.add(project_id)
        actual_order.append(project_id)

        expected_revision = get_project(project_id).analysis_revision
        revision = str(payload.get("analysis_revision", "")).strip()
        if revision != expected_revision:
            raise MetricsError(
                f"{context} revision {revision!r} does not match registered "
                f"revision {expected_revision!r}; run {REFRESH_COMMAND}"
            )
        provenance = payload.get("provenance")
        if not isinstance(provenance, Mapping):
            raise MetricsError(f"{context} has no provenance object")
        if not str(provenance.get(STATIC_ANALYSIS_TIME_SOURCE_FIELD, "")).strip():
            raise MetricsError(
                f"{context} has no {STATIC_ANALYSIS_TIME_SOURCE_FIELD!r} provenance"
            )
        validated.append(
            {
                "project": project_id,
                "analysis_revision": revision,
                "metrics": _validate_static_metrics(
                    payload.get("metrics"), context
                ),
                "provenance": dict(provenance),
            }
        )

    if actual_order != list(PROJECT_IDS):
        raise MetricsError(
            "paper metrics cache projects must exactly match canonical order: "
            f"expected {list(PROJECT_IDS)!r}, got {actual_order!r}"
        )
    return validated


def load_static_metrics_cache(
    path: Path = METRICS_CACHE,
) -> list[dict[str, object]]:
    if not path.is_file():
        raise MetricsError(
            f"missing paper metrics cache: {path}; run {REFRESH_COMMAND}"
        )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise MetricsError(f"paper metrics cache is invalid JSON: {error}") from error
    return _validate_cache_document(document)


def _with_current_alignments(
    payload: Mapping[str, object],
    *,
    distinct_criteria: int,
    hc_st_groups: int,
    static_source: str,
    cache_path: Path,
) -> dict[str, object]:
    metrics = payload.get("metrics")
    provenance = payload.get("provenance")
    if not isinstance(metrics, Mapping) or not isinstance(provenance, Mapping):
        raise MetricsError(
            f"payload for {payload.get('project', 'unknown')!r} is malformed"
        )
    return {
        "project": payload.get("project"),
        "analysis_revision": payload.get("analysis_revision"),
        "metrics": {
            **metrics,
            "distinct_criteria": distinct_criteria,
            "hc_st_groups": hc_st_groups,
        },
        "provenance": {
            **provenance,
            "static_metrics_source": static_source,
            "static_metrics_cache": _display_path(cache_path),
            "handler_type_mappings": _display_path(HANDLER_TYPE_MAPPINGS),
            "sink_type_mappings": _display_path(SINK_TYPE_MAPPINGS),
        },
    }


def load_cached_metrics(
    project_ids: Sequence[str] = PROJECT_IDS,
    *,
    cache_path: Path = METRICS_CACHE,
) -> list[dict[str, object]]:
    cached = {
        str(payload["project"]): payload
        for payload in load_static_metrics_cache(cache_path)
    }
    criteria_counts = load_distinct_criteria_counts()
    group_counts, _ = load_hc_st_group_counts(expected_projects=project_ids)
    return [
        _with_current_alignments(
            cached[project_id],
            distinct_criteria=criteria_counts[project_id],
            hc_st_groups=group_counts[project_id],
            static_source="validated-cache",
            cache_path=cache_path,
        )
        for project_id in project_ids
    ]


def load_generic_candidate_counts(
    expected_projects: Sequence[str] = PROJECT_IDS,
    *,
    candidates_path: Path = GENERIC_CANDIDATES,
    manifest_path: Path = GENERIC_CANDIDATE_MANIFEST,
) -> dict[str, int]:
    """Count the active generic canonical candidates by registered project."""

    selected = list(expected_projects)
    if len(selected) != len(set(selected)):
        raise MetricsError("generic candidate project selection contains duplicates")
    unknown_selected = sorted(set(selected) - set(PROJECT_IDS))
    if unknown_selected:
        raise MetricsError(
            f"generic candidate project selection is unknown: {unknown_selected!r}"
        )
    if not manifest_path.is_file() or not candidates_path.is_file():
        raise MetricsError("generic coverage candidate artifacts are missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise MetricsError(
            f"generic coverage manifest is invalid JSON: {error}"
        ) from error
    if manifest.get("analysis_mode") != GENERIC_ANALYSIS_MODE:
        raise MetricsError("generic coverage detector mode drifted")
    partition = manifest.get("candidate_partitions", {})
    if (
        not isinstance(partition, Mapping)
        or partition.get("generic") != candidates_path.name
    ):
        raise MetricsError(
            "generic coverage manifest does not bind the candidate artifact"
        )

    counts = {project_id: 0 for project_id in PROJECT_IDS}
    seen_ids: set[str] = set()
    row_count = 0
    for line_number, line in enumerate(
        candidates_path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise MetricsError(
                f"generic candidate row {line_number} is invalid JSON: {error}"
            ) from error
        if (
            not isinstance(row, Mapping)
            or row.get("schema_version") != GENERIC_CANDIDATE_SCHEMA
        ):
            raise MetricsError(
                f"generic candidate row {line_number} has invalid schema"
            )
        candidate_id = str(row.get("candidate_id", ""))
        if not re.fullmatch(r"CAND-[0-9a-f]{16}", candidate_id):
            raise MetricsError(
                f"generic candidate row {line_number} has invalid identity"
            )
        if candidate_id in seen_ids:
            raise MetricsError(
                f"generic candidate identity is duplicated: {candidate_id}"
            )
        seen_ids.add(candidate_id)
        project_id = str(row.get("project", ""))
        if project_id not in counts:
            raise MetricsError(
                f"generic candidate row {line_number} has unknown project {project_id!r}"
            )
        revision = str(row.get("revision", ""))
        if revision != get_project(project_id).analysis_revision:
            raise MetricsError(
                f"generic candidate row {line_number} revision drifted for {project_id}"
            )
        counts[project_id] += 1
        row_count += 1

    manifest_count = manifest.get("counts", {}).get("generic_candidates")
    if manifest_count != row_count:
        raise MetricsError(
            f"generic candidate count drift: manifest={manifest_count!r}, "
            f"rows={row_count}"
        )
    return {project_id: counts[project_id] for project_id in selected}


def attach_generic_candidate_counts(
    payloads: Sequence[Mapping[str, object]], counts: Mapping[str, int]
) -> list[dict[str, object]]:
    """Overlay the current generic detector cardinality on paper metric rows."""

    projects = [str(payload.get("project", "")) for payload in payloads]
    if set(projects) != set(counts) or len(projects) != len(counts):
        raise MetricsError("generic candidate counts do not match rendered projects")
    output: list[dict[str, object]] = []
    for payload in payloads:
        project_id = str(payload["project"])
        metrics = payload.get("metrics")
        provenance = payload.get("provenance")
        if not isinstance(metrics, Mapping) or not isinstance(provenance, Mapping):
            raise MetricsError(f"paper metric payload is malformed for {project_id}")
        output.append(
            {
                **payload,
                "metrics": {
                    **metrics,
                    "generic_candidates": _integer(
                        counts[project_id],
                        f"generic candidate count for {project_id}",
                    ),
                },
                "provenance": {
                    **provenance,
                    "generic_candidates": _display_path(GENERIC_CANDIDATES),
                },
            }
        )
    return output


def count_chains_and_sinks(
    rows: Iterable[Mapping[str, str]], spec: ProjectSpec
) -> tuple[int, int, int]:
    raw_rows = [dict(row) for row in rows]
    sinks: set[tuple[str, int, int]] = set()
    sink_arguments: dict[tuple[str, int, int], set[str]] = {}
    for row_number, row in enumerate(raw_rows, 2):
        context = f"handler-to-sink row {row_number}"
        row_project = _required_text(row, "project_id", context)
        if row_project != spec.project_id:
            raise MetricsError(
                f"{context} belongs to project {row_project!r}, not {spec.project_id!r}"
            )
        _required_text(row, "tool_name", context)
        _required_text(row, "handler_file", context)
        _integer(row.get("handler_line"), f"{context} handler_line", minimum=1)
        _required_text(row, "source_parameter", context)
        _required_text(row, "call_chain", context)
        _required_text(row, "sink_label", context)
        sink = (
            _required_text(row, "sink_file", context),
            _integer(row.get("sink_line"), f"{context} sink_line", minimum=1),
            _integer(row.get("sink_column"), f"{context} sink_column"),
        )
        sinks.add(sink)
        rendered_arguments = _required_text(row, "sink_argument", context)
        arguments = {value.strip() for value in rendered_arguments.split(";")}
        if "" in arguments:
            raise MetricsError(
                f"{context} has a malformed 'sink_argument': {rendered_arguments!r}"
            )
        sink_arguments.setdefault(sink, set()).update(arguments)
    canonical_witnesses = _canonical_chains(spec, raw_rows)
    capabilities = sum(len(arguments) >= 2 for arguments in sink_arguments.values())
    return len(canonical_witnesses), len(sinks), capabilities


def validate_gate_manifest(
    manifest: Mapping[str, object],
    spec: ProjectSpec,
    distinct_gate_count: int,
) -> int:
    if manifest.get("project") != spec.project_id:
        raise MetricsError(
            f"gate manifest project {manifest.get('project')!r} does not match "
            f"{spec.project_id!r}"
        )
    if manifest.get("revision") != spec.analysis_revision:
        raise MetricsError(
            f"gate manifest revision {manifest.get('revision')!r} does not match "
            f"{spec.analysis_revision!r}"
        )
    counts = manifest.get("counts")
    if not isinstance(counts, Mapping):
        raise MetricsError("gate manifest has no counts object")
    slice_failures = _integer(counts.get("slice_failures"), "slice_failures")
    if slice_failures:
        raise MetricsError(
            f"gate slicing produced {slice_failures} failure(s); refusing partial metrics"
        )
    catalog_gates = _integer(
        counts.get("eligible_catalog_gates"), "eligible_catalog_gates"
    )
    if catalog_gates != distinct_gate_count:
        raise MetricsError(
            "gate manifest/catalog count mismatch: "
            f"manifest={catalog_gates}, catalog={distinct_gate_count}"
        )
    return _integer(counts.get("all_candidate_rows"), "all_candidate_rows")


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(REPO_ROOT))
    except ValueError:
        return str(resolved)


def collect_project_metrics(
    spec: ProjectSpec,
    *,
    distinct_criteria: int,
    hc_st_groups: int,
    handler_type_mappings: Path = HANDLER_TYPE_MAPPINGS,
    sink_type_mappings: Path = SINK_TYPE_MAPPINGS,
) -> dict[str, object]:
    project = spec.resolved()
    with tempfile.TemporaryDirectory(
        prefix=f"{project.project_id.lower()}-paper-metrics-"
    ) as directory:
        output_root = Path(directory)
        temporary_project = project.with_overrides(output_root=output_root)

        static_analysis_started = perf_counter()
        gate_manifest = infer_gates(temporary_project)
        infer_call_chains(temporary_project)
        static_analysis_minutes = _elapsed_minutes(
            perf_counter() - static_analysis_started
        )
        if static_analysis_minutes <= 0:
            # Extremely fast mocked or fixture-backed runs should still satisfy
            # the positive cache contract without overstating paper precision.
            static_analysis_minutes = 0.1

        gate_rows = read_csv_rows(
            output_root / "gate-semantics/gate-index.csv",
            GATE_FIELDS,
            f"{temporary_project.project_id} gate catalog",
        )
        gate_counts = count_gate_modes(gate_rows)
        raw_candidate_rows = validate_gate_manifest(
            gate_manifest, temporary_project, sum(gate_counts.values())
        )

        handler_path = output_root / "metrics/tool-handler-entries.csv"
        run_query(
            temporary_project.codeql_database,
            "get_tool_handlers.ql",
            handler_path,
            query_pack=temporary_project.query_pack,
            expected_language=temporary_project.codeql_language,
        )
        handler_rows = read_csv_rows(
            handler_path,
            HANDLER_FIELDS,
            f"{temporary_project.project_id} handler inventory",
        )

        chain_path = output_root / "static/call-chains/handler-sink-chains.csv"
        chain_rows = read_csv_rows(
            chain_path,
            CHAIN_FIELDS,
            f"{temporary_project.project_id} handler-to-sink chains",
        )
        call_chains, sinks, capabilities = count_chains_and_sinks(
            chain_rows, temporary_project
        )

    metrics = ProjectMetrics(
        dom=gate_counts["dom"],
        filt=gate_counts["filt"],
        trans=gate_counts["trans"],
        cap=capabilities,
        handlers=count_handlers(handler_rows),
        sinks=sinks,
        call_chains=call_chains,
        distinct_criteria=distinct_criteria,
        static_analysis_minutes=static_analysis_minutes,
        hc_st_groups=hc_st_groups,
    )
    return {
        "project": temporary_project.project_id,
        "analysis_revision": temporary_project.analysis_revision,
        "metrics": metrics.as_dict(),
        "provenance": {
            "source_root": _display_path(temporary_project.source_root),
            "codeql_database": _display_path(temporary_project.codeql_database),
            "query_pack": _display_path(temporary_project.query_pack),
            "queries": [
                "get_gates.ql",
                "fte_filter.ql",
                "fte_transform.ql",
                "get_tool_handlers.ql",
                "get_handler_to_sink.ql",
            ],
            "raw_gate_candidate_rows": raw_candidate_rows,
            "static_analysis_timing": {
                **STATIC_ANALYSIS_TIMING,
                "implementation_stages": [
                    "infer_gates",
                    "infer_call_chains",
                ],
            },
            STATIC_ANALYSIS_TIME_SOURCE_FIELD: "live --refresh wall-clock measurement",
            "handler_type_mappings": _display_path(handler_type_mappings),
            "sink_type_mappings": _display_path(sink_type_mappings),
        },
    }


def collect_metrics(
    project_ids: Sequence[str] = PROJECT_IDS,
) -> list[dict[str, object]]:
    criteria_counts = load_distinct_criteria_counts()
    group_counts, _ = load_hc_st_group_counts(expected_projects=project_ids)
    return [
        collect_project_metrics(
            get_project(project_id),
            distinct_criteria=criteria_counts[project_id],
            hc_st_groups=group_counts[project_id],
        )
        for project_id in project_ids
    ]


def _cache_document_from_payloads(
    payloads: Iterable[Mapping[str, object]],
) -> dict[str, object]:
    by_project: dict[str, Mapping[str, object]] = {}
    for payload in payloads:
        project_id = str(payload.get("project", "")).strip()
        if project_id not in PROJECT_IDS:
            raise MetricsError(
                f"refreshed metrics have unknown project {project_id!r}"
            )
        if project_id in by_project:
            raise MetricsError(
                f"refreshed metrics duplicate project {project_id!r}"
            )
        by_project[project_id] = payload

    missing = [project_id for project_id in PROJECT_IDS if project_id not in by_project]
    if missing:
        raise MetricsError(
            f"refreshed metrics cannot form a complete cache; missing {missing!r}"
        )

    cache_projects: list[dict[str, object]] = []
    for project_id in PROJECT_IDS:
        payload = by_project[project_id]
        metrics = payload.get("metrics")
        provenance = payload.get("provenance")
        if not isinstance(metrics, Mapping):
            raise MetricsError(
                f"refreshed payload for {project_id!r} has no metrics object"
            )
        if not isinstance(provenance, Mapping):
            raise MetricsError(
                f"refreshed payload for {project_id!r} has no provenance object"
            )
        cache_projects.append(
            {
                "project": project_id,
                "analysis_revision": payload.get("analysis_revision"),
                "metrics": {
                    field: _integer(
                        metrics.get(field),
                        f"refreshed payload for {project_id!r} metric {field!r}",
                    )
                    for field in STATIC_METRIC_FIELDS
                }
                | {
                    STATIC_ANALYSIS_TIME_FIELD: _positive_number(
                        metrics.get(STATIC_ANALYSIS_TIME_FIELD),
                        "refreshed payload for "
                        f"{project_id!r} metric {STATIC_ANALYSIS_TIME_FIELD!r}",
                    )
                },
                "provenance": {
                    key: value
                    for key, value in provenance.items()
                    if key
                    not in {
                        "handler_type_mappings",
                        "sink_type_mappings",
                        "static_metrics_cache",
                        "static_metrics_source",
                    }
                },
            }
        )

    document: dict[str, object] = {
        "schema_version": METRICS_CACHE_SCHEMA,
        "generation_command": REFRESH_COMMAND,
        "static_analysis_timing": STATIC_ANALYSIS_TIMING,
        "projects": cache_projects,
    }
    _validate_cache_document(document)
    return document


def write_metrics_cache(
    payloads: Iterable[Mapping[str, object]],
    path: Path = METRICS_CACHE,
) -> None:
    """Atomically replace the cache after validating a complete snapshot."""

    document = _cache_document_from_payloads(payloads)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            json.dump(document, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def refresh_metrics(
    project_ids: Sequence[str] = PROJECT_IDS,
    *,
    cache_path: Path = METRICS_CACHE,
) -> list[dict[str, object]]:
    """Collect selected projects and update the complete cache atomically."""

    refreshed = collect_metrics(project_ids)
    refreshed_by_project = {
        str(payload.get("project", "")): payload for payload in refreshed
    }
    if len(refreshed_by_project) != len(project_ids):
        raise MetricsError("fresh collection did not return one payload per project")

    if set(project_ids) == set(PROJECT_IDS):
        combined_by_project: dict[str, Mapping[str, object]] = dict(
            refreshed_by_project
        )
    else:
        combined_by_project = {
            str(payload["project"]): payload
            for payload in load_static_metrics_cache(cache_path)
        }
        combined_by_project.update(refreshed_by_project)

    write_metrics_cache(
        [combined_by_project[project_id] for project_id in PROJECT_IDS],
        cache_path,
    )
    return [
        _with_current_alignments(
            payload,
            distinct_criteria=_integer(
                payload.get("metrics", {}).get("distinct_criteria")
                if isinstance(payload.get("metrics"), Mapping)
                else None,
                f"refreshed payload for {payload.get('project')!r} distinct criteria",
            ),
            hc_st_groups=_integer(
                payload.get("metrics", {}).get("hc_st_groups")
                if isinstance(payload.get("metrics"), Mapping)
                else None,
                f"refreshed payload for {payload.get('project')!r} HC-ST groups",
            ),
            static_source="fresh-codeql",
            cache_path=cache_path,
        )
        for payload in refreshed
    ]


def render_table(
    payloads: Iterable[Mapping[str, object]],
) -> str:
    headers = [
        "Project",
        "Dom.",
        "Filt.",
        "Trans.",
        "Cap.",
        "Handlers",
        "Sinks",
        "Call Chains",
        "Handler Types",
        "Call Chain Oracles",
        "Static Analysis Cost Time (min)",
        "Generic Candidates",
    ]
    lines = [
        "| " + " | ".join(headers) + " |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    metric_totals = {field: 0 for field in STATIC_METRIC_FIELDS}
    static_analysis_total = 0.0
    generic_candidate_total = 0
    for payload in payloads:
        metrics = payload.get("metrics")
        if not isinstance(metrics, Mapping):
            raise MetricsError(
                f"payload for {payload.get('project', 'unknown')!r} has no metrics object"
            )
        static_analysis_minutes = _positive_number(
            metrics.get(STATIC_ANALYSIS_TIME_FIELD),
            f"payload for {payload.get('project', 'unknown')!r} metric "
            f"{STATIC_ANALYSIS_TIME_FIELD!r}",
        )
        generic_candidates = _integer(
            metrics.get("generic_candidates"),
            f"payload for {payload.get('project', 'unknown')!r} generic candidates",
        )
        values = [
            payload.get("project", ""),
            metrics.get("dom", ""),
            metrics.get("filt", ""),
            metrics.get("trans", ""),
            metrics.get("cap", ""),
            metrics.get("handlers", ""),
            metrics.get("sinks", ""),
            metrics.get("call_chains", ""),
            metrics.get("distinct_criteria", ""),
            metrics.get("hc_st_groups", ""),
            f"{static_analysis_minutes:.1f}",
            generic_candidates,
        ]
        lines.append("| " + " | ".join(str(value) for value in values) + " |")
        static_analysis_total += static_analysis_minutes
        generic_candidate_total += generic_candidates
        for field in STATIC_METRIC_FIELDS:
            metric_totals[field] += _integer(
                metrics.get(field),
                f"payload for {payload.get('project', 'unknown')!r} metric {field!r}",
            )
    total_values: list[object] = [
        "**Total**",
        *[f"**{metric_totals[field]}**" for field in STATIC_METRIC_FIELDS],
        "--",
        "--",
        f"**{static_analysis_total:.1f}**",
        f"**{generic_candidate_total}**",
    ]
    lines.append("| " + " | ".join(str(value) for value in total_values) + " |")
    return "\n".join(lines)


def render_handler_criterion_summary(
    summary: HandlerCriterionSummary,
) -> str:
    return (
        "## Handler Criterion Support\n\n"
        f"Of the {summary.total_criteria} distinct handler criteria, "
        f"{summary.singleton_criteria} are singleton criteria "
        f"({summary.singleton_criterion_percentage:.1f}%). These singleton "
        f"criteria cover {summary.singleton_handlers} of the "
        f"{summary.total_handlers} resolved handlers "
        f"({summary.singleton_handler_percentage:.1f}%)."
    )


def replace_generated_section(document: str, generated: str) -> str:
    """Replace exactly one marked block while preserving all manual content."""

    if document.count(GENERATED_SECTION_START) != 1:
        raise MetricsError(
            "result document must contain exactly one generated-section start marker"
        )
    if document.count(GENERATED_SECTION_END) != 1:
        raise MetricsError(
            "result document must contain exactly one generated-section end marker"
        )
    start = document.index(GENERATED_SECTION_START)
    content_start = start + len(GENERATED_SECTION_START)
    end = document.index(GENERATED_SECTION_END)
    if end < content_start:
        raise MetricsError("result document generated-section markers are out of order")
    replacement = (
        GENERATED_SECTION_START
        + "\n\n"
        + generated.strip()
        + "\n\n"
        + GENERATED_SECTION_END
    )
    return document[:start] + replacement + document[end + len(GENERATED_SECTION_END) :]


def write_result_document(
    generated: str,
    path: Path = RESULT_PATH,
) -> None:
    """Atomically update the generated block without touching manual sections."""

    if not path.is_file():
        raise MetricsError(f"missing result document: {path}")
    original_mode = path.stat().st_mode & 0o7777
    updated = replace_generated_section(path.read_text(encoding="utf-8"), generated)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path.chmod(original_mode)
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Report the last validated paper metrics snapshot. Use --refresh to "
            "rerun the CodeQL collection."
        )
    )
    parser.add_argument(
        "--project",
        action="append",
        choices=PROJECT_IDS,
        dest="projects",
        help=(
            "Analyze only this project; repeat the option for multiple projects. "
            "The default reports all twelve projects in paper order."
        ),
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help=(
            "Rerun the expensive CodeQL collection for the selected projects and "
            "atomically update the validated cache."
        ),
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output a Markdown table (default) or structured JSON.",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help=(
            "Print Markdown instead of updating the marked generated block in "
            "design/paperdata/result.md. JSON output always uses stdout."
        ),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        selected_projects = list(dict.fromkeys(args.projects or PROJECT_IDS))
        payloads = (
            refresh_metrics(selected_projects)
            if args.refresh
            else load_cached_metrics(selected_projects)
        )
        rendered_projects = [str(payload.get("project", "")) for payload in payloads]
        generic_candidate_counts = load_generic_candidate_counts(
            expected_projects=rendered_projects
        )
        payloads = attach_generic_candidate_counts(
            payloads, generic_candidate_counts
        )
        criterion_summary = load_handler_criterion_summary(
            expected_projects=selected_projects
        )
        _, group_summary = load_hc_st_group_counts(
            expected_projects=selected_projects
        )
        if args.format == "json":
            output = json.dumps(
                {
                    "projects": payloads,
                    "handler_criterion_summary": criterion_summary.as_dict(),
                    "handler_sink_group_summary": group_summary.as_dict(),
                    "generic_candidate_counts": generic_candidate_counts,
                },
                indent=2,
                ensure_ascii=False,
            )
        else:
            output = (
                render_table(payloads)
                + "\n\n"
                + render_handler_criterion_summary(criterion_summary)
            )
            if not args.stdout and args.projects is None:
                write_result_document(output)
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    if args.format == "json" or args.stdout or args.projects is not None:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

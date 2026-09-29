"""Ground-truth-conditioned, label-blind handler trial selection."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.projects import ProjectSpec

from .contracts import BaselineError, canonical_json, contains_credentials, digest
from .ground_truth import CuratedReport, discover_reports
from .inventory import HandlerTrial


GROUND_TRUTH_SCOPE_VERSION = "claude-handler-baseline-ground-truth-scope/v1"
_LOCATION_RE = re.compile(
    r"^(?P<file>.+):(?P<line>[1-9][0-9]*)(?:\s+\((?P<revision>[0-9a-f]{7,40})\))?$",
    re.I,
)


def _location(value: object) -> tuple[str | None, int | None, str | None]:
    if not isinstance(value, str):
        return None, None, None
    match = _LOCATION_RE.fullmatch(value.strip())
    if match is None:
        return None, None, None
    return match.group("file"), int(match.group("line")), match.group("revision")


def _normalized_source(value: object) -> str:
    return " ".join(str(value or "").split())


def _source_confirms_handler(entry: Mapping[str, Any], trial: HandlerTrial) -> tuple[bool, str]:
    source = Path(trial.source_root) / trial.file
    if not source.is_file():
        return False, "current inventory file is absent"
    text = source.read_text(encoding="utf-8", errors="replace")
    normalized_text = _normalized_source(text)
    evidence = _normalized_source(entry.get("evidence"))
    if evidence and evidence in normalized_text:
        return True, "ground-truth handler quote occurs in the current inventory file"

    factory = str(entry.get("factory") or "").strip()
    if factory and factory.casefold() in trial.form.casefold() and factory in text:
        return True, "ground-truth factory and current inventory declaration form agree"

    return False, "neither the handler quote nor factory confirms the current inventory row"


def _binding_record(
    *,
    report: CuratedReport,
    binding_ordinal: int,
    entry: Mapping[str, Any],
    candidates: Sequence[HandlerTrial],
    markdown_fallback: bool,
) -> dict[str, Any]:
    name = str(entry.get("name") or "").strip()
    location_file, location_line, revision_hint = _location(entry.get("location"))
    binding_id = "GTB-" + digest(
        [report.report_id, binding_ordinal, name, dict(entry)]
    )[:16]
    exact: list[HandlerTrial] = []
    confirmed: list[tuple[HandlerTrial, str]] = []
    for trial in candidates:
        source_confirmed, reason = _source_confirms_handler(entry, trial)
        if (
            not markdown_fallback
            and location_file == trial.file
            and location_line == trial.line
            and source_confirmed
        ):
            exact.append(trial)
        elif source_confirmed:
            confirmed.append((trial, reason))

    selected: HandlerTrial | None = None
    if markdown_fallback and len(candidates) == 1:
        selected = candidates[0]
        status = "markdown-fallback"
        reason = "Markdown-only report names one uniquely registered current handler"
    elif len(exact) == 1:
        selected = exact[0]
        status = "exact"
        reason = "project, tool name, file, line, and handler quote match current source"
    elif len(exact) > 1:
        status = "ambiguous"
        reason = "multiple current inventory rows match the exact ground-truth anchor"
    elif len(confirmed) == 1:
        selected, confirmation = confirmed[0]
        status = "source-confirmed-drift"
        reason = f"stale file or line anchor; {confirmation}"
    elif len(confirmed) > 1:
        status = "ambiguous"
        reason = "multiple current inventory rows have source evidence for this handler"
    else:
        status = "unmapped"
        reason = (
            "no current inventory row has source evidence for the ground-truth handler"
            if candidates
            else "no current inventory row has the same project-scoped tool name"
        )

    revision_compatibility = "not-recorded"
    if revision_hint and selected is not None:
        current = selected.revision.casefold()
        hint = revision_hint.casefold()
        revision_compatibility = (
            "recorded-revision-match"
            if current.startswith(hint) or hint.startswith(current)
            else "current-handler-source-confirmed-with-different-recorded-revision"
        )

    return {
        "binding_id": binding_id,
        "report_id": report.report_id,
        "project": report.project,
        "report_name": report.report_name,
        "binding_ordinal": binding_ordinal,
        "ground_truth_handler": dict(entry),
        "mapping_status": status,
        "mapping_reason": reason,
        "ground_truth_revision_hint": revision_hint,
        "revision_compatibility": revision_compatibility,
        "trial_id": selected.trial_id if selected is not None else None,
        "current_handler": selected.record() if selected is not None else None,
        "candidate_trial_ids": sorted(trial.trial_id for trial in candidates),
    }


def build_ground_truth_handler_scope(
    *,
    specs: Sequence[ProjectSpec],
    trials: Sequence[HandlerTrial],
    require_mapped: bool = True,
) -> tuple[list[HandlerTrial], dict[str, Any]]:
    """Resolve every curated report-handler binding to a current handler trial.

    Ground-truth data is used only by the outer experiment controller. The selected
    Claude process still receives exactly one ordinary handler inventory row and can
    access only the chosen project source through Bubblewrap.
    """

    reports = discover_reports(specs)
    by_name: dict[tuple[str, str], list[HandlerTrial]] = defaultdict(list)
    by_id = {trial.trial_id: trial for trial in trials}
    for trial in trials:
        by_name[(trial.project, trial.tool_name.casefold())].append(trial)

    bindings: list[dict[str, Any]] = []
    for report in reports:
        raw_entries = report.invariant.get("handler_entries")
        markdown_fallback = not isinstance(raw_entries, list)
        if markdown_fallback:
            entries = [{"name": name, "source": "markdown-fallback"} for name in report.handlers]
        else:
            entries = [entry for entry in raw_entries if isinstance(entry, dict)]
        if not entries:
            entries = [{"name": "", "source": "missing-handler-definition"}]
        for ordinal, entry in enumerate(entries, 1):
            name = str(entry.get("name") or "").strip()
            candidates = by_name.get((report.project, name.casefold()), []) if name else []
            bindings.append(
                _binding_record(
                    report=report,
                    binding_ordinal=ordinal,
                    entry=entry,
                    candidates=candidates,
                    markdown_fallback=markdown_fallback,
                )
            )

    status_counts = Counter(str(row["mapping_status"]) for row in bindings)
    blocked = [
        row for row in bindings if row["mapping_status"] in {"ambiguous", "unmapped"}
    ]
    if require_mapped and blocked:
        details = "; ".join(
            f"{row['report_id']}:{row['ground_truth_handler'].get('name')}="
            f"{row['mapping_status']}" for row in blocked[:10]
        )
        raise BaselineError(
            f"ground-truth handler scope has {len(blocked)} unresolved bindings: {details}"
        )

    selected_ids = sorted(
        {str(row["trial_id"]) for row in bindings if isinstance(row.get("trial_id"), str)}
    )
    selected = [by_id[trial_id] for trial_id in selected_ids]
    report_inputs = {
        path: sha
        for report in reports
        for path, sha in zip(report.source_files, report.source_sha256)
    }
    report_bindings: dict[str, list[str]] = defaultdict(list)
    for row in bindings:
        if isinstance(row.get("trial_id"), str):
            report_bindings[str(row["report_id"])].append(str(row["trial_id"]))
    manifest: dict[str, Any] = {
        "schema_version": GROUND_TRUTH_SCOPE_VERSION,
        "verification_policy": "handler-root-binding/v1",
        "counts": {
            "curated_reports": len(reports),
            "report_handler_bindings": len(bindings),
            "unique_handler_trials": len(selected),
            "projects": len({trial.project for trial in selected}),
            "mapping_status": dict(sorted(status_counts.items())),
            "unresolved_bindings": len(blocked),
        },
        "ground_truth_inputs": dict(sorted(report_inputs.items())),
        "report_trial_bindings": {
            report_id: sorted(set(trial_ids))
            for report_id, trial_ids in sorted(report_bindings.items())
        },
        "bindings": bindings,
        "selected_trial_ids": selected_ids,
    }
    manifest["scope_digest"] = digest(manifest)
    if contains_credentials(canonical_json(manifest)):
        raise BaselineError("credential-shaped data in ground-truth handler scope")
    return selected, manifest

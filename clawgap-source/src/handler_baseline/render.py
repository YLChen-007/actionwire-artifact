"""Deterministic reports and token summaries for the handler baseline."""

from __future__ import annotations

import math
import statistics
from collections import Counter
from typing import Any, Mapping, Sequence

from .contracts import (
    ALL_FINDINGS_POLICY,
    MOST_CREDIBLE_VULNERABILITIES_POLICY,
    aggregate_calls,
)


TOKEN_KEYS = (
    "input_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
    "output_tokens",
    "total_input_tokens",
    "total_tokens",
)


def _token_zero() -> dict[str, int]:
    return {key: 0 for key in TOKEN_KEYS}


def _token_add(target: dict[str, int], usage: Mapping[str, Any]) -> None:
    for key in TOKEN_KEYS:
        target[key] += int(usage.get(key, 0) or 0)


def _percentile(values: Sequence[int], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def candidate_key(report_policy: str) -> str:
    return (
        "vulnerabilities"
        if report_policy == MOST_CREDIBLE_VULNERABILITIES_POLICY
        else "findings"
    )


def result_candidates(row: Mapping[str, Any], report_policy: str) -> list[Mapping[str, Any]]:
    result = row.get("result") or {}
    values = result.get(candidate_key(report_policy), [])
    return [value for value in values if isinstance(value, Mapping)]


def trial_outcome(row: Mapping[str, Any]) -> str:
    if row["status"] != "completed":
        return str(row["status"])
    result = row.get("result") or {}
    verdict = result.get("verdict")
    if verdict not in {"findings", "vulnerabilities"}:
        return str(verdict)
    values = result.get("vulnerabilities", result.get("findings", []))
    modes = {finding["failure_mode"] for finding in values}
    if modes == {"wrong-check"}:
        return "wrong-check-only"
    if modes == {"missing-check"}:
        return "missing-check-only"
    return "mixed-findings"


def trial_attempts(row: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    history = row.get("attempt_history")
    if isinstance(history, list) and history:
        return [attempt for attempt in history if isinstance(attempt, Mapping)]
    return [
        {
            "attempt": row.get("attempt", 1),
            "status": row.get("status", "unknown"),
            "elapsed_seconds": row.get("elapsed_seconds", 0),
            "calls": (row.get("transport") or {}).get("calls", []),
        }
    ]


def trial_calls(row: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [
        call
        for attempt in trial_attempts(row)
        for call in attempt.get("calls", [])
        if isinstance(call, Mapping)
    ]


def _usage_state(calls: Sequence[Mapping[str, Any]]) -> tuple[bool, bool]:
    reported = any(bool(call.get("provider_reported")) for call in calls)
    missing = not calls or any(not bool(call.get("provider_reported")) for call in calls)
    return reported, missing


def summarize_trials(
    rows: Sequence[Mapping[str, Any]], report_policy: str = ALL_FINDINGS_POLICY
) -> dict[str, Any]:
    status = Counter(str(row["status"]) for row in rows)
    outcomes = Counter(trial_outcome(row) for row in rows)
    candidates = [
        candidate
        for row in rows
        if row["status"] == "completed"
        for candidate in result_candidates(row, report_policy)
    ]
    mode_counts = Counter(str(row["failure_mode"]) for row in candidates)
    observed: list[int] = []
    missing_usage = 0
    total = _token_zero()
    by_project: dict[str, dict[str, Any]] = {}
    by_status: dict[str, dict[str, Any]] = {}
    by_outcome: dict[str, dict[str, Any]] = {}
    by_phase: dict[str, dict[str, Any]] = {}
    by_attempt_status: dict[str, dict[str, Any]] = {}
    total_attempts = 0
    attempt_elapsed = 0.0

    def bucket(mapping: dict[str, dict[str, Any]], key: str) -> dict[str, Any]:
        return mapping.setdefault(key, {"trials": 0, "missing_usage_trials": 0, **_token_zero()})

    for row in rows:
        attempts = trial_attempts(row)
        total_attempts += len(attempts)
        attempt_elapsed += sum(float(attempt.get("elapsed_seconds", 0) or 0) for attempt in attempts)
        calls = trial_calls(row)
        usage = aggregate_calls(calls)
        provider, usage_missing = _usage_state(calls)
        for mapping, key in (
            (by_project, str(row["project"])),
            (by_status, str(row["status"])),
            (by_outcome, trial_outcome(row)),
        ):
            group = bucket(mapping, key)
            group["trials"] += 1
            if provider:
                _token_add(group, usage)
            if usage_missing:
                group["missing_usage_trials"] += 1
        if provider:
            _token_add(total, usage)
            observed.append(int(usage["total_tokens"]))
        if usage_missing:
            missing_usage += 1
        for call in calls:
            phase = str(call.get("phase", "unknown"))
            group = by_phase.setdefault(
                phase, {"calls": 0, "missing_usage_calls": 0, **_token_zero()}
            )
            group["calls"] += 1
            call_usage = call.get("usage", {})
            if call.get("provider_reported"):
                _token_add(group, call_usage)
            else:
                group["missing_usage_calls"] += 1
        for attempt in attempts:
            attempt_calls = [
                call for call in attempt.get("calls", []) if isinstance(call, Mapping)
            ]
            attempt_usage = aggregate_calls(attempt_calls)
            attempt_provider, attempt_missing = _usage_state(attempt_calls)
            attempt_status = str(attempt.get("status", "unknown"))
            group = by_attempt_status.setdefault(
                attempt_status,
                {"attempts": 0, "missing_usage_attempts": 0, **_token_zero()},
            )
            group["attempts"] += 1
            if attempt_provider:
                _token_add(group, attempt_usage)
            if attempt_missing:
                group["missing_usage_attempts"] += 1

    descriptive = {
        "observed_trials": len(observed),
        "missing_usage_trials": missing_usage,
        "minimum": min(observed) if observed else None,
        "maximum": max(observed) if observed else None,
        "mean": statistics.fmean(observed) if observed else None,
        "median": statistics.median(observed) if observed else None,
        "p25": _percentile(observed, 0.25),
        "p75": _percentile(observed, 0.75),
        "p90": _percentile(observed, 0.90),
        "p95": _percentile(observed, 0.95),
        "p99": _percentile(observed, 0.99),
    }
    result = {
        "trials": len(rows),
        "attempts": total_attempts,
        "attempt_elapsed_seconds_sum": round(attempt_elapsed, 3),
        "status": dict(sorted(status.items())),
        "outcomes": dict(sorted(outcomes.items())),
        "observed_token_subtotal": total,
        "token_statistics_per_handler": descriptive,
        "tokens_by_project": dict(sorted(by_project.items())),
        "tokens_by_status": dict(sorted(by_status.items())),
        "tokens_by_outcome": dict(sorted(by_outcome.items())),
        "tokens_by_phase": dict(sorted(by_phase.items())),
        "tokens_by_attempt_status": dict(sorted(by_attempt_status.items())),
    }
    if report_policy == MOST_CREDIBLE_VULNERABILITIES_POLICY:
        result.update(
            {
                "vulnerabilities": len(candidates),
                "vulnerability_modes": dict(sorted(mode_counts.items())),
                "vulnerabilities_by_rank": dict(
                    sorted(Counter(str(row["rank"]) for row in candidates).items())
                ),
                "tokens_per_raw_vulnerability": (
                    total["total_tokens"] / len(candidates) if candidates else None
                ),
            }
        )
    else:
        result.update(
            {
                "findings": len(candidates),
                "finding_modes": dict(sorted(mode_counts.items())),
                "tokens_per_raw_finding": (
                    total["total_tokens"] / len(candidates) if candidates else None
                ),
            }
        )
    return result


def _fmt(value: object) -> str:
    if value is None:
        return "--"
    if isinstance(value, float):
        return f"{value:,.1f}"
    if isinstance(value, int):
        return f"{value:,}"
    return str(value)


def _token_breakdown_table(
    *,
    title: str,
    key_heading: str,
    rows: Mapping[str, Mapping[str, Any]],
    count_key: str,
    missing_key: str,
) -> list[str]:
    lines = [
        f"### {title}",
        "",
        f"| {key_heading} | Count | Input | Cache creation | Cache read | Output | Total input | Total | Missing usage |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for key, values in rows.items():
        lines.append(
            f"| `{key}` | {values[count_key]} | {values['input_tokens']} | "
            f"{values['cache_creation_input_tokens']} | {values['cache_read_input_tokens']} | "
            f"{values['output_tokens']} | {values['total_input_tokens']} | "
            f"{values['total_tokens']} | {values[missing_key]} |"
        )
    return lines


def render_blind_report(
    *, generation_command: str, rows: Sequence[Mapping[str, Any]], manifest: Mapping[str, Any]
) -> str:
    summary = manifest["counts"]
    report_policy = manifest.get("configuration", {}).get(
        "report_policy", ALL_FINDINGS_POLICY
    )
    vulnerability_policy = report_policy == MOST_CREDIBLE_VULNERABILITIES_POLICY
    plural = "vulnerabilities" if vulnerability_policy else "findings"
    singular = "vulnerability" if vulnerability_policy else "finding"
    title_plural = "Vulnerabilities" if vulnerability_policy else "Findings"
    count_key = "vulnerabilities" if vulnerability_policy else "findings"
    modes_key = "vulnerability_modes" if vulnerability_policy else "finding_modes"
    tokens_per_key = (
        "tokens_per_raw_vulnerability" if vulnerability_policy else "tokens_per_raw_finding"
    )
    tokens = summary["observed_token_subtotal"]
    stats = summary["token_statistics_per_handler"]
    lines = [
        "# Blind Claude Code Per-Handler Credible-Vulnerability Baseline"
        if vulnerability_policy
        else "# Blind Claude Code Per-Handler Baseline",
        "",
        f"> Generation command: `{generation_command}`",
        "",
        "This report is generated from blind, handler-scoped trials. Ground truth is not an input to this phase.",
        "",
        f"Invocation wall-clock time: **{_fmt(manifest['execution']['invocation_wall_clock_seconds'])} seconds**; "
        f"sum of all handler-attempt elapsed time: **{_fmt(summary['attempt_elapsed_seconds_sum'])} seconds**.",
        "",
        "## Trial Status",
        "",
        "| Status | Trials |",
        "|---|---:|",
    ]
    for key, count in summary["status"].items():
        lines.append(f"| `{key}` | {count} |")
    lines.extend(
        [
            "",
            f"Raw canonical {plural}: **{summary[count_key]}** "
            f"(Wrong-Check {summary[modes_key].get('wrong-check', 0)}, "
            f"Missing-Check {summary[modes_key].get('missing-check', 0)}).",
            *(
                [
                    "",
                    "Credibility ranks: "
                    f"rank 1 **{summary['vulnerabilities_by_rank'].get('1', 0)}**, "
                    f"rank 2 **{summary['vulnerabilities_by_rank'].get('2', 0)}**.",
                ]
                if vulnerability_policy
                else []
            ),
            "",
            "## Observed Token Cost",
            "",
            "Timed-out or failed trials without provider usage are unavailable, never zero-filled.",
            "",
            "| Input | Cache creation | Cache read | Output | Total input | Total | Missing-usage trials |",
            "|---:|---:|---:|---:|---:|---:|---:|",
            "| "
            + " | ".join(
                _fmt(value)
                for value in (
                    tokens["input_tokens"], tokens["cache_creation_input_tokens"],
                    tokens["cache_read_input_tokens"], tokens["output_tokens"],
                    tokens["total_input_tokens"], tokens["total_tokens"],
                    stats["missing_usage_trials"],
                )
            )
            + " |",
            "",
            f"| Min | P25 | Median | Mean | P75 | P90 | P95 | P99 | Max | Tokens/raw {singular} |",
            "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
            "| "
            + " | ".join(
                _fmt(value)
                for value in (
                    stats["minimum"], stats["p25"], stats["median"], stats["mean"],
                    stats["p75"], stats["p90"], stats["p95"], stats["p99"],
                    stats["maximum"], summary[tokens_per_key],
                )
            )
            + " |",
            "",
        ]
    )
    lines.extend(
        _token_breakdown_table(
            title="By Final Trial Status",
            key_heading="Status",
            rows=summary["tokens_by_status"],
            count_key="trials",
            missing_key="missing_usage_trials",
        )
    )
    lines.extend(
        ["", *_token_breakdown_table(
            title="By Trial Outcome",
            key_heading="Outcome",
            rows=summary["tokens_by_outcome"],
            count_key="trials",
            missing_key="missing_usage_trials",
        )]
    )
    lines.extend(
        ["", *_token_breakdown_table(
            title="By Call Phase",
            key_heading="Phase",
            rows=summary["tokens_by_phase"],
            count_key="calls",
            missing_key="missing_usage_calls",
        )]
    )
    lines.extend(
        ["", *_token_breakdown_table(
            title="By Attempt Status",
            key_heading="Status",
            rows=summary["tokens_by_attempt_status"],
            count_key="attempts",
            missing_key="missing_usage_attempts",
        )]
    )
    lines.extend(
        [
            "",
            "## Per-Project Results",
            "",
            f"| Project | Trials | Completed | {title_plural} | Observed tokens | Missing usage |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for project in sorted({str(row["project"]) for row in rows}):
        project_rows = [row for row in rows if row["project"] == project]
        project_tokens = summary["tokens_by_project"][project]
        project_findings = sum(
            len(result_candidates(row, report_policy)) for row in project_rows
        )
        lines.append(
            f"| `{project}` | {len(project_rows)} | "
            f"{sum(row['status'] == 'completed' for row in project_rows)} | "
            f"{project_findings} | "
            f"{_fmt(project_tokens['total_tokens'])} | {project_tokens['missing_usage_trials']} |"
        )
    lines.extend(
        [
            "",
            "## Trial Index",
            "",
            f"| Trial | Project | Tool | Status | Outcome | Attempts | {title_plural} | Tokens | Missing usage |",
            "|---|---|---|---|---|---:|---:|---:|---:|",
        ]
    )
    for row in sorted(rows, key=lambda item: item["trial_id"]):
        calls = trial_calls(row)
        usage = aggregate_calls(calls)
        _, usage_missing = _usage_state(calls)
        total_tokens: object = usage["total_tokens"] if usage["provider_reported"] else None
        lines.append(
            f"| `{row['trial_id']}` | `{row['project']}` | `{row['handler']['tool_name']}` | "
            f"`{row['status']}` | `{trial_outcome(row)}` | "
            f"{len(trial_attempts(row))} | "
            f"{len(result_candidates(row, report_policy))} | "
            f"{_fmt(total_tokens)} | {int(usage_missing)} |"
        )
    return "\n".join(lines) + "\n"


def render_ground_truth_report(
    *, generation_command: str, rows: Sequence[Mapping[str, Any]], manifest: Mapping[str, Any]
) -> str:
    counts = manifest["counts"]
    blind = manifest["blind_detection"]
    candidate_label = str(manifest.get("candidate_label", "finding"))
    candidate_plural = (
        "vulnerabilities" if candidate_label == "vulnerability" else "findings"
    )
    lines = [
        "# Blind Handler Baseline Ground-Truth Audit",
        "",
        f"> Generation command: `{generation_command}`",
        "",
        f"Strictly matched curated issues: **{counts['matched_reports']}/{counts['reports']}**.",
        "",
        f"Strict misses: **{counts['strict_missed_reports']}**; raw blind {candidate_plural}: "
        f"**{counts['raw_findings']}**; unmatched blind {candidate_plural}: **{counts['unmatched_findings']}**.",
        "",
        f"Blind outcomes included Wrong-Check **{blind['finding_modes'].get('wrong-check', 0)}**, "
        f"Missing-Check **{blind['finding_modes'].get('missing-check', 0)}**, "
        f"timeouts **{blind['status'].get('timed-out', 0)}**, and failures "
        f"**{blind['status'].get('failed', 0)}**. Blind invocation wall-clock time was "
        f"**{_fmt(blind['wall_clock_seconds'])} seconds**.",
        "",
        "A match requires the same controlled security invariant; handler or sink proximity alone is insufficient.",
        "",
        f"| Project | Report | Status | Matched {candidate_plural} | Reason |",
        "|---|---|---|---:|---|",
    ]
    for row in rows:
        reason = str(row["reason"]).replace("|", "\\|")
        lines.append(
            f"| `{row['project']}` | `{row['report_name']}` | `{row['status']}` | "
            f"{len(row['matched_finding_ids'])} | {reason} |"
        )
    if candidate_label == "vulnerability":
        validity = counts["validity_dispositions"]
        legacy = manifest.get("legacy_baseline_comparison")
        lines.extend(
            [
                "",
                "Under the top-two-per-handler contract, the frozen report/handler binding "
                f"graph permits at most **{counts['maximum_strict_report_coverage']}/{counts['reports']}** "
                f"strict matches (**{_fmt(100 * counts['maximum_strict_recall'])}%** recall).",
                "",
                "Manual vulnerability validity review: "
                f"TP **{validity['tp']}**, FP **{validity['fp']}**, "
                f"duplicate **{validity['duplicate']}**, unknown **{validity['unknown']}**, "
                f"pending **{counts['pending_vulnerability_validity_reviews']}**. "
                "Conditioned validity rate: **"
                + (
                    f"{_fmt(100 * counts['conditioned_validity_rate'])}%"
                    if counts["conditioned_validity_rate"] is not None
                    else "--"
                )
                + "**.",
                "",
                "Prior false-positive mechanisms reported as recurring: "
                + (
                    ", ".join(
                        f"`{item}`"
                        for item in counts["recurring_prior_false_positive_ids"]
                    )
                    if counts["recurring_prior_false_positive_ids"]
                    else "none in completed reviews"
                )
                + ".",
            ]
        )
        if isinstance(legacy, Mapping):
            old = legacy["dispositions"]
            lines.extend(
                [
                    "",
                    "Legacy conditioned baseline: "
                    f"**{legacy['raw_findings']}** raw findings, TP **{old['tp']}**, "
                    f"FP **{old['fp']}**, duplicate **{old['duplicate']}**, conditioned "
                    f"validity **{_fmt(100 * legacy['conditioned_validity_rate'])}%**.",
                ]
            )
    detection = manifest["detection_token_usage"]
    adjudication = manifest["token_usage"]
    combined = manifest["combined_token_usage"]
    lines.extend(
        [
            "",
            "## Token Cost",
            "",
            "| Phase | Input | Cache creation | Cache read | Output | Total input | Total | Missing usage |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
            f"| Blind detection | {detection['input_tokens']} | "
            f"{detection['cache_creation_input_tokens']} | {detection['cache_read_input_tokens']} | "
            f"{detection['output_tokens']} | {detection['total_input_tokens']} | "
            f"{detection['total_tokens']} | {blind['missing_usage_trials']} trials |",
            f"| Post-hoc adjudication | {adjudication['input_tokens']} | "
            f"{adjudication['cache_creation_input_tokens']} | {adjudication['cache_read_input_tokens']} | "
            f"{adjudication['output_tokens']} | {adjudication['total_input_tokens']} | "
            f"{adjudication['total_tokens']} | {counts['missing_usage_calls']} calls |",
            f"| Combined observed | {combined['input_tokens']} | "
            f"{combined['cache_creation_input_tokens']} | {combined['cache_read_input_tokens']} | "
            f"{combined['output_tokens']} | {combined['total_input_tokens']} | "
            f"{combined['total_tokens']} | -- |",
            "",
            f"Tokens per strictly matched issue: detection "
            f"**{_fmt(counts['detection_tokens_per_matched_issue'])}**, adjudication "
            f"**{_fmt(counts['adjudication_tokens_per_matched_issue'])}**, combined "
            f"**{_fmt(counts['combined_tokens_per_matched_issue'])}**.",
        ]
    )
    return "\n".join(lines) + "\n"

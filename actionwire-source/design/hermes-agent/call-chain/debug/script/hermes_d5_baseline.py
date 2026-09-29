#!/usr/bin/env python3
"""Monotonic item-level baseline contract for Hermes D5 coverage."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable


SCHEMA_VERSION = "hermes-d5-coverage-baseline/v1"
ITEM_KINDS = ("handler", "gate", "sink")
METADATA_FIELDS = (
    "json_id",
    "item_kind",
    "item_index",
    "gt_name",
    "gt_type",
    "gt_location",
)


class BaselineError(AssertionError):
    """Raised when current D5 coverage regresses from the approved baseline."""


def read_items(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = sorted(set(METADATA_FIELDS) - set(reader.fieldnames or []))
        if missing:
            raise BaselineError(
                f"D5 item CSV is missing required fields: {', '.join(missing)}"
            )
        return list(reader)


def item_key(row: dict[str, object]) -> tuple[str, str, int]:
    try:
        index = int(str(row["item_index"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise BaselineError(f"invalid D5 item index: {row!r}") from exc
    return str(row["json_id"]), str(row["item_kind"]), index


def item_label(row: dict[str, object]) -> str:
    json_id, kind, index = item_key(row)
    return f"{json_id}:{kind}:{index} {row.get('gt_name', '')}"


def normalized_metadata(rows: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    values = [
        {
            "json_id": str(row.get("json_id", "")),
            "item_kind": str(row.get("item_kind", "")),
            "item_index": item_key(row)[2],
            "gt_name": str(row.get("gt_name", "")),
            "gt_type": str(row.get("gt_type", "")),
            "gt_location": str(row.get("gt_location", "")),
        }
        for row in rows
    ]
    return sorted(
        values,
        key=lambda row: (
            str(row["json_id"]),
            str(row["item_kind"]),
            int(row["item_index"]),
        ),
    )


def metadata_sha256(rows: Iterable[dict[str, object]]) -> str:
    payload = json.dumps(
        normalized_metadata(rows),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def parse_verdicts(value: object) -> set[str]:
    return {part.strip() for part in str(value or "").split(";") if part.strip()}


def expand_required_items(
    baseline: dict[str, object],
) -> set[tuple[str, str, int]]:
    required = baseline.get("required_covered_items")
    if not isinstance(required, dict):
        raise BaselineError("baseline required_covered_items must be an object")
    output: set[tuple[str, str, int]] = set()
    for json_id, by_kind in required.items():
        if not isinstance(by_kind, dict):
            raise BaselineError(f"baseline report {json_id!r} must map kinds to indexes")
        for kind, indexes in by_kind.items():
            if kind not in ITEM_KINDS:
                raise BaselineError(f"unsupported baseline item kind: {kind!r}")
            if not isinstance(indexes, list):
                raise BaselineError(
                    f"baseline indexes for {json_id}:{kind} must be a list"
                )
            for index in indexes:
                try:
                    key = str(json_id), str(kind), int(index)
                except (TypeError, ValueError) as exc:
                    raise BaselineError(
                        f"invalid baseline index for {json_id}:{kind}: {index!r}"
                    ) from exc
                if key in output:
                    raise BaselineError(f"duplicate baseline item: {key}")
                output.add(key)
    return output


def load_baseline(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise BaselineError(f"baseline must be a JSON object: {path}")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise BaselineError(
            f"unsupported baseline schema: {value.get('schema_version')!r}"
        )
    return value


def _eligible_covered(
    row: dict[str, str],
    *,
    eligible_gate_verdicts: set[str],
    required_match_kinds: dict[str, set[str]],
) -> tuple[bool, str]:
    if row.get("coverage_status") != "covered":
        return False, f"coverage_status={row.get('coverage_status')!r}"
    kind = row.get("item_kind", "")
    if kind == "gate":
        verdicts = parse_verdicts(row.get("detector_verdict", ""))
        if not verdicts:
            return False, "covered gate has no detector verdict"
        unexpected = verdicts - eligible_gate_verdicts
        if unexpected:
            return False, "ineligible detector verdict(s): " + ", ".join(
                sorted(unexpected)
            )
    allowed_matches = required_match_kinds.get(kind, set())
    if allowed_matches and row.get("match_kind", "") not in allowed_matches:
        return (
            False,
            f"match_kind={row.get('match_kind')!r}, expected one of "
            + ", ".join(sorted(allowed_matches)),
        )
    return True, ""


def compare_coverage(
    rows: list[dict[str, str]],
    baseline: dict[str, object],
    *,
    analysis_revision: str,
) -> dict[str, object]:
    errors: list[str] = []
    expected_revision = str(baseline.get("analysis_revision", ""))
    if analysis_revision != expected_revision:
        errors.append(
            f"analysis revision mismatch: current={analysis_revision!r}, "
            f"baseline={expected_revision!r}"
        )

    expected_digest = str(baseline.get("normalized_gt_items_sha256", ""))
    actual_digest = metadata_sha256(rows)
    if actual_digest != expected_digest:
        errors.append(
            "ground-truth item identity changed: "
            f"current sha256={actual_digest}, baseline sha256={expected_digest}; "
            "review the GT change and create a new baseline version explicitly"
        )

    rows_by_key: dict[tuple[str, str, int], dict[str, str]] = {}
    for row in rows:
        key = item_key(row)
        if key in rows_by_key:
            errors.append(f"duplicate current D5 item: {key}")
        else:
            rows_by_key[key] = row

    eligible_gate_verdicts = {
        str(value)
        for value in baseline.get("eligible_gate_verdicts", [])
        if str(value)
    }
    if not eligible_gate_verdicts:
        errors.append("baseline has no eligible_gate_verdicts")
    match_config = baseline.get("required_match_kinds", {})
    if not isinstance(match_config, dict):
        errors.append("baseline required_match_kinds must be an object")
        match_config = {}
    required_match_kinds = {
        str(kind): {str(value) for value in values}
        for kind, values in match_config.items()
        if isinstance(values, list)
    }

    required = expand_required_items(baseline)
    covered: set[tuple[str, str, int]] = set()
    reasons: dict[tuple[str, str, int], str] = {}
    for key, row in rows_by_key.items():
        accepted, reason = _eligible_covered(
            row,
            eligible_gate_verdicts=eligible_gate_verdicts,
            required_match_kinds=required_match_kinds,
        )
        if accepted:
            covered.add(key)
        else:
            reasons[key] = reason

    for key in sorted(required - covered):
        row = rows_by_key.get(key)
        if row is None:
            errors.append(f"required baseline item is missing: {key}")
        else:
            errors.append(
                f"required baseline item regressed: {item_label(row)}; "
                f"{reasons.get(key, 'not eligible') }"
            )

    count_by_kind = Counter(kind for _json_id, kind, _index in covered)
    minimum_counts = baseline.get("minimum_covered_counts", {})
    if not isinstance(minimum_counts, dict):
        errors.append("baseline minimum_covered_counts must be an object")
        minimum_counts = {}
    for kind, expected in minimum_counts.items():
        actual = count_by_kind[str(kind)]
        if actual < int(expected):
            errors.append(
                f"covered {kind} count regressed: current={actual}, minimum={expected}"
            )

    if errors:
        raise BaselineError("Hermes D5 baseline regression:\n- " + "\n- ".join(errors))

    newly_covered = sorted(covered - required)
    return {
        "required_items": len(required),
        "covered_items": len(covered),
        "newly_covered": [
            {
                "json_id": key[0],
                "item_kind": key[1],
                "item_index": key[2],
                "gt_name": rows_by_key[key].get("gt_name", ""),
            }
            for key in newly_covered
        ],
        "covered_counts": {
            kind: count_by_kind[kind] for kind in ITEM_KINDS
        },
        "normalized_gt_items_sha256": actual_digest,
    }


def build_baseline(
    rows: list[dict[str, str]], *, analysis_revision: str
) -> dict[str, object]:
    """Build a reviewable baseline payload; callers decide whether to persist it."""

    required: dict[str, dict[str, list[int]]] = defaultdict(
        lambda: defaultdict(list)
    )
    eligible = {"confirmed", "branch-confirmed"}
    required_match_kinds = {
        "handler": {"tool-handler-root"},
        "sink": {"exact-location"},
    }
    counts: Counter[str] = Counter()
    for row in rows:
        accepted, _reason = _eligible_covered(
            row,
            eligible_gate_verdicts=eligible,
            required_match_kinds=required_match_kinds,
        )
        if not accepted:
            continue
        json_id, kind, index = item_key(row)
        required[json_id][kind].append(index)
        counts[kind] += 1

    return {
        "schema_version": SCHEMA_VERSION,
        "analysis_revision": analysis_revision,
        "normalized_gt_items_sha256": metadata_sha256(rows),
        "eligible_gate_verdicts": sorted(eligible),
        "required_match_kinds": {
            kind: sorted(values) for kind, values in required_match_kinds.items()
        },
        "minimum_covered_counts": {
            kind: counts[kind] for kind in ITEM_KINDS
        },
        "required_covered_items": {
            json_id: {
                kind: sorted(indexes)
                for kind, indexes in sorted(by_kind.items())
            }
            for json_id, by_kind in sorted(required.items())
        },
    }

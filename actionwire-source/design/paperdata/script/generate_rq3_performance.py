#!/usr/bin/env python3
"""Generate the RQ3 cross-project performance table from recorded evidence."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[3]
MEASUREMENTS_PATH = (
    REPO_ROOT / "design/paperdata/rq3-performance-measurements.json"
)
RESULT_PATH = REPO_ROOT / "design/paperdata/result.md"
DEFAULT_SESSION_ROOT = Path("/root/.claude/projects")
GENERATION_COMMAND = (
    "python design/paperdata/script/generate_rq3_performance.py"
)
GENERATED_SECTION_START = (
    "<!-- BEGIN GENERATED RQ3 PERFORMANCE: " + GENERATION_COMMAND + " -->"
)
GENERATED_SECTION_END = "<!-- END GENERATED RQ3 PERFORMANCE -->"
STAGE_ORDER = (
    "sink_capability_card",
    "handler_type_alignment",
    "sink_type_alignment",
    "group_oracle",
    "coverage_comparison",
)
STAGE_LABELS = {
    "sink_capability_card": "Sink Capability Card",
    "handler_type_alignment": "Handler-Type Alignment",
    "sink_type_alignment": "Sink-Type Alignment",
    "group_oracle": "Group-Oracle",
    "coverage_comparison": "Coverage Comparison",
}
TOKEN_FIELDS = (
    "input_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
    "output_tokens",
)


class PerformanceError(ValueError):
    """Raised when RQ3 measurement evidence is absent or inconsistent."""


@dataclass(frozen=True)
class StageMeasurement:
    key: str
    label: str
    tokens: int
    time_minutes: float
    workers: int
    provenance: str


@dataclass(frozen=True)
class PerformanceResults:
    stages: tuple[StageMeasurement, ...]
    total_tokens: int
    total_time_minutes: float
    sink_session_count: int
    sink_serial_seconds: int

    def as_dict(self) -> dict[str, object]:
        return {
            "stages": [asdict(stage) for stage in self.stages],
            "totals": {
                "tokens": self.total_tokens,
                "time_minutes": self.total_time_minutes,
            },
            "sink_capability_card_evidence": {
                "session_count": self.sink_session_count,
                "serial_seconds": self.sink_serial_seconds,
            },
        }


def _mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PerformanceError(f"{context} must be an object")
    return value


def _positive_int(value: object, context: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PerformanceError(f"{context} must be an integer")
    if value < 0 or (value == 0 and not allow_zero):
        qualifier = "non-negative" if allow_zero else "positive"
        raise PerformanceError(f"{context} must be {qualifier}")
    return value


def _positive_number(value: object, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PerformanceError(f"{context} must be numeric")
    number = float(value)
    if number <= 0:
        raise PerformanceError(f"{context} must be positive")
    return number


def load_measurements(path: Path = MEASUREMENTS_PATH) -> Mapping[str, object]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise PerformanceError(f"missing measurement file: {path}") from error
    except json.JSONDecodeError as error:
        raise PerformanceError(f"invalid measurement JSON in {path}: {error}") from error
    root = _mapping(document, "measurement document")
    expected_keys = {"sink_capability_card", "stages"}
    if set(root) != expected_keys:
        raise PerformanceError(
            "measurement document must contain exactly sink_capability_card and stages"
        )
    return root


def _parse_timestamp(value: object, context: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise PerformanceError(f"{context} must be a non-empty timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise PerformanceError(f"invalid timestamp for {context}: {value!r}") from error
    if parsed.tzinfo is None:
        raise PerformanceError(f"{context} must include a timezone")
    # The evaluation recorded elapsed time at whole-second resolution.
    return parsed.replace(microsecond=0)


def _read_session(path: Path, expected_session_id: str) -> list[Mapping[str, object]]:
    records: list[Mapping[str, object]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise PerformanceError(f"cannot read session log {path}: {error}") from error
    if not lines:
        raise PerformanceError(f"session log is empty: {path}")
    for line_number, line in enumerate(lines, 1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise PerformanceError(
                f"invalid JSON in {path}:{line_number}: {error.msg}"
            ) from error
        if not isinstance(record, Mapping):
            raise PerformanceError(f"session record {path}:{line_number} is not an object")
        records.append(record)
    if not any(
        record.get("sessionId") == expected_session_id
        and record.get("entrypoint") == "sink-capacity"
        for record in records
    ):
        raise PerformanceError(
            f"session {expected_session_id} is not identified as sink-capacity"
        )
    return records


def _find_session_file(session_root: Path, session_id: str) -> Path:
    matches = list(session_root.rglob(f"{session_id}.jsonl"))
    if len(matches) != 1:
        raise PerformanceError(
            f"expected exactly one log for session {session_id}, found {len(matches)}"
        )
    return matches[0]


def _normalized_usage(record: Mapping[str, object], context: str) -> tuple[int, ...]:
    message = _mapping(record.get("message"), f"{context} message")
    usage = _mapping(message.get("usage"), f"{context} usage")
    return tuple(
        _positive_int(usage.get(field, 0), f"{context} {field}", allow_zero=True)
        for field in TOKEN_FIELDS
    )


def collect_sink_capability_metrics(
    session_root: Path,
    config: Mapping[str, object],
) -> tuple[int, int, int, int]:
    expected_keys = {
        "entrypoint",
        "workers",
        "expected_sessions",
        "expected_total_tokens",
        "expected_serial_seconds",
        "session_ids",
    }
    if set(config) != expected_keys:
        raise PerformanceError(
            "sink_capability_card must contain exactly entrypoint, workers, "
            "expected_sessions, expected_total_tokens, expected_serial_seconds, "
            "and session_ids"
        )
    if config.get("entrypoint") != "sink-capacity":
        raise PerformanceError("sink capability entrypoint must be sink-capacity")
    workers = _positive_int(config.get("workers"), "sink capability workers")
    expected_sessions = _positive_int(
        config.get("expected_sessions"), "expected sink session count"
    )
    expected_tokens = _positive_int(
        config.get("expected_total_tokens"), "expected sink token count"
    )
    expected_seconds = _positive_int(
        config.get("expected_serial_seconds"), "expected sink serial seconds"
    )
    session_ids = config.get("session_ids")
    if not isinstance(session_ids, list) or not all(
        isinstance(session_id, str) and session_id for session_id in session_ids
    ):
        raise PerformanceError("sink capability session_ids must be non-empty strings")
    if len(session_ids) != len(set(session_ids)):
        raise PerformanceError("sink capability session_ids must be unique")
    if len(session_ids) != expected_sessions:
        raise PerformanceError(
            f"expected {expected_sessions} sink sessions, configured {len(session_ids)}"
        )

    request_usage: dict[tuple[str, str], tuple[int, ...]] = {}
    serial_seconds = 0
    for session_id in session_ids:
        path = _find_session_file(session_root, session_id)
        records = _read_session(path, session_id)
        timestamps = [
            _parse_timestamp(record["timestamp"], f"session {session_id}")
            for record in records
            if record.get("timestamp") is not None
        ]
        if len(timestamps) < 2:
            raise PerformanceError(f"session {session_id} has fewer than two timestamps")
        serial_seconds += int((max(timestamps) - min(timestamps)).total_seconds())

        session_requests = 0
        for record_number, record in enumerate(records, 1):
            if record.get("type") != "assistant":
                continue
            message = record.get("message")
            if not isinstance(message, Mapping) or message.get("usage") is None:
                continue
            message_id = message.get("id")
            if not isinstance(message_id, str) or not message_id:
                raise PerformanceError(
                    f"assistant usage in {path}:{record_number} has no message id"
                )
            usage = _normalized_usage(record, f"{path}:{record_number}")
            key = (session_id, message_id)
            previous = request_usage.get(key)
            if previous is not None and previous != usage:
                raise PerformanceError(
                    f"conflicting duplicate usage for session {session_id}, "
                    f"message {message_id}"
                )
            request_usage[key] = usage
            session_requests += 1
        if session_requests == 0:
            raise PerformanceError(f"session {session_id} has no token usage")

    total_tokens = sum(sum(usage) for usage in request_usage.values())
    if total_tokens != expected_tokens:
        raise PerformanceError(
            f"sink token total drifted: expected {expected_tokens}, found {total_tokens}"
        )
    if serial_seconds != expected_seconds:
        raise PerformanceError(
            f"sink serial time drifted: expected {expected_seconds}s, "
            f"found {serial_seconds}s"
        )
    return total_tokens, serial_seconds, workers, len(session_ids)


def calculate_results(
    measurements: Mapping[str, object],
    session_root: Path = DEFAULT_SESSION_ROOT,
) -> PerformanceResults:
    sink_config = _mapping(
        measurements.get("sink_capability_card"), "sink_capability_card"
    )
    sink_tokens, serial_seconds, sink_workers, session_count = (
        collect_sink_capability_metrics(session_root, sink_config)
    )
    stages_config = _mapping(measurements.get("stages"), "stages")
    expected_stage_keys = set(STAGE_ORDER[1:])
    if set(stages_config) != expected_stage_keys:
        raise PerformanceError(
            "stages must contain exactly handler_type_alignment, sink_type_alignment, "
            "group_oracle, and coverage_comparison"
        )

    stages = [
        StageMeasurement(
            key="sink_capability_card",
            label=STAGE_LABELS["sink_capability_card"],
            tokens=sink_tokens,
            time_minutes=serial_seconds / sink_workers / 60,
            workers=sink_workers,
            provenance="pinned sink-capacity session logs",
        )
    ]
    for key in STAGE_ORDER[1:]:
        config = _mapping(stages_config.get(key), f"stage {key}")
        if set(config) != {"tokens", "wall_clock_minutes", "workers"}:
            raise PerformanceError(
                f"stage {key} must contain exactly tokens, wall_clock_minutes, and workers"
            )
        stages.append(
            StageMeasurement(
                key=key,
                label=STAGE_LABELS[key],
                tokens=_positive_int(config.get("tokens"), f"stage {key} tokens"),
                time_minutes=_positive_number(
                    config.get("wall_clock_minutes"),
                    f"stage {key} wall_clock_minutes",
                ),
                workers=_positive_int(
                    config.get("workers"), f"stage {key} workers"
                ),
                provenance="approved wall-clock measurement",
            )
        )
    return PerformanceResults(
        stages=tuple(stages),
        total_tokens=sum(stage.tokens for stage in stages),
        total_time_minutes=sum(stage.time_minutes for stage in stages),
        sink_session_count=session_count,
        sink_serial_seconds=serial_seconds,
    )


def _millions(tokens: int) -> str:
    return f"{tokens / 1_000_000:.1f}"


def _minutes(value: float) -> str:
    rounded = round(value, 1)
    return str(int(rounded)) if rounded.is_integer() else f"{rounded:.1f}"


def render_markdown(results: PerformanceResults) -> str:
    labels = [stage.label for stage in results.stages]
    token_values = [_millions(stage.tokens) for stage in results.stages]
    time_values = [_minutes(stage.time_minutes) for stage in results.stages]
    workers = {stage.key: stage.workers for stage in results.stages}
    lines = [
        "| Metric | " + " | ".join(labels) + " | Total |",
        "|---|" + "---:|" * (len(labels) + 1),
        "| Tokens (M) | "
        + " | ".join(token_values)
        + f" | {_millions(results.total_tokens)} |",
        "| Time (min) | "
        + " | ".join(time_values)
        + f" | {_minutes(results.total_time_minutes)} |",
        "",
        "Tokens combine input, cache-creation input, cache-read input, and output "
        "tokens. Sink Capability Card construction used "
        f"{workers['sink_capability_card']} workers: "
        f"{results.sink_serial_seconds:,} seconds of serial session time divided by "
        f"{workers['sink_capability_card']} gives "
        f"{_minutes(results.stages[0].time_minutes)} minutes. Sink-Type Alignment "
        f"and Group-Oracle used {workers['sink_type_alignment']} and "
        f"{workers['group_oracle']} workers, respectively; their recorded times are "
        "already wall-clock measurements and are not divided again.",
    ]
    return "\n".join(lines)


def replace_generated_section(document: str, generated: str) -> str:
    if document.count(GENERATED_SECTION_START) != 1:
        raise PerformanceError(
            "result document must contain exactly one RQ3 start marker"
        )
    if document.count(GENERATED_SECTION_END) != 1:
        raise PerformanceError(
            "result document must contain exactly one RQ3 end marker"
        )
    start = document.index(GENERATED_SECTION_START)
    content_start = start + len(GENERATED_SECTION_START)
    end = document.index(GENERATED_SECTION_END)
    if end < content_start:
        raise PerformanceError("result document RQ3 markers are out of order")
    replacement = (
        GENERATED_SECTION_START
        + "\n\n"
        + generated.strip()
        + "\n\n"
        + GENERATED_SECTION_END
    )
    return document[:start] + replacement + document[end + len(GENERATED_SECTION_END) :]


def write_result_document(generated: str, path: Path = RESULT_PATH) -> None:
    if not path.is_file():
        raise PerformanceError(f"missing result document: {path}")
    original_mode = path.stat().st_mode & 0o7777
    original = path.read_text(encoding="utf-8")
    updated = replace_generated_section(original, generated)
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
        description="Generate the RQ3 cross-project performance table."
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="render Markdown (default) or print structured JSON",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="print Markdown without updating design/paperdata/result.md",
    )
    parser.add_argument(
        "--session-root",
        type=Path,
        default=DEFAULT_SESSION_ROOT,
        help=f"Claude session root (default: {DEFAULT_SESSION_ROOT})",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        results = calculate_results(load_measurements(), args.session_root)
        if args.format == "json":
            print(json.dumps(results.as_dict(), indent=2, ensure_ascii=False))
        else:
            rendered = render_markdown(results)
            if args.stdout:
                print(rendered)
            else:
                write_result_document(rendered)
    except (OSError, PerformanceError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

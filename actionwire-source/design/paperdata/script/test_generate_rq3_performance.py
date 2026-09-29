#!/usr/bin/env python3
"""Tests for the RQ3 performance-table generator."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import generate_rq3_performance as performance  # noqa: E402


def usage(
    message_id: str,
    timestamp: str,
    *,
    input_tokens: int,
    cache_creation_input_tokens: int = 0,
    cache_read_input_tokens: int = 0,
    output_tokens: int,
) -> dict[str, object]:
    return {
        "type": "assistant",
        "sessionId": "session-1",
        "entrypoint": "sink-capacity",
        "timestamp": timestamp,
        "message": {
            "id": message_id,
            "usage": {
                "input_tokens": input_tokens,
                "cache_creation_input_tokens": cache_creation_input_tokens,
                "cache_read_input_tokens": cache_read_input_tokens,
                "output_tokens": output_tokens,
            },
        },
    }


def measurement_document(
    *,
    expected_tokens: int = 36,
    expected_seconds: int = 60,
) -> dict[str, object]:
    return {
        "sink_capability_card": {
            "entrypoint": "sink-capacity",
            "workers": 10,
            "expected_sessions": 1,
            "expected_total_tokens": expected_tokens,
            "expected_serial_seconds": expected_seconds,
            "session_ids": ["session-1"],
        },
        "stages": {
            "handler_type_alignment": {
                "tokens": 1_200_000,
                "wall_clock_minutes": 7,
                "workers": 1,
            },
            "sink_type_alignment": {
                "tokens": 2_200_000,
                "wall_clock_minutes": 8,
                "workers": 10,
            },
            "group_oracle": {
                "tokens": 6_800_000,
                "wall_clock_minutes": 6,
                "workers": 10,
            },
            "coverage_comparison": {
                "tokens": 10_500_000,
                "wall_clock_minutes": 12,
                "workers": 1,
            },
        },
    }


def write_session(
    root: Path,
    records: list[object] | None = None,
    *,
    session_id: str = "session-1",
) -> Path:
    path = root / "project" / f"{session_id}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    if records is None:
        first = usage(
            "message-1",
            "2026-07-03T09:00:00.900Z",
            input_tokens=10,
            cache_creation_input_tokens=3,
            cache_read_input_tokens=5,
            output_tokens=2,
        )
        duplicate = json.loads(json.dumps(first))
        duplicate["timestamp"] = "2026-07-03T09:00:20.100Z"
        second = usage(
            "message-2",
            "2026-07-03T09:01:00.800Z",
            input_tokens=9,
            cache_read_input_tokens=4,
            output_tokens=3,
        )
        records = [first, duplicate, second]
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )
    return path


class SinkEvidenceTests(unittest.TestCase):
    def test_counts_tokens_once_and_normalizes_time_by_workers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_session(root)
            results = performance.calculate_results(measurement_document(), root)
        sink = results.stages[0]
        self.assertEqual(36, sink.tokens)
        self.assertAlmostEqual(0.1, sink.time_minutes)
        self.assertEqual(10, sink.workers)
        self.assertEqual(1, results.sink_session_count)
        self.assertEqual(60, results.sink_serial_seconds)

    def test_unrelated_session_is_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_session(root)
            unrelated = usage(
                "other-message",
                "2026-07-03T10:00:00Z",
                input_tokens=999,
                output_tokens=999,
            )
            unrelated["sessionId"] = "unrelated"
            write_session(root, [unrelated], session_id="unrelated")
            results = performance.calculate_results(measurement_document(), root)
        self.assertEqual(36, results.stages[0].tokens)

    def test_missing_pinned_session_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(performance.PerformanceError, "found 0"):
                performance.calculate_results(
                    measurement_document(), Path(directory)
                )

    def test_duplicate_session_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_session(root)
            duplicate = root / "second" / "session-1.jsonl"
            duplicate.parent.mkdir()
            duplicate.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(performance.PerformanceError, "found 2"):
                performance.calculate_results(measurement_document(), root)

    def test_malformed_jsonl_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "project" / "session-1.jsonl"
            path.parent.mkdir()
            path.write_text("{not json}\n", encoding="utf-8")
            with self.assertRaisesRegex(performance.PerformanceError, "invalid JSON"):
                performance.calculate_results(measurement_document(), root)

    def test_non_object_session_record_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_session(root, [[]])
            with self.assertRaisesRegex(performance.PerformanceError, "not an object"):
                performance.calculate_results(measurement_document(), root)

    def test_wrong_entrypoint_fails(self) -> None:
        record = usage(
            "message-1",
            "2026-07-03T09:00:00Z",
            input_tokens=10,
            output_tokens=2,
        )
        record["entrypoint"] = "gate-semantics"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_session(root, [record])
            with self.assertRaisesRegex(performance.PerformanceError, "not identified"):
                performance.calculate_results(measurement_document(), root)

    def test_missing_timestamps_fail(self) -> None:
        first = usage(
            "message-1",
            "2026-07-03T09:00:00Z",
            input_tokens=10,
            output_tokens=2,
        )
        first.pop("timestamp")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_session(root, [first])
            with self.assertRaisesRegex(performance.PerformanceError, "timestamps"):
                performance.calculate_results(measurement_document(), root)

    def test_missing_token_usage_fails(self) -> None:
        records = [
            {
                "type": "user",
                "sessionId": "session-1",
                "entrypoint": "sink-capacity",
                "timestamp": "2026-07-03T09:00:00Z",
                "message": {"content": "prompt"},
            },
            {
                "type": "assistant",
                "sessionId": "session-1",
                "entrypoint": "sink-capacity",
                "timestamp": "2026-07-03T09:01:00Z",
                "message": {"id": "message-1", "content": []},
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_session(root, records)
            with self.assertRaisesRegex(performance.PerformanceError, "no token usage"):
                performance.calculate_results(measurement_document(), root)

    def test_conflicting_duplicate_usage_fails(self) -> None:
        first = usage(
            "message-1",
            "2026-07-03T09:00:00Z",
            input_tokens=10,
            output_tokens=2,
        )
        second = usage(
            "message-1",
            "2026-07-03T09:01:00Z",
            input_tokens=11,
            output_tokens=2,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_session(root, [first, second])
            with self.assertRaisesRegex(
                performance.PerformanceError, "conflicting duplicate"
            ):
                performance.calculate_results(
                    measurement_document(expected_tokens=12), root
                )

    def test_token_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_session(root)
            with self.assertRaisesRegex(performance.PerformanceError, "token total drifted"):
                performance.calculate_results(
                    measurement_document(expected_tokens=37), root
                )

    def test_time_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_session(root)
            with self.assertRaisesRegex(performance.PerformanceError, "serial time drifted"):
                performance.calculate_results(
                    measurement_document(expected_seconds=61), root
                )

    def test_invalid_stage_measurement_fails(self) -> None:
        document = measurement_document()
        document["stages"]["coverage_comparison"]["tokens"] = 0  # type: ignore[index]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_session(root)
            with self.assertRaisesRegex(performance.PerformanceError, "must be positive"):
                performance.calculate_results(document, root)


class RenderingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.live_shape = performance.PerformanceResults(
            stages=(
                performance.StageMeasurement(
                    "sink_capability_card",
                    "Sink Capability Card",
                    12_264_167,
                    9.37,
                    10,
                    "pinned sink-capacity session logs",
                ),
                performance.StageMeasurement(
                    "handler_type_alignment",
                    "Handler-Type Alignment",
                    1_200_000,
                    7,
                    1,
                    "approved wall-clock measurement",
                ),
                performance.StageMeasurement(
                    "sink_type_alignment",
                    "Sink-Type Alignment",
                    2_200_000,
                    8,
                    10,
                    "approved wall-clock measurement",
                ),
                performance.StageMeasurement(
                    "group_oracle",
                    "Group-Oracle",
                    6_800_000,
                    6,
                    10,
                    "approved wall-clock measurement",
                ),
                performance.StageMeasurement(
                    "coverage_comparison",
                    "Coverage Comparison",
                    10_500_000,
                    12,
                    1,
                    "approved wall-clock measurement",
                ),
            ),
            total_tokens=32_964_167,
            total_time_minutes=42.37,
            sink_session_count=73,
            sink_serial_seconds=5_622,
        )

    def test_renders_approved_values_and_totals(self) -> None:
        rendered = performance.render_markdown(self.live_shape)
        self.assertIn(
            "| Tokens (M) | 12.3 | 1.2 | 2.2 | 6.8 | 10.5 | 33.0 |",
            rendered,
        )
        self.assertIn(
            "| Time (min) | 9.4 | 7 | 8 | 6 | 12 | 42.4 |",
            rendered,
        )
        self.assertIn("5,622 seconds of serial session time divided by 10", rendered)
        self.assertIn("are not divided again", rendered)

    def test_json_output_contains_raw_totals(self) -> None:
        decoded = json.loads(json.dumps(self.live_shape.as_dict()))
        self.assertEqual(12_264_167, decoded["stages"][0]["tokens"])
        self.assertEqual(32_964_167, decoded["totals"]["tokens"])
        self.assertEqual(5_622, decoded["sink_capability_card_evidence"]["serial_seconds"])


class ReportUpdateTests(unittest.TestCase):
    def test_replacement_preserves_all_content_outside_rq3_block(self) -> None:
        document = (
            "RQ1 bytes that must survive\n"
            + performance.GENERATED_SECTION_START
            + "\nold RQ3\n"
            + performance.GENERATED_SECTION_END
            + "\nmanual notes that must survive\n"
        )
        updated = performance.replace_generated_section(document, "new RQ3")
        self.assertEqual(
            "RQ1 bytes that must survive\n"
            + performance.GENERATED_SECTION_START
            + "\n\nnew RQ3\n\n"
            + performance.GENERATED_SECTION_END
            + "\nmanual notes that must survive\n",
            updated,
        )

    def test_missing_duplicate_and_reversed_markers_fail(self) -> None:
        with self.assertRaisesRegex(performance.PerformanceError, "start marker"):
            performance.replace_generated_section("manual only", "generated")
        duplicate = (
            performance.GENERATED_SECTION_START
            + performance.GENERATED_SECTION_START
            + performance.GENERATED_SECTION_END
        )
        with self.assertRaisesRegex(performance.PerformanceError, "start marker"):
            performance.replace_generated_section(duplicate, "generated")
        reversed_markers = (
            performance.GENERATED_SECTION_END
            + performance.GENERATED_SECTION_START
        )
        with self.assertRaisesRegex(performance.PerformanceError, "out of order"):
            performance.replace_generated_section(reversed_markers, "generated")

    def test_atomic_writer_preserves_permissions_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.md"
            path.write_text(
                "before\n"
                + performance.GENERATED_SECTION_START
                + "\nold\n"
                + performance.GENERATED_SECTION_END
                + "\nafter\n",
                encoding="utf-8",
            )
            path.chmod(0o640)
            performance.write_result_document("new", path)
            first = path.read_bytes()
            performance.write_result_document("new", path)
            second = path.read_bytes()
            mode = path.stat().st_mode & 0o7777
        self.assertEqual(first, second)
        self.assertEqual(0o640, mode)

    def test_validation_failure_leaves_result_untouched(self) -> None:
        original = "manual document without RQ3 markers\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.md"
            path.write_text(original, encoding="utf-8")
            with self.assertRaises(performance.PerformanceError):
                performance.write_result_document("generated", path)
            current = path.read_text(encoding="utf-8")
        self.assertEqual(original, current)


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.results = performance.PerformanceResults(
            stages=(),
            total_tokens=0,
            total_time_minutes=0,
            sink_session_count=0,
            sink_serial_seconds=0,
        )

    def test_default_updates_result_without_stdout(self) -> None:
        stdout = io.StringIO()
        with mock.patch.object(performance, "load_measurements", return_value={}), mock.patch.object(
            performance, "calculate_results", return_value=self.results
        ), mock.patch.object(
            performance, "render_markdown", return_value="rendered"
        ), mock.patch.object(performance, "write_result_document") as write:
            with contextlib.redirect_stdout(stdout):
                status = performance.main([])
        self.assertEqual(0, status)
        self.assertEqual("", stdout.getvalue())
        write.assert_called_once_with("rendered")

    def test_stdout_previews_without_writing(self) -> None:
        stdout = io.StringIO()
        with mock.patch.object(performance, "load_measurements", return_value={}), mock.patch.object(
            performance, "calculate_results", return_value=self.results
        ), mock.patch.object(
            performance, "render_markdown", return_value="rendered"
        ), mock.patch.object(performance, "write_result_document") as write:
            with contextlib.redirect_stdout(stdout):
                status = performance.main(["--stdout"])
        self.assertEqual(0, status)
        self.assertEqual("rendered\n", stdout.getvalue())
        write.assert_not_called()

    def test_json_prints_without_writing(self) -> None:
        stdout = io.StringIO()
        with mock.patch.object(performance, "load_measurements", return_value={}), mock.patch.object(
            performance, "calculate_results", return_value=self.results
        ), mock.patch.object(performance, "write_result_document") as write:
            with contextlib.redirect_stdout(stdout):
                status = performance.main(["--format", "json"])
        self.assertEqual(0, status)
        self.assertEqual(0, json.loads(stdout.getvalue())["totals"]["tokens"])
        write.assert_not_called()

    def test_evidence_failure_does_not_call_writer(self) -> None:
        stderr = io.StringIO()
        with mock.patch.object(performance, "load_measurements", return_value={}), mock.patch.object(
            performance,
            "calculate_results",
            side_effect=performance.PerformanceError("evidence failed"),
        ), mock.patch.object(performance, "write_result_document") as write:
            with contextlib.redirect_stderr(stderr):
                status = performance.main([])
        self.assertEqual(1, status)
        self.assertIn("evidence failed", stderr.getvalue())
        write.assert_not_called()


if __name__ == "__main__":
    unittest.main()

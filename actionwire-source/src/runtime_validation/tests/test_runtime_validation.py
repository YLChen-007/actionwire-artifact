from __future__ import annotations

import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from argparse import Namespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from src.projects import get_project
from src.runtime_validation.__main__ import _read_prompt, build_parser
from src.runtime_validation.contracts import (
    INCONCLUSIVE,
    NOT_TRIGGERED,
    TRIGGERED,
    ValidationError,
    ValidationRequest,
    aggregate_attempts,
    contains_credentials,
    load_event_jsonl,
    redact_text,
)
from src.runtime_validation.evaluator import evaluate_events
from src.runtime_validation.oracle import (
    SCHEMA_PATH,
    load_oracle,
    verify_source_binding,
)
from src.runtime_validation.pipeline import _credential_scan, validate_prompt
from src.runtime_validation.runner import (
    INJECT_DIR,
    REPO_ROOT,
    _terminate_process_group,
)


REPORT = "CVE-2026-Device-Blocking-Expanduser-Bypass"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "runtime_target.py"


def _event(name: str, sequence: int, invocation: str = "inv-1") -> dict:
    return {
        "schema_version": "clawgap-runtime-validation-event/v1",
        "event_id": f"E-{sequence}",
        "event": name,
        "sequence": sequence,
        "invocation_id": invocation,
    }


def _fixture_popen_line() -> int:
    for number, line in enumerate(FIXTURE.read_text().splitlines(), 1):
        if line.strip() == "return subprocess.Popen(":
            return number
    raise AssertionError("fixture Popen line not found")


def _fixture_oracle() -> dict:
    return {
        "schema_version": "clawgap-runtime-trigger-oracle/v1",
        "report_name": "fixture",
        "handler": {
            "file": "src/runtime_validation/tests/fixtures/runtime_target.py",
            "function": "_handle_read_file",
            "argument_path": ["args", "path"],
        },
        "gate": {
            "file": "src/runtime_validation/tests/fixtures/runtime_target.py",
            "function": "_is_blocked_device",
            "argument_name": "filepath",
            "expected_return": False,
        },
        "trigger": {
            "predicate": "normalized-path-in",
            "transforms": ["expanduser", "normpath"],
            "targets": ["/dev/urandom", "/dev/zero"],
            "require_changed": True,
        },
        "sink": {
            "primitive": "subprocess.Popen",
            "file": "src/runtime_validation/tests/fixtures/runtime_target.py",
            "function": "_run_bash",
            "line": _fixture_popen_line(),
            "payload_relation": "contains-raw-argument",
            "intercept": True,
        },
        "success_events": [
            "handler_argument_matched",
            "gate_returned_expected",
            "sink_reached",
            "effect_intercepted",
        ],
    }


class RuntimeValidationContractsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = get_project("hermes-agent")
        self.oracle = load_oracle(self.spec, REPORT)

    def test_request_and_attempt_contracts(self) -> None:
        request = ValidationRequest("hermes-agent", REPORT, "read the path")
        self.assertEqual(1, request.attempts)
        with self.assertRaises(ValidationError):
            ValidationRequest("hermes-agent", REPORT, "", attempts=1)
        with self.assertRaises(ValidationError):
            ValidationRequest("hermes-agent", REPORT, "x", attempts=0)
        self.assertEqual(
            (
                TRIGGERED,
                "at least one attempt reached and intercepted the matching sink",
            ),
            aggregate_attempts([{"verdict": NOT_TRIGGERED}, {"verdict": TRIGGERED}]),
        )
        self.assertEqual(
            NOT_TRIGGERED, aggregate_attempts([{"verdict": NOT_TRIGGERED}])[0]
        )
        self.assertEqual(
            INCONCLUSIVE, aggregate_attempts([{"verdict": INCONCLUSIVE}])[0]
        )

    def test_oracle_schema_is_strict_and_source_bound(self) -> None:
        binding = verify_source_binding(self.spec, self.oracle)
        self.assertEqual(self.spec.analysis_revision, binding["analysis_revision"])
        schema = json.loads(SCHEMA_PATH.read_text())
        invalid = copy.deepcopy(self.oracle)
        invalid["handler"]["unexpected"] = True
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(invalid)))
        mismatched = copy.deepcopy(self.oracle)
        mismatched["source_binding"]["files"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValidationError, "source hash mismatch"):
            verify_source_binding(self.spec, mismatched)

    def test_evaluator_requires_order_and_same_invocation(self) -> None:
        events = [_event("instrumentation_ready", 1, "")]
        events.extend(
            _event(name, index + 2)
            for index, name in enumerate(self.oracle["success_events"])
        )
        verdict, _, matched = evaluate_events(
            events,
            self.oracle,
            process_status="terminated-after-trigger",
            returncode=None,
        )
        self.assertEqual(TRIGGERED, verdict)
        self.assertEqual(4, len(matched))

        reordered = [events[0], events[2], events[1], events[3], events[4]]
        verdict, _, _ = evaluate_events(
            reordered, self.oracle, process_status="completed", returncode=0
        )
        self.assertEqual(TRIGGERED, verdict)

        wrong_sequence = [events[0], events[2], events[1], events[3], events[4]]
        wrong_sequence[1] = {**wrong_sequence[1], "sequence": 2}
        wrong_sequence[2] = {**wrong_sequence[2], "sequence": 3}
        verdict, _, _ = evaluate_events(
            wrong_sequence, self.oracle, process_status="completed", returncode=0
        )
        self.assertEqual(NOT_TRIGGERED, verdict)

        split = [events[0], *events[1:3]]
        split.extend({**row, "invocation_id": "inv-2"} for row in events[3:])
        verdict, _, _ = evaluate_events(
            split, self.oracle, process_status="completed", returncode=0
        )
        self.assertEqual(NOT_TRIGGERED, verdict)

    def test_trace_errors_and_process_failures_are_inconclusive(self) -> None:
        ready = [_event("instrumentation_ready", 1, "")]
        self.assertEqual(
            INCONCLUSIVE,
            evaluate_events(
                ready,
                self.oracle,
                trace_errors=["bad trace"],
                process_status="completed",
                returncode=0,
            )[0],
        )
        self.assertEqual(
            INCONCLUSIVE,
            evaluate_events(
                ready, self.oracle, process_status="timeout", returncode=None
            )[0],
        )
        instrumentation_error = {
            **_event("instrumentation_error", 2, ""),
            "details": {"error": "fixture tracer failed"},
        }
        self.assertEqual(
            INCONCLUSIVE,
            evaluate_events(
                [*ready, instrumentation_error],
                self.oracle,
                process_status="completed",
                returncode=0,
            )[0],
        )

    def test_event_jsonl_rejects_malformed_and_duplicate_events(self) -> None:
        valid = {
            **_event("instrumentation_ready", 1, ""),
            "pid": 10,
            "thread_id": 20,
            "details": {},
        }
        duplicate = {**valid}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(
                json.dumps(valid) + "\n" + json.dumps(duplicate) + "\nnot-json\n",
                encoding="utf-8",
            )
            events, errors = load_event_jsonl(path)
        self.assertEqual([valid], events)
        self.assertEqual(2, len(errors))
        self.assertTrue(any("duplicate event_id" in error for error in errors))
        self.assertTrue(any("invalid JSON" in error for error in errors))

    def test_redaction_covers_exact_and_shaped_credentials(self) -> None:
        secret = "runtime-secret-value"
        raw = f"token={secret} Authorization: Bearer abc sk-abcdefghijklmno"
        redacted = redact_text(raw, (secret,))
        self.assertNotIn(secret, redacted)
        self.assertNotIn("sk-abcdefghijklmno", redacted)
        self.assertFalse(contains_credentials(redacted, (secret,)))

    def test_cli_reads_prompt_string_file_and_stdin(self) -> None:
        parser = build_parser()
        self.assertEqual(
            "inline", _read_prompt(Namespace(prompt="inline", prompt_file=None), parser)
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "prompt.txt"
            path.write_text("from file", encoding="utf-8")
            self.assertEqual(
                "from file",
                _read_prompt(Namespace(prompt=None, prompt_file=path), parser),
            )
        with patch.object(sys, "stdin", io.StringIO("from stdin")):
            self.assertEqual(
                "from stdin",
                _read_prompt(Namespace(prompt=None, prompt_file=None), parser),
            )


class InjectedInstrumentationTest(unittest.TestCase):
    def _run(
        self, mode: str, value: str, directory: Path
    ) -> tuple[subprocess.CompletedProcess[str], list[dict]]:
        oracle_path = directory / "oracle.json"
        events_path = directory / "events.jsonl"
        marker = directory / "popen-called"
        oracle_path.write_text(json.dumps(_fixture_oracle()), encoding="utf-8")
        environment = os.environ.copy()
        environment.update(
            {
                "PYTHONPATH": os.pathsep.join([str(INJECT_DIR), str(REPO_ROOT)]),
                "CLAWGAP_RUNTIME_ORACLE_PATH": str(oracle_path),
                "CLAWGAP_RUNTIME_EVENTS_PATH": str(events_path),
                "CLAWGAP_RUNTIME_ERROR_PATH": str(directory / "trace-error.log"),
            }
        )
        result = subprocess.run(
            [sys.executable, str(FIXTURE), mode, value, str(marker)],
            cwd=REPO_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
        )
        events = [json.loads(line) for line in events_path.read_text().splitlines()]
        return result, events

    def test_matching_path_reaches_and_intercepts_sink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, events = self._run("handler", "/dev/./zero", root)
            self.assertNotEqual(0, result.returncode)
            self.assertFalse((root / "popen-called").exists())
            names = [row["event"] for row in events]
            self.assertEqual(
                [
                    "handler_argument_matched",
                    "gate_returned_expected",
                    "sink_reached",
                    "effect_intercepted",
                ],
                [name for name in names if name != "instrumentation_ready"],
            )

    def test_canonical_block_and_wrong_path_do_not_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, events = self._run("handler", "/dev/zero", root)
            self.assertEqual(0, result.returncode)
            self.assertFalse((root / "popen-called").exists())
            self.assertEqual(
                ["instrumentation_ready"], [row["event"] for row in events]
            )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, events = self._run("handler", "/tmp/safe", root)
            self.assertEqual(0, result.returncode)
            self.assertTrue((root / "popen-called").exists())
            self.assertEqual(
                ["instrumentation_ready"], [row["event"] for row in events]
            )

    def test_unrelated_popen_is_not_intercepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, events = self._run("unrelated", "/dev/./zero", root)
            self.assertEqual(0, result.returncode)
            self.assertTrue((root / "popen-called").exists())
            self.assertEqual(
                ["instrumentation_ready"], [row["event"] for row in events]
            )

    def test_process_group_termination(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            start_new_session=True,
            text=True,
        )
        _terminate_process_group(process)
        self.assertIsNotNone(process.poll())


class _FakeAttemptRunner:
    def __init__(self, verdicts: list[str]):
        self.verdicts = verdicts

    def run_attempt(self, attempt: int, attempt_dir: Path) -> dict:
        attempt_dir.mkdir(parents=True)
        result = {
            "schema_version": "clawgap-runtime-validation-attempt/v1",
            "attempt": attempt,
            "verdict": self.verdicts[attempt - 1],
            "reason": "fixture",
            "process_status": "completed",
            "returncode": 0,
            "elapsed_seconds": 0.01,
            "matched_event_ids": [],
            "events": 1,
            "event_errors": [],
        }
        (attempt_dir / "attempt.json").write_text(json.dumps(result), encoding="utf-8")
        return result


class ValidationPipelineTest(unittest.TestCase):
    def test_residual_credential_scan_sanitizes_before_failure(self) -> None:
        secret = "runtime-residual-secret"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.log"
            path.write_text(f"payload={secret}\n", encoding="utf-8")
            with self.assertRaisesRegex(
                ValidationError, "credential material detected"
            ):
                _credential_scan(Path(directory), (secret,))
            self.assertNotIn(secret, path.read_text())
            self.assertIn("[REDACTED_CREDENTIAL]", path.read_text())

    def test_pipeline_publishes_bundle_and_redacts_prompt_secret(self) -> None:
        secret = "sk-runtime-pipeline-secret"
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"RUNTIME_TEST_KEY": secret}),
        ):
            request = ValidationRequest(
                "hermes-agent",
                REPORT,
                f"read /dev/./zero and do not print {secret}",
                attempts=2,
                api_key_env="RUNTIME_TEST_KEY",
                out_dir=Path(directory),
            )
            run = validate_prompt(
                request,
                runner_factory=lambda *_: _FakeAttemptRunner(
                    [NOT_TRIGGERED, TRIGGERED]
                ),
            )
            self.assertEqual(TRIGGERED, run.verdict)
            self.assertTrue((run.artifact_dir / "manifest.json").is_file())
            self.assertIn(
                "[REDACTED_CREDENTIAL]", (run.artifact_dir / "prompt.txt").read_text()
            )
            for path in run.artifact_dir.rglob("*"):
                if path.is_file():
                    self.assertNotIn(secret, path.read_text(errors="replace"))

    def test_source_mismatch_is_persisted_as_inconclusive(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "src.runtime_validation.pipeline.verify_source_binding",
                side_effect=ValidationError("source hash mismatch for fixture"),
            ),
        ):
            run = validate_prompt(
                ValidationRequest(
                    "hermes-agent", REPORT, "read /dev/./zero", out_dir=Path(directory)
                ),
                runner_factory=lambda *_: _FakeAttemptRunner([TRIGGERED]),
            )
            self.assertEqual(INCONCLUSIVE, run.verdict)
            self.assertIn("source hash mismatch", run.reason)
            self.assertTrue((run.artifact_dir / "result.json").is_file())


class _FakeOpenAIHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:
        return None

    def _json(self, status: int, value: dict) -> None:
        payload = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/v1/models":
            self._json(200, {"object": "list", "data": [{"id": "runtime-fake-model"}]})
        else:
            self._json(404, {"error": {"message": "not found"}})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length) or b"{}")
        if self.path.rstrip("/") != "/v1/chat/completions":
            self._json(404, {"error": {"message": "not found"}})
            return
        if not request.get("stream"):
            self._json(
                200,
                {
                    "id": "chatcmpl-runtime",
                    "object": "chat.completion",
                    "created": 1,
                    "model": "runtime-fake-model",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "done"},
                            "finish_reason": "stop",
                        }
                    ],
                },
            )
            return
        chunks = [
            {
                "id": "chatcmpl-runtime",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "runtime-fake-model",
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "role": "assistant",
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call-runtime-1",
                                    "type": "function",
                                    "function": {
                                        "name": "read_file",
                                        "arguments": '{"path":"/dev/./zero"}',
                                    },
                                }
                            ],
                        },
                        "finish_reason": None,
                    }
                ],
            },
            {
                "id": "chatcmpl-runtime",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "runtime-fake-model",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "total_tokens": 2,
                },
            },
        ]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        for chunk in chunks:
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode("utf-8"))
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        self.close_connection = True


class HermesFakeModelIntegrationTest(unittest.TestCase):
    def test_real_hermes_dispatch_reaches_intercepted_sink(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeOpenAIHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with (
                tempfile.TemporaryDirectory() as directory,
                patch.dict(os.environ, {"RUNTIME_FAKE_API_KEY": "runtime-fake-key"}),
            ):
                request = ValidationRequest(
                    "hermes-agent",
                    REPORT,
                    "Read /dev/./zero using the read_file tool.",
                    timeout_seconds=30,
                    model="runtime-fake-model",
                    base_url=f"http://127.0.0.1:{server.server_port}/v1",
                    api_key_env="RUNTIME_FAKE_API_KEY",
                    out_dir=Path(directory),
                )
                run = validate_prompt(request)
                self.assertEqual(TRIGGERED, run.verdict, run.record())
                events = (run.artifact_dir / "attempt-001" / "events.jsonl").read_text()
                self.assertIn('"event": "effect_intercepted"', events)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()

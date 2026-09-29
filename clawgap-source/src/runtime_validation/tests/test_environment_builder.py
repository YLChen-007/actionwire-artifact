from __future__ import annotations

import copy
import json
import tempfile
import unittest
import urllib.request
from pathlib import Path

from src.projects import list_projects
from src.runtime_validation.contracts import ValidationError
from src.runtime_validation.environment_builder import (
    EnvironmentBuildRequest,
    PROFILE_SCHEMA_VERSION,
    _command,
    _verify_candidate,
    _launch_target,
    load_environment_profiles,
)


REPO_ROOT = Path(__file__).resolve().parents[3]


class EnvironmentPlanContractTest(unittest.TestCase):
    def test_profiles_cover_registry_exactly(self) -> None:
        profiles = load_environment_profiles()
        self.assertEqual(set(profiles), set(list_projects()))
        self.assertEqual(12, len(profiles))
        for project, profile in profiles.items():
            self.assertEqual(PROFILE_SCHEMA_VERSION, profile["schema_version"])
            self.assertTrue(profile["source_files"])
            self.assertIn(
                profile["runtime"], {"python", "node", "bun", "npm", "pnpm"}
            )

    def test_registry_revision_and_nonloopback_provider_drift_fail_closed(self) -> None:
        profiles = load_environment_profiles()
        invalid = copy.deepcopy(profiles["AstrBot"])
        invalid["revision"] = "0" * 40
        with self.assertRaisesRegex(ValidationError, "revision drift"):
            from src.runtime_validation.environment_builder import _validate_profile

            _validate_profile(invalid)
        invalid = copy.deepcopy(profiles["AstrBot"])
        invalid["provider"]["base_url"] = "https://example.invalid/v1"
        with self.assertRaisesRegex(
            ValidationError, "provider base URL|schema validation failed"
        ):
            _validate_profile(invalid)

    def test_candidate_identity_and_reproduction_command_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            candidates = Path(directory_name) / "candidates.jsonl"
            revision = load_environment_profiles()["AstrBot"]["revision"]
            rows = [
                {
                    "candidate_id": "CAND-good",
                    "project": "AstrBot",
                    "revision": revision,
                },
                {
                    "candidate_id": "CAND-wrong-project",
                    "project": "QwenPaw",
                    "revision": revision,
                },
            ]
            candidates.write_text(
                "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
            )
            request = EnvironmentBuildRequest(
                out_dir=Path(directory_name) / "out",
                projects=("AstrBot",),
                candidate_id="CAND-good",
                candidates_file=candidates,
            )
            self.assertEqual(
                "CAND-good", _verify_candidate(request, "AstrBot")["candidate_id"]
            )
            with self.assertRaisesRegex(ValidationError, "project does not match"):
                _verify_candidate(request, "QwenPaw")
            command = _command(request)
            self.assertIn("build-runtime-l2-environment", command)
            self.assertIn("--candidate-id CAND-good", command)
            self.assertIn("--setup-timeout 1200", command)


class SyntheticEnvironmentLifecycleTest(unittest.TestCase):
    def test_launch_provider_input_instrumentation_interceptor_and_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            project_root = directory / "project"
            home = directory / "home"
            temporary = directory / "temporary"
            project_root.mkdir()
            home.mkdir()
            temporary.mkdir()
            event_path = directory / "events.raw.jsonl"
            target_config = directory / "target.json"
            smoke_config = directory / "smoke.json"
            base = {
                "case_id": "ENV-synthetic-self-test",
                "correlation_id": "ENV-synthetic-self-test:1",
                "attempt": 1,
                "role": "self-test",
                "project": "synthetic",
                "environment_id": "ENV-synthetic-self-test:1",
                "probe_id": "ENV-synthetic-self-test",
                "candidate_id": None,
                "anchors": [
                    {
                        "kind": "provider-request",
                        "anchor": "target.py:1",
                    },
                    {"kind": "pre-effect", "anchor": "target.py:2"},
                ],
                "event_path": str(event_path),
                "provider_base_url": "http://127.0.0.1:18099",
            }
            target_config.write_text(
                json.dumps({**base, "intercept_effects": False}), encoding="utf-8"
            )
            smoke_config.write_text(
                json.dumps({**base, "intercept_effects": True}), encoding="utf-8"
            )
            config = {
                "project": "synthetic",
                "environment_id": base["environment_id"],
                "probe_id": base["probe_id"],
                "candidate_id": None,
                "runtime": "python",
                "project_root": project_root,
                "state_root": directory,
                "home": home,
                "temporary": temporary,
                "launch_command": (
                    "printf 'synthetic ready\\n'; python -c \"import urllib.request; "
                    "request=urllib.request.Request('http://127.0.0.1:18099/v1/chat/completions', "
                    "data=b'{}', headers={'Content-Type':'application/json',"
                    "'Authorization':'Bearer synthetic-secret'}); "
                    "urllib.request.urlopen(request)\""
                ),
                "probe_command": None,
                "readiness_pattern": "synthetic ready",
                "launch_timeout": 8,
                "launch_log": directory / "launch.log",
                "event_path": event_path,
                "transcript_path": directory / "provider-transcript.jsonl",
                "ready_path": directory / "provider.ready",
                "port": 18099,
                "protocol": "openai-chat-completions/v1",
                "response_mode": "json",
                "path": "/v1/chat/completions",
                "loader": REPO_ROOT
                / "src/runtime_validation/l2_instrumentation/python/sitecustomize.py",
                "input_kind": "cli-argument",
                "target_instrumentation": target_config,
                "smoke_instrumentation": smoke_config,
            }
            result = _launch_target(config)
            self.assertTrue(result["ready"], result["reasons"])
            self.assertEqual(1, result["provider_fixture"]["request_count"])
            self.assertEqual(
                "[REDACTED_CREDENTIAL]",
                result["provider_fixture"]["requests"][0]["authorization"],
            )
            events = [
                json.loads(line)
                for line in event_path.read_text(encoding="utf-8").splitlines()
            ]
            stages = {row["stage"] for row in events}
            self.assertIn("fixture_prepared", stages)
            self.assertIn("launch_started", stages)
            self.assertIn("input_delivered", stages)
            self.assertIn("provider_request", stages)
            self.assertIn("pre-effect", stages)
            intercepted = [row for row in events if row["stage"] == "pre-effect"]
            self.assertTrue(
                all(row.get("intercept_before_execution") is True for row in intercepted)
            )
            self.assertTrue((directory / "launch.log").read_text(encoding="utf-8").strip())


if __name__ == "__main__":
    unittest.main()

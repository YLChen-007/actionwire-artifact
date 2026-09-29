from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.runtime_validation.environment_smoke import (
    EXPECTED_PROJECTS,
    EXPECTED_STATUS_COUNTS,
    EnvironmentProjectSpec,
    EnvironmentSmokeRequest,
    _redact_environment_text,
    project_specs,
    run_environment_smoke,
)
from src.runtime_validation.contracts import ValidationError


class EnvironmentSmokeContractTest(unittest.TestCase):
    def test_exact_eleven_project_denominator(self) -> None:
        specs = project_specs()
        self.assertEqual(11, len(specs))
        self.assertEqual(EXPECTED_PROJECTS, tuple(spec.project for spec in specs))
        self.assertEqual(11, len({spec.project for spec in specs}))

    def test_expected_launch_outcome_and_l2_boundary(self) -> None:
        specs = project_specs()
        counts = {
            status: sum(spec.expected_launch_status == status for spec in specs)
            for status in ("launch-confirmed", "launch-blocked")
            if any(spec.expected_launch_status == status for spec in specs)
        }
        self.assertEqual(EXPECTED_STATUS_COUNTS, counts)
        lettabot = next(spec for spec in specs if spec.project == "lettabot")
        self.assertEqual("launch-confirmed", lettabot.expected_launch_status)
        self.assertEqual("mock-channel-bridge", lettabot.launch_fixture)
        self.assertIn("Started channel: Mock (Testing)", lettabot.readiness_pattern)
        self.assertEqual(2, len(lettabot.fixture_files))
        for spec in specs:
            self.assertTrue(spec.readiness_pattern)
            self.assertTrue(spec.setup_command)
            self.assertTrue(spec.launch_command)
            self.assertTrue(spec.binding_files)

    def test_request_rejects_duplicates_and_unknown_projects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out_dir = Path(directory) / "smoke"
            with self.assertRaisesRegex(ValidationError, "unique"):
                EnvironmentSmokeRequest(out_dir, projects=("AstrBot", "AstrBot"))
            with self.assertRaisesRegex(ValidationError, "unknown"):
                EnvironmentSmokeRequest(out_dir, projects=["unknown-project"])

    def test_environment_log_redaction(self) -> None:
        value = "Initial password: mnnebfNxZ9wU81Pvfus989JP\nsk-0123456789abcdefg\n"
        redacted = _redact_environment_text(value, ())
        self.assertNotIn("mnnebfNxZ9wU81Pvfus989JP", redacted)
        self.assertNotIn("sk-0123456789abcdefg", redacted)
        self.assertEqual(2, redacted.count("[REDACTED_CREDENTIAL]"))


class EnvironmentSmokeCampaignTest(unittest.TestCase):
    def test_campaign_publishes_exact_denominator_without_l2_promotion(self) -> None:
        def fake_run_project(
            spec: EnvironmentProjectSpec,
            request: EnvironmentSmokeRequest,
            setup_log: Path,
            launch_log: Path,
        ):
            setup_log.write_text("setup complete\n", encoding="utf-8")
            launch_log.write_text(
                f"{spec.readiness_pattern}\nInitial password: disposable-secret\n",
                encoding="utf-8",
            )
            from src.projects import get_project
            from src.runtime_validation.environment_smoke import EnvironmentSmokeResult
            from src.runtime_validation.environment_smoke import _source_hashes

            return EnvironmentSmokeResult(
                project=spec.project,
                setup_status="setup-confirmed",
                launch_status=spec.expected_launch_status,
                expected_launch_status=spec.expected_launch_status,
                readiness_observed=True,
                reasons=(spec.expected_reason,),
                launch_exit_code=124 if spec.expected_launch_status == "launch-confirmed" else 1,
                setup_log=str(setup_log),
                launch_log=str(launch_log),
                revision=get_project(spec.project).analysis_revision,
                source_hashes=_source_hashes(spec.project, spec.binding_files),
                source_drift=False,
                disposable_workspace_removed=True,
                credential_scan="passed",
                launch_fixture=spec.launch_fixture,
            )

        with tempfile.TemporaryDirectory() as directory:
            out_dir = Path(directory) / "smoke"
            with mock.patch(
                "src.runtime_validation.environment_smoke._run_project",
                side_effect=fake_run_project,
            ):
                manifest = run_environment_smoke(EnvironmentSmokeRequest(out_dir))
            self.assertTrue(manifest["complete_denominator"])
            self.assertTrue(manifest["expected_outcome"])
            self.assertEqual(EXPECTED_STATUS_COUNTS, manifest["status_counts"])
            self.assertFalse(manifest["canonical_l2_publication_ready"])
            rows = [
                json.loads(line)
                for line in (out_dir / "launch-ledger.jsonl").read_text().splitlines()
            ]
            self.assertEqual(11, len(rows))
            self.assertEqual(11, len({row["project"] for row in rows}))
            self.assertTrue(all(row["l2_ready"] is False for row in rows))
            lettabot = next(row for row in rows if row["project"] == "lettabot")
            self.assertEqual("mock-channel-bridge", lettabot["launch_fixture"])
            self.assertFalse(lettabot["native_channel"])
            self.assertTrue(lettabot["instrumented_channel_bridge"])
            self.assertEqual(10, sum(row["native_channel"] for row in rows))
            self.assertEqual(
                {"source-native": 10, "mock-channel-bridge": 1},
                manifest["launch_fixture_counts"],
            )
            self.assertIn("does not publish or imply canonical L2", (out_dir / "summary.md").read_text())


class LettaBotMockChannelBridgeTest(unittest.TestCase):
    def test_hooks_add_mock_channel_to_real_module_exports(self) -> None:
        repository_root = Path(__file__).resolve().parents[3]
        register = (
            repository_root
            / "src/runtime_validation/l2_instrumentation/node/lettabot_mock_channel_register.mjs"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "dist/config").mkdir(parents=True)
            (root / "dist/channels").mkdir(parents=True)
            (root / "dist/test").mkdir(parents=True)
            (root / "dist/config/types.js").write_text(
                "export function normalizeAgents(config) {\n"
                "  return [{ name: 'probe', channels: {} }];\n"
                "}\n",
                encoding="utf-8",
            )
            (root / "dist/channels/factory.js").write_text(
                "export function createChannelsForAgent(agentConfig) {\n"
                "  return [];\n"
                "}\n",
                encoding="utf-8",
            )
            (root / "dist/test/mock-channel.js").write_text(
                "export class MockChannelAdapter { id = 'mock'; }\n",
                encoding="utf-8",
            )
            entry = root / "entry.mjs"
            entry.write_text(
                "import { normalizeAgents } from './dist/config/types.js';\n"
                "import { createChannelsForAgent } from './dist/channels/factory.js';\n"
                "const config = { channels: { mock: { enabled: true } } };\n"
                "const agents = normalizeAgents(config);\n"
                "const adapters = createChannelsForAgent(agents[0], './attachments', 1000);\n"
                "if (agents[0].channels.mock?.enabled !== true) throw new Error('mock config dropped');\n"
                "if (adapters[0]?.id !== 'mock') throw new Error('mock adapter missing');\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                ("node", "--import", register.as_uri(), entry),
                cwd=root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stdout)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from src.projects import get_project
from src.runtime_validation.adapters import (
    CapabilitySandbox,
    adapter_ids,
    get_adapter,
    with_driver,
)
from src.runtime_validation.campaign import load_campaign_definition, run_campaign, validate_case
from src.runtime_validation.campaign_contracts import (
    INCONCLUSIVE,
    NOT_REPRODUCED,
    RUNTIME_CONFIRMED,
    UNSUPPORTED,
    CampaignGenerationRequest,
    CampaignRunRequest,
    CaseValidationRequest,
    aggregate_case_attempts,
    validate_runtime_case,
)
from src.runtime_validation.contracts import ValidationError, contains_credentials
from src.runtime_validation.generation import generate_covered_campaign
from src.runtime_validation.native_drivers import typescript_pair_driver
from src.runtime_validation.selection import select_covered_candidates
from src.runtime_validation.upgrade import (
    REPAIRED_CANDIDATES,
    CampaignUpgradeRequest,
    upgrade_covered_campaign,
)
from src.runtime_validation.triggerability import (
    PROJECT_FLOWS,
    TOOL_SURFACES,
    _verify_witness,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
COVERAGE_ROOT = REPO_ROOT / "output/cross-project/coverage-comparison"


def _fake_generator(_system: str, user: str) -> str:
    payload = json.loads(user)
    gt = payload["ground_truth"][0]
    tool = (gt.get("d5_tool_handler_entry") or [{}])[0].get("name", "tool")
    return json.dumps(
        {
            "status": "ready",
            "reason": "deterministic fixture generation",
            "tool_name": tool,
            "exploit_args": {"value": "exploit"},
            "control_args": {"value": "control"},
            "reproduction_prompt": "fixture replay",
            "relation": "equals",
            "argument_path": ["value"],
            "exploit_value": "exploit",
            "control_value": "control",
        }
    )


def _confirmed_pair(case, adapter, attempt, attempt_dir, sandbox):
    _ = case, adapter, attempt, attempt_dir, sandbox
    return {
        "exploit": {
            "healthy": True,
            "verdict": "triggered",
            "correlation_id": f"{case['case_id']}:exploit",
            "observed_stages": [row["stage_id"] for row in case["observations"]],
        },
        "control": {"healthy": True, "unsafe_matched": False},
        "sandbox": {"network": "loopback-only"},
    }


class CoveredSelectionTest(unittest.TestCase):
    def test_selector_freezes_exact_v15_training_overlay_denominator(self) -> None:
        selection = select_covered_candidates(COVERAGE_ROOT)
        self.assertEqual(61, len(selection.candidates))
        self.assertEqual(43, len(selection.covered_reports))
        self.assertEqual(76, selection.match_references)
        self.assertEqual(61, len(set(selection.candidate_ids)))
        self.assertEqual(
            {"wrong-check", "missing-check"},
            {row.candidate["failure_mode"] for row in selection.candidates},
        )
        self.assertTrue(all(row.source_files for row in selection.candidates))

    def test_selector_fails_closed_on_denominator_drift(self) -> None:
        with self.assertRaisesRegex(ValidationError, "candidate drift"):
            select_covered_candidates(COVERAGE_ROOT, expected_candidates=62)
        with self.assertRaisesRegex(ValidationError, "reference drift"):
            select_covered_candidates(COVERAGE_ROOT, expected_match_references=75)


class CampaignContractTest(unittest.TestCase):
    def test_attempt_aggregation_requires_paired_control(self) -> None:
        confirmed = {
            "exploit": {"healthy": True, "verdict": "triggered"},
            "control": {"healthy": True, "unsafe_matched": False},
        }
        self.assertEqual(
            RUNTIME_CONFIRMED,
            aggregate_case_attempts([confirmed], supported=True)[0],
        )
        unsafe_control = {
            **confirmed,
            "control": {"healthy": True, "unsafe_matched": True},
        }
        self.assertEqual(
            INCONCLUSIVE,
            aggregate_case_attempts([unsafe_control], supported=True)[0],
        )
        negative = {
            "exploit": {"healthy": True, "verdict": "not-triggered"},
            "control": {"healthy": True, "unsafe_matched": False},
        }
        self.assertEqual(
            NOT_REPRODUCED,
            aggregate_case_attempts([negative, negative, negative], supported=True)[0],
        )
        self.assertEqual(
            UNSUPPORTED,
            aggregate_case_attempts([], supported=False, reason="missing driver")[0],
        )

    def test_credential_scan_ignores_explicit_redaction_marker(self) -> None:
        self.assertFalse(contains_credentials("api_key: [REDACTED_CREDENTIAL]"))
        self.assertTrue(contains_credentials("api_key: live-secret-value"))

    def test_all_project_adapters_are_registered_and_source_bound(self) -> None:
        self.assertEqual(11, len(adapter_ids()))
        for adapter_id in adapter_ids():
            adapter = get_adapter(adapter_id)
            self.assertTrue(get_project(adapter.project_id).source_root.is_dir())
            self.assertIn(adapter.language, {"python", "typescript"})

    def test_capability_sandbox_builds_closed_fixture_families(self) -> None:
        fixtures = {
            "none",
            "temporary-filesystem",
            "loopback-http",
            "isolated-browser",
            "capture-messaging",
            "capture-subagent",
            "fake-adb",
        }
        with tempfile.TemporaryDirectory() as directory:
            for fixture in fixtures:
                root = Path(directory) / fixture
                case = {"fixture": fixture}
                sandbox = CapabilitySandbox(root, case)
                record = sandbox.prepare()
                self.assertEqual("loopback-only", record["network_policy"])
                self.assertFalse(record["host_writes"])
                self.assertTrue((root / "fixture-manifest.json").is_file())
                if fixture == "fake-adb":
                    self.assertTrue((root / "bin/adb").is_file())


class FullCampaignAccountingTest(unittest.TestCase):
    def test_fake_generator_and_native_drivers_cover_all_migrated_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(
            io.StringIO()
        ):
            root = Path(directory) / "campaign"
            definition = generate_covered_campaign(
                CampaignGenerationRequest(COVERAGE_ROOT, root),
                runner=_fake_generator,
            )
            self.assertEqual(61, len(definition.cases))
            self.assertLessEqual(len(definition.execution_groups), 61)
            loaded = load_campaign_definition(root)
            self.assertEqual(definition.campaign_id, loaded.campaign_id)
            overrides = {
                case["adapter"]: with_driver(
                    case["adapter"], _confirmed_pair, supported_tools=()
                )
                for case in definition.cases
            }
            run = run_campaign(
                CampaignRunRequest(root),
                runner_factory=_confirmed_pair,
                adapter_overrides=overrides,
            )
            self.assertEqual(61, len(run.candidate_results))
            self.assertEqual({"runtime-confirmed": 61}, run.disposition_counts)
            self.assertEqual(
                61,
                len(
                    {
                        row["candidate_id"]
                        for row in run.candidate_results
                    }
                ),
            )
            self.assertTrue((root / "campaign-summary.md").is_file())
            self.assertTrue((root / "manifest.json").is_file())
            first = dict(definition.cases[0])
            first["observations"] = [
                row for row in first["observations"] if row["kind"] != "gate"
            ]
            if first["failure_mode"] == "wrong-check":
                with self.assertRaisesRegex(ValidationError, "require a gate"):
                    validate_runtime_case(first)


class NativeDriverSmokeTest(unittest.TestCase):
    @staticmethod
    def _cases() -> list[dict]:
        path = REPO_ROOT / "output/cross-project/runtime-validation-covered-v2/cases.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()]

    def _run(self, candidate_id: str) -> str:
        case = next(
            row for row in self._cases() if row["candidate_ids"] == [candidate_id]
        )
        with tempfile.TemporaryDirectory() as directory:
            return validate_case(
                CaseValidationRequest(case, Path(directory))
            ).disposition

    def test_python_native_dispatch_drivers(self) -> None:
        self.assertEqual(RUNTIME_CONFIRMED, self._run("CAND-1a87e1e2f2db6ef1"))
        self.assertEqual(RUNTIME_CONFIRMED, self._run("CAND-5f02a952c6162929"))
        self.assertEqual(RUNTIME_CONFIRMED, self._run("CAND-23b257cdff7ad185"))
        self.assertEqual(RUNTIME_CONFIRMED, self._run("CAND-086793eb89ea02c8"))

    def test_cow_browser_native_dispatch_is_conclusive(self) -> None:
        self.assertEqual(NOT_REPRODUCED, self._run("CAND-5d05f43dd599478e"))


class CampaignV3Test(unittest.TestCase):
    def test_deterministic_upgrade_repairs_all_ten_without_model_calls(self) -> None:
        source = REPO_ROOT / "output/cross-project/runtime-validation-covered-v2"
        source_hash = (source / "cases.jsonl").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            definition = upgrade_covered_campaign(
                CampaignUpgradeRequest(source, Path(directory) / "v3")
            )
            self.assertEqual(100, len(definition.cases))
            self.assertTrue(
                all(
                    case["schema_version"] == "clawgap-runtime-validation-case/v3"
                    and case["generation"]["status"] == "ready"
                    for case in definition.cases
                )
            )
            repaired = {
                case["candidate_ids"][0]
                for case in definition.cases
                if case["candidate_ids"][0] in REPAIRED_CANDIDATES
            }
            self.assertEqual(REPAIRED_CANDIDATES, repaired)
            manifest = json.loads(
                (definition.root / "generation-manifest.json").read_text()
            )
            self.assertEqual(0, manifest["model_calls"])
            self.assertEqual(0, manifest["counts"]["unsupported_cases"])
        self.assertEqual(source_hash, (source / "cases.jsonl").read_bytes())

    def test_fixture_state_matchers_allow_identical_tool_arguments(self) -> None:
        source = REPO_ROOT / "output/cross-project/runtime-validation-covered-v2"
        with tempfile.TemporaryDirectory() as directory:
            definition = upgrade_covered_campaign(
                CampaignUpgradeRequest(source, Path(directory) / "v3")
            )
            fixture_cases = [
                case for case in definition.cases if case["matcher"]["source"] == "fixture-state"
            ]
            self.assertEqual(3, len(fixture_cases))
            for case in fixture_cases:
                self.assertEqual(
                    case["replay"]["exploit_args"], case["replay"]["control_args"]
                )
                validate_runtime_case(case)

    def test_aliases_and_openclaw_source_anchor_are_revision_bound(self) -> None:
        source = REPO_ROOT / "output/cross-project/runtime-validation-covered-v2"
        with tempfile.TemporaryDirectory() as directory:
            definition = upgrade_covered_campaign(
                CampaignUpgradeRequest(source, Path(directory) / "v3")
            )
            by_candidate = {
                case["candidate_ids"][0]: case for case in definition.cases
            }
            self.assertEqual("read_file", by_candidate["CAND-af0f6570a3e5cd90"]["replay"]["tool_name"])
            self.assertEqual("terminal", by_candidate["CAND-ebb6a830a2df13df"]["replay"]["tool_name"])
            openclaw = by_candidate["CAND-22aaceea2b7af96b"]
            self.assertEqual("src/process/spawn-utils.ts", openclaw["observations"][-2]["file"])
            self.assertIn(
                "src/process/spawn-utils.ts",
                {row["path"] for row in openclaw["source_binding"]["files"]},
            )

    def test_droidclaw_bun_dispatch_intercepts_adb(self) -> None:
        cases = [
            json.loads(line)
            for line in (
                REPO_ROOT / "output/cross-project/runtime-validation-covered-v3/cases.jsonl"
            ).read_text().splitlines()
        ]
        case = next(
            row for row in cases if row["candidate_ids"] == ["CAND-5625ea642cacc3cd"]
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = validate_case(CaseValidationRequest(case, root))
            self.assertEqual(RUNTIME_CONFIRMED, run.disposition)
            manifest = root / "attempt-001/transformed-source-manifest.json"
            self.assertTrue(manifest.is_file())
            transformed = json.loads(manifest.read_text())
            self.assertEqual("temporary-overlay", transformed["mode"])
            self.assertTrue(transformed["stages"])

    def test_typescript_native_dispatch_tool_families(self) -> None:
        cases = {
            row["candidate_ids"][0]: row
            for row in (
                json.loads(line)
                for line in (
                    REPO_ROOT / "output/cross-project/runtime-validation-covered-v3/cases.jsonl"
                ).read_text().splitlines()
            )
        }
        candidate_ids = [
            "CAND-5625ea642cacc3cd",  # DroidClaw shell
            "CAND-03c253bc5434cb23",  # LettaBot Task
            "CAND-28e10cd0024e26c3",  # Mercury run_command
            "CAND-cad9c7e353e2435e",  # NanoClaw send_file
            "CAND-22aaceea2b7af96b",  # OpenClaw exec
            "CAND-340a8c9fce77d465",  # OpenClaw CN exec
            "CAND-39b35c7f9cb17284",  # OpenClaw CN browser
            "CAND-3bb201596b6fff3a",  # OpenClaw CN apply_patch
            "CAND-9ee6e1a1e957bf8b",  # OpenClaw CN message
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for candidate_id in candidate_ids:
                case = cases[candidate_id]
                sandbox = CapabilitySandbox(root / candidate_id / "sandbox", case)
                sandbox.prepare()
                attempt = root / candidate_id / "attempt"
                attempt.mkdir(parents=True)
                result = typescript_pair_driver(case, 1, attempt, sandbox)
                self.assertTrue(result["exploit"]["healthy"], candidate_id)
                self.assertTrue(result["control"]["healthy"], candidate_id)
                manifest = json.loads(
                    (attempt / "transformed-source-manifest.json").read_text()
                )
                self.assertEqual(
                    [row["stage_id"] for row in case["observations"]],
                    [row["stage_id"] for row in manifest["stages"]],
                )
                source_maps = list((attempt / "source-maps").glob("*.map"))
                self.assertEqual(len(case["observations"]), len(source_maps))


class GroundTruthToolTriggerabilityTest(unittest.TestCase):
    def test_all_37_reports_have_current_model_facing_surfaces(self) -> None:
        cases = [
            json.loads(line)
            for line in (
                REPO_ROOT / "output/cross-project/runtime-validation-covered-v3/cases.jsonl"
            ).read_text().splitlines()
        ]
        reports: dict[str, tuple[str, str]] = {}
        for case in cases:
            for binding in case["report_bindings"]:
                reports[binding["report_id"]] = (case["project"], binding["path"])
        self.assertEqual(37, len(reports))
        for report_id, (project, report_path) in reports.items():
            report = json.loads((REPO_ROOT / report_path).read_text())
            entries = report.get("d5_tool_handler_entry") or []
            self.assertTrue(entries, report_id)
            self.assertIn(project, PROJECT_FLOWS)
            for entry in entries:
                key = (project, entry["name"])
                self.assertIn(key, TOOL_SURFACES)
                surface = TOOL_SURFACES[key]
                self.assertTrue(_verify_witness(project, surface["handler"])["valid"])
                self.assertTrue(_verify_witness(project, surface["registration"])["valid"])
                self.assertTrue(
                    _verify_witness(project, PROJECT_FLOWS[project]["exposure"])["valid"]
                )
                self.assertTrue(
                    _verify_witness(project, PROJECT_FLOWS[project]["dispatch"])["valid"]
                )

    def test_published_triggerability_ledger_has_complete_accounting(self) -> None:
        root = REPO_ROOT / "output/cross-project/ground-truth-tool-triggerability-v1"
        rows = [json.loads(line) for line in (root / "ground-truth-tool-triggerability.jsonl").read_text().splitlines()]
        self.assertEqual(37, len(rows))
        self.assertEqual(37, len({row["report_id"] for row in rows}))
        counts = Counter(row["disposition"] for row in rows)
        self.assertEqual(
            {"tool-call-triggerable": 36, "structured-action-triggerable": 1},
            dict(counts),
        )
        self.assertTrue(
            all(
                any(surface["native_probe"]["handler_observed"] for surface in row["surfaces"])
                for row in rows
            )
        )


if __name__ == "__main__":
    unittest.main()

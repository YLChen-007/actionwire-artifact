from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.runtime_validation.contracts import ValidationError
from src.runtime_validation.qualification_contracts import (
    QualificationGenerationRequest,
    QualificationExpansionRequest,
    QualificationRunRequest,
    qualification_case_content,
    stable_qualification_case_id,
    validate_qualification_case,
)
from src.runtime_validation.qualification_runner import (
    run_adapter_qualification,
    run_hermes_qualification_smoke,
)
from src.runtime_validation.qualification_selection import (
    generate_adapter_qualification,
    generate_adapter_qualification_expansion,
)
from src.runtime_validation.qualification_images import prepare_qualification_containers


REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_CAMPAIGN = REPO_ROOT / "output/cross-project/runtime-validation-ground-truth-v1"


class _FakeContainerRuntime:
    def __init__(self, *, ready: bool = True) -> None:
        self.ready = ready
        self.preflighted: list[str] = []
        self.pairs: list[tuple[str, int]] = []
        self.closed = False

    def preflight(self, case):
        self.preflighted.append(case["case_id"])
        if not self.ready:
            return False, "test OCI image unavailable", {}
        return True, "test OCI bridge ready", {"image": "test", "network": "none"}

    def run_pair(self, case, attempt):
        self.pairs.append((case["case_id"], attempt))
        required = [row["stage_id"] for row in case["observations"]]
        return (
            {
                "exploit": {
                    "healthy": True,
                    "verdict": "triggered",
                    "observed_stages": required,
                },
                "control": {"healthy": True, "unsafe_matched": False},
            },
            {"reset": "passed", "host_effect_canary": "unchanged"},
        )

    def close(self) -> None:
        self.closed = True


class AdapterQualificationTest(unittest.TestCase):
    def _generate(self, root: Path):
        return generate_adapter_qualification(
            QualificationGenerationRequest(SOURCE_CAMPAIGN, root)
        )

    def test_selector_preserves_exact_23_families_and_reviewed_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            campaign = self._generate(Path(temporary) / "qualification")
            self.assertEqual(23, len(campaign.cases))
            self.assertEqual(42, len(campaign.selection))
            self.assertEqual(23, sum(row["selected"] for row in campaign.selection))
            families = {tuple(case["selection"]["family_key"]) for case in campaign.cases}
            self.assertEqual(23, len(families))
            for case in campaign.cases:
                validate_qualification_case(case)
                self.assertEqual(
                    case["replay"]["tool_name"], case["mock_provider"]["tool_calls"]["exploit"]["name"]
                )
                self.assertNotIn("vulnerability", case)

    def test_fake_oci_bridge_qualifies_all_selected_families_with_complete_events(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "qualification"
            self._generate(root)
            runtime = _FakeContainerRuntime()
            run = run_adapter_qualification(
                QualificationRunRequest(root), runtime=runtime
            )
            self.assertEqual({"qualified": 23}, dict(run.qualification_counts))
            self.assertEqual({"confirmed": 23}, dict(run.forced_path_counts))
            self.assertEqual({"not-run": 23}, dict(run.live_triggerability_counts))
            self.assertTrue(runtime.closed)
            self.assertEqual(69, len(runtime.pairs))
            first = run.results[0]
            events_path = root / "runs" / first["case_id"] / "attempt-001" / "events.jsonl"
            events = [json.loads(line) for line in events_path.read_text().splitlines()]
            self.assertEqual(2, len({row["side"] for row in events}))
            for row in events:
                self.assertEqual(run.campaign_id, row["campaign_id"])
                self.assertEqual(first["case_id"], row["case_id"])
                self.assertIn("correlation_id", row)
                self.assertIn("source_binding_sha256", row)
                self.assertIn("value_id", row)
            self.assertFalse(any("vulnerability" in row for row in run.results))

    def test_unavailable_oci_images_remain_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "qualification"
            self._generate(root)
            runtime = _FakeContainerRuntime(ready=False)
            run = run_adapter_qualification(
                QualificationRunRequest(root), runtime=runtime
            )
            self.assertEqual({"blocked": 23}, dict(run.qualification_counts))
            self.assertEqual({"inconclusive": 23}, dict(run.forced_path_counts))
            self.assertEqual([], runtime.pairs)

    def test_preanalysis_container_definitions_bind_each_project_revision_and_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "qualification"
            self._generate(root)
            manifest = prepare_qualification_containers(root)
            self.assertEqual(11, len(manifest["projects"]))
            self.assertEqual("pre-analysis", manifest["build_phase"])
            self.assertEqual(["hermes-agent"], manifest["smoke_order"])
            self.assertEqual("hermes-agent", manifest["projects"][0]["project"])
            for row in manifest["projects"]:
                self.assertRegex(row["revision"], r"^[0-9a-f]{40}$")
                self.assertIn("source_binding", row)
                self.assertIn("dependency_binding", row)
                self.assertTrue(row["source_root"].startswith("benchmark/"))
                self.assertIn(row["project"], manifest["bindings"])
                self.assertIn("definition_digest", row)
                self.assertTrue(row["buildable"])
                self.assertIsNotNone(row["dockerfile_path"])
                definition = Path(__file__).parents[3] / str(row["dockerfile_path"])
                self.assertTrue(definition.is_file())
                self.assertIn("COPY benchmark/", definition.read_text(encoding="utf-8"))
            self.assertFalse(list((root / "containers").glob("*.Dockerfile")))

    def test_source_or_lock_binding_drift_is_inconclusive_not_qualified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "qualification"
            self._generate(root)
            rows = [json.loads(line) for line in (root / "cases.jsonl").read_text().splitlines()]
            rows[0]["source_binding"]["files"][0]["sha256"] = "0" * 64
            rows[0]["native_case"]["source_binding"]["files"][0]["sha256"] = "0" * 64
            rows[0]["case_id"] = stable_qualification_case_id(
                qualification_case_content(rows[0])
            )
            (root / "cases.jsonl").write_text(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
            )
            campaign = json.loads((root / "campaign.json").read_text())
            campaign["target"]["case_ids"][0] = rows[0]["case_id"]
            (root / "campaign.json").write_text(json.dumps(campaign))
            run = run_adapter_qualification(
                QualificationRunRequest(root), runtime=_FakeContainerRuntime()
            )
            self.assertEqual(1, run.qualification_counts["inconclusive"])
            self.assertEqual(22, run.qualification_counts["qualified"])

    def test_hermes_smoke_uses_three_mock_provider_pairs_without_live_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "qualification"
            self._generate(root)
            runtime = _FakeContainerRuntime()
            run = run_hermes_qualification_smoke(
                root,
                Path(temporary) / "hermes-smoke",
                build_image=False,
                runtime=runtime,
            )
            self.assertEqual({"qualified": 1}, dict(run.qualification_counts))
            self.assertEqual({"confirmed": 1}, dict(run.forced_path_counts))
            self.assertEqual({"not-run": 1}, dict(run.live_triggerability_counts))
            self.assertEqual(3, len(runtime.pairs))
            self.assertEqual("hermes-agent", run.results[0]["family"]["project"])
            self.assertEqual("read_file", run.results[0]["family"]["tool_name"])
            summary = (run.artifact_dir / "qualification-summary.md").read_text()
            self.assertIn("Complete reproduction command:", summary)
            self.assertIn("not a vulnerability verdict", summary)

    def test_hermes_smoke_cannot_build_container_during_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "qualification"
            self._generate(root)
            with self.assertRaisesRegex(
                ValidationError,
                "containers must be built in pre-analysis",
            ):
                run_hermes_qualification_smoke(root, Path(temporary) / "smoke", build_image=True)

    def test_event_ids_are_deterministic_and_provider_transcripts_are_published(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event_ids = []
            for name in ("first", "second"):
                root = Path(temporary) / name
                self._generate(root)
                run = run_adapter_qualification(
                    QualificationRunRequest(root), runtime=_FakeContainerRuntime()
                )
                first = run.results[0]
                path = root / "runs" / first["case_id"] / "attempt-001"
                events = [
                    json.loads(line)
                    for line in (path / "events.jsonl").read_text().splitlines()
                ]
                transcripts = [
                    json.loads(line)
                    for line in (path / "provider-transcript.jsonl").read_text().splitlines()
                ]
                self.assertEqual(2, len(transcripts))
                self.assertEqual(
                    {"exploit", "control"}, {row["side"] for row in transcripts}
                )
                event_ids.append([row["event_id"] for row in events])
            self.assertEqual(event_ids[0], event_ids[1])

    def test_all_42_expansion_is_gated_by_23_qualified_families(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "qualification"
            self._generate(root)
            expansion = Path(temporary) / "expansion"
            request = QualificationExpansionRequest(SOURCE_CAMPAIGN, root, expansion)
            with self.assertRaisesRegex(ValidationError, "qualification-results.jsonl"):
                generate_adapter_qualification_expansion(request)
            run_adapter_qualification(
                QualificationRunRequest(root), runtime=_FakeContainerRuntime()
            )
            campaign = generate_adapter_qualification_expansion(request)
            self.assertEqual(42, len(campaign.cases))
            self.assertEqual(42, len(campaign.selection))
            self.assertEqual(
                23,
                len({tuple(case["selection"]["family_key"]) for case in campaign.cases}),
            )
            published = json.loads((expansion / "campaign.json").read_text())
            self.assertEqual(42, published["target"]["cases"])
            self.assertEqual(23, published["target"]["families"])
            self.assertEqual(
                "23-of-23-qualified",
                published["qualification_gate"]["status"],
            )


if __name__ == "__main__":
    unittest.main()

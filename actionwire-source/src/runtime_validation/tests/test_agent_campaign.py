from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.runtime_validation.agent_candidate_intake import load_candidate_bundle
from src.runtime_validation.agent_controller import ScriptedPilotController
from src.runtime_validation.agent_lab import RuntimeAgentLab
from src.runtime_validation.contracts import ValidationError


CANDIDATE_ID = "CAND-925c9d1319c3ccbd"
COVERAGE_ROOT = Path("output/cross-project/coverage-comparison")


class AgentRuntimeValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.out = Path(self.temporary.name)
        self.bundle = load_candidate_bundle(COVERAGE_ROOT, CANDIDATE_ID, "hermes-agent")
        self.lab = RuntimeAgentLab(
            self.bundle,
            self.out,
            campaign_id="RAC-test000000000000000",
        )
        self.controller = ScriptedPilotController()

    def _inspect(self) -> list[dict[str, object]]:
        anchors = self.lab.execute(
            **dict(
                self.controller({"stage": "anchors", "anchors": self.bundle.anchors})
            )
        )["anchors"]
        return [
            row for row in anchors if row["mandatory"] and not row["diagnostic_only"]
        ]

    def test_intake_binds_candidate_semantic_and_candidate_gate(self) -> None:
        self.assertEqual(
            self.bundle.candidate["revision"],
            self.bundle.semantic["project"]["revision"],
        )
        self.assertEqual(
            self.bundle.candidate["sink_id"], self.bundle.semantic["sink"]["sink_id"]
        )
        self.assertIn(
            "G-candidate-gu81ab86be2df208e2213c",
            {row["anchor_id"] for row in self.bundle.anchors},
        )
        self.assertTrue(all(row["sha256"] for row in self.bundle.source_bindings))

    def test_plan_rejects_unknown_anchor(self) -> None:
        self.lab.execute("get_candidate", {})
        selected = [row["anchor_id"] for row in self._inspect()]
        proposal = self.controller({"stage": "plan", "anchors": self.bundle.anchors})[
            "arguments"
        ]
        proposal["selected_anchor_ids"] = [*selected[:-1], "A-invented-by-model"]
        with self.assertRaisesRegex(ValidationError, "unknown anchor"):
            self.lab.execute("propose_plan", proposal)

    def test_plan_rejects_missing_mandatory_anchor(self) -> None:
        self.lab.execute("get_candidate", {})
        proposal = self.controller({"stage": "plan", "anchors": self.bundle.anchors})[
            "arguments"
        ]
        proposal["selected_anchor_ids"] = proposal["selected_anchor_ids"][:-1]
        with self.assertRaisesRegex(ValidationError, "mandatory anchors missing"):
            self.lab.execute("propose_plan", proposal)

    def test_state_machine_rejects_run_before_compile_and_finalize_before_evaluate(
        self,
    ) -> None:
        with self.assertRaisesRegex(ValidationError, "compiled plan"):
            self.lab.execute("run_pair", {})
        self.lab.execute("get_candidate", {})
        self._inspect()
        proposal = self.controller({"stage": "plan", "anchors": self.bundle.anchors})[
            "arguments"
        ]
        self.lab.execute("propose_plan", proposal)
        with self.assertRaisesRegex(ValidationError, "deterministic evaluation"):
            self.lab.execute(
                "finalize_result",
                {
                    "evaluation_id": "EVAL-model-invented",
                    "candidate_id": CANDIDATE_ID,
                    "plan_hash": "PLAN-model-invented",
                    "trial_id": "TRIAL-model-invented",
                },
            )

    def test_source_access_is_confined_and_bounded(self) -> None:
        self.lab.execute("get_candidate", {})
        with self.assertRaisesRegex(ValidationError, "candidate-relative"):
            self.lab.execute(
                "read_source", {"file": "../../README.md", "start": 1, "end": 2}
            )
        with self.assertRaisesRegex(ValidationError, "source range exceeds"):
            self.lab.execute(
                "read_source", {"file": "tools/file_tools.py", "start": 1, "end": 500}
            )

    def test_scripted_controller_plan_compiles(self) -> None:
        self.lab.execute("get_candidate", {})
        self._inspect()
        proposal = self.controller({"stage": "plan", "anchors": self.bundle.anchors})[
            "arguments"
        ]
        proposed = self.lab.execute("propose_plan", proposal)
        self.assertEqual(proposed["status"], "proposed")
        compiled = self.lab.execute(**dict(self.controller({"stage": "compile"})))
        self.assertEqual(compiled["status"], "compiled")
        self.assertTrue((self.out / CANDIDATE_ID / "result.json").exists() is False)

    def test_member_inapplicable_candidate_is_not_admitted(self) -> None:
        with self.assertRaisesRegex(ValidationError, "not uniquely bound"):
            load_candidate_bundle(
                COVERAGE_ROOT, "CAND-3e313ae3b7496e18", "hermes-agent"
            )


if __name__ == "__main__":
    unittest.main()

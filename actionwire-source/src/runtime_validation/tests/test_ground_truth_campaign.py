from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from src.runtime_validation.contracts import ValidationError
from src.runtime_validation.ground_truth_campaign import (
    audit_ground_truth,
    generate_ground_truth_campaign,
    review_ground_truth_campaign,
    run_ground_truth_campaign,
)
from src.runtime_validation.ground_truth_contracts import (
    GroundTruthAuditRequest,
    GroundTruthGenerationRequest,
    GroundTruthReviewRequest,
    GroundTruthRunRequest,
    validate_ground_truth_case,
)


def _generator(_system: str, user: str) -> str:
    payload = json.loads(user)
    report = payload["report"]
    return json.dumps(
        {
            "status": "ready",
            "reason": "deterministic ground-truth fixture",
            "tool_name": report["tool_name"],
            "exploit_args": {"value": "exploit"},
            "control_args": {"value": "control"},
            "reproduction_prompt": "fixture replay",
            "matcher_source": "tool-argument",
            "relation": "equals",
            "path": ["value"],
            "exploit_value": "exploit",
            "control_value": "control",
            "fixture_state": {"exploit": {}, "control": {}},
            "gate_anchor_ids": [report["anchor_catalog"]["gates"][0]["anchor_id"]]
            if report["failure_mode"] == "wrong-check"
            else [],
        }
    )


def _reviewer(_system: str, _user: str) -> str:
    return json.dumps(
        {
            "verdict": "approve",
            "reason": "independent fixture review approved",
            "checks": {
                "source_reachable": True,
                "exploit_semantic": True,
                "control_safe": True,
                "native_tool_identity": True,
                "fixture_safe": True,
                "ordered_stages": True,
                "effect_intercepted": True,
            },
        }
    )


def _confirmed_pair(case, _attempt, _attempt_dir, _sandbox):
    return {
        "exploit": {
            "healthy": True,
            "verdict": "triggered",
            "correlation_id": f"{case['case_id']}:exploit",
            "observed_stages": [row["stage_id"] for row in case["observations"]],
            "handler_reached": True,
        },
        "control": {
            "healthy": True,
            "unsafe_matched": False,
            "handler_reached": True,
        },
        "sandbox": {"effect": "fixture intercepted"},
    }


class GroundTruthAuditTest(unittest.TestCase):
    def test_authoritative_denominator_and_anchor_rebase(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            audit = audit_ground_truth(GroundTruthAuditRequest(Path(directory) / "audit"))
            self.assertEqual(46, len(audit.reports))
            self.assertEqual({"ready": 42, "not-applicable": 4}, dict(audit.counts))
            manifest = json.loads((audit.root / "manifest.json").read_text())
            self.assertEqual(42, manifest["counts"]["eligible"])
            self.assertEqual(1, manifest["counts"]["fixed"])
            self.assertEqual(1, manifest["counts"]["not_present"])
            self.assertEqual(2, manifest["counts"]["out_of_model"])
            self.assertEqual(19, manifest["counts"]["reports_with_rebased_stale_anchors"])
            serialized = json.dumps(manifest)
            self.assertNotIn("candidates.jsonl", serialized)
            self.assertNotIn("comparisons.jsonl", serialized)
            self.assertNotIn("group-oracle", serialized)

    def test_ground_truth_case_review_hash_is_strict(self) -> None:
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            root = Path(directory)
            audit = audit_ground_truth(GroundTruthAuditRequest(root / "audit"))
            campaign = generate_ground_truth_campaign(
                GroundTruthGenerationRequest(audit.root, root / "campaign"),
                runner=_generator,
            )
            review_ground_truth_campaign(
                GroundTruthReviewRequest(campaign.root), runner=_reviewer
            )
            case = json.loads((campaign.root / "cases.jsonl").read_text().splitlines()[0])
            validate_ground_truth_case(case)
            case["replay"]["exploit_args"]["value"] = "tampered"
            with self.assertRaises(ValidationError):
                validate_ground_truth_case(case)


class GroundTruthFullAccountingTest(unittest.TestCase):
    def test_fake_generation_review_and_runtime_account_all_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            root = Path(directory)
            audit = audit_ground_truth(GroundTruthAuditRequest(root / "audit"))
            campaign = generate_ground_truth_campaign(
                GroundTruthGenerationRequest(audit.root, root / "campaign"),
                runner=_generator,
            )
            self.assertEqual(42, len(campaign.cases))
            self.assertEqual(46, len(campaign.accounting))
            review = review_ground_truth_campaign(
                GroundTruthReviewRequest(campaign.root), runner=_reviewer
            )
            self.assertEqual((42, 0), (review.approved, review.rejected))
            run = run_ground_truth_campaign(
                GroundTruthRunRequest(campaign.root), pair_runner=_confirmed_pair
            )
            self.assertEqual({"ready": 42, "not-applicable": 4}, dict(run.support_counts))
            self.assertEqual(
                {"not-applicable": 4, "runtime-confirmed": 42},
                dict(run.outcome_counts),
            )
            self.assertEqual(46, len(run.report_results))
            self.assertEqual(46, len({row["report_id"] for row in run.report_results}))
            self.assertTrue((campaign.root / "summary.md").is_file())
            self.assertTrue((campaign.root / "manifest.json").is_file())


if __name__ == "__main__":
    unittest.main()

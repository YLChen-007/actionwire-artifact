import copy
import unittest

from src.coverage_comparison.scoped_ablation import (
    card_facts_only, group_requirements, match_job, payload_for, select_reports, validate_matches, validate_reuse_inputs,
)


class ScopedAblationTests(unittest.TestCase):
    def test_exact_report_scope_excludes_out_of_model(self):
        rows = [{"report_id": str(i), "boundary_status": "eligible", "evaluation_partition": "training", "chain_ids": ["C-1"]} for i in range(43)]
        rows.append({"report_id": "excluded", "boundary_status": "out-of-model"})
        self.assertEqual(len(select_reports(rows)), 43)
        with self.assertRaises(ValueError):
            select_reports(rows[1:])
        rows[1]["report_id"] = rows[0]["report_id"]
        with self.assertRaises(ValueError):
            select_reports(rows)

    def test_training_fallback_never_leaks_to_another_member(self):
        chain = {"group_id": "G", "project": "p", "chain_id": "C1"}
        pool = [{"group_id": "G", "requirement_id": "shared"},
                {"group_id": "G", "requirement_id": "member", "member_scope": ["p", "C2"]},
                {"group_id": "other", "requirement_id": "other"}]
        self.assertEqual([r["requirement_id"] for r in group_requirements(pool, chain)], ["shared"])
        chain["chain_id"] = "C2"
        self.assertEqual(len(group_requirements(pool, chain)), 2)

    def test_policy_contract_removed_without_changing_card_line_numbers(self):
        lines = ["api: f", "policy_contract:", "  requirements:", "    - rule: CARD_ONLY", "provenance:", "  - docs", "```"]
        clean = card_facts_only(lines)
        self.assertEqual(len(clean), len(lines))
        self.assertNotIn("CARD_ONLY", "\n".join(clean))
        self.assertEqual(clean[4:], lines[4:])

    def test_capability_payload_has_no_group_or_gt_requirements(self):
        chain = {"group_id": "G", "chain_id": "C", "capability_card": {"path": "f", "sha256": "x"},
                 "card_lines": ["api: f", "policy_contract:", "  rule: CARD_ONLY"],
                 "semantic_ir": {"gates": [], "values": [], "sink_constraint": {}},
                 "ground_truth_invariant": "TARGET_ANSWER"}
        requirements = [{"requirement_id": "GROUP_ONLY", "rule": "group policy"}]
        cap = payload_for(chain, "capability-only", requirements)
        self.assertEqual(cap["group_requirements"], [])
        self.assertNotIn("GROUP_ONLY", str(cap))
        self.assertNotIn("TARGET_ANSWER", str(cap))
        self.assertIn("CARD_ONLY", str(cap))
        group = payload_for(chain, "group-only", requirements)
        self.assertIn("GROUP_ONLY", str(group))
        self.assertNotIn("CARD_ONLY", str(group))
        self.assertNotIn("TARGET_ANSWER", str(group))

    def test_acceptance_requires_exact_identity_and_semantics(self):
        response = {"report_id": "GT", "assessments": [{"candidate_id": "C", "verdict": "match", "same_controlled_security_invariant": True, "reason": "exact policy"}]}
        self.assertEqual(len(validate_matches(response, "GT", {"C"})), 1)
        with self.assertRaises(ValueError):
            validate_matches(response, "GT", {"C", "D"})
        response["assessments"][0]["same_controlled_security_invariant"] = False
        with self.assertRaises(ValueError):
            validate_matches(response, "GT", {"C"})

    def test_unknown_is_not_silently_reported_as_a_miss(self):
        report = {"report_id": "GT", "report_name": "case", "project": "p", "chain_ids": ["C1"]}
        unresolved = match_job(report, "group-only", [], {("group-only", "p", "C1")}, None)
        self.assertEqual(unresolved["status"], "inconclusive")
        complete = match_job(report, "group-only", [], set(), None)
        self.assertEqual(complete["status"], "not-detected")

    def test_group_reuse_checks_scope_model_and_prompts(self):
        prior = {"chains": ["chain"], "reports": ["report"], "group_requirements": ["rule"],
                 "model_settings": {"model": "m"}, "source_inventory_sha256": "h",
                 "prompts": {"group-only": "group", "match": "match", "capability-only": "old"}}
        current = copy.deepcopy(prior)
        current["prompts"]["capability-only"] = "clarified schema"
        validate_reuse_inputs(prior, current)
        for key in ["chains", "reports", "group_requirements", "model_settings"]:
            bad = copy.deepcopy(current)
            bad[key] = []
            with self.assertRaises(ValueError):
                validate_reuse_inputs(prior, bad)
        current["prompts"]["group-only"] = "changed"
        with self.assertRaises(ValueError):
            validate_reuse_inputs(prior, current)


if __name__ == "__main__":
    unittest.main()

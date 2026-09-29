from __future__ import annotations

import unittest
from dataclasses import replace

from src.coverage_comparison.canonical_requirements import (
    canonicalize_requirement,
    merge_canonical_requirements,
    migrate_candidate,
    route_canonical_source_chains,
    stable_cr_id,
    stable_v7_candidate_id,
)
from src.coverage_comparison.tests.test_coverage_comparison import coverage_chain


class CanonicalRequirementTests(unittest.TestCase):
    def test_cr_identity_normalizes_whitespace(self) -> None:
        first = canonicalize_requirement(
            {
                "requirement_id": "R-" + "1" * 16,
                "rule": "Reject  private destinations.",
                "applicability": "When model controls URL.",
                "dimension": "network-policy",
            },
            group_id="HSG-" + "2" * 16,
        )
        second = canonicalize_requirement(
            {
                "requirement_id": "R-" + "1" * 16,
                "rule": " Reject private   destinations. ",
                "applicability": "When model controls URL.",
                "dimension": "network-policy",
            },
            group_id="HSG-" + "2" * 16,
        )
        self.assertEqual(first["requirement_id"], second["requirement_id"])
        self.assertRegex(first["requirement_id"], r"^CR-[0-9a-f]{16}$")

    def test_many_sources_merge_without_losing_legacy_ids(self) -> None:
        base = {
            "requirement_id": "R-" + "1" * 16,
            "rule": "Reject private destinations.",
            "applicability": "When model controls URL.",
            "controlled_facet": "model URL",
            "enforcement_stage": "pre-effect",
            "state_lifetime": "single-call",
            "security_effect": "Prevent internal network access.",
        }
        group = canonicalize_requirement(base, group_id="HSG-" + "2" * 16)
        card = canonicalize_requirement(
            {**base, "requirement_id": "CAPR-" + "3" * 16},
            group_id="HSG-" + "2" * 16,
        )
        rows, mapping = merge_canonical_requirements([group, card])
        self.assertEqual(1, len(rows))
        self.assertEqual(2, len(rows[0]["provenance"]["sources"]))
        self.assertEqual(
            mapping[("HSG-" + "2" * 16, base["requirement_id"])],
            rows[0]["requirement_id"],
        )

    def test_candidate_recomputes_identity_from_cr(self) -> None:
        chain = coverage_chain()
        old = {
            "schema_version": "coverage-candidate/v6",
            "candidate_id": "CAND-" + "1" * 16,
            "requirement_source": "group-oracle",
            "provenance": {"kind": "group-oracle", "requirement_id": "R-" + "2" * 16},
            "group_id": chain.group_id,
            "handler_criterion_id": chain.handler_criterion_id,
            "sink_type_id": chain.sink_type_id,
            "project": chain.project,
            "revision": chain.revision,
            "chain_id": chain.chain_id,
            "handler_id": chain.handler_id,
            "sink_id": chain.sink_id,
            "failure_mode": "missing-check",
            "requirement_id": "R-" + "2" * 16,
            "requirement_rule": "Reject private destinations.",
            "requirement_applicability": "When model controls URL.",
            "gate_ids": [],
            "gate_semantics": [],
            "reason": "No relevant gate.",
            "trigger_goal": "Reach the sink.",
            "group_oracle_status": "complete",
            "semantic_ir_status": "complete",
            "capability_card": {"path": "card.md", "sha256": "3" * 64},
        }
        requirement = canonicalize_requirement(
            {
                "requirement_id": old["requirement_id"],
                "rule": old["requirement_rule"],
                "applicability": old["requirement_applicability"],
            },
            group_id=chain.group_id,
        )
        migrated, ledger = migrate_candidate(old, requirement=requirement)
        self.assertNotEqual(old["candidate_id"], migrated["candidate_id"])
        self.assertEqual(requirement["requirement_id"], migrated["requirement_id"])
        self.assertEqual(old["candidate_id"], ledger["old_candidate_id"])
        self.assertEqual(migrated["candidate_id"], ledger["new_candidate_id"])

    def test_router_is_budgeted_and_deterministic(self) -> None:
        chains = [
            replace(coverage_chain(), chain_id=f"C-{number:012x}")
            for number in range(80)
        ]
        result = route_canonical_source_chains(
            chains=chains,
            origin_audit=[],
            candidates=[],
            learned_chain_ids=set(),
            budget=64,
        )
        repeat = route_canonical_source_chains(
            chains=chains,
            origin_audit=[],
            candidates=[],
            learned_chain_ids=set(),
            budget=64,
        )
        self.assertEqual(64, len(result.selected))
        self.assertEqual(result.selected, repeat.selected)

    def test_router_uses_only_locked_scores_and_preserves_regressions(self) -> None:
        chains = [
            replace(coverage_chain(), chain_id=f"C-{number:012x}")
            for number in range(6)
        ]
        required = {chains[-1].key}
        result = route_canonical_source_chains(
            chains=chains,
            origin_audit=[],
            candidates=[],
            learned_chain_ids=set(),
            required_regression_chain_ids=required,
            budget=4,
        )
        selected = {(row["project"], row["chain_id"]): row for row in result.selected}
        self.assertIn(chains[-1].key, selected)
        self.assertEqual(
            "frozen-training-regression",
            selected[chains[-1].key]["selection_reason"],
        )
        self.assertNotIn(
            "content-bound-source-cache",
            {reason["reason"] for row in result.selected for reason in row["reasons"]},
        )
        self.assertEqual(
            {
                "origin-changed": 100,
                "no-primary-candidate": 80,
                "learned-routed": 60,
                "semantic-ir-partial": 40,
                "group-oracle-partial": 30,
                "high-risk-capability": 20,
            },
            result.config["weights"],
        )

    def test_router_all_scope_covers_every_chain(self) -> None:
        chains = [
            replace(coverage_chain(), chain_id=f"C-{number:012x}")
            for number in range(80)
        ]
        result = route_canonical_source_chains(
            chains=chains,
            origin_audit=[],
            candidates=[],
            learned_chain_ids=set(),
            budget=64,
            scope="all",
        )
        self.assertEqual(80, len(result.selected))
        self.assertFalse(result.excluded)

    def test_low_level_identity_helpers_require_cr(self) -> None:
        fields = {
            "rule": "rule",
            "applicability": "applicable",
            "controlled_facet": "value",
            "enforcement_stage": "pre-effect",
            "state_lifetime": "single-call",
            "security_effect": "effect",
        }
        cr_id = stable_cr_id(group_id="HSG-" + "1" * 16, fields=fields)
        candidate = stable_v7_candidate_id(
            group_id="HSG-" + "1" * 16,
            project="fixture",
            revision="rev",
            chain_id="C-" + "2" * 12,
            requirement_id=cr_id,
            failure_mode="missing-check",
            gate_ids=[],
        )
        self.assertRegex(candidate, r"^CAND-[0-9a-f]{16}$")


if __name__ == "__main__":
    unittest.main()

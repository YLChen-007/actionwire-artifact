from __future__ import annotations

import copy
import unittest

from src.coverage_comparison.contracts import CoverageComparisonError, canonical_json
from src.coverage_comparison.v15_normative_projection import (
    build_normative_projection,
    infer_applicability_contract,
)


def evidence(evidence_id: str, kind: str) -> dict[str, object]:
    return {
        "evidence_id": evidence_id,
        "kind": kind,
        "source_path": "card.md" if "capability" in kind else "policy.md",
        "sha256": "a" * 64,
        "exact_quote": "Model-selected URLs must respect the private-network boundary.",
        "supported_claim": "SSRF destination validation is required.",
    }


def requirement(
    requirement_id: str,
    source_kind: str,
    legacy_id: str,
    *,
    policy_basis: str = "group-oracle",
) -> dict[str, object]:
    row: dict[str, object] = {
        "requirement_id": requirement_id,
        "group_id": "HSG-test",
        "rule": "Validate a model-selected destination URL against SSRF policy.",
        "applicability": "When a remote destination URL is active.",
        "controlled_facet": "destination-url",
        "security_effect": "Prevent private-network requests.",
        "policy_basis": policy_basis,
        "evidence": [],
        "provenance": {
            "sources": [{"kind": source_kind, "legacy_requirement_id": legacy_id}]
        },
    }
    if source_kind == "source-derived":
        row["evidence"] = [
            {
                "role": "policy",
                "file": "policy.md",
                "sha256": "b" * 64,
                "excerpt": "Remote URLs must be checked before retrieval.",
                "claim": "The project establishes an SSRF boundary.",
            }
        ]
    return row


def comparison(project: str, chain_id: str) -> dict[str, object]:
    return {
        "group_id": "HSG-test",
        "project": project,
        "chain_id": chain_id,
        "capability_card": {"path": "card.md"},
    }


def view(project: str, chain_id: str) -> dict[str, object]:
    return {
        "project": project,
        "chain_id": chain_id,
        "roles": [{"role_id": "destination-url", "matched_bindings": ["args.url"]}],
        "active_facets": [{"facet_id": "ssrf-protection"}],
    }


def base_inputs() -> dict[str, object]:
    requirements = [
        requirement(
            "CR-source",
            "source-derived",
            "SR-source",
            policy_basis="explicit-source-policy",
        ),
        requirement(
            "CR-learned",
            "learned-invariant",
            "LIR-learned",
            policy_basis="learned-security-invariant",
        ),
        requirement("CR-group", "group-oracle", "R-doc"),
        requirement("CR-capability", "group-oracle", "R-card"),
    ]
    return {
        "requirements": requirements,
        "comparisons": [comparison("alpha", "C-alpha"), comparison("beta", "C-beta")],
        "group_oracles": [
            {
                "group_id": "HSG-test",
                "status": "complete",
                "requirements": [
                    {"requirement_id": "R-doc", "evidence_ids": ["EV-doc"]},
                    {"requirement_id": "R-card", "evidence_ids": ["EV-card"]},
                ],
            }
        ],
        "evidence_index": {
            "evidence": [
                evidence("EV-doc", "documentation"),
                evidence("EV-card", "capability-card"),
            ]
        },
        "learned_catalog": {
            "schema_version": "learned-invariant-catalog/v9",
            "patterns": [
                {
                    "requirement_id": "LIR-learned",
                    "pattern_key": "network-destination",
                    "training_report_ids": ["GT-must-not-project"],
                }
            ],
        },
        "effective_views": [view("alpha", "C-alpha"), view("beta", "C-beta")],
        "card_payloads": {
            "card.md": {
                "capability_class": "network-egress",
                "roles": [{"role_id": "destination-url"}],
            }
        },
    }


class V15NormativeProjectionTests(unittest.TestCase):
    def test_bracket_model_field_selects_exact_sink_role(self) -> None:
        req = requirement("CR-bracket", "group-oracle", "R-bracket")
        req["controlled_facet"] = "args['url'] -> HTTP response body"
        result = infer_applicability_contract(
            requirement=req,
            member_comparisons=[comparison("alpha", "C-alpha")],
            effective_views={("alpha", "C-alpha"): view("alpha", "C-alpha")},
            card_payloads={
                "card.md": {
                    "capability_class": "network-egress",
                    "roles": [
                        {"role_id": "destination-url"},
                        {"role_id": "request-body"},
                    ],
                }
            },
        )
        self.assertEqual(["destination-url"], result["required_sink_roles"])

    def test_source_learned_and_group_authority_admit_without_cross_mutation(
        self,
    ) -> None:
        inputs = base_inputs()
        before = copy.deepcopy(inputs)
        result = build_normative_projection(**inputs)
        self.assertEqual(before, inputs)
        self.assertEqual(
            {"CR-source", "CR-learned", "CR-group"},
            {row["requirement_id"] for row in result.admitted_requirements},
        )
        self.assertEqual(
            ["CR-capability"],
            [row["requirement_id"] for row in result.capability_hypotheses],
        )
        self.assertNotIn("GT-must-not-project", canonical_json(result.resolutions))

    def test_versioned_capability_policy_is_read_from_source_card(self) -> None:
        inputs = base_inputs()
        inputs["requirements"] = [requirement("CR-policy", "group-oracle", "R-policy")]
        inputs["group_oracles"][0]["requirements"] = [
            {"requirement_id": "R-policy", "evidence_ids": ["EV-policy"]}
        ]
        inputs["evidence_index"]["evidence"] = [
            evidence("EV-policy", "capability-policy")
        ]
        inputs["card_payloads"]["card.md"]["policy_contract"] = {
            "schema_version": "approval-policy-contract/v1"
        }
        before = copy.deepcopy(inputs)
        result = build_normative_projection(**inputs)
        self.assertEqual(before, inputs)
        self.assertEqual(
            ["CR-policy"],
            [row["requirement_id"] for row in result.admitted_requirements],
        )

    def test_unsupported_and_duplicate_evidence_fail_closed(self) -> None:
        for rows, message in (
            ([evidence("EV-doc", "unsupported")], "invalid normative evidence"),
            ([evidence("EV-doc", "documentation")] * 2, "duplicate evidence"),
        ):
            with self.subTest(message=message):
                inputs = base_inputs()
                inputs["requirements"] = [
                    requirement("CR-group", "group-oracle", "R-doc")
                ]
                inputs["evidence_index"]["evidence"] = rows
                with self.assertRaisesRegex(CoverageComparisonError, message):
                    build_normative_projection(**inputs)

    def test_primary_role_breaks_tie_and_unregistered_tie_fails_closed(self) -> None:
        req = requirement("CR-ambiguous", "group-oracle", "R-ambiguous")
        req["rule"] = "Apply the security policy."
        req["applicability"] = "When the capability is active."
        req["controlled_facet"] = "security-policy"
        req["security_effect"] = "Preserve the protected boundary."
        comparisons = [comparison("alpha", "C-alpha")]
        cards = {
            "card.md": {
                "capability_class": "network-egress",
                "roles": [
                    {"role_id": "destination-url"},
                    {"role_id": "request-body"},
                ],
            }
        }
        ambiguous_view = view("alpha", "C-alpha")
        ambiguous_view["roles"].append(
            {"role_id": "request-body", "matched_bindings": ["args.body"]}
        )
        primary = infer_applicability_contract(
            requirement=req,
            member_comparisons=comparisons,
            effective_views={("alpha", "C-alpha"): ambiguous_view},
            card_payloads=cards,
        )
        self.assertEqual(["destination-url"], primary["required_sink_roles"])
        ambiguous_view["roles"] = [
            {"role_id": "headers", "matched_bindings": ["args.headers"]},
            {"role_id": "request-body", "matched_bindings": ["args.body"]},
        ]
        cards["card.md"]["roles"] = [
            {"role_id": "headers"},
            {"role_id": "request-body"},
        ]
        with self.assertRaisesRegex(
            CoverageComparisonError, "ambiguous required sink role"
        ):
            infer_applicability_contract(
                requirement=req,
                member_comparisons=comparisons,
                effective_views={("alpha", "C-alpha"): ambiguous_view},
                card_payloads=cards,
            )
        facet_view = view("alpha", "C-alpha")
        facet_view["active_facets"] = [
            {"facet_id": "alpha-facet"},
            {"facet_id": "beta-facet"},
        ]
        req["controlled_facet"] = "destination-url"
        contract = infer_applicability_contract(
            requirement=req,
            member_comparisons=comparisons,
            effective_views={("alpha", "C-alpha"): facet_view},
            card_payloads={
                "card.md": {
                    "capability_class": "network-egress",
                    "roles": [{"role_id": "destination-url"}],
                }
            },
        )
        self.assertEqual(
            ["capability-family:network-request"],
            contract["required_capability_facets"],
        )

    def test_explicit_multi_role_and_normative_conflict(self) -> None:
        req = requirement("CR-role", "group-oracle", "R-role")
        req["rule"] = "The environment parameter must be validated."
        req["applicability"] = "When process execution is active."
        req["security_effect"] = "Prevent unsafe environment injection."
        comparisons = [comparison("alpha", "C-alpha")]
        cards = {
            "card.md": {
                "capability_class": "process-spawn",
                "roles": [
                    {"role_id": "command"},
                    {"role_id": "environment"},
                    {"role_id": "path"},
                ],
            }
        }
        role_view = {
            "project": "alpha",
            "chain_id": "C-alpha",
            "roles": [
                {"role_id": "command", "matched_bindings": ["args.command"]},
                {"role_id": "environment", "matched_bindings": ["args.env"]},
                {"role_id": "path", "matched_bindings": ["args.path"]},
            ],
        }
        req["controlled_facet"] = "args.env and args.command"
        multi = infer_applicability_contract(
            requirement=req,
            member_comparisons=comparisons,
            effective_views={("alpha", "C-alpha"): role_view},
            card_payloads=cards,
        )
        self.assertEqual(["environment", "command"], multi["required_sink_roles"])
        req["controlled_facet"] = "security-policy"
        normative = infer_applicability_contract(
            requirement=req,
            member_comparisons=comparisons,
            effective_views={("alpha", "C-alpha"): role_view},
            card_payloads=cards,
        )
        self.assertEqual(["environment"], normative["required_sink_roles"])
        req["controlled_facet"] = "args.path"
        with self.assertRaisesRegex(
            CoverageComparisonError, "controlled facet conflicts with normative role"
        ):
            infer_applicability_contract(
                requirement=req,
                member_comparisons=comparisons,
                effective_views={("alpha", "C-alpha"): role_view},
                card_payloads=cards,
            )


if __name__ == "__main__":
    unittest.main()

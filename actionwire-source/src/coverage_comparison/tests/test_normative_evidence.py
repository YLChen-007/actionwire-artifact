from __future__ import annotations

import unittest

from src.coverage_comparison.applicability_contract import (
    APPLICABILITY_CONTRACT_VERSION,
    validate_applicability_contract,
)
from src.coverage_comparison.contracts import CoverageComparisonError, canonical_json
from src.coverage_comparison.normative_evidence import (
    resolve_normative_evidence,
    validate_normative_evidence_resolution,
)


def contract(**updates: object) -> dict[str, object]:
    row: dict[str, object] = {
        "schema_version": APPLICABILITY_CONTRACT_VERSION,
        "required_sink_roles": ["url"],
        "allowed_value_authorities": ["model-arbitrary", "model-component"],
        "required_capability_facets": ["network-egress"],
        "required_boundary": "private-network",
        "required_effect": "outbound-request",
        "call_shape_predicates": ["remote-url"],
    }
    row.update(updates)
    return row


def evidence(evidence_id: str, kind: str) -> dict[str, object]:
    row: dict[str, object] = {
        "evidence_id": evidence_id,
        "kind": kind,
        "source_path": "policy.md",
        "sha256": "a" * 64,
        "exact_quote": "The selected destination must respect the network boundary.",
        "supported_claim": "Destination validation is required.",
    }
    if kind == "capability-policy":
        row["policy_contract_schema_version"] = "approval-policy-contract/v1"
    return row


class NormativeEvidenceTests(unittest.TestCase):
    def test_all_generic_normative_authorities_are_accepted(self) -> None:
        for kind in (
            "explicit-source-policy",
            "fixed-delta",
            "standard",
            "documentation",
            "capability-policy",
        ):
            with self.subTest(kind=kind):
                row = evidence("EV-authority", kind)
                result = resolve_normative_evidence(
                    group_id="HSG-test",
                    requirement_id="R-test",
                    evidence_ids=["EV-authority"],
                    evidence_rows=[row],
                    applicability_contract=contract(),
                )
                self.assertEqual("normative", result["status"])
                self.assertEqual([kind], result["authority_kinds"])

    def test_capability_card_is_supplemental_only(self) -> None:
        capability = evidence("EV-card", "capability-card")
        alone = resolve_normative_evidence(
            group_id="HSG-test",
            requirement_id="R-test",
            evidence_ids=["EV-card"],
            evidence_rows=[capability],
            applicability_contract=contract(),
        )
        self.assertEqual("non-normative", alone["status"])
        self.assertEqual(["EV-card"], alone["supplemental_evidence_ids"])

        fixed = evidence("EV-delta", "fixed-delta")
        combined = resolve_normative_evidence(
            group_id="HSG-test",
            requirement_id="R-test",
            evidence_ids=["EV-card", "EV-delta"],
            evidence_rows=[capability, fixed],
            applicability_contract=contract(),
        )
        self.assertEqual("normative", combined["status"])
        self.assertEqual(["EV-delta"], combined["normative_evidence_ids"])

    def test_learned_catalog_is_exact_versioned_authority_without_gt_output(
        self,
    ) -> None:
        catalog = {
            "schema_version": "learned-invariant-catalog/v15",
            "patterns": [
                {
                    "requirement_id": "LIR-test",
                    "applicability_contract": contract(),
                    "training_report_ids": ["GT-private-training-provenance"],
                }
            ],
        }
        result = resolve_normative_evidence(
            group_id="HSG-test",
            requirement_id="CR-test",
            evidence_ids=[],
            evidence_rows=[],
            applicability_contract=contract(),
            learned_requirement_ids=["LIR-test"],
            learned_catalog=catalog,
        )
        self.assertEqual("normative", result["status"])
        self.assertEqual(["learned-invariant"], result["authority_kinds"])
        self.assertNotIn("GT-private", canonical_json(result))

    def test_missing_contract_or_partial_upstream_fails_closed(self) -> None:
        row = evidence("EV-doc", "documentation")
        for contract_value, upstream in ((None, "complete"), (contract(), "partial")):
            with self.subTest(contract=contract_value, upstream=upstream):
                result = resolve_normative_evidence(
                    group_id="HSG-test",
                    requirement_id="R-test",
                    evidence_ids=["EV-doc"],
                    evidence_rows=[row],
                    applicability_contract=contract_value,
                    upstream_status=upstream,
                )
                self.assertEqual("upstream-incomplete", result["status"])

    def test_contract_acceptance_negatives_fail_closed(self) -> None:
        invalid_rows = [
            {
                key: value
                for key, value in contract().items()
                if key != "required_boundary"
            },
            contract(allowed_value_authorities=["unknown"]),
            contract(required_capability_facets=[]),
            contract(call_shape_predicates=["remote-url", "remote-url"]),
            contract(required_effect="contains spaces"),
        ]
        for row in invalid_rows:
            with self.subTest(row=row), self.assertRaises(CoverageComparisonError):
                validate_applicability_contract(row)

    def test_unversioned_policy_and_unknown_learned_id_are_rejected(self) -> None:
        policy = evidence("EV-policy", "capability-policy")
        policy.pop("policy_contract_schema_version")
        with self.assertRaisesRegex(CoverageComparisonError, "not versioned"):
            resolve_normative_evidence(
                group_id="HSG-test",
                requirement_id="R-test",
                evidence_ids=["EV-policy"],
                evidence_rows=[policy],
                applicability_contract=contract(),
            )
        with self.assertRaisesRegex(CoverageComparisonError, "unknown learned"):
            resolve_normative_evidence(
                group_id="HSG-test",
                requirement_id="R-test",
                evidence_ids=[],
                evidence_rows=[],
                applicability_contract=contract(),
                learned_requirement_ids=["LIR-missing"],
                learned_catalog={"schema_version": "catalog/v1", "patterns": []},
            )

    def test_resolution_rejects_report_fields_and_authority_drift(self) -> None:
        result = resolve_normative_evidence(
            group_id="HSG-test",
            requirement_id="R-test",
            evidence_ids=["EV-doc"],
            evidence_rows=[evidence("EV-doc", "documentation")],
            applicability_contract=contract(),
        )
        with_report = {**result, "report_id": "GT-forbidden"}
        with self.assertRaisesRegex(CoverageComparisonError, "fields mismatch"):
            validate_normative_evidence_resolution(with_report)
        drifted = {**result, "allowed_validation_policy_bases": ["fixed-delta"]}
        with self.assertRaisesRegex(CoverageComparisonError, "contradict"):
            validate_normative_evidence_resolution(drifted)


if __name__ == "__main__":
    unittest.main()

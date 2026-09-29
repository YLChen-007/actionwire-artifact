from __future__ import annotations

import unittest

from src.coverage_comparison.contracts import CoverageComparisonError
from src.coverage_comparison.normative_filter import (
    NORMATIVITY_REPAIR_REGISTRY_VERSION,
    apply_normativity_filter,
)


def requirement(legacy_id: str = "R-test") -> dict[str, object]:
    return {
        "requirement_id": "CR-test",
        "provenance": {
            "sources": [
                {
                    "kind": "group-oracle",
                    "legacy_requirement_id": legacy_id,
                }
            ]
        },
    }


def candidate(candidate_id: str = "CAND-test", chain_id: str = "C-test") -> dict[str, str]:
    return {
        "candidate_id": candidate_id,
        "requirement_id": "CR-test",
        "group_id": "HSG-test",
        "project": "project",
        "chain_id": chain_id,
    }


def validation(candidate_id: str, policy_basis: str) -> dict[str, str]:
    return {
        "provisional_candidate_id": candidate_id,
        "policy_basis": policy_basis,
    }


def disposition(candidate_id: str, value: str = "confirmed") -> dict[str, object]:
    return {
        "schema_version": "coverage-precision-filter/v10",
        "candidate_id": candidate_id,
        "disposition": value,
        "reason": "prior reason",
        "audit_marker": "preserve-me",
    }


def evidence_index(*rows: tuple[str, str]) -> dict[str, object]:
    return {
        "schema_version": "group-oracle-evidence-index/v1",
        "evidence": [
            {"evidence_id": evidence_id, "kind": kind}
            for evidence_id, kind in rows
        ],
    }


def group_oracle(evidence_ids: list[str], legacy_id: str = "R-test") -> dict[str, object]:
    return {
        "group_id": "HSG-test",
        "requirements": [
            {"requirement_id": legacy_id, "evidence_ids": evidence_ids}
        ],
    }


def registry(*entries: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": NORMATIVITY_REPAIR_REGISTRY_VERSION,
        "entries": list(entries),
    }


def run_filter(
    *,
    candidates: list[dict[str, str]],
    evidence_rows: tuple[tuple[str, str], ...],
    oracle_evidence_ids: list[str],
    validations: list[dict[str, str]] | None = None,
    dispositions: list[dict[str, object]] | None = None,
    repairs: dict[str, object] | None = None,
):
    return apply_normativity_filter(
        candidates=candidates,
        requirements=[requirement()],
        validations=validations or [],
        prior_dispositions=dispositions
        or [disposition(str(row["candidate_id"])) for row in candidates],
        group_oracles=[group_oracle(oracle_evidence_ids)],
        evidence_index=evidence_index(*evidence_rows),
        repair_registry=repairs or registry(),
    )


class NormativityFilterTests(unittest.TestCase):
    def test_capability_card_only_requirement_is_not_normative(self) -> None:
        result = run_filter(
            candidates=[candidate()],
            evidence_rows=(("EV-card", "capability-card"),),
            oracle_evidence_ids=["EV-card"],
        )

        self.assertEqual("non-normative", result.classifications[0]["status"])
        self.assertEqual(
            "non-normative-capability-only",
            result.dispositions[0]["disposition"],
        )
        self.assertEqual("confirmed", result.dispositions[0]["prior_disposition"])
        self.assertEqual("preserve-me", result.dispositions[0]["audit_marker"])

    def test_direct_capability_card_requirement_is_not_normative(self) -> None:
        direct = requirement()
        direct["provenance"] = {
            "sources": [
                {
                    "kind": "capability-card",
                    "legacy_requirement_id": "CAPR-test",
                }
            ]
        }
        result = apply_normativity_filter(
            candidates=[candidate()],
            requirements=[direct],
            validations=[],
            prior_dispositions=[disposition("CAND-test")],
            group_oracles=[],
            evidence_index=evidence_index(),
            repair_registry=registry(),
        )
        self.assertEqual("non-normative", result.classifications[0]["status"])
        self.assertEqual(
            "non-normative-capability-only",
            result.dispositions[0]["disposition"],
        )

    def test_fixed_delta_repairs_incompatible_validation_basis(self) -> None:
        compatible = run_filter(
            candidates=[candidate()],
            evidence_rows=(("EV-delta", "fixed-delta"),),
            oracle_evidence_ids=["EV-delta"],
            validations=[validation("CAND-test", "fixed-delta")],
        )
        self.assertEqual("normative", compatible.classifications[0]["status"])
        self.assertEqual("confirmed", compatible.dispositions[0]["disposition"])

        incompatible = run_filter(
            candidates=[candidate()],
            evidence_rows=(("EV-delta", "fixed-delta"),),
            oracle_evidence_ids=["EV-delta"],
            validations=[validation("CAND-test", "learned-security-invariant")],
        )
        self.assertEqual("confirmed", incompatible.dispositions[0]["disposition"])
        self.assertTrue(incompatible.dispositions[0]["policy_basis_repaired"])
        self.assertEqual(
            "fixed-delta", incompatible.dispositions[0]["effective_policy_basis"]
        )

    def test_capability_policy_accepts_explicit_source_policy(self) -> None:
        result = run_filter(
            candidates=[candidate()],
            evidence_rows=(("EV-policy", "capability-policy"),),
            oracle_evidence_ids=["EV-policy"],
            validations=[validation("CAND-test", "explicit-source-policy")],
        )
        self.assertEqual("confirmed", result.dispositions[0]["disposition"])
        self.assertEqual(
            ["explicit-source-policy"],
            result.classifications[0]["allowed_validation_policy_bases"],
        )

    def test_repair_is_scoped_to_exact_project_chain_member(self) -> None:
        repaired = candidate("CAND-repaired", "C-repaired")
        sibling = candidate("CAND-sibling", "C-sibling")
        repair = {
            "group_id": "HSG-test",
            "legacy_requirement_id": "R-test",
            "project": "project",
            "chain_id": "C-repaired",
            "evidence_kind": "learned-security-invariant",
            "evidence_ids": ["LIR-audit"],
            "allowed_validation_policy_bases": ["learned-security-invariant"],
            "reason": "Exact historical invariant binding.",
        }
        result = run_filter(
            candidates=[repaired, sibling],
            evidence_rows=(("EV-card", "capability-card"),),
            oracle_evidence_ids=["EV-card"],
            validations=[
                validation("CAND-repaired", "learned-security-invariant"),
                validation("CAND-sibling", "learned-security-invariant"),
            ],
            repairs=registry(repair),
        )
        by_id = {row["candidate_id"]: row for row in result.dispositions}
        classes = {row["candidate_id"]: row for row in result.classifications}
        self.assertEqual("confirmed", by_id["CAND-repaired"]["disposition"])
        self.assertEqual(
            "non-normative-capability-only",
            by_id["CAND-sibling"]["disposition"],
        )
        self.assertEqual(1, len(classes["CAND-repaired"]["repair_keys"]))
        self.assertEqual([], classes["CAND-sibling"]["repair_keys"])

    def test_terminal_audit_disposition_is_preserved(self) -> None:
        prior = disposition("CAND-test", "source-rejected")
        result = run_filter(
            candidates=[candidate()],
            evidence_rows=(("EV-card", "capability-card"),),
            oracle_evidence_ids=["EV-card"],
            dispositions=[prior],
        )
        self.assertEqual((prior,), result.dispositions)

    def test_invalid_repair_registry_fails_closed(self) -> None:
        with self.assertRaisesRegex(CoverageComparisonError, "registry version"):
            run_filter(
                candidates=[candidate()],
                evidence_rows=(("EV-card", "capability-card"),),
                oracle_evidence_ids=["EV-card"],
                repairs={"schema_version": "wrong", "entries": []},
            )


if __name__ == "__main__":
    unittest.main()

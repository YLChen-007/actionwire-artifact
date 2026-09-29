from __future__ import annotations

import json
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from src.coverage_comparison.contracts import (
    CoverageComparisonError,
    stable_candidate_id,
    validate_comparison_response,
)
from src.coverage_comparison.inputs import (
    CoverageChain,
    CoverageInputs,
    _capability_card,
)
from src.coverage_comparison.pipeline import (
    _assessment_record,
    _candidate_record,
    _challenge_requirement_ids,
    _merge_challenge,
    _normalize_correction_response,
    _requirement_batches,
    _publish_directory,
    _validated_call,
    run_coverage_comparison,
)
from src.coverage_comparison.prompts import (
    COMPARE_SYSTEM,
    REPAIR_SYSTEM,
    build_compare_user,
    contains_credentials,
)
from src.coverage_comparison.transport import ExactPromptReplayRunner
from src.coverage_comparison.source_validation import (
    SourceValidationConfig,
    deterministic_precision_sample,
    run_source_validation,
    source_validation_checkpoint_root,
)
from src.coverage_comparison.source_validation_prompts import SOURCE_VALIDATION_SYSTEM
from src.projects import ProjectSpec


HC = "HC-" + "a" * 16
ST = "ST-" + "b" * 16
HSG = "HSG-" + "c" * 16
RID = "R-" + "d" * 16
GATE = "GU" + "e" * 20


def requirement() -> dict:
    return {
        "requirement_id": RID,
        "dimension": "destination-policy",
        "rule": "Reject destinations outside the allowed network scope.",
        "applicability": "When a model-controlled destination is requested.",
        "evidence_ids": ["EV-" + "1" * 16],
        "source_proposal_ids": ["RP-" + "2" * 16],
        "origin_chain_refs": [
            {"project": "fixture", "revision": "revision", "chain_id": "C-" + "1" * 12}
        ],
        "origin_gate_ids": [GATE],
    }


def semantic(*, gate: bool = True, partial: bool = False) -> dict:
    gates = []
    if gate:
        gates.append(
            {
                "gate_number": 1,
                "gate_uid": GATE,
                "gate_name": "untrusted name",
                "callsite": "source.py:2:1",
                "static_verdict": "confirmed",
                "semantic": {
                    "summary": "Rejects only one literal host.",
                    "status": "complete",
                },
            }
        )
    return {
        "schema_version": "call-chain-semantic-ir/v3",
        "project": {"id": "fixture", "revision": "revision"},
        "chain_id": "C-" + "1" * 12,
        "handler": {"tool_name": "request", "qualified_name": "request"},
        "sink": {"sink_id": "S-" + "3" * 16},
        "sink_constraint": {
            "constraint_id": "SC-" + "4" * 16,
            "sink_id": "S-" + "3" * 16,
            "sink_api": "request",
            "capability_class": "network-egress",
            "location": "source.py:3:1",
            "controlled_argument": "url",
            "call_shape": "request(model_url, follow_redirects=True)",
            "capability_card": {"path": "card.md", "sha256": "0" * 64},
        },
        "values": [
            {
                "id": "CV-1",
                "source_parameter": "url",
                "sink_binding": "url",
                "gate_bindings": [],
            }
        ],
        "summary": "fixture",
        "gates": gates,
        "unresolved": ["dependency"] if partial else [],
        "status": "partial" if partial else "complete",
    }


def coverage_chain(
    *,
    gate: bool = True,
    partial_oracle: bool = False,
    empty: bool = False,
    partial_semantic: bool = False,
) -> CoverageChain:
    requirements = [] if empty else [requirement()]
    oracle = {
        "schema_version": "group-oracle/v1",
        "group_id": HSG,
        "handler_criterion_id": HC,
        "sink_type_id": ST,
        "status": "partial" if partial_oracle or empty else "complete",
        "seed": {
            "project": "fixture",
            "revision": "revision",
            "chain_id": "C-" + "1" * 12,
            "selection_policy": "complete-lexicographic",
        },
        "member_chain_refs": [
            {"project": "fixture", "revision": "revision", "chain_id": "C-" + "1" * 12}
        ],
        "requirements": requirements,
        "rejected_proposal_ids": ["RP-" + "9" * 16] if partial_oracle or empty else [],
    }
    return CoverageChain(
        project="fixture",
        revision="revision",
        chain_id="C-" + "1" * 12,
        handler_id="H-" + "5" * 16,
        handler_criterion_id=HC,
        handler_type_id="HT-" + "6" * 16,
        sink_id="S-" + "3" * 16,
        sink_type_id=ST,
        group_id=HSG,
        oracle=oracle,
        semantic_ir=semantic(gate=gate, partial=partial_semantic),
        capability_card_path="src/sink_capacity/sink-capability-cards/card.md",
        capability_card_sha256="7" * 64,
        capability_card="# request\nCapability: arbitrary network destination.\nDefault: redirects followed.",
        capability_card_lines=(
            "# request",
            "Capability: arbitrary network destination.",
            "Default: redirects followed.",
        ),
        requirement_evidence=(
            {
                "evidence_id": "EV-" + "1" * 16,
                "kind": "documentation",
                "supported_claim": "Destination policy is required.",
            },
        ),
    )


def inputs(chain: CoverageChain) -> CoverageInputs:
    return CoverageInputs(
        chains=(chain,),
        exclusions=(),
        digests={"fixture": "8" * 64},
        structural_chain_count=1,
    )


class FakeRunner:
    def __init__(self, decision: str, *, invalid_first: bool = False):
        self.decision = decision
        self.invalid_first = invalid_first
        self.calls: list[tuple[str, str]] = []

    def __call__(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if self.invalid_first and len(self.calls) == 1:
            return "not json"
        if system == REPAIR_SYSTEM:
            # The repair prompt contains the original request text; return a valid fixture.
            system = COMPARE_SYSTEM
        if system != COMPARE_SYSTEM:
            raise AssertionError(system)
        if self.decision == "covered":
            gates, covered, gap = (
                [GATE],
                "Rejects every out-of-scope destination.",
                None,
            )
        elif self.decision == "wrong-check":
            gates, covered, gap = (
                [GATE],
                "Rejects one literal host.",
                "Other private hosts remain reachable.",
            )
        elif self.decision == "missing-check":
            gates, covered, gap = [], None, "No destination policy is enforced."
        else:
            gates, covered, gap = [], None, None
        applicability = (
            "not-applicable"
            if self.decision == "not-applicable"
            else "unknown"
            if self.decision == "unknown"
            else "applicable"
        )
        return json.dumps(
            {
                "group_id": HSG,
                "chain_id": "C-" + "1" * 12,
                "applicable_defaults": ["Redirects are followed."],
                "requirements": [
                    {
                        "requirement_id": RID,
                        "applicability": applicability,
                        "decision": self.decision,
                        "capability_line_refs": []
                        if self.decision == "unknown"
                        else [{"start_line": 2, "end_line": 3}],
                        "call_shape_facts": []
                        if self.decision == "unknown"
                        else ["The URL is model-controlled and redirects are enabled."],
                        "gate_ids": gates,
                        "covered_semantics": covered,
                        "gap": gap,
                        "uncertainty": "The effective destination cannot be resolved."
                        if self.decision == "unknown"
                        else None,
                    }
                ],
            }
        )

    def audit_payload(self) -> dict:
        return {"transport": "fake", "available_tools": [], "calls": []}


def project_spec(source_root: Path) -> ProjectSpec:
    return ProjectSpec(
        project_id="fixture",
        source_root=source_root,
        analysis_revision="revision",
        codeql_database=source_root / "db",
        design_root=source_root / "design",
        output_root=source_root / "output",
        ground_truth_root=source_root / "groundtruth",
        codeql_adapter="fixture",
        source_language="python",
        codeql_language="python",
        query_pack=source_root / "ql",
    )


class FakeSourceRunner:
    def __init__(self, verdict: str = "confirmed-uncovered") -> None:
        self.verdict = verdict
        self.calls: list[tuple[str, str]] = []

    def __call__(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        self.assert_system(system)
        payload = json.loads(user.split("\n", 1)[1])
        candidate = payload["provisional_candidates"][0]["candidate"]
        if self.verdict == "confirmed-uncovered":
            final_decision = candidate["failure_mode"]
            covering_gate_ids = []
            gate_coverage = "uncovered"
            roles = ["handler", "controlled-value", "sink", "policy", "impact"]
            impact, severity, complete = "concrete", "high", True
            policy_basis = "explicit-source-policy"
            security_effect = "The request reaches a private destination."
            uncertainties = []
        elif self.verdict == "not-applicable":
            final_decision = "not-applicable"
            covering_gate_ids = []
            gate_coverage = "unknown"
            roles = ["controlled-value", "sink"]
            impact, severity, complete = "none", "unknown", True
            policy_basis = "none"
            security_effect = None
            uncertainties = []
        elif self.verdict == "covered":
            final_decision = "covered"
            covering_gate_ids = [GATE]
            gate_coverage = "covered"
            roles = ["gate"]
            impact, severity, complete = "none", "unknown", True
            policy_basis = "explicit-source-policy"
            security_effect = None
            uncertainties = []
        else:
            final_decision = "unknown"
            covering_gate_ids = []
            gate_coverage = "uncatalogued-check"
            roles = []
            impact, severity, complete = "unknown", "unknown", False
            policy_basis = "unknown"
            security_effect = None
            uncertainties = ["A helper check has no supplied gate identity."]
        evidence = [
            {
                "role": role,
                "file": "source.py",
                "line_start": 1,
                "line_end": 1,
                "claim": f"Source evidence for {role}.",
            }
            for role in roles
        ]
        return json.dumps(
            {
                "project": payload["project"],
                "revision": payload["revision"],
                "chain_id": payload["chain_id"],
                "validations": [
                    {
                        "provisional_candidate_id": candidate["candidate_id"],
                        "verdict": self.verdict,
                        "final_decision": final_decision,
                        "covering_gate_ids": covering_gate_ids,
                        "policy_basis": policy_basis,
                        "controlled_flow": (
                            "confirmed"
                            if self.verdict == "confirmed-uncovered"
                            else "refuted"
                            if self.verdict == "not-applicable"
                            else "unknown"
                        ),
                        "sink_reachability": (
                            "confirmed"
                            if self.verdict in {"confirmed-uncovered", "covered"}
                            else "refuted"
                            if self.verdict == "not-applicable"
                            else "unknown"
                        ),
                        "gate_coverage": gate_coverage,
                        "impact": impact,
                        "impact_severity": severity,
                        "source_research_complete": complete,
                        "source_evidence": evidence,
                        "preconditions": [],
                        "security_effect": security_effect,
                        "uncertainties": uncertainties,
                        "reason": "Source-aware fixture verdict.",
                    }
                ],
            }
        )

    def assert_system(self, system: str) -> None:
        if system != SOURCE_VALIDATION_SYSTEM:
            raise AssertionError(system)

    def audit_payload(self) -> dict:
        return {
            "transport": "fake-source-agent",
            "available_tools": ["Read", "Grep", "Glob"],
            "token_usage": {},
        }

    def chat_payload(self) -> dict:
        return {
            "transport": "fake-source-agent",
            "turns": [
                {"system_prompt": system, "user_prompt": user}
                for system, user in self.calls
            ],
        }

    def close(self) -> None:
        return None


class ContractTests(unittest.TestCase):
    def normalized_assessment(self, decision: str) -> dict:
        response = json.loads(FakeRunner(decision)(COMPARE_SYSTEM, "unused"))
        _, [row] = validate_comparison_response(
            response,
            group_id=HSG,
            chain_id="C-" + "1" * 12,
            requirements={RID: requirement()},
            allowed_gate_ids={GATE},
            card_lines=("title", "capability", "default"),
        )
        return row

    def test_challenge_affirmation_keeps_primary(self) -> None:
        primary = self.normalized_assessment("covered")
        final, record = _merge_challenge(coverage_chain(), primary, dict(primary))
        self.assertEqual(primary, final)
        self.assertEqual("affirmed", record["disposition"])

    def test_challenge_can_revise_covered_to_wrong_check(self) -> None:
        primary = self.normalized_assessment("covered")
        challenge = self.normalized_assessment("wrong-check")
        final, record = _merge_challenge(coverage_chain(), primary, challenge)
        self.assertEqual("wrong-check", final["decision"])
        self.assertEqual("revised-uncovered", record["disposition"])

    def test_challenge_can_revise_not_applicable_to_missing_check(self) -> None:
        primary = self.normalized_assessment("not-applicable")
        challenge = self.normalized_assessment("missing-check")
        final, record = _merge_challenge(coverage_chain(gate=False), primary, challenge)
        self.assertEqual("missing-check", final["decision"])
        self.assertEqual("revised-uncovered", record["disposition"])

    def test_non_uncovered_challenge_disagreement_becomes_unknown(self) -> None:
        primary = self.normalized_assessment("covered")
        challenge = self.normalized_assessment("not-applicable")
        final, record = _merge_challenge(coverage_chain(), primary, challenge)
        self.assertEqual("unknown", final["decision"])
        self.assertEqual("conflict-unknown", record["disposition"])

    def test_uncovered_and_unknown_requirements_are_not_challenged(self) -> None:
        rows = [
            self.normalized_assessment(decision)
            for decision in ("wrong-check", "missing-check", "unknown")
        ]
        self.assertEqual([], _challenge_requirement_ids(rows))

    def test_requirement_batches_are_bounded_and_complete(self) -> None:
        requirement_ids = [f"R-{number:016x}" for number in range(19)]
        batches = _requirement_batches(requirement_ids)
        self.assertEqual([8, 8, 3], [len(batch) for batch in batches])
        self.assertEqual(
            sorted(requirement_ids), [item for batch in batches for item in batch]
        )
        self.assertEqual(
            [sorted(requirement_ids[:8])],
            _requirement_batches(requirement_ids[:8]),
        )

    def test_correction_normalizer_never_marks_zero_gate_row_covered(self) -> None:
        response = json.loads(FakeRunner("covered")(COMPARE_SYSTEM, "unused"))
        response["requirements"][0]["gate_ids"] = []
        response["requirements"][0].pop("gap")
        normalized = _normalize_correction_response(response)
        row = normalized["requirements"][0]
        self.assertEqual("missing-check", row["decision"])
        self.assertEqual([], row["gate_ids"])
        self.assertIsNone(row["covered_semantics"])
        self.assertIsNotNone(row["gap"])

    def test_stable_candidate_identity_ignores_gate_order(self) -> None:
        second = "GU" + "f" * 20
        left = stable_candidate_id(
            group_id=HSG,
            project="p",
            revision="r",
            chain_id="C-" + "1" * 12,
            requirement_id=RID,
            failure_mode="wrong-check",
            gate_ids=[GATE, second],
        )
        right = stable_candidate_id(
            group_id=HSG,
            project="p",
            revision="r",
            chain_id="C-" + "1" * 12,
            requirement_id=RID,
            failure_mode="wrong-check",
            gate_ids=[second, GATE],
        )
        self.assertEqual(left, right)

    def test_card_line_quotes_are_extracted_not_trusted(self) -> None:
        runner = FakeRunner("wrong-check")
        response = json.loads(runner(COMPARE_SYSTEM, "unused"))
        _, rows = validate_comparison_response(
            response,
            group_id=HSG,
            chain_id="C-" + "1" * 12,
            requirements={RID: requirement()},
            allowed_gate_ids={GATE},
            card_lines=("title", "capability", "default"),
        )
        self.assertEqual(
            "capability\ndefault", rows[0]["capability_evidence"][0]["quote"]
        )

    def test_out_of_range_card_reference_fails(self) -> None:
        response = json.loads(FakeRunner("wrong-check")(COMPARE_SYSTEM, "unused"))
        response["requirements"][0]["capability_line_refs"] = [
            {"start_line": 2, "end_line": 99}
        ]
        with self.assertRaisesRegex(CoverageComparisonError, "out of range"):
            validate_comparison_response(
                response,
                group_id=HSG,
                chain_id="C-" + "1" * 12,
                requirements={RID: requirement()},
                allowed_gate_ids={GATE},
                card_lines=("title", "capability", "default"),
            )

    def test_field_mismatch_names_extra_fields_for_repair(self) -> None:
        response = json.loads(FakeRunner("wrong-check")(COMPARE_SYSTEM, "unused"))
        response["requirements"][0]["reason"] = "unsupported extra field"
        with self.assertRaisesRegex(CoverageComparisonError, r"extra=\['reason'\]"):
            validate_comparison_response(
                response,
                group_id=HSG,
                chain_id="C-" + "1" * 12,
                requirements={RID: requirement()},
                allowed_gate_ids={GATE},
                card_lines=("title", "capability", "default"),
            )

    def test_repair_contract_requires_explicit_nullable_fields(self) -> None:
        self.assertIn("add that key explicitly with JSON null", REPAIR_SYSTEM)
        self.assertIn("never omit covered_semantics, gap, or", REPAIR_SYSTEM)
        self.assertIn("zero relevant gate IDs always", REPAIR_SYSTEM)
        self.assertIn("Never preserve\na decision that contradicts", REPAIR_SYSTEM)

    def test_wrong_check_and_missing_check_gate_invariants(self) -> None:
        wrong = json.loads(FakeRunner("wrong-check")(COMPARE_SYSTEM, "unused"))
        wrong["requirements"][0]["gate_ids"] = []
        with self.assertRaisesRegex(CoverageComparisonError, "wrong-check"):
            validate_comparison_response(
                wrong,
                group_id=HSG,
                chain_id="C-" + "1" * 12,
                requirements={RID: requirement()},
                allowed_gate_ids={GATE},
                card_lines=("title", "capability", "default"),
            )

    def test_response_requires_exact_requirement_coverage_and_allowed_ids(self) -> None:
        response = json.loads(FakeRunner("covered")(COMPARE_SYSTEM, "unused"))
        response["requirements"] = []
        with self.assertRaisesRegex(CoverageComparisonError, "every requirement"):
            validate_comparison_response(
                response,
                group_id=HSG,
                chain_id="C-" + "1" * 12,
                requirements={RID: requirement()},
                allowed_gate_ids={GATE},
                card_lines=("title", "capability", "default"),
            )
        response = json.loads(FakeRunner("covered")(COMPARE_SYSTEM, "unused"))
        response["requirements"].append(dict(response["requirements"][0]))
        with self.assertRaisesRegex(CoverageComparisonError, "every requirement"):
            validate_comparison_response(
                response,
                group_id=HSG,
                chain_id="C-" + "1" * 12,
                requirements={RID: requirement()},
                allowed_gate_ids={GATE},
                card_lines=("title", "capability", "default"),
            )
        response = json.loads(FakeRunner("covered")(COMPARE_SYSTEM, "unused"))
        response["requirements"][0]["gate_ids"] = ["GU" + "0" * 20]
        with self.assertRaisesRegex(CoverageComparisonError, "unknown identifiers"):
            validate_comparison_response(
                response,
                group_id=HSG,
                chain_id="C-" + "1" * 12,
                requirements={RID: requirement()},
                allowed_gate_ids={GATE},
                card_lines=("title", "capability", "default"),
            )

    def test_complete_concrete_call_shape_is_preserved_in_prompt(self) -> None:
        fixed_semantic = semantic()
        fixed_semantic["sink_constraint"]["call_shape"] = (
            "request('https://fixed.example', follow_redirects=False)"
        )
        fixed_semantic["values"] = [
            {
                "id": "CV-1",
                "source_parameter": "body",
                "sink_binding": "json",
                "gate_bindings": [],
            }
        ]
        fixed = replace(coverage_chain(), semantic_ir=fixed_semantic)
        controlled_semantic = semantic()
        controlled_semantic["sink_constraint"]["call_shape"] = (
            "request(model_url, follow_redirects=True)"
        )
        controlled = replace(coverage_chain(), semantic_ir=controlled_semantic)
        argv_semantic = semantic()
        argv_semantic["sink_constraint"]["call_shape"] = (
            "subprocess.run([program, argument], shell=False)"
        )
        argv = replace(coverage_chain(), semantic_ir=argv_semantic)
        shell_semantic = semantic()
        shell_semantic["sink_constraint"]["call_shape"] = (
            "subprocess.run(command, shell=True)"
        )
        shell = replace(coverage_chain(), semantic_ir=shell_semantic)

        fixed_prompt = build_compare_user(fixed)
        controlled_prompt = build_compare_user(controlled)
        argv_prompt = build_compare_user(argv)
        shell_prompt = build_compare_user(shell)
        self.assertIn("fixed.example", fixed_prompt)
        self.assertIn("follow_redirects=False", fixed_prompt)
        self.assertIn('"source_parameter": "body"', fixed_prompt)
        self.assertIn("model_url", controlled_prompt)
        self.assertIn("follow_redirects=True", controlled_prompt)
        self.assertIn("shell=False", argv_prompt)
        self.assertIn("shell=True", shell_prompt)
        self.assertEqual(
            4, len({fixed_prompt, controlled_prompt, argv_prompt, shell_prompt})
        )

    def test_zero_gate_prompt_forbids_gate_dependent_decisions(self) -> None:
        prompt = build_compare_user(coverage_chain(gate=False))
        self.assertIn('"zero_gate_chain": true', prompt)
        self.assertIn('"covered_or_wrong_check_permitted": false', prompt)
        self.assertIn(
            '"applicable_decision_when_no_relevant_gate": "missing-check"',
            prompt,
        )

    def test_combined_multi_gate_coverage_is_accepted(self) -> None:
        second_gate = "GU" + "f" * 20
        response = json.loads(FakeRunner("covered")(COMPARE_SYSTEM, "unused"))
        response["requirements"][0]["gate_ids"] = [second_gate, GATE]
        response["requirements"][0]["covered_semantics"] = (
            "The first gate validates scheme and the second validates destination."
        )
        _, rows = validate_comparison_response(
            response,
            group_id=HSG,
            chain_id="C-" + "1" * 12,
            requirements={RID: requirement()},
            allowed_gate_ids={GATE, second_gate},
            card_lines=("title", "capability", "default"),
        )
        self.assertEqual(sorted([GATE, second_gate]), rows[0]["gate_ids"])
        missing = json.loads(FakeRunner("missing-check")(COMPARE_SYSTEM, "unused"))
        missing["requirements"][0]["gate_ids"] = [GATE]
        with self.assertRaisesRegex(CoverageComparisonError, "missing-check"):
            validate_comparison_response(
                missing,
                group_id=HSG,
                chain_id="C-" + "1" * 12,
                requirements={RID: requirement()},
                allowed_gate_ids={GATE},
                card_lines=("title", "capability", "default"),
            )

    def test_capability_card_is_confined_and_digest_bound(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        with self.assertRaisesRegex(CoverageComparisonError, "outside"):
            _capability_card(
                repo_root=repo_root,
                raw_path="paper-writting/tex/method.tex",
                expected_digest="0" * 64,
                context="fixture",
            )
        real = "src/sink_capacity/sink-capability-cards/subprocess.run.md"
        with self.assertRaisesRegex(CoverageComparisonError, "digest drift"):
            _capability_card(
                repo_root=repo_root,
                raw_path=real,
                expected_digest="0" * 64,
                context="fixture",
            )
        with self.assertRaisesRegex(CoverageComparisonError, "does not exist"):
            _capability_card(
                repo_root=repo_root,
                raw_path="src/sink_capacity/sink-capability-cards/not-present.md",
                expected_digest="0" * 64,
                context="fixture",
            )

    def test_prompt_injection_is_untrusted_and_credentials_are_redacted(self) -> None:
        chain = coverage_chain()
        self.assertIn("untrusted DATA", COMPARE_SYSTEM)
        self.assertFalse(contains_credentials(chain.capability_card))


class PipelineTests(unittest.TestCase):
    def run_fixture(
        self,
        root: Path,
        *,
        decision: str = "wrong-check",
        chain: CoverageChain | None = None,
        invalid_first: bool = False,
    ):
        selected = chain or coverage_chain(gate=decision != "missing-check")
        runner = FakeRunner(decision, invalid_first=invalid_first)
        out = root / "coverage-comparison"
        with patch(
            "src.coverage_comparison.pipeline.load_coverage_inputs",
            return_value=inputs(selected),
        ):
            result = run_coverage_comparison(
                capability_card_analysis=False,
                specs=[],
                handler_root=root,
                sink_root=root,
                group_root=root,
                evidence_registry=root / "registry.json",
                out_dir=out,
                generation_command="python -m src.coverage_comparison --all",
                runner=runner,
            )
        return result, runner, out

    def test_wrong_check_generates_deterministic_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result, runner, out = self.run_fixture(Path(raw))
            self.assertEqual(1, result["manifest"]["counts"]["wrong_check"])
            self.assertEqual(1, result["manifest"]["counts"]["candidates"])
            candidate = json.loads((out / "candidates.jsonl").read_text())
            self.assertEqual("wrong-check", candidate["failure_mode"])
            self.assertEqual([GATE], candidate["gate_ids"])
            self.assertEqual([], result["manifest"]["transport"]["available_tools"])
            self.assertIn("numbered_lines", runner.calls[0][1])

    def test_missing_check_from_zero_gate_chain(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result, _, out = self.run_fixture(Path(raw), decision="missing-check")
            self.assertEqual(1, result["manifest"]["counts"]["missing_check"])
            candidate = json.loads((out / "candidates.jsonl").read_text())
            self.assertEqual([], candidate["gate_ids"])

    def test_covered_not_applicable_and_unknown_do_not_generate_candidates(
        self,
    ) -> None:
        for decision in ("covered", "not-applicable", "unknown"):
            with self.subTest(decision=decision), tempfile.TemporaryDirectory() as raw:
                result, _, out = self.run_fixture(Path(raw), decision=decision)
                self.assertEqual(0, result["manifest"]["counts"]["candidates"])
                self.assertEqual("", (out / "candidates.jsonl").read_text())

    def test_partial_provenance_survives_candidate_generation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            chain = coverage_chain(partial_oracle=True, partial_semantic=True)
            result, _, out = self.run_fixture(Path(raw), chain=chain)
            comparison = json.loads((out / "comparisons.jsonl").read_text())
            candidate = json.loads((out / "candidates.jsonl").read_text())
            self.assertEqual("partial", comparison["status"])
            self.assertEqual("partial", candidate["group_oracle_status"])
            self.assertEqual("partial", candidate["semantic_ir_status"])
            self.assertEqual(1, result["manifest"]["counts"]["partial_comparisons"])

    def test_zero_requirement_oracle_is_inconclusive_without_model_call(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result, runner, out = self.run_fixture(
                Path(raw), chain=coverage_chain(empty=True)
            )
            self.assertEqual([], runner.calls)
            comparison = json.loads((out / "comparisons.jsonl").read_text())
            self.assertEqual("inconclusive", comparison["status"])
            self.assertEqual([], comparison["requirements"])
            self.assertEqual(0, result["manifest"]["counts"]["primary_requests"])

    def test_one_repair_is_permitted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result, runner, _ = self.run_fixture(Path(raw), invalid_first=True)
            self.assertEqual(1, result["manifest"]["counts"]["repair_calls"])
            self.assertEqual(REPAIR_SYSTEM, runner.calls[1][0])

    def test_token_overflow_occurs_before_transport(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            runner = FakeRunner("wrong-check")
            with patch(
                "src.coverage_comparison.pipeline.load_coverage_inputs",
                return_value=inputs(coverage_chain()),
            ):
                with self.assertRaisesRegex(CoverageComparisonError, "never truncated"):
                    run_coverage_comparison(
                        capability_card_analysis=False,
                        specs=[],
                        handler_root=root,
                        sink_root=root,
                        group_root=root,
                        evidence_registry=root / "registry",
                        out_dir=root / "out",
                        generation_command="command",
                        runner=runner,
                        input_token_limit=1,
                    )
            self.assertEqual([], runner.calls)

    def test_failed_run_preserves_previous_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            out = root / "coverage-comparison"
            out.mkdir()
            (out / "sentinel").write_text("previous")

            class Broken:
                def __call__(self, _system: str, _user: str) -> str:
                    return "not json"

            with patch(
                "src.coverage_comparison.pipeline.load_coverage_inputs",
                return_value=inputs(coverage_chain()),
            ):
                with self.assertRaises(CoverageComparisonError):
                    run_coverage_comparison(
                        capability_card_analysis=False,
                        specs=[],
                        handler_root=root,
                        sink_root=root,
                        group_root=root,
                        evidence_registry=root / "registry",
                        out_dir=out,
                        generation_command="command",
                        runner=Broken(),
                    )
            self.assertEqual("previous", (out / "sentinel").read_text())

    def test_atomic_publish(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            out, staging = root / "out", root / "staging"
            out.mkdir()
            staging.mkdir()
            (out / "old").write_text("old")
            (staging / "new").write_text("new")
            _publish_directory(staging, out)
            self.assertFalse((out / "old").exists())
            self.assertEqual("new", (out / "new").read_text())

    def test_run_neither_invokes_sink_capacity_nor_changes_cards(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        card_root = repo_root / "src/sink_capacity/sink-capability-cards"
        before = {
            path.relative_to(card_root): path.read_bytes()
            for path in sorted(card_root.glob("*.md"))
        }
        with (
            tempfile.TemporaryDirectory() as raw,
            patch(
                "src.sink_capacity.main.main",
                side_effect=AssertionError(
                    "coverage comparison must not generate cards"
                ),
            ),
            patch(
                "subprocess.run",
                side_effect=AssertionError(
                    "coverage comparison must not launch a generator"
                ),
            ),
        ):
            self.run_fixture(Path(raw), decision="covered")
        after = {
            path.relative_to(card_root): path.read_bytes()
            for path in sorted(card_root.glob("*.md"))
        }
        self.assertEqual(before, after)


class SourceValidationTests(unittest.TestCase):
    def run_fixture(self, root: Path, verdict: str):
        source_root = root / "source"
        source_root.mkdir()
        (source_root / "source.py").write_text(
            "def request(url): return send(url)\n", encoding="utf-8"
        )
        primary = FakeRunner("wrong-check")
        source_runners: list[FakeSourceRunner] = []

        def factory(_spec: ProjectSpec, _config: SourceValidationConfig):
            runner = FakeSourceRunner(verdict)
            source_runners.append(runner)
            return runner

        out = root / "coverage-comparison"
        with patch(
            "src.coverage_comparison.pipeline.load_coverage_inputs",
            return_value=inputs(coverage_chain()),
        ):
            result = run_coverage_comparison(
                capability_card_analysis=False,
                specs=[project_spec(source_root)],
                handler_root=root,
                sink_root=root,
                group_root=root,
                evidence_registry=root / "registry.json",
                out_dir=out,
                generation_command="python -m src.coverage_comparison --all",
                runner=primary,
                source_validation_config=SourceValidationConfig(
                    model="fixture-model",
                    agent_transport="cli",
                    enable_lsp=False,
                    jobs=2,
                    strategy="agent-only",
                ),
                source_validation_runner_factory=factory,
            )
        return result, source_runners, out

    def test_confirmed_candidate_survives_and_is_ranked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result, runners, out = self.run_fixture(Path(raw), "confirmed-uncovered")
            self.assertEqual(1, len(runners))
            self.assertEqual(1, result["manifest"]["counts"]["provisional_candidates"])
            self.assertEqual(1, result["manifest"]["counts"]["candidates"])
            self.assertEqual(1, result["manifest"]["counts"]["source_validation_high"])
            validation = json.loads(
                (out / "candidate-validations.jsonl").read_text(encoding="utf-8")
            )
            self.assertEqual("confirmed", validation["disposition"])
            self.assertEqual("high", validation["review_priority"])
            self.assertEqual(64, len(validation["source_evidence"][0]["sha256"]))
            self.assertIn(
                "Generation command", (out / "candidate-ranking.md").read_text()
            )

    def test_refuted_candidate_is_removed_and_assessment_changes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result, _, out = self.run_fixture(Path(raw), "not-applicable")
            self.assertEqual(0, result["manifest"]["counts"]["candidates"])
            self.assertEqual(
                1, result["manifest"]["counts"]["source_validation_refuted"]
            )
            self.assertEqual("", (out / "candidates.jsonl").read_text())
            assessment = json.loads((out / "requirement-assessments.jsonl").read_text())
            self.assertEqual("not-applicable", assessment["decision"])
            self.assertTrue((out / "provisional-candidates.jsonl").read_text())

    def test_uncatalogued_check_becomes_unknown_and_nonzero_signal(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result, _, out = self.run_fixture(Path(raw), "upstream-inconsistent")
            self.assertTrue(result["source_validation_incomplete"])
            self.assertEqual(
                1, result["manifest"]["counts"]["source_validation_unknown"]
            )
            assessment = json.loads((out / "requirement-assessments.jsonl").read_text())
            self.assertEqual("unknown", assessment["decision"])
            comparison = json.loads((out / "comparisons.jsonl").read_text())
            self.assertEqual("partial", comparison["status"])

    def test_covered_requires_existing_gate_identity(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result, _, out = self.run_fixture(Path(raw), "covered")
            self.assertEqual(0, result["manifest"]["counts"]["candidates"])
            assessment = json.loads((out / "requirement-assessments.jsonl").read_text())
            self.assertEqual("covered", assessment["decision"])
            self.assertEqual([GATE], assessment["gate_ids"])

    def test_precision_sample_is_deterministic_and_bounded(self) -> None:
        candidates = [
            {
                "candidate_id": f"CAND-{number:016x}",
                "project": "a" if number % 2 else "b",
                "chain_id": "C-" + f"{number:012x}",
                "requirement_id": RID,
                "failure_mode": "wrong-check" if number % 3 else "missing-check",
            }
            for number in range(120)
        ]
        left = deterministic_precision_sample(candidates)
        right = deterministic_precision_sample(list(reversed(candidates)))
        self.assertEqual(left, right)
        self.assertEqual(100, len(left))
        self.assertEqual(list(range(1, 101)), [row["sample_ordinal"] for row in left])

    def test_invalid_source_evidence_becomes_audited_operational_failure(self) -> None:
        class InvalidPathRunner(FakeSourceRunner):
            def __call__(self, system: str, user: str) -> str:
                payload = json.loads(super().__call__(system, user))
                payload["validations"][0]["source_evidence"][0]["file"] = (
                    "../outside.py"
                )
                return json.dumps(payload)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source_root = root / "source"
            source_root.mkdir()
            (source_root / "source.py").write_text("pass\n")
            out = root / "coverage-comparison"
            with patch(
                "src.coverage_comparison.pipeline.load_coverage_inputs",
                return_value=inputs(coverage_chain()),
            ):
                result = run_coverage_comparison(
                    capability_card_analysis=False,
                    specs=[project_spec(source_root)],
                    handler_root=root,
                    sink_root=root,
                    group_root=root,
                    evidence_registry=root / "registry",
                    out_dir=out,
                    generation_command="command",
                    runner=FakeRunner("wrong-check"),
                    source_validation_config=SourceValidationConfig(
                        model="fixture",
                        agent_transport="cli",
                        enable_lsp=False,
                        strategy="agent-only",
                    ),
                    source_validation_runner_factory=lambda _spec, _config: (
                        InvalidPathRunner()
                    ),
                )
            self.assertTrue(result["source_validation_incomplete"])
            self.assertEqual(
                1,
                result["manifest"]["counts"]["source_validation_operational_failures"],
            )
            validation = json.loads((out / "candidate-validations.jsonl").read_text())
            self.assertTrue(validation["operational_error"])

    def test_unbound_covered_verdict_downgrades_to_unknown(self) -> None:
        class UnboundCoveredRunner(FakeSourceRunner):
            def __call__(self, system: str, user: str) -> str:
                payload = json.loads(super().__call__(system, user))
                payload["validations"][0]["covering_gate_ids"] = []
                return json.dumps(payload)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source_root = root / "source"
            source_root.mkdir()
            (source_root / "source.py").write_text(
                "def request(url): return send(url)\n", encoding="utf-8"
            )
            out = root / "coverage-comparison"
            with patch(
                "src.coverage_comparison.pipeline.load_coverage_inputs",
                return_value=inputs(coverage_chain()),
            ):
                result = run_coverage_comparison(
                    capability_card_analysis=False,
                    specs=[project_spec(source_root)],
                    handler_root=root,
                    sink_root=root,
                    group_root=root,
                    evidence_registry=root / "registry",
                    out_dir=out,
                    generation_command="command",
                    runner=FakeRunner("wrong-check"),
                    source_validation_config=SourceValidationConfig(
                        model="fixture",
                        agent_transport="cli",
                        enable_lsp=False,
                        strategy="agent-only",
                    ),
                    source_validation_runner_factory=lambda _spec, _config: (
                        UnboundCoveredRunner("covered")
                    ),
                )
            self.assertEqual(
                0,
                result["manifest"]["counts"][
                    "source_validation_operational_failures"
                ],
            )
            validation = json.loads(
                (out / "candidate-validations.jsonl").read_text()
            )
            self.assertEqual("upstream-inconsistent", validation["verdict"])
            self.assertEqual("unknown", validation["final_assessment"]["decision"])

    def test_invalid_multi_candidate_batch_retries_individually(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source_root = root / "source"
            source_root.mkdir()
            (source_root / "source.py").write_text(
                "def request(url): return send(url)\n", encoding="utf-8"
            )
            chain = coverage_chain()
            second_requirement = {
                **requirement(),
                "requirement_id": "R-" + "f" * 16,
                "rule": "Reject redirect targets outside the allowed network scope.",
            }
            chain = replace(
                chain,
                oracle={
                    **chain.oracle,
                    "requirements": [requirement(), second_requirement],
                },
            )
            raw_assessments = [
                {
                    "requirement_id": item["requirement_id"],
                    "applicability": "applicable",
                    "decision": "missing-check",
                    "capability_evidence": [
                        {"start_line": 2, "end_line": 3, "quote": "evidence"}
                    ],
                    "call_shape_facts": ["the model controls url"],
                    "gate_ids": [],
                    "covered_semantics": None,
                    "gap": "No destination check is present.",
                    "uncertainty": None,
                }
                for item in chain.oracle["requirements"]
            ]
            assessments = [
                _assessment_record(chain, item) for item in raw_assessments
            ]
            candidates = [
                _candidate_record(chain, assessment, item)
                for assessment, item in zip(
                    assessments, chain.oracle["requirements"], strict=True
                )
            ]

            class BatchInvalidRunner(FakeSourceRunner):
                def __init__(self) -> None:
                    super().__init__("not-applicable")
                    self.single_calls = 0

                def __call__(self, system: str, user: str) -> str:
                    if system != SOURCE_VALIDATION_SYSTEM:
                        return "{}"
                    payload = json.loads(user.split("\n", 1)[1])
                    if len(payload["allowed_candidate_ids"]) > 1:
                        return "{}"
                    self.single_calls += 1
                    return super().__call__(system, user)

            runner = BatchInvalidRunner()
            result = run_source_validation(
                chains={chain.key: chain},
                provisional_candidates=candidates,
                assessments=assessments,
                specs=[project_spec(source_root)],
                prior_root=root / "out",
                config=SourceValidationConfig(
                    model="fixture",
                    agent_transport="cli",
                    enable_lsp=False,
                    strategy="agent-only",
                ),
                runner_factory=lambda _spec, _config: runner,
            )
            self.assertEqual(2, runner.single_calls)
            self.assertEqual(0, result.operational_failures)
            self.assertEqual(2, result.refuted_count)

    def test_content_bound_source_validation_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.run_fixture(root, "confirmed-uncovered")
            source_root = root / "source"
            out = root / "coverage-comparison"
            with patch(
                "src.coverage_comparison.pipeline.load_coverage_inputs",
                return_value=inputs(coverage_chain()),
            ):
                result = run_coverage_comparison(
                    capability_card_analysis=False,
                    specs=[project_spec(source_root)],
                    handler_root=root,
                    sink_root=root,
                    group_root=root,
                    evidence_registry=root / "registry",
                    out_dir=out,
                    generation_command="python -m src.coverage_comparison --all",
                    runner=FakeRunner("wrong-check"),
                    source_validation_config=SourceValidationConfig(
                        model="fixture-model",
                        agent_transport="cli",
                        enable_lsp=False,
                        jobs=2,
                        strategy="agent-only",
                    ),
                    source_validation_runner_factory=lambda _spec, _config: (
                        _ for _ in ()
                    ).throw(AssertionError("must reuse")),
                )
            self.assertEqual(
                1, result["manifest"]["source_validation"]["reused_sessions"]
            )

    def test_interrupted_run_reuses_per_chain_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source_root = root / "source"
            source_root.mkdir()
            (source_root / "source.py").write_text("pass\n")
            legacy_out = root / "legacy"
            chain = coverage_chain()
            with patch(
                "src.coverage_comparison.pipeline.load_coverage_inputs",
                return_value=inputs(chain),
            ):
                run_coverage_comparison(
                    capability_card_analysis=False,
                    specs=[],
                    handler_root=root,
                    sink_root=root,
                    group_root=root,
                    evidence_registry=root / "registry",
                    out_dir=legacy_out,
                    generation_command="legacy",
                    runner=FakeRunner("wrong-check"),
                )
            candidate = json.loads((legacy_out / "candidates.jsonl").read_text())
            assessment = json.loads(
                (legacy_out / "requirement-assessments.jsonl").read_text()
            )
            future_out = root / "future-output"
            config = SourceValidationConfig(
                model="fixture-model",
                agent_transport="cli",
                enable_lsp=False,
                strategy="agent-only",
            )
            first = run_source_validation(
                chains={chain.key: chain},
                provisional_candidates=[candidate],
                assessments=[assessment],
                specs=[project_spec(source_root)],
                prior_root=future_out,
                config=config,
                runner_factory=lambda _spec, _config: FakeSourceRunner(),
            )
            self.assertEqual(1, first.generated_chains)
            self.assertTrue(source_validation_checkpoint_root(future_out).is_dir())
            second = run_source_validation(
                chains={chain.key: chain},
                provisional_candidates=[candidate],
                assessments=[assessment],
                specs=[project_spec(source_root)],
                prior_root=future_out,
                config=config,
                runner_factory=lambda _spec, _config: (_ for _ in ()).throw(
                    AssertionError("must reuse checkpoint")
                ),
            )
            self.assertEqual(1, second.reused_chains)

    def test_source_validation_runs_independent_chains_in_parallel(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source_root = root / "source"
            source_root.mkdir()
            (source_root / "source.py").write_text("pass\n")
            first = coverage_chain()
            second_semantic = json.loads(json.dumps(first.semantic_ir))
            second_semantic["chain_id"] = "C-" + "2" * 12
            second = replace(
                first,
                chain_id="C-" + "2" * 12,
                semantic_ir=second_semantic,
            )
            selected_inputs = CoverageInputs(
                chains=(first, second),
                exclusions=(),
                digests={"fixture": "8" * 64},
                structural_chain_count=2,
            )

            class DynamicPrimary:
                def __call__(self, _system: str, user: str) -> str:
                    payload = json.loads(user.split("\n", 1)[1])
                    response = json.loads(
                        FakeRunner("wrong-check")(COMPARE_SYSTEM, "unused")
                    )
                    response["chain_id"] = payload["chain_id"]
                    return json.dumps(response)

                def audit_payload(self) -> dict:
                    return {"transport": "fake", "available_tools": [], "calls": []}

            barrier = threading.Barrier(2)

            class ParallelRunner(FakeSourceRunner):
                def __call__(self, system: str, user: str) -> str:
                    barrier.wait(timeout=2)
                    return super().__call__(system, user)

            with patch(
                "src.coverage_comparison.pipeline.load_coverage_inputs",
                return_value=selected_inputs,
            ):
                result = run_coverage_comparison(
                    capability_card_analysis=False,
                    specs=[project_spec(source_root)],
                    handler_root=root,
                    sink_root=root,
                    group_root=root,
                    evidence_registry=root / "registry",
                    out_dir=root / "coverage-comparison",
                    generation_command="command",
                    runner=DynamicPrimary(),
                    source_validation_config=SourceValidationConfig(
                        model="fixture",
                        agent_transport="cli",
                        enable_lsp=False,
                        jobs=2,
                        strategy="agent-only",
                    ),
                    source_validation_runner_factory=lambda _spec, _config: (
                        ParallelRunner()
                    ),
                )
            self.assertEqual(
                2, result["manifest"]["source_validation"]["jobs_effective"]
            )
            self.assertEqual(2, result["manifest"]["counts"]["candidates"])


class ReplayTests(unittest.TestCase):
    def test_plain_prompt_replay_ignores_tool_agent_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "coverage-comparison"
            sidecar = (
                root
                / "repository"
                / "source-validate"
                / "fixture-C-111111111111"
                / "chat.json"
            )
            sidecar.parent.mkdir(parents=True)
            sidecar.write_text(json.dumps({"transport": "agent", "turns": []}))
            runner = ExactPromptReplayRunner(lambda _s, _u: "live", root)
            self.assertEqual("live", runner("system", "user"))

    def test_plain_prompt_replay_ignores_source_discovery_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "coverage-comparison"
            sidecar = (
                root
                / "repository"
                / "source-discover"
                / "fixture"
                / "chat.json"
            )
            sidecar.parent.mkdir(parents=True)
            sidecar.write_text(json.dumps({"transport": "agent", "turns": []}))
            runner = ExactPromptReplayRunner(lambda _s, _u: "live", root)
            self.assertEqual("live", runner("system", "user"))

    def test_exact_replay_and_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "coverage-comparison"
            calls: list[tuple[str, str]] = []
            first = ExactPromptReplayRunner(
                lambda system, user: calls.append((system, user)) or "response", root
            )
            self.assertEqual("response", first("system", "user"))
            root.mkdir()
            (root / "manifest.json").write_text(
                json.dumps(
                    {
                        "transport": {
                            "transport": "openai-compatible/v1",
                            "prompt_replay": {
                                "enabled": True,
                                "exact_prompt_hits": 7,
                                "exact_prompt_misses": 3,
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            resumed = ExactPromptReplayRunner(
                lambda _s, _u: (_ for _ in ()).throw(AssertionError("must replay")),
                root,
            )
            self.assertEqual("response", resumed("system", "user"))
            self.assertEqual(
                {
                    "enabled": True,
                    "replay_only": False,
                    "exact_prompt_hits": 1,
                    "exact_prompt_misses": 0,
                },
                resumed.audit_payload()["prompt_replay"],
            )
            current = resumed.current_audit_payload()
            self.assertEqual("coverage-exact-prompt-replay/v7", current["transport"])
            self.assertEqual(1, len(current["calls"]))
            self.assertEqual(0, current["token_usage"]["total_tokens"])
            self.assertEqual([("system", "user")], calls)
            resumed.clear_checkpoint()
            self.assertFalse(
                (root.parent / ".coverage-comparison.prompt-checkpoint.jsonl").exists()
            )

    def test_unrepaired_prompts_are_evicted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "coverage-comparison"
            runner = ExactPromptReplayRunner(lambda _s, _u: "{}", root)
            with self.assertRaisesRegex(CoverageComparisonError, "unrepaired"):
                _validated_call(
                    runner=runner,
                    system="contract",
                    user="request",
                    validator=lambda _response: (_ for _ in ()).throw(
                        CoverageComparisonError("invalid")
                    ),
                    context="fixture",
                )
            checkpoint = root.parent / ".coverage-comparison.prompt-checkpoint.jsonl"
            self.assertEqual("", checkpoint.read_text())


if __name__ == "__main__":
    unittest.main()

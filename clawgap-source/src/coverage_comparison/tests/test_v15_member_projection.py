from __future__ import annotations

import copy
import unittest

from src.coverage_comparison.applicability_contract import (
    APPLICABILITY_CONTRACT_VERSION,
)
from src.coverage_comparison.contracts import CoverageComparisonError, canonical_json
from src.coverage_comparison.normative_evidence import resolve_normative_evidence
from src.coverage_comparison.v15_member_projection import (
    build_call_shape_exclusions,
    build_member_projection,
    build_source_validation_field_flows,
)


def contract() -> dict[str, object]:
    return {
        "schema_version": APPLICABILITY_CONTRACT_VERSION,
        "required_sink_roles": ["destination-url"],
        "allowed_value_authorities": ["model-arbitrary"],
        "required_capability_facets": ["ssrf-protection"],
        "required_boundary": "host-to-network",
        "required_effect": "network-request",
        "call_shape_predicates": ["http-client-active"],
    }


def resolution() -> dict[str, object]:
    return resolve_normative_evidence(
        group_id="HSG-test",
        requirement_id="CR-test",
        evidence_ids=["EV-policy"],
        evidence_rows=[
            {
                "evidence_id": "EV-policy",
                "kind": "explicit-source-policy",
                "source_path": "policy.md",
                "sha256": "a" * 64,
                "exact_quote": "Remote destinations must be checked.",
                "supported_claim": "The network boundary is mandatory.",
            }
        ],
        applicability_contract=contract(),
    )


def comparison(project: str, chain_id: str) -> dict[str, object]:
    return {
        "group_id": "HSG-test",
        "project": project,
        "revision": "revision",
        "chain_id": chain_id,
        "capability_card": {"path": "card.md"},
        "semantic_ir_status": "complete",
        "values": [{"source_parameter": "args.url"}],
        "requirements": [{"requirement_id": "CR-test"}],
    }


def assessment(project: str, chain_id: str) -> dict[str, object]:
    return {
        "project": project,
        "revision": "revision",
        "chain_id": chain_id,
        "requirement_id": "CR-test",
        "applicability": "applicable",
    }


def effective_view(project: str, chain_id: str) -> dict[str, object]:
    return {
        "project": project,
        "chain_id": chain_id,
        "active_facets": [{"facet_id": "ssrf-protection"}],
    }


def flow(project: str, chain_id: str) -> dict[str, object]:
    return {
        "witness_id": "FFW-" + project,
        "project": project,
        "chain_id": chain_id,
        "requirement_id": "CR-test",
        "sink_role": "destination-url",
        "tool_schema_field": "url",
        "value_authority": "model-arbitrary",
        "proof_kind": "source-validation-cited-field-flow",
    }


class V15MemberProjectionTests(unittest.TestCase):
    def test_cross_member_applicability_is_independent_and_exhaustive(self) -> None:
        comparisons = [comparison("alpha", "C-alpha"), comparison("beta", "C-beta")]
        assessments = [assessment("alpha", "C-alpha"), assessment("beta", "C-beta")]
        result = build_member_projection(
            comparisons=comparisons,
            assessments=assessments,
            admitted_requirement_ids={"CR-test"},
            requirements={
                "CR-test": {
                    "rule": "Validate a model-controlled URL.",
                    "applicability": "When args.url is selected.",
                    "controlled_facet": "destination-url",
                }
            },
            resolutions=[resolution()],
            contracts={"CR-test": contract()},
            effective_views=[
                effective_view("alpha", "C-alpha"),
                effective_view("beta", "C-beta"),
            ],
            card_payloads={"card.md": {"capability_class": "network-egress"}},
            field_flow_witnesses=[flow("alpha", "C-alpha")],
            field_flow_exclusions=[
                {
                    "project": "beta",
                    "chain_id": "C-beta",
                    "requirement_id": "CR-test",
                    "sink_role": "destination-url",
                    "authoritative": True,
                }
            ],
        )
        decisions = {
            row["project"]: row["decision"] for row in result.applicability.assessments
        }
        self.assertEqual({"alpha": "applicable", "beta": "not-applicable"}, decisions)
        self.assertEqual(2, len(result.member_facts))
        self.assertNotIn("report", canonical_json(result.member_facts).lower())

    def test_generic_flow_cannot_bypass_field_role_compatibility(self) -> None:
        bad_flow = {
            **flow("alpha", "C-alpha"),
            "tool_schema_field": "path",
        }
        result = build_member_projection(
            comparisons=[comparison("alpha", "C-alpha")],
            assessments=[assessment("alpha", "C-alpha")],
            admitted_requirement_ids={"CR-test"},
            requirements={
                "CR-test": {
                    "rule": "Validate a model-controlled URL.",
                    "applicability": "When args.url is selected.",
                    "controlled_facet": "destination-url",
                }
            },
            resolutions=[resolution()],
            contracts={"CR-test": contract()},
            effective_views=[effective_view("alpha", "C-alpha")],
            card_payloads={"card.md": {"capability_class": "network-egress"}},
            field_flow_witnesses=[bad_flow],
            field_flow_exclusions=[],
        )
        self.assertEqual("unknown", result.applicability.assessments[0]["decision"])
        self.assertEqual([], result.member_facts[0]["field_witnesses"])

    def test_source_validation_produces_only_exact_complete_field_witness(self) -> None:
        candidates = [
            {
                "candidate_id": "CAND-test",
                "project": "alpha",
                "revision": "revision",
                "chain_id": "C-alpha",
                "requirement_id": "CR-test",
                "sink_id": "S-test",
            }
        ]
        requirement = {
            "requirement_id": "CR-test",
            "rule": "Validate a model-controlled URL.",
            "applicability": "When args.url is selected.",
            "controlled_facet": "destination-url",
        }
        evidence = [
            {
                "role": role,
                "file": f"{role}.py",
                "line_start": 1,
                "line_end": 1,
                "sha256": "b" * 64,
                "claim": "args.url flows to the request URL",
                "excerpt": "value = args.url",
            }
            for role in ("handler", "controlled-value", "sink")
        ]
        validation = {
            "validation_id": "SVAL-test",
            "verdict": "confirmed-uncovered",
            "controlled_flow": "confirmed",
            "sink_reachability": "confirmed",
            "source_research_complete": True,
            "uncertainties": [],
            "operational_error": None,
            "source_evidence": evidence,
        }
        inputs = {
            "candidates": candidates,
            "requirements": {"CR-test": requirement},
            "contracts": {"CR-test": contract()},
            "validations": {"CAND-test": validation},
            "comparisons": {("alpha", "C-alpha"): comparison("alpha", "C-alpha")},
        }
        before = copy.deepcopy(inputs)
        rows = build_source_validation_field_flows(**inputs)
        self.assertEqual(before, inputs)
        self.assertEqual("url", rows[0]["tool_schema_field"])
        self.assertEqual("destination-url", rows[0]["sink_role"])
        invalid = copy.deepcopy(inputs)
        invalid["validations"]["CAND-test"]["source_evidence"][1]["sha256"] = "bad"
        self.assertEqual((), build_source_validation_field_flows(**invalid))
        ambiguous = copy.deepcopy(inputs)
        for row in ambiguous["validations"]["CAND-test"]["source_evidence"]:
            row["claim"] = "A value reaches the sink."
            row["excerpt"] = "send(value)"
        ambiguous["comparisons"][("alpha", "C-alpha")]["values"] = [
            {"source_parameter": "args.url;args.body"}
        ]
        self.assertEqual((), build_source_validation_field_flows(**ambiguous))
        conflicting = copy.deepcopy(inputs)
        controlled = conflicting["validations"]["CAND-test"]["source_evidence"][1]
        controlled["claim"] = "args.url and args.body both reach the request"
        controlled["excerpt"] = "send(args.url, args.body)"
        selected = build_source_validation_field_flows(**conflicting)
        self.assertEqual(["url"], [row["tool_schema_field"] for row in selected])

    def test_source_validation_requires_original_field_not_helper_alias(self) -> None:
        candidate = {
            "candidate_id": "CAND-url-alias",
            "project": "alpha",
            "revision": "revision",
            "chain_id": "C-alpha",
            "requirement_id": "CR-test",
            "sink_id": "S-test",
            "source_context": {"controlled_facet": "args.targetUrl reaches openTab"},
        }
        requirement = {
            "requirement_id": "CR-test",
            "rule": "Validate the destination URL.",
            "applicability": "When browser navigation is active.",
            "controlled_facet": "args.targetUrl reaches openTab(url)",
        }
        alias_only_evidence = [
            {
                "role": role,
                "file": f"{role}.ts",
                "line_start": 1,
                "line_end": 1,
                "sha256": "b" * 64,
                "claim": "The handler forwards the URL to browser navigation.",
                "excerpt": "const openTab = async (url: string): Promise<Tab> => send(url)",
            }
            for role in ("handler", "controlled-value", "sink")
        ]
        common = {
            "candidates": [candidate],
            "requirements": {"CR-test": requirement},
            "contracts": {"CR-test": contract()},
            "comparisons": {
                ("alpha", "C-alpha"): {
                    **comparison("alpha", "C-alpha"),
                    "values": [{"source_parameter": "args"}],
                }
            },
        }
        rows = build_source_validation_field_flows(
            **common,
            validations={
                "CAND-url-alias": {
                    "validation_id": "SVAL-url-alias",
                    "verdict": "confirmed-uncovered",
                    "controlled_flow": "confirmed",
                    "sink_reachability": "confirmed",
                    "source_research_complete": True,
                    "uncertainties": [],
                    "operational_error": None,
                    "source_evidence": alias_only_evidence,
                }
            },
        )
        self.assertEqual((), rows)
        exact_evidence = copy.deepcopy(alias_only_evidence)
        for row in exact_evidence:
            row["excerpt"] = "const targetUrl = args.targetUrl; openTab(targetUrl)"
        exact_rows = build_source_validation_field_flows(
            **common,
            validations={
                "CAND-url-alias": {
                    "validation_id": "SVAL-url-alias",
                    "verdict": "confirmed-uncovered",
                    "controlled_flow": "confirmed",
                    "sink_reachability": "confirmed",
                    "source_research_complete": True,
                    "uncertainties": [],
                    "operational_error": None,
                    "source_evidence": exact_evidence,
                }
            },
        )
        self.assertEqual(
            ["targetUrl"], [row["tool_schema_field"] for row in exact_rows]
        )

    def test_source_validation_rejects_selector_as_command_field(self) -> None:
        inputs = self._command_validation_inputs(
            field="session_id",
            requirement={
                "requirement_id": "CR-command",
                "rule": "Dangerous commands require approval.",
                "applicability": "When command execution is active.",
                "controlled_facet": "session availability controls approval",
            },
        )
        self.assertEqual((), build_source_validation_field_flows(**inputs))

    def test_source_validation_allows_path_component_in_shell_command(self) -> None:
        inputs = self._command_validation_inputs(
            field="path",
            requirement={
                "requirement_id": "CR-command",
                "rule": "Canonicalize a file path before shell command execution.",
                "applicability": "The path is embedded in a shell-backed file read.",
                "controlled_facet": "model-controlled path reaches a shell command",
            },
        )
        rows = build_source_validation_field_flows(**inputs)
        self.assertEqual(["path"], [row["tool_schema_field"] for row in rows])
        self.assertEqual("model-component", rows[0]["value_authority"])

    def test_source_validation_reads_local_assignment_and_destructuring(self) -> None:
        cwd_inputs = self._command_validation_inputs(
            field="cwd",
            requirement={
                "requirement_id": "CR-command",
                "rule": "Validate the working directory.",
                "applicability": "When process execution is active.",
                "controlled_facet": "model-controlled cwd",
            },
        )
        cwd_inputs["contracts"]["CR-command"]["required_sink_roles"] = [
            "working-directory"
        ]
        for row in cwd_inputs["validations"]["CAND-command"]["source_evidence"]:
            row["excerpt"] = "working_dir = cwd"
        cwd_rows = build_source_validation_field_flows(**cwd_inputs)
        self.assertEqual(["cwd"], [row["tool_schema_field"] for row in cwd_rows])

        command_inputs = self._command_validation_inputs(
            field="command",
            requirement={
                "requirement_id": "CR-command",
                "rule": "Classify the effective shell command.",
                "applicability": "When process execution is active.",
                "controlled_facet": "model-controlled command",
            },
        )
        for row in command_inputs["validations"]["CAND-command"]["source_evidence"]:
            row["excerpt"] = "execute: async ({ command, timeout }) => run(command)"
        command_rows = build_source_validation_field_flows(**command_inputs)
        self.assertEqual(
            ["command"], [row["tool_schema_field"] for row in command_rows]
        )

    def test_source_validation_does_not_invent_environment_from_env_file(self) -> None:
        inputs = self._command_validation_inputs(
            field="path",
            requirement={
                "requirement_id": "CR-command",
                "rule": "Redact secrets read from a .env file.",
                "applicability": "The model selects a file path.",
                "controlled_facet": "model-controlled path",
            },
        )
        inputs["contracts"]["CR-command"]["required_sink_roles"] = ["environment"]
        inputs["comparisons"][("alpha", "C-alpha")]["values"] = [
            {"source_parameter": "path"}
        ]
        for row in inputs["validations"]["CAND-command"]["source_evidence"]:
            row["claim"] = "The selected .env file path reaches the sink."
            row["excerpt"] = "value = args.get('path')"
        self.assertEqual((), build_source_validation_field_flows(**inputs))

    def _command_validation_inputs(
        self, *, field: str, requirement: dict[str, object]
    ) -> dict[str, object]:
        evidence = [
            {
                "role": role,
                "file": f"{role}.py",
                "line_start": 1,
                "line_end": 1,
                "sha256": "b" * 64,
                "claim": f"The handler reads the selected {field} value.",
                "excerpt": f"value = args.get('{field}')",
            }
            for role in ("handler", "controlled-value", "sink")
        ]
        command_contract = {
            **contract(),
            "required_sink_roles": ["command"],
            "required_capability_facets": ["process-execution"],
            "required_boundary": "model-to-host-process",
            "required_effect": "process-execution",
            "call_shape_predicates": ["process-execution-active"],
        }
        return {
            "candidates": [
                {
                    "candidate_id": "CAND-command",
                    "project": "alpha",
                    "revision": "revision",
                    "chain_id": "C-alpha",
                    "requirement_id": "CR-command",
                    "sink_id": "S-command",
                }
            ],
            "requirements": {"CR-command": requirement},
            "contracts": {"CR-command": command_contract},
            "validations": {
                "CAND-command": {
                    "validation_id": "SVAL-command",
                    "verdict": "confirmed-uncovered",
                    "controlled_flow": "confirmed",
                    "sink_reachability": "confirmed",
                    "source_research_complete": True,
                    "uncertainties": [],
                    "operational_error": None,
                    "source_evidence": evidence,
                }
            },
            "comparisons": {
                ("alpha", "C-alpha"): {
                    **comparison("alpha", "C-alpha"),
                    "values": [{"source_parameter": "command;cwd;timeout"}],
                }
            },
        }

    def test_duplicate_member_inputs_and_ambiguous_source_fields_fail_closed(
        self,
    ) -> None:
        cmp = comparison("alpha", "C-alpha")
        with self.assertRaisesRegex(CoverageComparisonError, "duplicate comparison"):
            build_member_projection(
                comparisons=[cmp, cmp],
                assessments=[assessment("alpha", "C-alpha")],
                admitted_requirement_ids={"CR-test"},
                requirements={"CR-test": {"controlled_facet": "destination-url"}},
                resolutions=[resolution()],
                contracts={"CR-test": contract()},
                effective_views=[effective_view("alpha", "C-alpha")],
                card_payloads={"card.md": {"capability_class": "network-egress"}},
                field_flow_witnesses=[],
                field_flow_exclusions=[],
            )
        with self.assertRaisesRegex(
            CoverageComparisonError, "duplicate field-flow witness"
        ):
            build_member_projection(
                comparisons=[cmp],
                assessments=[assessment("alpha", "C-alpha")],
                admitted_requirement_ids={"CR-test"},
                requirements={"CR-test": {"controlled_facet": "destination-url"}},
                resolutions=[resolution()],
                contracts={"CR-test": contract()},
                effective_views=[effective_view("alpha", "C-alpha")],
                card_payloads={"card.md": {"capability_class": "network-egress"}},
                field_flow_witnesses=[flow("alpha", "C-alpha")] * 2,
                field_flow_exclusions=[],
            )

    def test_call_shape_exclusion_requires_an_exact_sink_role_and_fact(self) -> None:
        base = {
            "project": "alpha",
            "revision": "revision",
            "chain_id": "C-alpha",
            "requirement_id": "CR-test",
            "applicability": "not-applicable",
            "call_shape_facts": ["The URL role is absent."],
        }
        self.assertEqual((), build_call_shape_exclusions(assessments=[base]))
        rows = build_call_shape_exclusions(
            assessments=[{**base, "sink_role": "destination-url"}]
        )
        self.assertEqual("destination-url", rows[0]["sink_role"])


if __name__ == "__main__":
    unittest.main()

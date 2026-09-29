"""Offline URL-policy retention tests using bounded, recorded-style model responses.

These exercise real pipeline schemas, evidence authority, publication and cache behavior.
They do not prove that a live LLM identifies model origin or interprets URL policies;
the fake supplies explicit expected decisions, including the origin-screened exclusions.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from src.group_oracle import pipeline
from src.group_oracle.contracts import EVIDENCE_SCHEMA_VERSION, GroupOracleError, stable_evidence_id
from src.group_oracle.inputs import OracleChain, OracleInputs, _manual_evidence
from src.group_oracle.prompts import (
    EVIDENCE_EXTENSION_SYSTEM, PEER_SYSTEM, POLICY_CONSOLIDATION_SYSTEM, SEED_SYSTEM,
)


ROOT = Path(__file__).resolve().parents[3]
G06 = "HSG-2a9409f6633c1b6a"
G25 = "HSG-3209832c56152666"
SECRET = "GUfa8fbd80e924f0481119"
ADDRESS = "GU1ed6874487204858ee3a"
BLOCKLIST = "GU1228344ddaf94b9b1c88"
IMAGE_ADMISSION = "GUd41b18fdd81044c24697"
WECHAT_SCHEME = "GUb6fd39b96570f9649480"
CONFIG_ONLY = "GU" + "7" * 20
UNKNOWN_ORIGIN = "GU" + "8" * 20

EXPECTED_POLICIES = {
    SECRET: {
        "dimension": "url-secret-pattern-block",
        "rule": "Reject the entire invocation before backend dispatch if any raw URL or its once-percent-decoded form matches a recognized protected token pattern. Preserve pattern boundaries; this is not detection of every secret.",
        "applicability": "External content retrieval of model-origin urls elements under a recognized-token protection policy.",
        "origin_marker": "urls list parameter",
    },
    ADDRESS: {
        "dimension": "url-address-prefilter",
        "rule": "Reject missing or always-blocked metadata hosts and every resolved address in the always-blocked IP/network sets regardless of private-address opt-outs. Ordinary private/internal addresses may pass only with an explicit private-address opt-out or trusted-HTTPS-host exception. Reject DNS and unhandled validation errors. Filter each URL and dispatch only safe_urls, with no dispatch if empty; do not promise service-side DNS or redirect enforcement.",
        "applicability": "Model-origin urls elements submitted through a local destination prefilter before external content retrieval.",
        "origin_marker": "urls list",
    },
    BLOCKLIST: {
        "dimension": "configured-website-blocklist",
        "rule": "Reject the HTTP request before dispatch when the normalized model URL hostname matches the active exact-host, dot-suffix or wildcard block rule, even for a public IP and allowed scheme. Preserve disabled, cached and default-path load-error allow behavior as limitations, not a mandatory fail-closed policy.",
        "applicability": "Only members with an enabled and successfully loaded website-blocklist policy, while downloading an args-derived image_url; other members need not introduce a blocklist.",
        "origin_marker": "args-derived URL",
    },
    IMAGE_ADMISSION: {
        "dimension": "remote-image-url-admission",
        "rule": "Require HTTP or HTTPS for the remote image download branch. Where the recorded address policy applies, reject missing or always-blocked metadata hosts and every resolved address in always-blocked IP/network sets regardless of private opt-outs; ordinary private/internal addresses require an explicit opt-out or trusted-HTTPS exception. Reject DNS and unhandled URL-validation errors independently of blocklist configuration load failures. Do not prohibit a separately supported local-image branch.",
        "applicability": "A model-origin image URL admitted to remote HTTP download; address restrictions apply to members providing the recorded destination policy, independently of whether website blocklisting is enabled or loads successfully.",
        "origin_marker": "derived from args",
    },
}


def url_inputs(*, normative=True):
    samples = json.loads((Path(__file__).parent / "fixtures/url-gate-groups.json").read_text())
    hcs = {sample["group"]["handler_criterion_id"]: sample["handler_criterion"] for sample in samples}
    sts = {sample["group"]["sink_type_id"]: sample["sink_type"] for sample in samples}
    docs = _manual_evidence(
        repo_root=ROOT,
        registry_path=ROOT / "src/group_oracle/oracle-evidence-registry-url-gates.json",
        valid_hcs=set(hcs), valid_sts=set(sts),
    ) if normative else []
    chains = {}
    evidence = list(docs)
    evidence_by_group = {}
    for sample in samples:
        group = sample["group"]
        hc, st = group["handler_criterion_id"], group["sink_type_id"]
        quote = "The service can retrieve caller-selected URLs."
        card = {
            "evidence_id": stable_evidence_id("capability-card", "fixture-card.md", "0" * 64, st, quote, quote),
            "kind": "capability-card",
            "applicability": {"handler_criterion_ids": [hc], "sink_type_ids": [st]},
            "source_path": "fixture-card.md", "sha256": "0" * 64,
            "locator": st, "exact_quote": quote, "supported_claim": quote,
        }
        evidence.append(card)
        evidence_by_group[group["handler_sink_group_id"]] = tuple(
            [card] + [doc for doc in docs if hc in doc["applicability"]["handler_criterion_ids"] and st in doc["applicability"]["sink_type_ids"]]
        )
        for semantic in sample["members"]:
            member = OracleChain(
                project=semantic["project"]["id"], revision=semantic["project"]["revision"],
                chain_id=semantic["chain_id"], handler_criterion_id=hc,
                handler_type_id="HT-" + "1" * 16, sink_type_id=st,
                semantic_ir=semantic, capability_card=quote,
                capability_card_path=card["source_path"], capability_evidence_id=card["evidence_id"],
            )
            chains[member.key] = member
    return OracleInputs(
        handler_criteria=hcs, sink_types=sts,
        security_groups=tuple(sample["group"] for sample in samples), excluded_groups=(),
        chains=chains, evidence_index={"schema_version": EVIDENCE_SCHEMA_VERSION, "evidence": evidence},
        evidence_by_group=evidence_by_group, digests={"fixture": "url-gate-groups.json"},
    )


class UrlPolicyResponseRunner:
    """Returns reviewed expected responses, never calls a model or network endpoint."""

    def __init__(self):
        self.calls = []

    @staticmethod
    def candidates(semantic):
        rows = []
        for gate in semantic["gates"]:
            policy = EXPECTED_POLICIES.get(gate["gate_uid"])
            if policy is None or policy["origin_marker"] not in gate["semantic"].get("input", ""):
                continue
            rows.append({
                key: policy[key] for key in ("dimension", "rule", "applicability")
            } | {
                "origin_gate_ids": [gate["gate_uid"]],
                "reason": "Reviewed response: the supplied input binds the checked URL to a model field; configuration is a comparison policy.",
            })
        return rows

    def __call__(self, system, user):
        payload = json.loads(user)
        self.calls.append((system, payload))
        if "seed_semantic_ir" in payload:
            return json.dumps({
                "group_id": payload["group_id"], "policy_atoms": [],
                "candidate_requirements": self.candidates(payload["seed_semantic_ir"]),
            })
        if system == EVIDENCE_EXTENSION_SYSTEM:
            # Isolate gate-derived retention: the docs support assessment, not fallback injection.
            return json.dumps({"group_id": payload["group_id"], "candidate_requirements": []})
        if system == PEER_SYSTEM:
            existing = {row["dimension"] for row in payload["frozen_seed_profile"]["candidate_requirements"]}
            return json.dumps({"chains": [{
                "chain_ref": member["chain_ref"],
                "candidate_requirements": [row for row in self.candidates(member["semantic_ir"]) if row["dimension"] not in existing],
            } for member in payload["candidate_chains"]]})
        if "policy_clusters" in payload:
            return json.dumps({"clusters": payload["policy_clusters"]})
        if "source_proposals" in payload:
            normative = set(payload["evidence_authority"]["normative_evidence_ids"])
            rows = []
            for proposal in payload["source_proposals"]:
                ids = [row["evidence_id"] for row in payload["applicable_pinned_evidence"] if row["evidence_id"] in normative and row["locator"] == proposal["dimension"]]
                rows.append({
                    "proposal_id": proposal["proposal_id"],
                    "decision": "add" if ids else "reject", "selected_proposal_id": None,
                    "evidence_ids": ids,
                    "reason": "The pinned policy supports this conditional URL objective." if ids else "No normative evidence supports this requirement.",
                })
            return json.dumps({"assessments": rows})
        raise AssertionError("Unexpected inference stage")


class PolicyMetaResponseRunner(UrlPolicyResponseRunner):
    """Control response that introduces a zero-gate policy-summary requirement."""

    def __call__(self, system, user):
        payload = json.loads(user)
        if system == EVIDENCE_EXTENSION_SYSTEM:
            self.calls.append((system, payload))
            return json.dumps({
                "group_id": payload["group_id"],
                "candidate_requirements": [{
                    "dimension": "policy-meta-summary",
                    "rule": "Retain the policy documentation's stated applicability and enforcement limitations.",
                    "applicability": "When publishing an explanation of the policy.",
                    "evidence_ids": payload["allowed_evidence_ids"],
                    "reason": "Control response used to detect unintended evidence-only expansion.",
                }],
            })
        if "source_proposals" in payload and all(
            row["dimension"] == "policy-meta-summary" for row in payload["source_proposals"]
        ):
            self.calls.append((system, payload))
            return json.dumps({"assessments": [{
                "proposal_id": row["proposal_id"], "decision": "add",
                "selected_proposal_id": None,
                "evidence_ids": payload["evidence_authority"]["normative_evidence_ids"],
                "reason": "Control response accepts the evidence-only summary.",
            } for row in payload["source_proposals"]]})
        return super().__call__(system, user)


class UrlGateRegressionTests(unittest.TestCase):
    def run_fixture(self, out, inputs, *, runner=None, reuse_prior=True, observed_gates_only=False):
        runner = runner or UrlPolicyResponseRunner()
        with patch("src.group_oracle.pipeline.load_oracle_inputs", return_value=inputs):
            result = pipeline.run_group_oracle(
                specs=[], handler_root=out.parent / "handlers", sink_root=out.parent / "sinks",
                evidence_registry=ROOT / "src/group_oracle/oracle-evidence-registry-url-gates.json",
                out_dir=out, generation_command="python -m unittest src.group_oracle.tests.test_url_gate_regressions",
                runner=runner, group_ids=[G06, G25], reuse_prior=reuse_prior,
                observed_gates_only=observed_gates_only,
            )
        return result, runner

    def read_rows(self, out, filename):
        return [json.loads(line) for line in (out / filename).read_text().splitlines()]

    def test_four_url_objectives_survive_with_exact_member_and_gate_provenance(self):
        inputs = url_inputs()
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "oracle"
            result, runner = self.run_fixture(out, inputs)
            oracles = {row["group_id"]: row for row in self.read_rows(out, "oracles.jsonl")}
            self.assertEqual({G06, G25}, set(oracles))
            self.assertEqual(4, result["manifest"]["counts"]["eligible_chains"])
            for group in inputs.security_groups:
                refs = oracles[group["handler_sink_group_id"]]["member_chain_refs"]
                expected = sorted((r["project"], r["chain_id"]) for r in group["chain_refs"])
                self.assertEqual(expected, sorted((r["project"], r["chain_id"]) for r in refs))
                for ref in refs:
                    self.assertEqual(inputs.chains[(ref["project"], ref["chain_id"])].revision, ref["revision"])
            policies = {r["dimension"]: r for oracle in oracles.values() for r in oracle["requirements"]}
            self.assertEqual({p["dimension"] for p in EXPECTED_POLICIES.values()}, set(policies))
            for gate, expected in EXPECTED_POLICIES.items():
                actual = policies[expected["dimension"]]
                self.assertEqual(expected["rule"], actual["rule"])
                self.assertEqual(expected["applicability"], actual["applicability"])
                self.assertEqual([gate], actual["origin_gate_ids"])
            self.assertEqual([], oracles[G06]["rejected_proposal_ids"])
            self.assertEqual([], oracles[G25]["rejected_proposal_ids"])
            evidence = {row["evidence_id"]: row for row in json.loads((out / "evidence-index.json").read_text())["evidence"]}
            for requirement in policies.values():
                self.assertTrue(all(evidence[ev]["kind"] == "documentation" for ev in requirement["evidence_ids"]))
            g25_seed = next(p for s, p in runner.calls if s == SEED_SYSTEM and p["group_id"] == G25)
            self.assertEqual("chatgpt-on-wechat:C-cc8199b82f91", g25_seed["seed_chain_ref"])
            self.assertEqual([WECHAT_SCHEME], [gate["gate_uid"] for gate in g25_seed["seed_semantic_ir"]["gates"]])
            block = next(p for p in self.read_rows(out, "proposals.jsonl") if p["dimension"] == "configured-website-blocklist")
            self.assertEqual("peer", block["origin"])
            self.assertEqual([BLOCKLIST], block["origin_gate_ids"])
            self.assertNotIn(WECHAT_SCHEME, block["origin_gate_ids"])
            self.assertEqual(["C-806a548b73e2"], [ref["chain_id"] for ref in block["origin_chain_refs"]])

    def test_g25_blocklist_does_not_replace_remote_scheme_and_address_admission(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "oracle"
            self.run_fixture(out, url_inputs())
            oracle = next(row for row in self.read_rows(out, "oracles.jsonl") if row["group_id"] == G25)
            requirements = {row["dimension"]: row for row in oracle["requirements"]}
            self.assertEqual({"configured-website-blocklist", "remote-image-url-admission"}, set(requirements))
            blocklist = requirements["configured-website-blocklist"]
            admission = requirements["remote-image-url-admission"]
            self.assertEqual([BLOCKLIST], blocklist["origin_gate_ids"])
            self.assertEqual([IMAGE_ADMISSION], admission["origin_gate_ids"])
            self.assertEqual(EXPECTED_POLICIES[IMAGE_ADMISSION]["rule"], admission["rule"])
            self.assertEqual(EXPECTED_POLICIES[BLOCKLIST]["rule"], blocklist["rule"])
            self.assertNotEqual(blocklist["evidence_ids"], admission["evidence_ids"])
            for requirement in requirements.values():
                self.assertEqual(["hermes-agent"], [ref["project"] for ref in requirement["origin_chain_refs"]])
                self.assertNotIn(WECHAT_SCHEME, requirement["origin_gate_ids"])

    def test_origin_screened_responses_do_not_promote_config_or_unknown_subjects(self):
        inputs = url_inputs()
        members = {}
        for key, member in inputs.chains.items():
            semantic = deepcopy(member.semantic_ir)
            semantic["gates"].extend([
                {"gate_uid": CONFIG_ONLY, "semantic": {"input": "params.ask, a trusted configuration-only approval mode"}},
                {"gate_uid": UNKNOWN_ORIGIN, "semantic": {"input": "helper URL parameter; field-level model source unresolved"}},
            ])
            members[key] = replace(member, semantic_ir=semantic)
        inputs = replace(inputs, chains=members)
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "oracle"
            _, runner = self.run_fixture(out, inputs)
            seen_input = json.dumps(runner.calls)
            self.assertIn(CONFIG_ONLY, seen_input)
            self.assertIn(UNKNOWN_ORIGIN, seen_input)
            for proposal in self.read_rows(out, "proposals.jsonl"):
                self.assertTrue(set(proposal["origin_gate_ids"]) <= set(EXPECTED_POLICIES))
            for oracle in self.read_rows(out, "oracles.jsonl"):
                for requirement in oracle["requirements"]:
                    self.assertTrue(set(requirement["origin_gate_ids"]) <= set(EXPECTED_POLICIES))

    def test_capability_only_evidence_does_not_authorize_the_same_url_proposals(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "oracle"
            self.run_fixture(out, url_inputs(normative=False))
            self.assertEqual(4, len(self.read_rows(out, "proposals.jsonl")))
            for oracle in self.read_rows(out, "oracles.jsonl"):
                self.assertEqual([], oracle["requirements"])
            self.assertTrue(all(row["decision"] == "reject" for row in self.read_rows(out, "proposal-assessments.jsonl")))

    def test_validator_blocks_a_model_attempt_to_add_with_capability_only_evidence(self):
        base = UrlPolicyResponseRunner()

        def invalid_add(system, user):
            payload = json.loads(user)
            request = payload.get("original_request", payload)
            if "source_proposals" not in request:
                return base(system, user)
            return json.dumps({"assessments": [{
                "proposal_id": proposal["proposal_id"], "decision": "add",
                "selected_proposal_id": None,
                "evidence_ids": request["evidence_authority"]["capability_only_evidence_ids"],
                "reason": "Invalid model response attempts to promote capability alone.",
            } for proposal in request["source_proposals"]]})

        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "oracle"
            with self.assertRaisesRegex(GroupOracleError, "add requires normative evidence"):
                self.run_fixture(out, url_inputs(normative=False), runner=invalid_add)
            self.assertFalse((out / "oracles.jsonl").exists())

    def test_new_construction_policy_invalidates_whole_group_reuse(self):
        inputs = url_inputs()
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "oracle"
            original, _ = self.run_fixture(out, inputs)
            reused, runner = self.run_fixture(out, inputs)
            self.assertEqual([], runner.calls)
            self.assertEqual(2, reused["manifest"]["counts"]["content_bound_reused_groups"])
            with patch.object(pipeline, "SEED_SYSTEM", pipeline.SEED_SYSTEM + "\nChanged model-origin policy."):
                changed, runner = self.run_fixture(out, inputs)
            self.assertTrue(runner.calls)
            self.assertEqual(0, changed["manifest"]["counts"]["content_bound_reused_groups"])
            self.assertNotEqual(original["manifest"]["construction_policy_sha256"], changed["manifest"]["construction_policy_sha256"])
            requirements = [row for oracle in self.read_rows(out, "oracles.jsonl") for row in oracle["requirements"]]
            self.assertEqual(4, len(requirements))
            self.assertTrue(all(row["evidence_ids"] for row in requirements))
            self.assertTrue(all(row["decision"] != "reject" for row in self.read_rows(out, "proposal-assessments.jsonl")))
            # Seed/continuity same-ID collisions must retain the normative origin IDs.
            proposals = self.read_rows(out, "proposals.jsonl")
            g06 = [row for row in proposals if row["group_id"] == G06]
            self.assertEqual(2, len(g06))
            self.assertTrue(all(row.get("origin_evidence_ids") for row in g06))

    def test_fresh_reexecutes_both_groups_without_loading_prior(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "oracle"
            inputs = url_inputs()
            self.run_fixture(out, inputs)
            with patch("src.group_oracle.pipeline._prior_group_snapshot") as snapshot:
                result, runner = self.run_fixture(out, inputs, reuse_prior=False)
                snapshot.assert_not_called()
            self.assertTrue(runner.calls)
            self.assertEqual(2, result["manifest"]["counts"]["inferred_groups"])

    def test_observed_gate_mode_skips_extension_and_filters_prior_zero_gate_policies(self):
        inputs = url_inputs()
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "oracle"
            expanded, runner = self.run_fixture(out, inputs, runner=PolicyMetaResponseRunner())
            self.assertEqual(2, expanded["manifest"]["counts"]["evidence_extension_requests"])
            self.assertEqual(2, sum(system == EVIDENCE_EXTENSION_SYSTEM for system, _ in runner.calls))
            self.assertEqual(0, expanded["manifest"]["counts"]["policy_consolidation_requests"])
            self.assertFalse(any(system == POLICY_CONSOLIDATION_SYSTEM for system, _ in runner.calls))
            self.assertEqual(2, sum(
                requirement["origin_gate_ids"] == []
                for oracle in self.read_rows(out, "oracles.jsonl")
                for requirement in oracle["requirements"]
            ))
            observed, runner = self.run_fixture(
                out, inputs, runner=PolicyMetaResponseRunner(), observed_gates_only=True
            )
            self.assertTrue(observed["manifest"]["observed_gates_only"])
            self.assertEqual(0, observed["manifest"]["counts"]["content_bound_reused_groups"])
            self.assertEqual(0, observed["manifest"]["counts"]["evidence_extension_requests"])
            self.assertEqual(0, observed["manifest"]["counts"]["evidence_extension_proposals"])
            self.assertEqual(2, observed["manifest"]["counts"]["policy_consolidation_requests"])
            self.assertEqual(2, sum(system == POLICY_CONSOLIDATION_SYSTEM for system, _ in runner.calls))
            self.assertFalse(any(system == EVIDENCE_EXTENSION_SYSTEM for system, _ in runner.calls))
            requirements = [r for oracle in self.read_rows(out, "oracles.jsonl") for r in oracle["requirements"]]
            self.assertEqual(4, len(requirements))
            self.assertTrue(all(requirement["origin_gate_ids"] for requirement in requirements))
            self.assertNotIn("policy-meta-summary", {row["dimension"] for row in requirements})
            reused, runner = self.run_fixture(
                out, inputs, runner=PolicyMetaResponseRunner(), observed_gates_only=True
            )
            self.assertEqual([], runner.calls)
            self.assertEqual(2, reused["manifest"]["counts"]["content_bound_reused_groups"])
            # The manifest counts retained audited stages; the runner made no new calls.
            self.assertEqual(2, reused["manifest"]["counts"]["policy_consolidation_requests"])

    def test_default_mode_does_not_reuse_observed_only_results(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "oracle"
            inputs = url_inputs()
            self.run_fixture(out, inputs, observed_gates_only=True)
            expanded, runner = self.run_fixture(out, inputs, runner=PolicyMetaResponseRunner())
            self.assertFalse(expanded["manifest"]["observed_gates_only"])
            self.assertTrue(runner.calls)
            self.assertEqual(0, expanded["manifest"]["counts"]["content_bound_reused_groups"])
            self.assertEqual(2, expanded["manifest"]["counts"]["evidence_extension_requests"])
            self.assertEqual(0, expanded["manifest"]["counts"]["policy_consolidation_requests"])

    def test_policy_consolidation_rejects_dropped_or_unknown_proposal_and_evidence_ids(self):
        for invalid in ("dropped-proposal", "unknown-proposal", "unknown-evidence"):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as raw:
                out = Path(raw) / "oracle"
                base = UrlPolicyResponseRunner()

                def invalid_policy(system, user):
                    payload = json.loads(user)
                    request = payload.get("original_request", payload)
                    if "policy_clusters" not in request:
                        return base(system, user)
                    clusters = deepcopy(request["policy_clusters"])
                    if invalid == "dropped-proposal":
                        clusters.pop()
                    elif invalid == "unknown-proposal":
                        clusters[0]["proposal_ids"] = ["RP-" + "0" * 16]
                    else:
                        clusters[0]["evidence_ids"] = ["EV-" + "0" * 16]
                    return json.dumps({"clusters": clusters})

                with self.assertRaisesRegex(GroupOracleError, "policy consolidation: unrepaired"):
                    self.run_fixture(
                        out, url_inputs(), runner=invalid_policy, observed_gates_only=True
                    )
                self.assertFalse((out / "oracles.jsonl").exists())


if __name__ == "__main__":
    unittest.main()

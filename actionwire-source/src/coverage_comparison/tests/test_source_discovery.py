from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.coverage_comparison.pipeline import _assessment_record
from src.coverage_comparison.source_discovery import (
    SOURCE_DISCOVERY_SYSTEM,
    SourceDiscoveryConfig,
    run_source_discovery,
    stable_source_requirement_id,
)
from src.coverage_comparison.source_validation import (
    SourceValidationConfig,
    run_source_validation,
    validate_source_validation_artifacts,
)
from src.coverage_comparison.tests.test_coverage_comparison import (
    FakeSourceRunner,
    coverage_chain,
    project_spec,
)


class FakeDiscoveryRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def __call__(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if system != SOURCE_DISCOVERY_SYSTEM:
            raise AssertionError(system)
        payload = json.loads(user.split("\n", 1)[1])
        return json.dumps(
            {
                "project": payload["project"],
                "revision": payload["revision"],
                "chains": [
                    {
                        "chain_id": chain["chain_id"],
                        "proposals": [
                            {
                                "action": "add",
                                "dimension": "redirect-destination-policy",
                                "rule": "Redirect destinations must satisfy the same network policy as the initial URL.",
                                "applicability": "When a model-controlled request follows redirects.",
                                "controlled_facet": "url -> redirect target -> network request",
                                "enforcement_stage": "post-action",
                                "state_lifetime": "single-call",
                                "policy_basis": "fixed-delta",
                                "protected_asset": "private network services",
                                "security_effect": "A redirect can reach a private service that direct requests block.",
                                "failure_mode": "missing-check",
                                "gate_ids": [],
                                "covered_semantics": None,
                                "gap": "No redirect destination policy is applied.",
                                "refines_requirement_ids": [],
                                "preconditions": [
                                    "The remote server returns a redirect."
                                ],
                                "source_evidence": [
                                    {
                                        "role": role,
                                        "file": "source.py",
                                        "line_start": 1,
                                        "line_end": 1,
                                        "claim": f"Source supports the {role} fact.",
                                    }
                                    for role in (
                                        "handler",
                                        "controlled-value",
                                        "sink",
                                        "policy",
                                        "impact",
                                    )
                                ],
                            }
                        ],
                    }
                    for chain in payload["chains"]
                ],
            }
        )

    def close(self) -> None:
        return None

    def chat_payload(self) -> dict:
        return {"turns": []}

    def audit_payload(self) -> dict:
        return {"token_usage": {"input_tokens": 10, "output_tokens": 5}}


class SourceDiscoveryTests(unittest.TestCase):
    def test_stable_source_requirement_identity(self) -> None:
        first = stable_source_requirement_id(
            project="fixture",
            revision="revision",
            chain_id="C-" + "1" * 12,
            dimension="redirect-destination-policy",
            rule="Reject private redirect targets.",
            applicability="When redirects are followed.",
            controlled_facet="url -> redirect",
            enforcement_stage="post-action",
            state_lifetime="single-call",
        )
        second = stable_source_requirement_id(
            project="fixture",
            revision="revision",
            chain_id="C-" + "1" * 12,
            dimension="redirect destination policy",
            rule=" Reject  private redirect targets. ",
            applicability="When redirects are followed.",
            controlled_facet="url -> redirect",
            enforcement_stage="post-action",
            state_lifetime="single-call",
        )
        self.assertEqual(first, second)
        self.assertRegex(first, r"^SR-[0-9a-f]{16}$")

    def test_discovery_candidate_requires_independent_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source_root = root / "source"
            source_root.mkdir()
            (source_root / "source.py").write_text(
                "def request(url): return send(url)\n", encoding="utf-8"
            )
            chain = coverage_chain()
            requirement = chain.oracle["requirements"][0]
            group_assessment = _assessment_record(
                chain,
                {
                    "requirement_id": requirement["requirement_id"],
                    "applicability": "applicable",
                    "decision": "covered",
                    "capability_evidence": [
                        {"start_line": 2, "end_line": 3, "quote": "evidence"}
                    ],
                    "call_shape_facts": ["request uses model URL"],
                    "gate_ids": [chain.semantic_ir["gates"][0]["gate_uid"]],
                    "covered_semantics": "The initial URL is checked.",
                    "gap": None,
                    "uncertainty": None,
                },
            )
            runner = FakeDiscoveryRunner()
            discovery = run_source_discovery(
                chains=[chain],
                group_assessments=[group_assessment],
                specs=[project_spec(source_root)],
                prior_root=root / "out",
                config=SourceDiscoveryConfig(
                    model="fixture",
                    agent_transport="cli",
                    enable_lsp=False,
                ),
                runner_factory=lambda _spec, _config: runner,
            )
            self.assertEqual(1, len(discovery.proposals))
            self.assertEqual(1, len(discovery.provisional_candidates))
            candidate = discovery.provisional_candidates[0]
            self.assertEqual("source-derived", candidate["requirement_source"])
            validation = run_source_validation(
                chains={chain.key: chain},
                provisional_candidates=discovery.provisional_candidates,
                assessments=discovery.assessments,
                specs=[project_spec(source_root)],
                prior_root=root / "validation",
                config=SourceValidationConfig(
                    model="fixture",
                    agent_transport="cli",
                    enable_lsp=False,
                    strategy="agent-only",
                ),
                runner_factory=lambda _spec, _config: FakeSourceRunner(
                    "confirmed-uncovered"
                ),
                extra_requirements=discovery.requirements,
            )
            validate_source_validation_artifacts(
                provisional_candidates=discovery.provisional_candidates,
                records=validation.records,
            )
            self.assertEqual(1, validation.confirmed_count)


if __name__ == "__main__":
    unittest.main()

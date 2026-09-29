from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.coverage_comparison.contracts import CoverageComparisonError
from src.coverage_comparison.source_validation_packets import (
    _is_source_hop,
    build_source_validation_packet,
    normalize_packet_validation_payload,
    parse_packet_validation_response,
)
from src.coverage_comparison.tests.test_coverage_comparison import (
    GATE,
    RID,
    coverage_chain,
)
from src.projects import ProjectSpec


def _spec(root: Path) -> ProjectSpec:
    return ProjectSpec(
        project_id="fixture",
        source_root=root / "source",
        analysis_revision="revision",
        codeql_database=root / "database",
        design_root=root / "design",
        output_root=root / "output",
        ground_truth_root=root / "design/groundtruth",
        codeql_adapter="fixture",
        source_language="python",
        codeql_language="python",
        query_pack=root / "query-pack",
    )


def _write_structural(spec: ProjectSpec, *, handler_file: str = "source.py") -> None:
    path = spec.output_root / "static/call-chains/handler-sink-chains.csv"
    path.parent.mkdir(parents=True)
    path.write_text(
        "chain_id,handler_file,handler_line,sink_file,sink_line,source_parameter,"
        "sink_argument,sink_label,call_chain\n"
        f"C-111111111111,{handler_file},1,{handler_file},4,url,url,fetch,"
        f"1#request@{Path(handler_file).name}->fetch@{Path(handler_file).name}\n",
        encoding="utf-8",
    )


def _candidate() -> dict:
    return {
        "candidate_id": "CAND-" + "1" * 16,
        "requirement_id": RID,
        "failure_mode": "wrong-check",
    }


def _requirement(*, policy_basis: str = "learned-security-invariant") -> dict:
    return {
        "requirement_id": RID,
        "policy_basis": policy_basis,
        "rule": "Reject private destinations.",
        "applicability": "A model controls a fetched URL.",
    }


class SourceValidationPacketTests(unittest.TestCase):
    def test_non_source_resource_hop_is_not_resolved_as_code(self) -> None:
        self.assertFalse(_is_source_hop("outbound.db"))
        self.assertTrue(_is_source_hop("delivery.ts"))

    def test_packet_binds_contiguous_source_searches_and_digest_drift(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            spec = _spec(root)
            spec.source_root.mkdir()
            source = spec.source_root / "source.py"
            source.write_text(
                "def request(url):\n"
                "    if not authorize(url):\n"
                "        raise ValueError('blocked')\n"
                "    return fetch(url)\n",
                encoding="utf-8",
            )
            _write_structural(spec)
            chain = coverage_chain()
            first = build_source_validation_packet(
                chain=chain,
                candidates=[_candidate()],
                assessments={RID: {"requirement_id": RID, "decision": "wrong-check"}},
                requirements={RID: _requirement()},
                spec=spec,
            )
            self.assertTrue(
                first["handler_to_sink_source_coverage"][
                    "continuous_pre_sink_coverage"
                ]
            )
            self.assertTrue(first["exact_chain_value_search_results"])
            self.assertTrue(first["exact_chain_guard_search_results"])
            self.assertTrue(
                all(
                    hop["source_anchor"]["source_span_id"].startswith("SPAN-")
                    for hop in first["ordered_structural_hops"]
                )
            )

            source.write_text(source.read_text(encoding="utf-8") + "# drift\n")
            second = build_source_validation_packet(
                chain=chain,
                candidates=[_candidate()],
                assessments={RID: {"requirement_id": RID, "decision": "wrong-check"}},
                requirements={RID: _requirement()},
                spec=spec,
            )
            self.assertNotEqual(first["packet_digest"], second["packet_digest"])

    def test_packet_rejects_preferred_path_outside_source_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            spec = _spec(root)
            spec.source_root.mkdir()
            (root / "escape.py").write_text(
                "def request(url):\n    return fetch(url)\n",
                encoding="utf-8",
            )
            _write_structural(spec, handler_file="../escape.py")
            with self.assertRaisesRegex(CoverageComparisonError, "escapes source root"):
                build_source_validation_packet(
                    chain=coverage_chain(),
                    candidates=[_candidate()],
                    assessments={RID: {"requirement_id": RID}},
                    requirements={RID: _requirement()},
                    spec=spec,
                )

    def test_wire_normalization_does_not_change_verdict(self) -> None:
        packet = {
            "provisional_candidates": [{"candidate": _candidate()}],
            "requirements": [_requirement()],
        }
        payload = {
            "validations": [
                {
                    "provisional_candidate_id": _candidate()["candidate_id"],
                    "verdict": "confirmed-uncovered",
                    "final_decision": "covered",
                    "covering_gate_ids": [GATE],
                    "policy_basis": "learned-invariant",
                    "source_evidence": [
                        {"role": "propagation"},
                        {"role": "gate-definition"},
                    ],
                }
            ]
        }
        normalized, changes = normalize_packet_validation_payload(
            payload, packet=packet
        )
        [row] = normalized["validations"]
        self.assertEqual("confirmed-uncovered", row["verdict"])
        self.assertEqual("wrong-check", row["final_decision"])
        self.assertEqual([], row["covering_gate_ids"])
        self.assertEqual("learned-security-invariant", row["policy_basis"])
        self.assertEqual(
            ["controlled-value", "gate"],
            [value["role"] for value in row["source_evidence"]],
        )
        self.assertTrue(changes)

    def test_needs_deep_response_cannot_smuggle_validations(self) -> None:
        packet = {
            "project": "fixture",
            "revision": "revision",
            "chain_id": "C-" + "1" * 12,
        }
        raw = json.dumps(
            {
                "decision": "needs-deep",
                **packet,
                "reason": "missing source",
                "validations": [{}],
            }
        )
        with self.assertRaisesRegex(CoverageComparisonError, "must not validate"):
            parse_packet_validation_response(raw, packet=packet)


if __name__ == "__main__":
    unittest.main()

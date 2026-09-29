"""Reviewed qualification is immutable input binding, not automatic taint inference."""

import json
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from src.group_oracle.contracts import GroupOracleError, digest
from src.group_oracle.gate_qualification import qualify_inputs
from src.group_oracle.tests.test_url_gate_regressions import EXPECTED_POLICIES, url_inputs


def qualification(inputs):
    chains = []
    for key, chain in sorted(inputs.chains.items()):
        sem = chain.semantic_ir
        selected = [g["gate_uid"] for g in sem["gates"] if g["gate_uid"] in EXPECTED_POLICIES]
        chains.append({
            "project": key[0], "chain_id": key[1], "revision": chain.revision,
            "semantic_ir_sha256": digest(sem), "qualified_gate_uids": selected,
            "model_origin_evidence": [
                {"gate_uid": g["gate_uid"], "input_locator": f"/gates/{i}/semantic/input",
                 "exact_value": g["semantic"]["input"]}
                for i, g in enumerate(sem["gates"]) if g["gate_uid"] in selected
            ],
        })
    return {"schema_version": "reviewed-gate-qualification/v1",
            "group_ids": [g["handler_sink_group_id"] for g in inputs.security_groups], "chains": chains}


class GateQualificationTests(unittest.TestCase):
    def apply(self, inputs, document):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw)/"qualification.json"
            path.write_text(json.dumps(document))
            return qualify_inputs(inputs, path)

    def test_filters_unqualified_gates_without_changing_members_or_original_ir(self):
        inputs = url_inputs()
        before = {key: deepcopy(c.semantic_ir) for key, c in inputs.chains.items()}
        selected, audit = self.apply(inputs, qualification(inputs))
        self.assertEqual(set(inputs.chains), set(selected.chains))
        self.assertFalse(audit["raw_inputs_modified"])
        for key, chain in selected.chains.items():
            self.assertEqual(before[key], inputs.chains[key].semantic_ir)
            self.assertTrue({g["gate_uid"] for g in chain.semantic_ir["gates"]} <= set(EXPECTED_POLICIES))
            if key[0] == "chatgpt-on-wechat":
                self.assertEqual([], chain.semantic_ir["gates"])

    def test_rejects_semantic_and_revision_drift(self):
        inputs = url_inputs()
        for field, value in [("semantic_ir_sha256", "0"*64), ("revision", "different")]:
            with self.subTest(field=field):
                doc = qualification(inputs);doc["chains"][0][field] = value
                with self.assertRaisesRegex(GroupOracleError, "drift"):
                    self.apply(inputs, doc)

    def test_rejects_unknown_gate_and_missing_origin_evidence(self):
        inputs = url_inputs()
        doc = qualification(inputs)
        row = next(r for r in doc["chains"] if r["qualified_gate_uids"])
        row["qualified_gate_uids"].append("GU"+"0"*20)
        with self.assertRaisesRegex(GroupOracleError, "unknown"):
            self.apply(inputs, doc)
        doc = qualification(inputs)
        next(r for r in doc["chains"] if r["qualified_gate_uids"])["model_origin_evidence"] = []
        with self.assertRaisesRegex(GroupOracleError, "exact reviewed origin"):
            self.apply(inputs, doc)

    def test_rejects_quote_and_pointer_mismatch(self):
        inputs = url_inputs()
        for field, value in [("exact_value", "different source"), ("input_locator", "/missing")]:
            with self.subTest(field=field):
                doc = qualification(inputs)
                proof = next(r for r in doc["chains"] if r["model_origin_evidence"])["model_origin_evidence"][0]
                proof[field] = value
                with self.assertRaises(GroupOracleError):
                    self.apply(inputs, doc)

    def test_requires_exact_group_and_member_scope(self):
        inputs = url_inputs()
        for mutation in [lambda d: d["chains"].pop(), lambda d: d["chains"].append(d["chains"][0]), lambda d: d["group_ids"].pop()]:
            doc = qualification(inputs);mutation(doc)
            with self.assertRaises(GroupOracleError):
                self.apply(inputs, doc)


if __name__ == "__main__":
    unittest.main()

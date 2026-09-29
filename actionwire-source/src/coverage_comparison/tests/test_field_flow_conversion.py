from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from src.coverage_comparison.field_flow_contract import FieldFlowContractError
from src.coverage_comparison.field_flow_conversion import convert_rows


class FieldFlowConversionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "handler.py").write_text("value = args['url']\n")
        (self.root / "sink.py").write_text("send(value)\n")
        self.binding = {
            "schema_version": "field-flow-chain-binding/v1",
            "project": "fixture",
            "revision": "abc123",
            "chain_id": "C-fixture",
            "handler_id": "H-fixture",
            "sink_id": "S-fixture",
            "handler": {"name": "execute", "file": "handler.py", "line": 1},
            "sink": {"file": "sink.py", "line": 1, "column": 1, "role": "url"},
        }
        self.base = {
            "project": "fixture",
            "handler_name": "execute",
            "handler_file": "handler.py",
            "handler_line": "1",
            "source_parameter": "args",
            "field": "url",
            "property_read": "handler.py:1:9",
            "sink_file": "sink.py",
            "sink_line": "1",
            "sink_column": "1",
            "sink_role": "url",
            "value_authority": "model-arbitrary",
            "access_kind": "mapping-subscript",
            "transforms": "trim;parse",
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_converts_witness_and_exclusion_with_hashes(self) -> None:
        witness = {
            **self.base,
            "proof": "explicit-bridge",
            "path_nodes": (
                "field-read@handler.py:1:9;assignment@handler.py:1:1;"
                "argument@handler.py:1:9;bridge@sink.py:1:1;"
                "parameter@sink.py:1:1;return@sink.py:1:1;"
                "transform@sink.py:1:1;sink-role@sink.py:1:1"
            ),
        }
        exclusion = {
            **self.base,
            "exclusion_reason": "missing-explicit-bridge",
            "path_nodes": "field-read@handler.py:1:9;sink-role@sink.py:1:1",
        }
        witnesses, exclusions = convert_rows(
            [witness], [exclusion], [self.binding], self.root
        )
        self.assertEqual(witnesses[0]["chain_id"], "C-fixture")
        self.assertEqual(witnesses[0]["proof_kind"], "explicit-bridge")
        self.assertEqual([node["kind"] for node in witnesses[0]["path_nodes"]], [
            "field-read", "assignment", "argument", "bridge",
            "parameter", "return", "transform", "sink-role",
        ])
        self.assertEqual(witnesses[0]["transforms"][0]["name"], "trim")
        expected = hashlib.sha256((self.root / "handler.py").read_bytes()).hexdigest()
        self.assertEqual(witnesses[0]["source_hashes"]["handler.py"], expected)
        self.assertEqual(exclusions[0]["exclusion_reason"], "missing-explicit-bridge")

    def test_fails_closed_on_unbound_or_ambiguous_chain(self) -> None:
        row = {
            **self.base,
            "proof": "direct",
            "path_nodes": "field-read@handler.py:1:9;sink-role@sink.py:1:1",
        }
        with self.assertRaises(FieldFlowContractError):
            convert_rows([row], [], [], self.root)
        with self.assertRaises(FieldFlowContractError):
            convert_rows([row], [], [self.binding, self.binding], self.root)

    def test_rejects_invalid_authority_and_missing_bridge_node(self) -> None:
        row = {
            **self.base,
            "proof": "explicit-bridge",
            "path_nodes": "field-read@handler.py:1:9;sink-role@sink.py:1:1",
        }
        with self.assertRaises(FieldFlowContractError):
            convert_rows([row], [], [self.binding], self.root)
        row["proof"] = "direct"
        row["value_authority"] = "model-controlled"
        with self.assertRaises(FieldFlowContractError):
            convert_rows([row], [], [self.binding], self.root)


if __name__ == "__main__":
    unittest.main()

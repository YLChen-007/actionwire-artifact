from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("render_d5_chain_coverage.py")
SPEC = importlib.util.spec_from_file_location("cow_d5_coverage", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def candidate(**overrides):
    values = {
        "chain_id": "C-test",
        "sequence": 1,
        "detector": "dominance",
        "gate_uid": "GU-test",
        "gate_id": "G-test",
        "name": "inline-condition",
        "file": "agent/tool.py",
        "line": 3,
        "enclosing_function": "execute",
        "verdict": "confirmed",
        "call_expression": "warning",
        "qualified_function": "inline-condition",
        "semantic_status": "complete",
        "semantic_summary": "",
        "semantic_text": "reject shutdown and reboot commands",
    }
    values.update(overrides)
    return MODULE.GateCandidate(**values)


class MatchingTests(unittest.TestCase):
    def test_stale_exact_line_does_not_cover_unrelated_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "agent/tool.py"
            path.parent.mkdir(parents=True)
            path.write_text(
                "class Tool:\n"
                "    def execute(self, args):\n"
                "        warning = check_shutdown(args)\n",
                encoding="utf-8",
            )
            source = MODULE.SourceIndex(root)
            item = {
                "name": "credential-file regex",
                "type": "dominance",
                "location": "agent/tool.py:3",
                "evidence": "if '.cow/.env' in command:",
                "policy": "deny credential file access",
            }
            evaluation = MODULE.evaluate_gate(item, candidate(), source)
            self.assertEqual(0, evaluation.score)
            self.assertIn("collid", evaluation.rejection_reason)

    def test_transform_gt_requires_transform_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "agent/tool.py"
            path.parent.mkdir(parents=True)
            path.write_text(
                "class Tool:\n"
                "    def execute(self, args):\n"
                "        value = resolve(args)\n",
                encoding="utf-8",
            )
            source = MODULE.SourceIndex(root)
            item = {
                "name": "resolve",
                "type": "transform",
                "location": "agent/tool.py:3",
                "evidence": "value = resolve(args)",
            }
            evaluation = MODULE.evaluate_gate(item, candidate(), source)
            self.assertEqual(0, evaluation.score)
            self.assertIn("type", evaluation.rejection_reason)

    def test_missing_control_profile_uses_semantics(self) -> None:
        scheme_only = candidate(
            semantic_text="reject URL unless scheme is http or https"
        )
        public_only = candidate(
            semantic_text="validate destination and reject private or loopback addresses"
        )
        self.assertFalse(
            MODULE.missing_control_match("public-destination-validation", scheme_only)[
                0
            ]
        )
        self.assertTrue(
            MODULE.missing_control_match("public-destination-validation", public_only)[
                0
            ]
        )

    def test_transform_does_not_fabricate_missing_denial(self) -> None:
        path_transform = candidate(
            detector="transform",
            semantic_text="resolve a proc environ alias to an absolute path",
        )
        matched, reason = MODULE.missing_control_match(
            "credential-file-alias-denial", path_transform
        )
        self.assertFalse(matched)
        self.assertIn("no conditional rejection", reason)


class RepositoryIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.args = MODULE.build_parser().parse_args([])
        cls.result = MODULE.analyze(cls.args)

    def test_current_cowagent_coverage_findings(self) -> None:
        self.assertEqual(7, self.result.stats["reports"])
        self.assertEqual(6, self.result.stats["dimensions"])
        self.assertEqual(7, self.result.stats["target_sink_covered"])
        self.assertEqual(7, self.result.stats["target_sink_constrained"])
        self.assertEqual(26, self.result.stats["existing_gate_total"])
        self.assertEqual(26, self.result.stats["existing_gate_covered"])
        self.assertEqual(4, self.result.stats["expected_missing_preserved"])
        self.assertEqual(1, self.result.stats["oracle_gaps"])

    def test_transform_hit_and_browser_oracle_gap_remain_visible(self) -> None:
        findings = {
            (row["gt_name"], row["coverage_status"]) for row in self.result.item_rows
        }
        self.assertIn(("Read._resolve_path", "covered"), findings)
        self.assertIn(
            ("missing browser navigation scheme allowlist", "oracle-gap"),
            findings,
        )

    def test_markdown_starts_with_reproduction_command(self) -> None:
        markdown = MODULE.render_markdown(self.result, self.args.out_dir)
        first_lines = "\n".join(markdown.splitlines()[:8])
        self.assertIn("Generation command:", first_lines)
        self.assertIn(
            "design/chatgpt-on-wechat/call-chain/debug/script/"
            "render_d5_chain_coverage.py",
            first_lines,
        )


if __name__ == "__main__":
    unittest.main()

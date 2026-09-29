from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("generate_zero_gate_audit.py")
SPEC = importlib.util.spec_from_file_location("generate_zero_gate_audit", SCRIPT)
assert SPEC and SPEC.loader
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def valid_manifest():
    cells = []
    records = []
    for index, (project, mode) in enumerate(audit.AUDITED_CELLS):
        revision = audit.get_project(project).analysis_revision
        cells.append(
            {
                "project": project,
                "revision": revision,
                "mode": mode,
                "original_table_count": 0,
                "raw_detector_rows": 1,
                "eligible_gate_uids": 0,
                "canonical_witnesses": 1,
                "classifications": {"confirmed-zero": 1},
                "detector_scope": audit.CELL_SCOPE[mode],
            }
        )
        records.append(
            {
                "project": project,
                "revision": revision,
                "witness_id": f"C-{index:012x}",
                "mode": mode,
                "classification": "confirmed-zero",
                "source_evidence": {
                    "handler_source": "handler@file:1 source=args",
                    "ordered_path": "handler->sink",
                    "sink": "sink@file:2:1",
                    "gate_evidence": [],
                },
                "rationale": "audited",
                "matching_detector_uids": [],
            }
        )
    return {
        "schema_version": audit.SCHEMA,
        "generation_command": audit.GENERATION_COMMAND,
        "cells": cells,
        "records": records,
        "issues": [],
    }


class ZeroGateAuditValidationTest(unittest.TestCase):
    def test_chatgpt_read_transform_policy_is_exact(self):
        policy = audit.DETECTED_WITNESSES[("chatgpt-on-wechat", "transform")]
        read_chain = {
            "tool_name": "read",
            "sink_file": "agent/tools/read/read.py",
            "sink_line": "248",
            "call_chain": "Read.execute->Read._read_text->open",
        }
        edit_chain = {
            "tool_name": "edit",
            "sink_file": "agent/tools/edit/edit.py",
            "sink_line": "79",
            "call_chain": "Edit.execute->open",
        }
        self.assertTrue(audit._matches_witness(read_chain, policy))
        self.assertFalse(audit._matches_witness(edit_chain, policy))

    def test_witness_policy_can_exclude_non_admission_path(self):
        policy = audit.DETECTED_WITNESSES[("poco-agent", "filter")]
        row = {
            "tool_name": "memory_create",
            "sink_file": "executor/app/core/memory.py",
            "sink_line": "42",
            "call_chain": "memory_create->MemoryClient.create_memory_text->client.request",
        }
        self.assertFalse(audit._matches_witness(row, policy))

    def test_openclaw_filter_policy_matches_only_source_backed_witnesses(self):
        policy = audit.DETECTED_WITNESSES[("openclaw", "filter")]
        apply_patch = {
            "tool_name": "apply_patch",
            "sink_file": "src/agents/apply-patch.ts",
            "sink_line": "143",
            "call_chain": "execute->applyPatch->writeFile",
        }
        unrelated_exec_spawn = {
            "tool_name": "exec",
            "sink_file": "src/process/spawn-utils.ts",
            "sink_line": "67",
            "call_chain": "execute->spawnImpl",
        }
        self.assertEqual("parsePatchText", next(iter(audit._matching_policy(apply_patch, policy)["gate_names"])))
        self.assertIsNone(audit._matching_policy(unrelated_exec_spawn, policy))

    def test_valid_manifest(self):
        self.assertEqual([], audit.validate_manifest(valid_manifest()))

    def test_stale_revision(self):
        manifest = valid_manifest()
        manifest["cells"][0]["revision"] = "stale"
        self.assertTrue(any("revision is stale" in issue for issue in audit.validate_manifest(manifest)))

    def test_missing_canonical_witness(self):
        manifest = valid_manifest()
        manifest["records"].pop(0)
        self.assertTrue(any("witness coverage" in issue for issue in audit.validate_manifest(manifest)))

    def test_unresolved_detector_gap(self):
        manifest = valid_manifest()
        manifest["records"][0]["classification"] = "detector-gap"
        self.assertTrue(any("unresolved detector gap" in issue for issue in audit.validate_manifest(manifest)))

    def test_raw_and_eligible_are_distinct(self):
        manifest = valid_manifest()
        manifest["cells"][0]["raw_detector_rows"] = 0
        manifest["cells"][0]["eligible_gate_uids"] = 1
        self.assertTrue(any("exceeds raw" in issue for issue in audit.validate_manifest(manifest)))

    def test_generation_command_required(self):
        manifest = valid_manifest()
        manifest["generation_command"] = ""
        self.assertTrue(any("generation command" in issue for issue in audit.validate_manifest(manifest)))

    def test_report_starts_with_repository_command(self):
        report = audit.render_report(valid_manifest())
        self.assertIn(audit.GENERATION_COMMAND, report.splitlines()[0])


if __name__ == "__main__":
    unittest.main()

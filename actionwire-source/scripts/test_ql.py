#!/usr/bin/env python3
"""Run CodeQL fixtures, production compilation, and project GT regressions."""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
CODEQL = ROOT / "bin" / "codeql"
QL_PACK = ROOT / "src" / "ql"
QL_TESTS = QL_PACK / "tests"
JS_QL_PACK = ROOT / "src" / "ql-js"
JS_QL_TESTS = JS_QL_PACK / "tests"
HERMES_BASELINE_UNIT_TEST = (
    ROOT
    / "design/hermes-agent/call-chain/debug/script/test_hermes_d5_baseline.py"
)
HERMES_BASELINE_RUNNER = ROOT / "scripts/test_hermes_d5_baseline.py"
COWAGENT_BASELINE_UNIT_TEST = (
    ROOT
    / "design/chatgpt-on-wechat/call-chain/debug/script/"
    "test_render_gt_coverage.py"
)
COWAGENT_BASELINE_RUNNER = (
    ROOT / "scripts/test_chatgpt_on_wechat_gt_coverage.py"
)
ASTRBOT_BASELINE_UNIT_TEST = (
    ROOT / "design/AstrBot/call-chain/debug/script/test_render_gt_coverage.py"
)
ASTRBOT_BASELINE_RUNNER = ROOT / "scripts/test_astrbot_gt_coverage.py"
QWENPAW_BASELINE_UNIT_TEST = (
    ROOT / "design/QwenPaw/call-chain/debug/script/test_render_gt_coverage.py"
)
QWENPAW_BASELINE_RUNNER = ROOT / "scripts/test_qwenpaw_gt_coverage.py"
NANOBOT_BASELINE_UNIT_TEST = (
    ROOT / "design/nanobot/call-chain/debug/script/test_render_gt_coverage.py"
)
NANOBOT_BASELINE_RUNNER = ROOT / "scripts/test_nanobot_gt_coverage.py"
POCO_AGENT_BASELINE_UNIT_TEST = (
    ROOT / "design/poco-agent/call-chain/debug/script/test_render_gt_coverage.py"
)
POCO_AGENT_BASELINE_RUNNER = ROOT / "scripts/test_poco_agent_gt_coverage.py"
OPENCLAW_INVENTORY_UNIT_TEST = (
    ROOT / "design/openclaw/inventory/debug/scripts/test_generate_inventory.py"
)
OPENCLAW_COVERAGE_UNIT_TEST = (
    ROOT / "design/openclaw/call-chain/debug/scripts/test_render_gt_coverage.py"
)
OPENCLAW_D5_COVERAGE_UNIT_TEST = (
    ROOT / "design/openclaw/call-chain/debug/scripts/test_render_d5_chain_coverage.py"
)
OPENCLAW_BASELINE_RUNNER = ROOT / "scripts/test_openclaw_gt_coverage.py"
OPENCLAW_CN_INVENTORY_UNIT_TEST = (
    ROOT / "design/openclaw-cn/inventory/debug/scripts/test_generate_inventory.py"
)
OPENCLAW_CN_COVERAGE_UNIT_TEST = (
    ROOT / "design/openclaw-cn/call-chain/debug/scripts/test_render_gt_coverage.py"
)
OPENCLAW_CN_BASELINE_RUNNER = ROOT / "scripts/test_openclaw_cn_gt_coverage.py"
NANOCLAW_INVENTORY_UNIT_TEST = (
    ROOT / "design/nanoclaw/inventory/debug/scripts/test_generate_inventory.py"
)
NANOCLAW_COVERAGE_UNIT_TEST = (
    ROOT / "design/nanoclaw/call-chain/debug/scripts/test_render_gt_coverage.py"
)
NANOCLAW_BASELINE_RUNNER = ROOT / "scripts/test_nanoclaw_gt_coverage.py"
MERCURY_AGENT_INVENTORY_UNIT_TEST = (
    ROOT / "design/mercury-agent/inventory/debug/scripts/test_generate_inventory.py"
)
MERCURY_AGENT_COVERAGE_UNIT_TEST = (
    ROOT / "design/mercury-agent/call-chain/debug/scripts/test_render_gt_coverage.py"
)
MERCURY_AGENT_BASELINE_RUNNER = ROOT / "scripts/test_mercury_agent_gt_coverage.py"
DROIDCLAW_INVENTORY_UNIT_TEST = (
    ROOT / "design/droidclaw/inventory/debug/scripts/test_generate_inventory.py"
)
DROIDCLAW_COVERAGE_UNIT_TEST = (
    ROOT / "design/droidclaw/call-chain/debug/scripts/test_render_gt_coverage.py"
)
DROIDCLAW_BASELINE_RUNNER = ROOT / "scripts/test_droidclaw_gt_coverage.py"
LETTABOT_BASELINE_RUNNER = ROOT / "scripts/test_lettabot_adapter.py"
ZERO_GATE_AUDIT_UNIT_TEST = (
    ROOT / "design/paperdata/script/test_generate_zero_gate_audit.py"
)

PROJECT_BASELINE_UNIT_TESTS = (
    HERMES_BASELINE_UNIT_TEST,
    COWAGENT_BASELINE_UNIT_TEST,
    ASTRBOT_BASELINE_UNIT_TEST,
    QWENPAW_BASELINE_UNIT_TEST,
    NANOBOT_BASELINE_UNIT_TEST,
    POCO_AGENT_BASELINE_UNIT_TEST,
    OPENCLAW_INVENTORY_UNIT_TEST,
    OPENCLAW_COVERAGE_UNIT_TEST,
    OPENCLAW_D5_COVERAGE_UNIT_TEST,
    OPENCLAW_CN_INVENTORY_UNIT_TEST,
    OPENCLAW_CN_COVERAGE_UNIT_TEST,
    NANOCLAW_INVENTORY_UNIT_TEST,
    NANOCLAW_COVERAGE_UNIT_TEST,
    MERCURY_AGENT_INVENTORY_UNIT_TEST,
    MERCURY_AGENT_COVERAGE_UNIT_TEST,
    DROIDCLAW_INVENTORY_UNIT_TEST,
    DROIDCLAW_COVERAGE_UNIT_TEST,
    ZERO_GATE_AUDIT_UNIT_TEST,
)
PROJECT_BASELINE_RUNNERS = (
    HERMES_BASELINE_RUNNER,
    COWAGENT_BASELINE_RUNNER,
    ASTRBOT_BASELINE_RUNNER,
    QWENPAW_BASELINE_RUNNER,
    NANOBOT_BASELINE_RUNNER,
    POCO_AGENT_BASELINE_RUNNER,
    OPENCLAW_BASELINE_RUNNER,
    OPENCLAW_CN_BASELINE_RUNNER,
    NANOCLAW_BASELINE_RUNNER,
    MERCURY_AGENT_BASELINE_RUNNER,
    DROIDCLAW_BASELINE_RUNNER,
    LETTABOT_BASELINE_RUNNER,
)


def run(command: Sequence[str | Path]) -> None:
    rendered = [str(part) for part in command]
    print(f"+ {shlex.join(rendered)}", flush=True)
    subprocess.run(rendered, cwd=ROOT, check=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run QL fixtures and fast project regression tests, then compile "
            "production queries and regenerate every registered revision-pinned project "
            "static acceptance baselines, including all TypeScript projects."
        )
    )
    parser.add_argument(
        "--unit-only",
        action="store_true",
        help=(
            "Run only fixture-based QL tests and fast project regression tests; "
            "the required pre-handoff check omits this flag."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not CODEQL.is_file():
        raise SystemExit(f"CodeQL executable not found: {CODEQL}")

    run(
        [
            CODEQL,
            "test",
            "run",
            f"--additional-packs={QL_PACK}",
            "--",
            QL_TESTS,
        ]
    )
    run(
        [
            CODEQL,
            "test",
            "run",
            "--threads=1",
            f"--additional-packs={JS_QL_PACK}",
            "--",
            JS_QL_TESTS,
        ]
    )
    for unit_test in PROJECT_BASELINE_UNIT_TESTS:
        run([sys.executable, unit_test])

    if not args.unit_only:
        queries = sorted(QL_PACK.glob("*.ql"))
        if not queries:
            raise SystemExit(f"No production QL queries found under {QL_PACK}")
        run(
            [
                CODEQL,
                "query",
                "compile",
                f"--additional-packs={QL_PACK}",
                *queries,
            ]
        )
        js_queries = sorted(JS_QL_PACK.glob("*.ql"))
        if not js_queries:
            raise SystemExit(f"No production QL queries found under {JS_QL_PACK}")
        run(
            [
                CODEQL,
                "query",
                "compile",
                f"--additional-packs={JS_QL_PACK}",
                *js_queries,
            ]
        )
        for runner in PROJECT_BASELINE_RUNNERS:
            run([sys.executable, runner])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Project-local entry point for the shared nanobot call-chain report."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[5]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from design.common.call_chain_report import run_call_chain_report  # noqa: E402


PROJECT_ID = "nanobot"
SCRIPT_PATH = Path("design/nanobot/call-chain/debug/script/count_detected_call_chains.py")


def main(argv: Sequence[str] | None = None) -> int:
    return run_call_chain_report(PROJECT_ID, SCRIPT_PATH, argv)


if __name__ == "__main__":
    raise SystemExit(main())

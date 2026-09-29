"""Isolated process entry point for one native exploit/control replay pair."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .adapters import CapabilitySandbox
from .contracts import ValidationError, atomic_write_json
from .native_drivers import run_native_pair_inprocess


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    request = json.loads(args.request.read_text(encoding="utf-8"))
    if request.get("schema_version") != "clawgap-runtime-native-driver-request/v1":
        raise ValidationError("unsupported native driver request")
    case = request["case"]
    sandbox = CapabilitySandbox(Path(request["sandbox_root"]), case)
    if not (sandbox.root / "fixture-manifest.json").is_file():
        sandbox.prepare()
    result = run_native_pair_inprocess(
        case,
        int(request["attempt"]),
        Path(request["attempt_dir"]),
        sandbox,
    )
    atomic_write_json(args.result, result)
    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(exit_code)

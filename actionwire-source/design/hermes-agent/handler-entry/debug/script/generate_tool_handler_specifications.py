#!/usr/bin/env python3
"""Compatibility launcher for the shared handler-specification extractor.

The public implementation now lives in ``src.handler_specifications``. Public
Hermes evaluator helpers are re-exported so existing focused tests and callers
continue to work, while command execution writes the canonical v2 artifacts to
``output/hermes/handler-specifications``.
"""

# ruff: noqa: E402

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Sequence

_REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from src.handler_specifications import core as shared_core
from src.handler_specifications import hermes as shared_hermes
from src.handler_specifications.hermes import *  # noqa: F401,F403
from src.handler_specifications.hermes import parse_args
from src.handler_specifications.service import (
    build_project_inventory,
    reproduction_command,
)
from src.projects import get_project


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    args = parse_args(raw)
    source_override = (
        args.source_root.resolve() != shared_hermes.DEFAULT_SOURCE_ROOT.resolve()
    )
    if source_override and not args.analysis_revision:
        raise ValueError("--source-root requires an explicit --analysis-revision")

    spec = get_project("hermes-agent")
    if source_override or args.analysis_revision:
        spec = spec.with_overrides(
            source_root=args.source_root,
            analysis_revision=args.analysis_revision,
        )
    command = reproduction_command(["--project", "hermes-agent"])
    inventory = build_project_inventory(
        spec,
        handler_inventory=args.handler_csv,
        command=command,
    )

    shared_core._atomic_write(  # noqa: SLF001 - compatibility output names
        args.out_json,
        json.dumps(inventory, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    shared_core._atomic_write(  # noqa: SLF001 - compatibility output names
        args.out_md,
        shared_core.render_markdown(inventory),
    )
    print(
        f"Wrote {inventory['counts']['unique_tools']} Hermes tool specifications "
        f"to {shared_core.repo_path(args.out_json)} and "
        f"{shared_core.repo_path(args.out_md)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

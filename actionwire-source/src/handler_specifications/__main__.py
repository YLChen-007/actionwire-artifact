"""Command-line entry point for shared handler-specification extraction."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from src.projects import get_project, list_projects

from .core import repo_path
from .service import (
    build_project_inventory,
    generate_all,
    reproduction_command,
    write_project_inventory,
)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--project", choices=list_projects())
    mode.add_argument("--all", action="store_true")
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--handler-inventory", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--output-directory", type=Path)
    args = parser.parse_args(argv)
    overrides = (
        args.source_root,
        args.handler_inventory,
        args.revision,
        args.output_directory,
    )
    if args.all and any(item is not None for item in overrides):
        parser.error("--all does not accept single-project path or revision overrides")
    if args.source_root is not None and args.revision is None:
        parser.error("--source-root requires an explicit --revision")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    args = parse_args(raw)
    if args.all:
        paths = generate_all()
        print(f"Wrote {len(paths)} project handler-specification artifact pairs.")
        return 0

    spec = get_project(args.project)
    if args.source_root is not None or args.revision is not None:
        spec = spec.with_overrides(
            source_root=args.source_root,
            analysis_revision=args.revision,
        )
    command = reproduction_command(raw)
    inventory = build_project_inventory(
        spec,
        handler_inventory=args.handler_inventory,
        command=command,
    )
    out_json, out_md = write_project_inventory(
        spec,
        inventory,
        output_directory=args.output_directory,
    )
    counts = inventory["counts"]
    print(
        f"Wrote {counts['unique_tools']} tool specifications "
        f"({counts['unresolved']} unresolved) to {repo_path(out_json)} and "
        f"{repo_path(out_md)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


"""CLI for cross-project NanoBot-seeded handler-type alignment."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path

from src.pipeline.provider import OpenAICompatibleRunner
from src.projects import get_project, list_projects

from .pipeline import run_handler_type_alignment


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", required=True)
    parser.add_argument(
        "--out-dir", type=Path, default=Path("output/cross-project/handler-types")
    )
    parser.add_argument("--model")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument(
        "--max-output-tokens",
        type=int,
        default=32768,
        help="output budget for canonicalization, matching, and adjudication batches",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(raw)
    nanobot = get_project("nanobot")
    if not os.environ.get(nanobot.llm.api_key_env, "").strip():
        raise SystemExit(f"set {nanobot.llm.api_key_env} before handler-type alignment")
    runner = OpenAICompatibleRunner(
        base_url=nanobot.llm.base_url,
        model=args.model or nanobot.llm.model,
        api_key_env=nanobot.llm.api_key_env,
        timeout=args.timeout,
        max_tokens=args.max_output_tokens,
    )
    manifest = run_handler_type_alignment(
        specs=[get_project(project_id) for project_id in list_projects()],
        out_dir=args.out_dir,
        generation_command=shlex.join(
            ["python", "-m", "src.handler_type_alignment", *raw]
        ),
        runner=runner,
    )
    print(json.dumps(manifest["counts"], indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

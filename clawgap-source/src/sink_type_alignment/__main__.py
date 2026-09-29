"""CLI for HC-conditioned global sink-type alignment."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from src.pipeline.provider import OpenAICompatibleRunner
from src.projects import get_project, list_projects

from .pipeline import run_sink_type_alignment
from .transport import ExactPromptReplayRunner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", required=True)
    parser.add_argument(
        "--handler-root",
        type=Path,
        default=Path("output/cross-project/handler-types"),
    )
    parser.add_argument(
        "--out-dir", type=Path, default=Path("output/cross-project/sink-types")
    )
    parser.add_argument("--model")
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="ignore exact audited prompt replays and call the configured model",
    )
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--max-output-tokens", type=int, default=32768)
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="preview the generated Markdown without replacing the output directory",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(raw)
    seed = get_project("nanobot")
    live_runner = OpenAICompatibleRunner(
        base_url=seed.llm.base_url,
        model=args.model or seed.llm.model,
        api_key_env=seed.llm.api_key_env,
        timeout=args.timeout,
        max_tokens=args.max_output_tokens,
    )
    runner = (
        live_runner
        if args.fresh
        else ExactPromptReplayRunner(live_runner, args.out_dir)
    )
    command = shlex.join(["python", "-m", "src.sink_type_alignment", *raw])
    result = run_sink_type_alignment(
        specs=[get_project(project_id) for project_id in list_projects()],
        handler_root=args.handler_root,
        out_dir=args.out_dir,
        generation_command=command,
        runner=runner,
        publish=not args.stdout,
    )
    if args.stdout:
        print(result["report"], end="")
    else:
        clear_checkpoint = getattr(runner, "clear_checkpoint", None)
        if callable(clear_checkpoint):
            clear_checkpoint()
        print(json.dumps(result["manifest"]["counts"], indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

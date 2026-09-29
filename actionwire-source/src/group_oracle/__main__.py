"""CLI for HC-conditioned group-oracle construction."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from src.pipeline.provider import OpenAICompatibleRunner
from src.projects import get_project, list_projects

from .pipeline import DEFAULT_INPUT_TOKEN_LIMIT, run_group_oracle
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
        "--sink-root",
        type=Path,
        default=Path("output/cross-project/sink-types"),
    )
    parser.add_argument(
        "--evidence-registry",
        type=Path,
        default=Path("src/group_oracle/oracle-evidence-registry.json"),
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("output/cross-project/group-oracles"),
    )
    parser.add_argument(
        "--correction-ledger",
        type=Path,
        help="validated post-hoc correction ledger; requires a non-baseline out-dir",
    )
    parser.add_argument("--model")
    parser.add_argument(
        "--group-id",
        action="append",
        dest="group_ids",
        help="infer only this HSG (repeatable); requires a separate output directory",
    )
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument(
        "--observed-gates-only", action="store_true",
        help="derive proposals from supplied gates only; evidence supports assessment but does not add zero-gate policies",
    )
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--gate-qualification", type=Path, help="reviewed, hash-bound model-origin gate selection for every selected member")
    parser.add_argument("--max-output-tokens", type=int, default=16384)
    parser.add_argument(
        "--input-token-limit", type=int, default=DEFAULT_INPUT_TOKEN_LIMIT
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="run the full inference and preview Markdown without publishing artifacts",
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
    runner = live_runner if args.fresh else ExactPromptReplayRunner(live_runner, args.out_dir)
    command = shlex.join(["python", "-m", "src.group_oracle", *raw])
    result = run_group_oracle(
        specs=[get_project(project_id) for project_id in list_projects()],
        handler_root=args.handler_root,
        sink_root=args.sink_root,
        evidence_registry=args.evidence_registry,
        out_dir=args.out_dir,
        generation_command=command,
        runner=runner,
        correction_ledger=args.correction_ledger,
        group_ids=args.group_ids,
        reuse_prior=not args.fresh,
        observed_gates_only=args.observed_gates_only,
        gate_qualification=args.gate_qualification,
        publish=not args.stdout,
        input_token_limit=args.input_token_limit,
    )
    if args.stdout:
        print(result["report"], end="")
    else:
        if callable(getattr(runner, "clear_checkpoint", None)):
            runner.clear_checkpoint()
        print(json.dumps(result["manifest"]["counts"], indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Command-line interface for the reusable multi-language benchmark pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

from src.projects import get_project, list_projects

from .orchestrator import PipelineError, run_stage


STAGES = (
    "infer-gates",
    "infer-call-chains",
    "infer-gate-semantics",
    "infer-call-chain-semantics",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the four-stage static/semantic pipeline for an agent benchmark."
    )
    parser.add_argument("--project", required=True, choices=list_projects())
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--design-root", type=Path)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--ground-truth-root", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--llm-base-url")
    parser.add_argument("--model")
    subparsers = parser.add_subparsers(dest="stage", required=True)
    for stage in (*STAGES, "all"):
        sub = subparsers.add_parser(stage)
        if stage in {"infer-gate-semantics", "all"}:
            selection = sub.add_mutually_exclusive_group()
            selection.add_argument("--gate-number", type=int, action="append")
            selection.add_argument("--only", nargs="*")
            sub.add_argument("--max-gates", type=int)
            sub.add_argument("--timeout", type=int, default=900)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    spec = get_project(args.project).with_overrides(
        source_root=args.source_root,
        codeql_database=args.database,
        design_root=args.design_root,
        output_root=args.output_root,
        ground_truth_root=args.ground_truth_root,
        analysis_revision=args.revision,
    )
    if args.llm_base_url or args.model:
        spec = replace(
            spec,
            llm=replace(
                spec.llm,
                base_url=args.llm_base_url or spec.llm.base_url,
                model=args.model or spec.llm.model,
            ),
        )
    gate_numbers = getattr(args, "gate_number", None)
    if gate_numbers and (any(number < 1 for number in gate_numbers) or len(gate_numbers) != len(set(gate_numbers))):
        parser.error("--gate-number values must be positive and unique")
    max_gates = getattr(args, "max_gates", None)
    if max_gates is not None and max_gates < 1:
        parser.error("--max-gates must be positive")
    stages = STAGES if args.stage == "all" else (args.stage,)
    try:
        for stage in stages:
            manifest = run_stage(
                spec,
                stage,
                gate_numbers=gate_numbers,
                only=set(getattr(args, "only", None) or []),
                max_gates=max_gates,
                timeout=getattr(args, "timeout", 900),
            )
            print(
                json.dumps(
                    {"stage": stage, "counts": manifest.get("counts", {})},
                    indent=2,
                    ensure_ascii=False,
                )
            )
            if manifest.get("counts", {}).get("slice_failures") or manifest.get("counts", {}).get("analysis_failures") or manifest.get("counts", {}).get("assembly_failures"):
                return 1
    except (PipelineError, FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())

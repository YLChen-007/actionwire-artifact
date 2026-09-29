"""CLI for callsite-bound gate semantic extraction through a Claude agent."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from .pipeline import GateSelectionError, run_pipeline


DEFAULT_DEBUG = Path("design/hermes-agent/gate/debug")
DEFAULT_OUTPUT = Path("output/hermes/gate-semantics")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build callsite-bound gate source slices and compact GateSemanticIRV1 "
            "records using the read-only Claude Agent SDK with LSP-MCP research."
        )
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path("benchmark/python/hermes-agent"),
        help="analyzed Hermes Python source root",
    )
    parser.add_argument(
        "--dominance-candidates",
        type=Path,
        default=DEFAULT_DEBUG / "gate-candidates.csv",
    )
    parser.add_argument(
        "--filter-candidates",
        type=Path,
        default=DEFAULT_DEBUG / "gate-filter.csv",
    )
    parser.add_argument(
        "--transform-candidates",
        type=Path,
        default=DEFAULT_DEBUG / "transform-candidates.csv",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=(
            "canonical output directory for slices, per-gate semantic JSON, "
            "audit sidecars, catalogs, and the manifest"
        ),
    )
    parser.add_argument(
        "--build-slices-only",
        action="store_true",
        help="build deterministic GateSliceV1 inputs without invoking Claude",
    )
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument(
        "--only",
        nargs="*",
        default=None,
        help="restrict to gate UIDs, current gate IDs, or detector gate names",
    )
    selection.add_argument(
        "--gate-number",
        action="append",
        type=int,
        default=None,
        help=(
            "analyze one catalog ordinal; repeat for multiple gates. Numbering is "
            "assigned over the complete current catalog before filtering; repository "
            "lookup uses gate_uid, not this ordinal"
        ),
    )
    parser.add_argument(
        "--max-gates",
        type=int,
        default=None,
        help="analyze at most this many sorted gate instances",
    )
    parser.add_argument(
        "--model", default=None, help="override the configured agent model"
    )
    parser.add_argument(
        "--timeout", type=int, default=900, help="per-gate timeout in seconds"
    )
    parser.add_argument(
        "--max-turns",
        type=int,
        default=20,
        help="maximum Claude tool-use turns per gate",
    )
    parser.add_argument(
        "--agent-transport",
        choices=("sdk", "cli"),
        default="sdk",
        help=(
            "Claude transport: Agent SDK with structured LSP audit (default), or "
            "the legacy CLI fallback"
        ),
    )
    parser.add_argument(
        "--no-lsp",
        action="store_true",
        help="disable LSP-MCP while preserving Read, Grep, and Glob",
    )
    parser.add_argument(
        "--debug-fidelity-review",
        action="store_true",
        help=(
            "run an additional boundary/fidelity reviewer after the normal one-call "
            "gate analysis; intended only for selected-gate debugging"
        ),
    )
    return parser


def explicit_generation_command(args: argparse.Namespace) -> str:
    parts = [
        "python",
        "-m",
        "src.gate_semantics.main",
        "--source-root",
        str(args.source_root),
        "--dominance-candidates",
        str(args.dominance_candidates),
        "--filter-candidates",
        str(args.filter_candidates),
        "--transform-candidates",
        str(args.transform_candidates),
        "--out-dir",
        str(args.out_dir),
        "--timeout",
        str(args.timeout),
        "--max-turns",
        str(args.max_turns),
        "--agent-transport",
        args.agent_transport,
    ]
    if args.no_lsp:
        parts.append("--no-lsp")
    if args.debug_fidelity_review:
        parts.append("--debug-fidelity-review")
    if args.build_slices_only:
        parts.append("--build-slices-only")
    if args.only:
        parts.extend(["--only", *args.only])
    for gate_number in args.gate_number or []:
        parts.extend(["--gate-number", str(gate_number)])
    if args.max_gates is not None:
        parts.extend(["--max-gates", str(args.max_gates)])
    if args.model:
        parts.extend(["--model", args.model])
    return shlex.join(parts)


def independent_example_command(args: argparse.Namespace, gate_number: int = 4) -> str:
    parts = [
        "python",
        "-m",
        "src.gate_semantics.main",
        "--source-root",
        str(args.source_root),
        "--dominance-candidates",
        str(args.dominance_candidates),
        "--filter-candidates",
        str(args.filter_candidates),
        "--transform-candidates",
        str(args.transform_candidates),
        "--out-dir",
        str(args.out_dir),
        "--gate-number",
        str(gate_number),
        "--timeout",
        str(args.timeout),
        "--max-turns",
        str(args.max_turns),
        "--agent-transport",
        args.agent_transport,
    ]
    if args.no_lsp:
        parts.append("--no-lsp")
    if args.debug_fidelity_review:
        parts.append("--debug-fidelity-review")
    if args.model:
        parts.extend(["--model", args.model])
    return shlex.join(parts)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_gates is not None and args.max_gates < 1:
        parser.error("--max-gates must be positive")
    if args.gate_number:
        if any(number < 1 for number in args.gate_number):
            parser.error("--gate-number must be positive")
        if len(args.gate_number) != len(set(args.gate_number)):
            parser.error("--gate-number values must be unique")

    try:
        manifest = run_pipeline(
            source_root=args.source_root,
            dominance_candidates=args.dominance_candidates,
            filter_candidates=args.filter_candidates,
            transform_candidates=args.transform_candidates,
            out_dir=args.out_dir,
            generation_command=explicit_generation_command(args),
            build_slices_only=args.build_slices_only,
            model=args.model,
            timeout=args.timeout,
            max_turns=args.max_turns,
            agent_transport=args.agent_transport,
            enable_lsp=not args.no_lsp,
            debug_fidelity_review=args.debug_fidelity_review,
            max_gates=args.max_gates,
            only=set(args.only or []),
            gate_numbers=args.gate_number,
            independent_example_command=independent_example_command(args),
        )
    except GateSelectionError as exc:
        parser.error(str(exc))
    print(json.dumps(manifest["counts"], indent=2, ensure_ascii=False))
    return (
        1
        if manifest["counts"]["slice_failures"]
        or manifest["counts"]["analysis_failures"]
        else 0
    )


if __name__ == "__main__":
    sys.exit(main())

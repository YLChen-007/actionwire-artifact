"""CLI for deterministic ordered call-chain gate semantics."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from .assembler import ChainAssemblyError
from .pipeline import run_pipeline


CALL_DEBUG = Path("design/hermes-agent/call-chain/debug")
GATE_OUTPUT = Path("output/hermes/gate-semantics")
CALL_OUTPUT = Path("output/hermes/call-chain-semantics")
DEFAULT_GT = Path(
    "design/hermes-agent/groudtruth/new-vuls/"
    "feat__configurable_approval_mode_for_cron_jobs__approvals_cr-762f7e97-"
    "Batch-Runner-Variant.json"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Assemble per-gate semantic IRs into one ordered sink-bounded record."
    )
    parser.add_argument(
        "--source-root", type=Path, default=Path("benchmark/python/hermes-agent")
    )
    parser.add_argument("--ground-truth-json", type=Path, default=DEFAULT_GT)
    parser.add_argument(
        "--coverage-items",
        type=Path,
        default=CALL_DEBUG / "d5-chain-coverage-items.csv",
    )
    parser.add_argument(
        "--handler-sink-chains",
        type=Path,
        default=CALL_DEBUG / "handler-sink-chains.csv",
    )
    parser.add_argument(
        "--chain-gates", type=Path, default=CALL_DEBUG / "chain-gates.csv"
    )
    parser.add_argument(
        "--gate-index",
        type=Path,
        default=None,
        help="gate catalog; defaults to <gate-semantics-dir>/gate-index.csv",
    )
    parser.add_argument(
        "--gate-semantics-dir",
        type=Path,
        default=GATE_OUTPUT,
        help=(
            "canonical per-gate artifact store produced by src.gate_semantics; "
            "the chain stage reads repository/<gate_uid>/semantic.json"
        ),
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=CALL_OUTPUT,
        help="canonical output directory for assembled call-chain semantics",
    )
    return parser


def explicit_generation_command(args: argparse.Namespace) -> str:
    gate_index = args.gate_index or args.gate_semantics_dir / "gate-index.csv"
    parts = [
        "python",
        "-m",
        "src.call_chain_semantics.main",
        "--source-root",
        str(args.source_root),
        "--ground-truth-json",
        str(args.ground_truth_json),
        "--coverage-items",
        str(args.coverage_items),
        "--handler-sink-chains",
        str(args.handler_sink_chains),
        "--chain-gates",
        str(args.chain_gates),
        "--gate-index",
        str(gate_index),
        "--gate-semantics-dir",
        str(args.gate_semantics_dir),
        "--out-dir",
        str(args.out_dir),
    ]
    return shlex.join(parts)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    gate_index = args.gate_index or args.gate_semantics_dir / "gate-index.csv"
    try:
        manifest = run_pipeline(
            source_root=args.source_root,
            ground_truth_json=args.ground_truth_json,
            coverage_items_csv=args.coverage_items,
            handler_sink_chains_csv=args.handler_sink_chains,
            chain_gates_csv=args.chain_gates,
            gate_index_csv=gate_index,
            gate_semantics_dir=args.gate_semantics_dir,
            out_dir=args.out_dir,
            generation_command=explicit_generation_command(args),
        )
    except ChainAssemblyError as exc:
        parser.error(str(exc))
    print(json.dumps(manifest["counts"], indent=2, ensure_ascii=False))
    return 1 if manifest["counts"]["assembly_failures"] else 0


if __name__ == "__main__":
    sys.exit(main())

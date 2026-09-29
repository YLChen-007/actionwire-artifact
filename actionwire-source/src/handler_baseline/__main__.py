"""CLI for the blind Claude Code per-handler comparison experiment."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from src.projects import get_project, list_projects

from .contracts import (
    ALL_FINDINGS_POLICY,
    MOST_CREDIBLE_VULNERABILITIES_POLICY,
    REPORT_POLICIES,
    BaselineError,
)
from .ground_truth import run_ground_truth_audit
from .inventory import build_inventory, inventory_digest, inventory_jsonl
from .pipeline import run_blind_experiment
from .scope import build_ground_truth_handler_scope
from .transport import DEFAULT_BASE_URL, DEFAULT_MODEL


DEFAULT_OUT = Path("output/cross-project/claude-handler-baseline")
GROUND_TRUTH_HANDLERS_OUT = Path(
    "output/cross-project/claude-handler-baseline-ground-truth-handlers"
)
CREDIBLE_OUT = Path(
    "output/cross-project/claude-handler-baseline-credible-vulnerabilities"
)
CREDIBLE_GROUND_TRUTH_HANDLERS_OUT = Path(
    "output/cross-project/claude-handler-baseline-credible-vulnerabilities-ground-truth-handlers"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--claude-bin", default="claude")
    parser.add_argument("--bwrap-bin", default="bwrap")
    parser.add_argument(
        "--report-policy",
        choices=REPORT_POLICIES,
        default=ALL_FINDINGS_POLICY,
        help="blind reporting contract; the precision-first policy returns at most two vulnerabilities",
    )
    parser.add_argument("--only", help="run one exact HB-* trial ID")
    parser.add_argument(
        "--inventory-only", action="store_true",
        help="print the deterministic inventory without invoking Claude Code",
    )
    parser.add_argument(
        "--ground-truth-only", action="store_true",
        help="audit frozen blind findings against curated new-vuls reports",
    )
    parser.add_argument(
        "--ground-truth-handlers",
        action="store_true",
        help=(
            "select one blind trial per unique current handler referenced by curated "
            "ground truth; report details are never exposed to Claude"
        ),
    )
    parser.add_argument("--max-output-tokens", type=int, default=4096)
    return parser


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(raw)
    specs = [get_project(name) for name in list_projects()]
    trials = build_inventory(specs)
    scope_manifest = None
    if args.ground_truth_handlers:
        trials, scope_manifest = build_ground_truth_handler_scope(
            specs=specs, trials=trials
        )
    if args.out_dir is not None:
        out_dir = args.out_dir
    elif args.report_policy == MOST_CREDIBLE_VULNERABILITIES_POLICY:
        out_dir = (
            CREDIBLE_GROUND_TRUTH_HANDLERS_OUT
            if args.ground_truth_handlers
            else CREDIBLE_OUT
        )
    else:
        out_dir = GROUND_TRUTH_HANDLERS_OUT if args.ground_truth_handlers else DEFAULT_OUT
    if args.inventory_only:
        print(inventory_jsonl(trials), end="")
        summary = {
            "projects": len({trial.project for trial in trials}),
            "trials": len(trials),
            "digest": inventory_digest(trials),
        }
        if scope_manifest is not None:
            summary["ground_truth_scope"] = scope_manifest["counts"]
            summary["ground_truth_scope_digest"] = scope_manifest["scope_digest"]
        print(json.dumps(summary, ensure_ascii=False), file=sys.stderr)
        return 0
    command = shlex.join(["python", "-m", "src.handler_baseline", *raw])
    if args.ground_truth_only:
        result = run_ground_truth_audit(
            specs=specs,
            out_dir=out_dir,
            generation_command=command,
            model=args.model,
            base_url=args.base_url,
            timeout=args.timeout,
            max_output_tokens=args.max_output_tokens,
        )
        print(json.dumps(result["manifest"]["counts"], indent=2, ensure_ascii=False))
        return 0
    if args.only:
        selected = [trial for trial in trials if trial.trial_id == args.only]
        if not selected:
            raise BaselineError(f"unknown trial ID: {args.only}")
        run_out_dir = out_dir / "focused" / args.only
    else:
        selected = trials
        run_out_dir = out_dir
    result = run_blind_experiment(
        trials=selected,
        out_dir=run_out_dir,
        generation_command=command,
        workers=args.workers,
        timeout=args.timeout,
        model=args.model,
        base_url=args.base_url,
        claude_bin=args.claude_bin,
        bwrap_bin=args.bwrap_bin,
        allow_freeze=args.only is None,
        scope_manifest=scope_manifest,
        report_policy=args.report_policy,
    )
    print(json.dumps(result["manifest"]["counts"], indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BaselineError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

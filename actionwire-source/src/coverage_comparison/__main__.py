"""Single canonical CR coverage-comparison CLI."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.pipeline.provider import OpenAICompatibleRunner
from src.projects import get_project, list_projects

from .contracts import CoverageComparisonError
from .transport import ExactPromptReplayRunner
from .v8 import (
    ANALYSIS_MODE as V8_ANALYSIS_MODE,
    prepare_v8,
    publish_v8,
    validate_v8_artifacts,
)
from .v9 import (
    ANALYSIS_MODE as V9_ANALYSIS_MODE,
    prepare_v9,
    publish_v9,
    validate_v9_artifacts,
)
from .v10 import (
    ANALYSIS_MODE as V10_ANALYSIS_MODE,
    prepare_v10,
    publish_v10,
    validate_v10_artifacts,
)
from .v11 import (
    ANALYSIS_MODE as V11_ANALYSIS_MODE,
    prepare_v11,
    publish_v11,
    validate_v11_artifacts,
)
from .v12 import (
    ANALYSIS_MODE as V12_ANALYSIS_MODE,
    prepare_v12,
    publish_v12,
    validate_v12_artifacts,
)
from .v13 import (
    ANALYSIS_MODE as V13_ANALYSIS_MODE,
    prepare_v13,
    publish_v13,
    validate_v13_artifacts,
)
from .v14 import (
    ANALYSIS_MODE as V14_ANALYSIS_MODE,
    prepare_v14,
    publish_v14,
    validate_v14_artifacts,
)
from .v15 import (
    ANALYSIS_MODE as V15_ANALYSIS_MODE,
    prepare_v15,
    publish_v15,
    validate_v15_artifacts,
)
from .v7_artifacts import analysis_plan, validate_v7_artifacts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", required=True)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("output/cross-project/coverage-comparison"),
    )
    parser.add_argument("--canonical-source-budget", type=int, default=64)
    parser.add_argument(
        "--canonical-source-scope", choices=("routed", "all"), default="routed"
    )
    parser.add_argument("--canonical-source-jobs", type=int, default=4)
    parser.add_argument("--canonical-source-max-turns", type=int, default=8)
    parser.add_argument(
        "--source-validation-strategy",
        choices=("packet-first", "agent-only"),
        default="packet-first",
    )
    parser.add_argument(
        "--source-validation-deep-max-tool-calls", type=int, default=16
    )
    parser.add_argument("--fresh-canonical-source-analysis", action="store_true")
    parser.add_argument(
        "--learned-invariant-catalog",
        type=Path,
        default=Path("src/coverage_comparison/learned-invariants.json"),
    )
    parser.add_argument("--learned-invariant-jobs", type=int, default=4)
    parser.add_argument("--fresh-learned-invariant-analysis", action="store_true")
    parser.add_argument("--full-source-validation", action="store_true")
    parser.add_argument("--analysis-plan", action="store_true")
    parser.add_argument("--replay-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    if args.canonical_source_budget < 1:
        raise CoverageComparisonError("canonical source budget must be positive")
    if args.canonical_source_jobs < 1 or args.learned_invariant_jobs < 1:
        raise CoverageComparisonError("canonical job counts must be positive")
    if (
        args.fresh_canonical_source_analysis
        or args.fresh_learned_invariant_analysis
        or args.full_source_validation
        or args.canonical_source_scope == "all"
    ):
        raise CoverageComparisonError(
            "fresh CR v7 inference requires a new detector freeze; current canonical "
            "publication is replay-only and fail-closed"
        )
    manifest_path = args.out_dir / "manifest.json"
    if not manifest_path.is_file():
        raise CoverageComparisonError("canonical coverage manifest is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    mode = manifest.get("analysis_mode")
    if mode == V15_ANALYSIS_MODE:
        result = validate_v15_artifacts(args.out_dir)
    elif mode == V14_ANALYSIS_MODE:
        if args.replay_only:
            result = validate_v14_artifacts(args.out_dir)
        elif args.analysis_plan:
            result = {
                "analysis_mode": V14_ANALYSIS_MODE,
                "next_analysis_mode": V15_ANALYSIS_MODE,
                "capability_card_schema": "sink-capability-card/v2",
                "generic_candidate_partition": True,
                "member_applicability": True,
                "training_fallback_limit": 4,
                "training_recall_gate": "43/43",
            }
        else:
            stage_root = args.out_dir.parent / "coverage-comparison-v15-staging"
            prepare_v15(
                specs=[get_project(project_id) for project_id in list_projects()],
                active_root=args.out_dir,
                group_root=Path("output/cross-project/group-oracles"),
                stage_root=stage_root,
                fallback_registry_path=Path(
                    "src/coverage_comparison/normative-provenance-repairs-v14.json"
                ),
                learned_catalog_path=args.learned_invariant_catalog,
            )
            validate_v15_artifacts(stage_root)
            publish_v15(
                active_root=args.out_dir,
                stage_root=stage_root,
                archive_root=args.out_dir.parent
                / "archive/coverage-comparison-v14",
            )
            result = validate_v15_artifacts(args.out_dir)
    elif mode == V13_ANALYSIS_MODE:
        if args.analysis_plan:
            result = {
                "analysis_mode": V13_ANALYSIS_MODE,
                "next_analysis_mode": V14_ANALYSIS_MODE,
                "ordinary_capability_card_normative": False,
                "member_scoped_training_repairs": 4,
                "training_recall_gate": "43/43",
            }
        else:
            stage_root = args.out_dir.parent / "coverage-comparison-v14-staging"
            prepare_v14(
                active_root=args.out_dir,
                base_v9_root=args.out_dir.parent
                / "archive/coverage-comparison-v9",
                group_root=Path("output/cross-project/group-oracles"),
                stage_root=stage_root,
                repair_registry_path=Path(
                    "src/coverage_comparison/normative-provenance-repairs-v14.json"
                ),
            )
            validate_v14_artifacts(stage_root)
            publish_v14(
                active_root=args.out_dir,
                stage_root=stage_root,
                archive_root=args.out_dir.parent
                / "archive/coverage-comparison-v13",
            )
            result = validate_v14_artifacts(args.out_dir)
    elif mode == V12_ANALYSIS_MODE:
        if args.analysis_plan:
            result = {
                "analysis_mode": V12_ANALYSIS_MODE,
                "next_analysis_mode": V13_ANALYSIS_MODE,
                "deferred_candidate_target": 149,
                "partial_group_fail_closed": True,
                "training_recall_gate": "43/43",
            }
        else:
            if args.replay_only:
                raise CoverageComparisonError(
                    "v13 dense-chain validation requires content-bound packet calls"
                )
            seed = get_project("nanobot")
            packet_runner = OpenAICompatibleRunner(
                base_url=seed.llm.base_url,
                model=seed.llm.model,
                api_key_env=seed.llm.api_key_env,
                timeout=900,
                max_tokens=8192,
            )
            stage_root = args.out_dir.parent / "coverage-comparison-v13-staging"
            prepare_v13(
                specs=[get_project(project_id) for project_id in list_projects()],
                active_root=args.out_dir,
                base_v9_root=args.out_dir.parent
                / "archive/coverage-comparison-v9",
                stage_root=stage_root,
                handler_root=Path("output/cross-project/handler-types"),
                sink_root=Path("output/cross-project/sink-types"),
                group_root=Path("output/cross-project/group-oracles"),
                evidence_registry=Path(
                    "src/group_oracle/oracle-evidence-registry.json"
                ),
                packet_runner=packet_runner,
            )
            validate_v13_artifacts(stage_root)
            publish_v13(
                active_root=args.out_dir,
                stage_root=stage_root,
                archive_root=args.out_dir.parent
                / "archive/coverage-comparison-v12",
            )
            result = validate_v13_artifacts(args.out_dir)
    elif mode == V11_ANALYSIS_MODE:
        if args.analysis_plan:
            result = {
                "analysis_mode": V11_ANALYSIS_MODE,
                "next_analysis_mode": V12_ANALYSIS_MODE,
                "structured_applicability": True,
                "wrong_check_batches": 33,
                "training_recall_gate": "43/43",
            }
        else:
            if args.replay_only:
                raise CoverageComparisonError(
                    "v12 wrong-check validation requires content-bound packet calls"
                )
            seed = get_project("nanobot")
            packet_runner = OpenAICompatibleRunner(
                base_url=seed.llm.base_url,
                model=seed.llm.model,
                api_key_env=seed.llm.api_key_env,
                timeout=900,
                max_tokens=8192,
            )
            stage_root = args.out_dir.parent / "coverage-comparison-v12-staging"
            prepare_v12(
                specs=[get_project(project_id) for project_id in list_projects()],
                active_root=args.out_dir,
                base_v9_root=args.out_dir.parent
                / "archive/coverage-comparison-v9",
                stage_root=stage_root,
                handler_root=Path("output/cross-project/handler-types"),
                sink_root=Path("output/cross-project/sink-types"),
                group_root=Path("output/cross-project/group-oracles"),
                evidence_registry=Path(
                    "src/group_oracle/oracle-evidence-registry.json"
                ),
                packet_runner=packet_runner,
            )
            validate_v12_artifacts(stage_root)
            publish_v12(
                active_root=args.out_dir,
                stage_root=stage_root,
                archive_root=args.out_dir.parent
                / "archive/coverage-comparison-v11",
            )
            result = validate_v12_artifacts(args.out_dir)
    elif mode == V10_ANALYSIS_MODE:
        if args.analysis_plan:
            result = {
                "analysis_mode": V10_ANALYSIS_MODE,
                "next_analysis_mode": V11_ANALYSIS_MODE,
                "direct_model_reachable_impact": True,
                "full_conjunctive_rule_support": True,
                "training_recall_gate": "43/43",
            }
        else:
            stage_root = args.out_dir.parent / "coverage-comparison-v11-staging"
            prepare_v11(
                active_root=args.out_dir,
                base_v9_root=args.out_dir.parent
                / "archive/coverage-comparison-v9",
                stage_root=stage_root,
            )
            validate_v11_artifacts(stage_root)
            publish_v11(
                active_root=args.out_dir,
                stage_root=stage_root,
                archive_root=args.out_dir.parent
                / "archive/coverage-comparison-v10",
            )
            result = validate_v11_artifacts(args.out_dir)
    elif mode == V9_ANALYSIS_MODE:
        if args.analysis_plan:
            result = {
                "analysis_mode": V9_ANALYSIS_MODE,
                "next_analysis_mode": V10_ANALYSIS_MODE,
                "canonical_promotion": "source-confirmed-only",
                "training_recall_gate": "43/43",
                "synthetic_detectability_gate": "46/46-separate",
            }
        else:
            if args.replay_only:
                raise CoverageComparisonError(
                    "v10 precision staging requires content-bound packet calls"
                )
            seed = get_project("nanobot")
            packet_runner = OpenAICompatibleRunner(
                base_url=seed.llm.base_url,
                model=seed.llm.model,
                api_key_env=seed.llm.api_key_env,
                timeout=900,
                max_tokens=8192,
            )
            stage_root = args.out_dir.parent / "coverage-comparison-v10-staging"
            prepare_v10(
                specs=[get_project(project_id) for project_id in list_projects()],
                active_root=args.out_dir,
                stage_root=stage_root,
                handler_root=Path("output/cross-project/handler-types"),
                sink_root=Path("output/cross-project/sink-types"),
                group_root=Path("output/cross-project/group-oracles"),
                evidence_registry=Path(
                    "src/group_oracle/oracle-evidence-registry.json"
                ),
                packet_runner=packet_runner,
            )
            validate_v10_artifacts(stage_root)
            publish_v10(
                active_root=args.out_dir,
                stage_root=stage_root,
                archive_root=args.out_dir.parent
                / "archive/coverage-comparison-v9",
            )
            result = validate_v10_artifacts(args.out_dir)
    elif mode == V8_ANALYSIS_MODE:
        if args.analysis_plan:
            result = {
                "analysis_mode": V8_ANALYSIS_MODE,
                "next_analysis_mode": V9_ANALYSIS_MODE,
                "source_validation_strategy": args.source_validation_strategy,
                "deep_max_turns": args.canonical_source_max_turns,
                "deep_max_tool_calls": args.source_validation_deep_max_tool_calls,
                "training_recall_gate": "43/43",
            }
        else:
            if args.replay_only:
                raise CoverageComparisonError(
                    "v9 staging has no complete replay cache; live calls are required"
                )
            if (
                args.source_validation_strategy != "packet-first"
                or args.canonical_source_max_turns != 8
                or args.source_validation_deep_max_tool_calls != 16
            ):
                raise CoverageComparisonError(
                    "canonical v9 requires packet-first, 8 deep turns, and 16 tool calls"
                )
            seed = get_project("nanobot")

            def new_runner(max_tokens: int) -> OpenAICompatibleRunner:
                return OpenAICompatibleRunner(
                    base_url=seed.llm.base_url,
                    model=seed.llm.model,
                    api_key_env=seed.llm.api_key_env,
                    timeout=900,
                    max_tokens=max_tokens,
                )

            stage_root = args.out_dir.parent / "coverage-comparison-v9-staging"
            prepare_v9(
                specs=[get_project(project_id) for project_id in list_projects()],
                active_root=args.out_dir,
                stage_root=stage_root,
                handler_root=Path("output/cross-project/handler-types"),
                sink_root=Path("output/cross-project/sink-types"),
                group_root=Path("output/cross-project/group-oracles"),
                evidence_registry=Path(
                    "src/group_oracle/oracle-evidence-registry.json"
                ),
                learned_runner=new_runner(16384),
                packet_runner=new_runner(8192),
                gt_runner=new_runner(4096),
            )
            validate_v9_artifacts(stage_root)
            publish_v9(
                active_root=args.out_dir,
                stage_root=stage_root,
                archive_root=args.out_dir.parent
                / "archive/coverage-comparison-v8",
            )
            result = validate_v9_artifacts(args.out_dir)
    elif mode == "canonical-trained-detector/v7":
        if args.analysis_plan:
            result = {
                **analysis_plan(args.out_dir),
                "next_analysis_mode": V8_ANALYSIS_MODE,
                "approval_policy_scope": sorted(
                    ["hermes-agent:C-728f8e5e6c99", "mercury-agent:C-11e5d5e54b4a"]
                ),
            }
        else:
            validate_v7_artifacts(args.out_dir)
            seed = get_project("nanobot")
            live_runner = OpenAICompatibleRunner(
                base_url=seed.llm.base_url,
                model=seed.llm.model,
                api_key_env=seed.llm.api_key_env,
                timeout=900,
                max_tokens=32768,
            )
            stage_root = args.out_dir.parent / "coverage-comparison-v8-staging"
            runner = ExactPromptReplayRunner(
                live_runner,
                args.out_dir,
                checkpoint_root=stage_root,
                replay_only=args.replay_only,
            )
            specs = [get_project(project_id) for project_id in list_projects()]
            prepare_v8(
                specs=specs,
                active_root=args.out_dir,
                stage_root=stage_root,
                handler_root=Path("output/cross-project/handler-types"),
                sink_root=Path("output/cross-project/sink-types"),
                group_root=Path("output/cross-project/group-oracles"),
                evidence_registry=Path(
                    "src/group_oracle/oracle-evidence-registry.json"
                ),
                runner=runner,
            )
            validate_v8_artifacts(stage_root)
            publish_v8(
                active_root=args.out_dir,
                stage_root=stage_root,
                archive_root=args.out_dir.parent
                / "archive/coverage-comparison-v7",
            )
            runner.clear_checkpoint()
            result = validate_v8_artifacts(args.out_dir)
    else:
        raise CoverageComparisonError(
            f"unsupported canonical analysis mode {mode!r}"
        )
    payload = result if args.analysis_plan else result["manifest"]["counts"]
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

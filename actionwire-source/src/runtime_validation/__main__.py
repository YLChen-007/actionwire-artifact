"""Validate whether an LLM agent prompt triggers a revision-bound runtime issue."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .campaign import run_campaign
from .campaign_contracts import CampaignGenerationRequest, CampaignRunRequest
from .contracts import INCONCLUSIVE, NOT_TRIGGERED, ValidationError, ValidationRequest
from .generation import generate_covered_campaign
from .pipeline import validate_prompt
from .upgrade import CampaignUpgradeRequest, upgrade_covered_campaign
from .provision import ProvisionRequest, provision_drivers
from .triggerability import TriggerabilityRequest, audit_ground_truth_tool_triggerability
from .ground_truth_campaign import (
    audit_ground_truth,
    generate_ground_truth_campaign,
    review_ground_truth_campaign,
    run_ground_truth_campaign,
)
from .ground_truth_contracts import (
    GroundTruthAuditRequest,
    GroundTruthGenerationRequest,
    GroundTruthReviewRequest,
    GroundTruthRunRequest,
)
from .production_like_smoke import run_production_like_smoke
from .propagation_contracts import ProductionLikeSmokeRequest
from .agent_campaign import run_agent_runtime_validation
from .agent_contracts import AgentRuntimeValidationRequest
from .dynamic_trigger import (
    DynamicTriggerGenerationRequest,
    DynamicTriggerReviewRequest,
    DynamicTriggerRunRequest,
    generate_dynamic_trigger,
    provision_dynamic_drivers,
    review_dynamic_trigger,
    run_dynamic_trigger,
)
from .l2_runtime import (
    L2QualificationRequest,
    L2RunRequest,
    qualify_l2,
    run_l2,
)
from .droidclaw_l2 import (
    DEFAULT_SOURCE_CAMPAIGN as DEFAULT_DROIDCLAW_SOURCE_CAMPAIGN,
    DroidClawL2RunRequest,
    run_droidclaw_l2,
)
from .mercury_l2 import (
    DEFAULT_SOURCE_CAMPAIGN as DEFAULT_MERCURY_SOURCE_CAMPAIGN,
    MercuryL2RunRequest,
    run_mercury_l2,
)
from .letta_l2 import DEFAULT_SOURCE_CAMPAIGN, LettaL2RunRequest, run_letta_l2
from .openclaw_l2 import (
    DEFAULT_SOURCE_CAMPAIGN as DEFAULT_OPENCLAW_SOURCE_CAMPAIGN,
    OpenClawL2RunRequest,
    run_openclaw_l2,
)
from .openclaw_cn_l2 import (
    DEFAULT_SOURCE_CAMPAIGN as DEFAULT_OPENCLAW_CN_SOURCE_CAMPAIGN,
    OpenClawCNL2RunRequest,
    run_openclaw_cn_l2,
)
from .nanoclaw_l2 import (
    DEFAULT_SOURCE_CAMPAIGN as DEFAULT_NANOCLAW_SOURCE_CAMPAIGN,
    NanoClawL2RunRequest,
    run_nanoclaw_l2,
)
from .chatgpt_on_wechat_l2 import (
    DEFAULT_SOURCE_CAMPAIGN as DEFAULT_CHATGPT_ON_WECHAT_SOURCE_CAMPAIGN,
    ChatGPTOnWeChatL2RunRequest,
    run_chatgpt_on_wechat_l2,
)
from .astrbot_l2 import (
    DEFAULT_SOURCE_CAMPAIGN as DEFAULT_ASTRBOT_SOURCE_CAMPAIGN,
    AstrBotL2RunRequest,
    run_astrbot_l2,
)
from .qwenpaw_l2 import (
    DEFAULT_SOURCE_CAMPAIGN as DEFAULT_QWENPAW_SOURCE_CAMPAIGN,
    QwenPawL2RunRequest,
    run_qwenpaw_l2,
)
from .hermes_agent_l2 import (
    DEFAULT_SOURCE_CAMPAIGN as DEFAULT_HERMES_AGENT_SOURCE_CAMPAIGN,
    HermesAgentL2RunRequest,
    run_hermes_agent_l2,
)
from .nanobot_l2 import (
    DEFAULT_SOURCE_CAMPAIGN as DEFAULT_NANOBOT_SOURCE_CAMPAIGN,
    NanobotL2RunRequest,
    run_nanobot_l2,
)
from .source_revised_native_l2 import (
    SourceRevisedNativeL2RunRequest,
    run_source_revised_native_l2,
)
from .environment_smoke import EnvironmentSmokeRequest, run_environment_smoke
from .environment_builder import (
    EnvironmentBuildRequest,
    build_runtime_l2_environments,
)
from .candidate_l2 import (
    GT_REGRESSION_COHORT,
    CandidateL2Request,
    validate_candidate_l2,
)
from .qualification_contracts import (
    QualificationGenerationRequest,
    QualificationExpansionRequest,
    QualificationRunRequest,
)
from .qualification_runner import (
    resolve_oci_engine,
    run_adapter_qualification,
    run_exploratory_triggerability,
    run_hermes_qualification_smoke,
)
from .qualification_selection import (
    generate_adapter_qualification,
    generate_adapter_qualification_expansion,
)
from .qualification_images import (
    build_qualification_image,
    prebuild_qualification_containers,
    render_qualification_image_recipes,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--report", required=True)
    prompt_group = parser.add_mutually_exclusive_group()
    prompt_group.add_argument("--prompt")
    prompt_group.add_argument("--prompt-file", type=Path)
    parser.add_argument("--attempts", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--model")
    parser.add_argument("--base-url")
    parser.add_argument("--api-key-env")
    parser.add_argument("--out-dir", type=Path)
    return parser


def build_generate_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate the corrected-v2 strict-matched runtime campaign"
    )
    parser.add_argument("--coverage-root", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--model", default="deepseek-v4-flash")
    parser.add_argument("--base-url", default="https://api.deepseek.com/v1")
    parser.add_argument("--api-key-env", default="DEEPSEEK_API_KEY")
    return parser


def build_campaign_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a generated corrected-v2 native replay campaign"
    )
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--jobs", type=int, default=4)
    return parser


def build_upgrade_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Upgrade the frozen corrected-v2 campaign to executable v3 cases"
    )
    parser.add_argument("--source-campaign", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    return parser


def build_provision_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Provision pinned dependencies and report native-driver readiness"
    )
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--check-only", action="store_true")
    return parser


def build_triggerability_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit model-facing tool reachability for all targeted ground truths"
    )
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    return parser


def build_gt_audit_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit all authoritative ground truths for source-valid runtime support"
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    return parser


def build_gt_generate_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate one report-centric native replay oracle per eligible ground truth"
    )
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--model", default="deepseek-v4-flash")
    parser.add_argument("--base-url", default="https://api.deepseek.com/v1")
    parser.add_argument("--api-key-env", default="DEEPSEEK_API_KEY")
    return parser


def build_gt_review_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Independently review generated ground-truth runtime oracles"
    )
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--model", default="deepseek-v4-flash")
    parser.add_argument("--base-url", default="https://api.deepseek.com/v1")
    parser.add_argument("--api-key-env", default="DEEPSEEK_API_KEY")
    return parser


def build_gt_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the independently reviewed ground-truth native replay campaign"
    )
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--jobs", type=int, default=4)
    return parser


def build_production_smoke_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the Claude-designed Hermes prompt-to-sink propagation smoke"
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--claude-model", default="deepseek-v4-pro")
    parser.add_argument(
        "--claude-base-url", default="https://api.deepseek.com/anthropic"
    )
    parser.add_argument("--claude-credential-env", default="DEEPSEEK_API_KEY")
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--design-timeout", type=int, default=1800)
    parser.add_argument("--max-turns", type=int, default=40)
    return parser


def build_qualification_generate_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Select one reviewed ground-truth case per adapter/tool/probe family"
    )
    parser.add_argument("--source-campaign", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    return parser


def build_qualification_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the containerized mock-provider adapter qualification campaign"
    )
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--engine", choices=("docker", "podman", "auto"), default="auto")
    return parser


def build_qualification_expansion_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Expand qualification to all reviewed ground truths after the 23-family gate"
    )
    parser.add_argument("--source-campaign", type=Path, required=True)
    parser.add_argument("--qualification-campaign", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    return parser


def build_live_triggerability_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Publish noncanonical live-triggerability records for a qualification campaign"
    )
    parser.add_argument("--campaign", type=Path, required=True)
    return parser


def build_qualification_recipe_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render revision-bound OCI bridge recipes for a qualification campaign"
    )
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--engine", choices=("docker", "podman", "auto"), default="auto")
    return parser


def build_qualification_prebuild_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build checked-in qualification containers during pre-analysis"
    )
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--project")
    parser.add_argument("--engine", choices=("docker", "podman", "auto"), default="auto")
    return parser



def build_qualification_image_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a revision- and lockfile-bound qualification OCI image"
    )
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--engine", choices=("docker", "podman", "auto"), default="auto")
    return parser


def build_hermes_qualification_smoke_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the Hermes deterministic mock-provider OCI qualification smoke"
    )
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--engine", choices=("docker", "podman", "auto"), default="auto")
    parser.add_argument("--attempts", type=int, default=3)
    return parser


def build_agent_runtime_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the LLM-agent-guided Hermes candidate runtime validation pilot"
    )
    parser.add_argument(
        "--coverage-root",
        type=Path,
        default=Path("output/cross-project/coverage-comparison"),
    )
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--controller",
        choices=("scripted-pilot", "openai-compatible"),
        default="scripted-pilot",
    )
    parser.add_argument("--model")
    parser.add_argument("--base-url")
    parser.add_argument("--api-key-env")
    parser.add_argument("--max-iterations", type=int, default=4)
    parser.add_argument("--confirmation-attempts", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=60)
    return parser


def build_dynamic_generate_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate the universal 78-candidate dynamic-trigger campaign"
    )
    parser.add_argument("--coverage-root", type=Path, required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--model", default="deepseek-v4-flash")
    parser.add_argument("--base-url", default="https://api.deepseek.com/v1")
    parser.add_argument("--api-key-env", default="DEEPSEEK_API_KEY")
    return parser


def build_dynamic_review_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Independently review all universal dynamic-trigger cases"
    )
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--model", default="deepseek-v4-flash")
    parser.add_argument("--base-url", default="https://api.deepseek.com/v1")
    parser.add_argument("--api-key-env", default="DEEPSEEK_API_KEY")
    return parser


def build_dynamic_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run paired native dynamic-trigger validation for all candidates"
    )
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument(
        "--require-green-46",
        action="store_true",
        help="fail closed if a green 46/46 runtime-detection claim is impossible",
    )
    return parser


def build_lettabot_l2_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run targeted forced-provider L2 validation for all LettaBot candidates"
    )
    parser.add_argument(
        "--campaign",
        type=Path,
        default=DEFAULT_SOURCE_CAMPAIGN,
        help="reviewed dynamic-trigger campaign (default: canonical all-candidate artifact)",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--candidate-id")
    return parser


def build_droidclaw_l2_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run targeted forced-provider L2 validation for the DroidClaw shell candidate"
    )
    parser.add_argument(
        "--campaign",
        type=Path,
        default=DEFAULT_DROIDCLAW_SOURCE_CAMPAIGN,
        help="reviewed dynamic-trigger campaign (default: canonical all-candidate artifact)",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=45)
    return parser


def build_mercury_agent_l2_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run targeted forced-provider L2 validation for all Mercury-Agent candidates"
    )
    parser.add_argument(
        "--campaign",
        type=Path,
        default=DEFAULT_MERCURY_SOURCE_CAMPAIGN,
        help="reviewed dynamic-trigger campaign (default: canonical all-candidate artifact)",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=45)
    return parser


def build_openclaw_l2_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run targeted forced-provider L2 validation for linked OpenClaw candidates"
    )
    parser.add_argument(
        "--campaign",
        type=Path,
        default=DEFAULT_OPENCLAW_SOURCE_CAMPAIGN,
        help="reviewed dynamic-trigger campaign (default: canonical all-candidate artifact)",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--build-timeout", type=int, default=1200)
    parser.add_argument("--candidate-id")
    parser.add_argument("--build-dir", type=Path)
    return parser


def build_openclaw_cn_l2_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run targeted forced-provider L2 validation for linked OpenClaw-CN candidates"
    )
    parser.add_argument(
        "--campaign",
        type=Path,
        default=DEFAULT_OPENCLAW_CN_SOURCE_CAMPAIGN,
        help="reviewed dynamic-trigger campaign (default: canonical all-candidate artifact)",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--build-timeout", type=int, default=1800)
    parser.add_argument("--candidate-id")
    parser.add_argument("--build-dir", type=Path)
    return parser


def build_nanoclaw_l2_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run targeted forced-provider L2 validation for linked NanoClaw candidates"
    )
    parser.add_argument(
        "--campaign",
        type=Path,
        default=DEFAULT_NANOCLAW_SOURCE_CAMPAIGN,
        help="reviewed dynamic-trigger campaign (default: canonical all-candidate artifact)",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=150)
    parser.add_argument("--build-timeout", type=int, default=1800)
    parser.add_argument("--candidate-id")
    parser.add_argument("--build-dir", type=Path)
    return parser


def build_chatgpt_on_wechat_l2_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run targeted forced-provider L2 validation for linked CowAgent candidates"
        )
    )
    parser.add_argument(
        "--campaign",
        type=Path,
        default=DEFAULT_CHATGPT_ON_WECHAT_SOURCE_CAMPAIGN,
        help="reviewed dynamic-trigger campaign (default: canonical all-candidate artifact)",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--build-timeout", type=int, default=1800)
    parser.add_argument("--candidate-id")
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument(
        "--historical",
        action="store_true",
        help="run only the reviewed WebFetch/Vision post-hoc historical overlay",
    )
    return parser


def build_astrbot_l2_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run targeted forced-provider L2 validation for linked AstrBot candidates"
        )
    )
    parser.add_argument(
        "--campaign",
        type=Path,
        default=DEFAULT_ASTRBOT_SOURCE_CAMPAIGN,
        help="reviewed dynamic-trigger campaign (default: canonical all-candidate artifact)",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=150)
    parser.add_argument("--build-timeout", type=int, default=1800)
    parser.add_argument("--candidate-id")
    parser.add_argument("--build-dir", type=Path)
    return parser


def build_qwenpaw_l2_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run targeted forced-provider L2 validation for the GT-linked QwenPaw candidate"
        )
    )
    parser.add_argument(
        "--campaign",
        type=Path,
        default=DEFAULT_QWENPAW_SOURCE_CAMPAIGN,
        help="reviewed dynamic-trigger campaign (default: canonical all-candidate artifact)",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--build-timeout", type=int, default=1800)
    parser.add_argument("--candidate-id")
    parser.add_argument("--build-dir", type=Path)
    return parser


def build_hermes_agent_l2_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run targeted forced-provider L2 validation for GT-linked Hermes Agent candidates"
        )
    )
    parser.add_argument(
        "--campaign",
        type=Path,
        default=DEFAULT_HERMES_AGENT_SOURCE_CAMPAIGN,
        help="reviewed dynamic-trigger campaign (default: expanded-v3 all-candidate artifact)",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--build-timeout", type=int, default=1800)
    parser.add_argument("--candidate-id")
    parser.add_argument("--build-dir", type=Path)
    return parser


def build_nanobot_l2_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run targeted forced-provider L2 validation for GT-linked nanobot candidates"
        )
    )
    parser.add_argument(
        "--campaign",
        type=Path,
        default=DEFAULT_NANOBOT_SOURCE_CAMPAIGN,
        help="reviewed dynamic-trigger campaign (default: expanded-v3 all-candidate artifact)",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--build-timeout", type=int, default=900)
    parser.add_argument("--candidate-id")
    parser.add_argument("--build-dir", type=Path)
    return parser


def build_source_revised_native_l2_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the unified source-revised native-tool L2 campaign for four reports"
        )
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--project", choices=("nanobot", "openclaw", "chatgpt-on-wechat"))
    parser.add_argument("--report-id")
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--build-timeout", type=int, default=1800)
    parser.add_argument("--build-dir", type=Path)
    return parser


def build_candidate_l2_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate one canonical 78-row candidate through real-entrypoint L2"
    )
    parser.add_argument("--project", required=True)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument(
        "--candidates",
        type=Path,
        default=Path(
            "output/cross-project/coverage-comparison/candidates.jsonl"
        ),
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--source-campaign",
        type=Path,
        default=Path(
            "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
        ),
    )
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--setup-timeout", type=int, default=1200)
    parser.add_argument("--launch-timeout", type=int, default=90)
    parser.add_argument("--generate-plans", action="store_true")
    parser.add_argument("--model", default="deepseek-v4-flash")
    parser.add_argument("--base-url", default="https://api.deepseek.com/v1")
    parser.add_argument("--api-key-env", default="DEEPSEEK_API_KEY")
    return parser


def build_gt_regression_candidate_l2_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the post-hoc 61-ID / 43-report GT-regression candidate L2 cohort"
    )
    parser.add_argument("--project")
    parser.add_argument("--candidate-id")
    parser.add_argument(
        "--candidates",
        type=Path,
        default=Path(
            "output/cross-project/coverage-comparison/training-regression-candidates.jsonl"
        ),
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--source-campaign",
        type=Path,
        default=Path(
            "output/cross-project/runtime-dynamic-trigger-all-candidates-v1"
        ),
    )
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--setup-timeout", type=int, default=1200)
    parser.add_argument("--launch-timeout", type=int, default=90)
    parser.add_argument("--generate-plans", action="store_true")
    parser.add_argument("--model", default="deepseek-v4-flash")
    parser.add_argument("--base-url", default="https://api.deepseek.com/v1")
    parser.add_argument("--api-key-env", default="DEEPSEEK_API_KEY")
    return parser


def build_l2_qualification_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Qualify real-entrypoint L2 launch profiles for all non-Hermes projects"
    )
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--launch",
        action="store_true",
        help="also attempt launch probes for profiles already marked ready",
    )
    return parser


def build_l2_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run canonical forced-provider L2 replay after complete qualification"
    )
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--jobs", type=int, default=4)
    return parser


def build_environment_smoke_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run disposable launch-environment smoke tests for all 11 projects"
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--project",
        action="append",
        dest="projects",
        help="restrict the run to a registered project; repeat for multiple projects",
    )
    parser.add_argument("--setup-timeout", type=int, default=1200)
    parser.add_argument("--launch-timeout", type=int, default=60)
    parser.add_argument(
        "--require-all-confirmed",
        action="store_true",
        help="fail closed unless every selected environment launches",
    )
    return parser


def build_environment_builder_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build native disposable runtime L2 environments for benchmark projects"
    )
    parser.add_argument(
        "--project",
        action="append",
        dest="projects",
        help="registered benchmark project; repeat for multiple projects",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="build all projects in the benchmark registry",
    )
    parser.add_argument("--candidate-id")
    parser.add_argument(
        "--candidates",
        type=Path,
        default=Path("output/cross-project/coverage-comparison/candidates.jsonl"),
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--setup-timeout", type=int, default=1200)
    parser.add_argument("--launch-timeout", type=int, default=90)
    return parser


def _read_prompt(args: argparse.Namespace, parser: argparse.ArgumentParser) -> str:
    if args.prompt is not None:
        return args.prompt
    if args.prompt_file is not None:
        try:
            return args.prompt_file.read_text(encoding="utf-8")
        except OSError as exc:
            parser.error(f"cannot read --prompt-file: {exc}")
    if sys.stdin.isatty():
        parser.error("provide --prompt, --prompt-file, or pipe the prompt on stdin")
    return sys.stdin.read()


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "build-runtime-l2-environment":
        parser = build_environment_builder_parser()
        args = parser.parse_args(argv[1:])
        if args.all and args.projects:
            parser.error("use either --all or --project, not both")
        if not args.all and not args.projects:
            parser.error("select --all or at least one --project")
        projects = tuple(args.projects or ())
        if args.all:
            from src.projects import list_projects

            projects = list_projects()
        manifest = build_runtime_l2_environments(
            EnvironmentBuildRequest(
                out_dir=args.out_dir,
                projects=tuple(sorted(projects)),
                candidate_id=args.candidate_id,
                candidates_file=args.candidates,
                setup_timeout=args.setup_timeout,
                launch_timeout=args.launch_timeout,
            )
        )
        print(json.dumps(manifest, indent=2))
        return 0 if not manifest["status_counts"].get("environment-blocked") else 2
    if argv and argv[0] == "validate-candidate-l2":
        parser = build_candidate_l2_parser()
        args = parser.parse_args(argv[1:])
        manifest = validate_candidate_l2(
            CandidateL2Request(
                out_dir=args.out_dir,
                candidates=args.candidates,
                coverage_root=args.candidates.parent,
                source_campaign=args.source_campaign,
                project=args.project,
                candidate_id=args.candidate_id,
                attempts=args.attempts,
                setup_timeout=args.setup_timeout,
                launch_timeout=args.launch_timeout,
                generate_plans=args.generate_plans,
                model=args.model,
                base_url=args.base_url,
                api_key_env=args.api_key_env,
            )
        )
        print(json.dumps(manifest, indent=2))
        return 0 if manifest["status_counts"].get("runtime-confirmed") == 1 else 2
    if argv and argv[0] == "validate-gt-linked-candidates-l2":
        parser = build_gt_regression_candidate_l2_parser()
        args = parser.parse_args(argv[1:])
        manifest = validate_candidate_l2(
            CandidateL2Request(
                out_dir=args.out_dir,
                candidates=args.candidates,
                source_campaign=args.source_campaign,
                project=args.project,
                candidate_id=args.candidate_id,
                attempts=args.attempts,
                setup_timeout=args.setup_timeout,
                launch_timeout=args.launch_timeout,
                generate_plans=args.generate_plans,
                model=args.model,
                base_url=args.base_url,
                api_key_env=args.api_key_env,
                cohort=GT_REGRESSION_COHORT,
            )
        )
        print(json.dumps(manifest, indent=2))
        return 0
    if argv and argv[0] == "generate-dynamic-trigger":
        parser = build_dynamic_generate_parser()
        args = parser.parse_args(argv[1:])
        manifest = generate_dynamic_trigger(
            DynamicTriggerGenerationRequest(
                args.coverage_root,
                args.candidates,
                args.out_dir,
                args.model,
                args.base_url,
                args.api_key_env,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": manifest["campaign_id"],
                    "candidate_count": manifest["candidate_count"],
                    "artifact_dir": str(args.out_dir),
                },
                indent=2,
            )
        )
        return 0
    if argv and argv[0] == "qualify-dynamic-trigger-l2":
        parser = build_l2_qualification_parser()
        args = parser.parse_args(argv[1:])
        manifest = qualify_l2(
            L2QualificationRequest(args.campaign, args.out_dir, args.launch)
        )
        print(
            json.dumps(
                {
                    "campaign_id": manifest["campaign_id"],
                    "candidate_count": manifest["candidate_count"],
                    "project_count": manifest["project_count"],
                    "status_counts": manifest["status_counts"],
                    "canonical_publication_ready": manifest["canonical_publication_ready"],
                    "artifact_dir": str(args.out_dir),
                },
                indent=2,
            )
        )
        return 0
    if argv and argv[0] == "run-dynamic-trigger-l2":
        parser = build_l2_run_parser()
        args = parser.parse_args(argv[1:])
        report = run_l2(
            L2RunRequest(
                args.campaign,
                args.qualification,
                args.out_dir,
                args.attempts,
                args.jobs,
            )
        )
        print(json.dumps(report, indent=2))
        return 0
    if argv and argv[0] == "review-dynamic-trigger":
        parser = build_dynamic_review_parser()
        args = parser.parse_args(argv[1:])
        report = review_dynamic_trigger(
            DynamicTriggerReviewRequest(
                args.campaign, args.model, args.base_url, args.api_key_env
            )
        )
        print(json.dumps(report, indent=2))
        return 0
    if argv and argv[0] == "run-dynamic-trigger":
        parser = build_dynamic_run_parser()
        args = parser.parse_args(argv[1:])
        report = run_dynamic_trigger(
            DynamicTriggerRunRequest(
                args.campaign, args.attempts, args.jobs, args.require_green_46
            )
        )
        print(json.dumps(report, indent=2))
        if report.get("truth_gate") == "blocked-green-46-claim":
            return 2
        return 0
    if argv and argv[0] == "run-dynamic-trigger-lettabot-l2":
        parser = build_lettabot_l2_run_parser()
        args = parser.parse_args(argv[1:])
        manifest = run_letta_l2(
            LettaL2RunRequest(
                args.campaign,
                args.out_dir,
                args.attempts,
                args.timeout,
                args.candidate_id,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": manifest["campaign_id"],
                    "candidate_count": manifest["candidate_count"],
                    "status_counts": manifest["status_counts"],
                    "artifact_dir": str(args.out_dir),
                },
                indent=2,
            )
        )
        return 0 if not manifest["status_counts"].get("inconclusive") else 2
    if argv and argv[0] == "run-dynamic-trigger-droidclaw-l2":
        parser = build_droidclaw_l2_run_parser()
        args = parser.parse_args(argv[1:])
        manifest = run_droidclaw_l2(
            DroidClawL2RunRequest(args.campaign, args.out_dir, args.attempts, args.timeout)
        )
        print(
            json.dumps(
                {
                    "campaign_id": manifest["campaign_id"],
                    "candidate_count": manifest["candidate_count"],
                    "status_counts": manifest["status_counts"],
                    "artifact_dir": str(args.out_dir),
                },
                indent=2,
            )
        )
        return 0 if not manifest["status_counts"].get("inconclusive") else 2
    if argv and argv[0] == "run-dynamic-trigger-mercury-agent-l2":
        parser = build_mercury_agent_l2_run_parser()
        args = parser.parse_args(argv[1:])
        manifest = run_mercury_l2(
            MercuryL2RunRequest(
                args.campaign,
                args.out_dir,
                args.attempts,
                args.timeout,
                args.candidate_id,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": manifest["campaign_id"],
                    "candidate_count": manifest["candidate_count"],
                    "status_counts": manifest["status_counts"],
                    "artifact_dir": str(args.out_dir),
                },
                indent=2,
            )
        )
        return 0 if not manifest["status_counts"].get("inconclusive") else 2
    if argv and argv[0] == "run-dynamic-trigger-openclaw-l2":
        parser = build_openclaw_l2_run_parser()
        args = parser.parse_args(argv[1:])
        manifest = run_openclaw_l2(
            OpenClawL2RunRequest(
                campaign=args.campaign,
                out_dir=args.out_dir,
                attempts=args.attempts,
                timeout=args.timeout,
                build_timeout=args.build_timeout,
                candidate_id=args.candidate_id,
                build_dir=args.build_dir,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": manifest["campaign_id"],
                    "candidate_count": manifest["candidate_count"],
                    "status_counts": manifest["status_counts"],
                    "artifact_dir": str(args.out_dir),
                },
                indent=2,
            )
        )
        return 0 if not manifest["status_counts"].get("inconclusive") else 2
    if argv and argv[0] == "run-dynamic-trigger-openclaw-cn-l2":
        parser = build_openclaw_cn_l2_run_parser()
        args = parser.parse_args(argv[1:])
        manifest = run_openclaw_cn_l2(
            OpenClawCNL2RunRequest(
                campaign=args.campaign,
                out_dir=args.out_dir,
                attempts=args.attempts,
                timeout=args.timeout,
                build_timeout=args.build_timeout,
                candidate_id=args.candidate_id,
                build_dir=args.build_dir,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": manifest["campaign_id"],
                    "candidate_count": manifest["candidate_count"],
                    "status_counts": manifest["status_counts"],
                    "artifact_dir": str(args.out_dir),
                },
                indent=2,
            )
        )
        return 0 if not manifest["status_counts"].get("inconclusive") else 2
    if argv and argv[0] == "run-dynamic-trigger-nanoclaw-l2":
        parser = build_nanoclaw_l2_run_parser()
        args = parser.parse_args(argv[1:])
        manifest = run_nanoclaw_l2(
            NanoClawL2RunRequest(
                campaign=args.campaign,
                out_dir=args.out_dir,
                attempts=args.attempts,
                timeout=args.timeout,
                build_timeout=args.build_timeout,
                candidate_id=args.candidate_id,
                build_dir=args.build_dir,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": manifest["campaign_id"],
                    "candidate_count": manifest["candidate_count"],
                    "status_counts": manifest["status_counts"],
                    "artifact_dir": str(args.out_dir),
                },
                indent=2,
            )
        )
        return 0 if not manifest["status_counts"].get("inconclusive") else 2
    if argv and argv[0] == "run-dynamic-trigger-chatgpt-on-wechat-l2":
        parser = build_chatgpt_on_wechat_l2_run_parser()
        args = parser.parse_args(argv[1:])
        manifest = run_chatgpt_on_wechat_l2(
            ChatGPTOnWeChatL2RunRequest(
                campaign=args.campaign,
                out_dir=args.out_dir,
                attempts=args.attempts,
                timeout=args.timeout,
                build_timeout=args.build_timeout,
                candidate_id=args.candidate_id,
                build_dir=args.build_dir,
                historical=args.historical,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": manifest["campaign_id"],
                    "candidate_count": manifest["candidate_count"],
                    "status_counts": manifest["status_counts"],
                    "artifact_dir": str(args.out_dir),
                },
                indent=2,
            )
        )
        return 0 if not manifest["status_counts"].get("inconclusive") else 2
    if argv and argv[0] == "run-dynamic-trigger-astrbot-l2":
        parser = build_astrbot_l2_run_parser()
        args = parser.parse_args(argv[1:])
        manifest = run_astrbot_l2(
            AstrBotL2RunRequest(
                campaign=args.campaign,
                out_dir=args.out_dir,
                attempts=args.attempts,
                timeout=args.timeout,
                build_timeout=args.build_timeout,
                candidate_id=args.candidate_id,
                build_dir=args.build_dir,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": manifest["campaign_id"],
                    "candidate_count": manifest["candidate_count"],
                    "status_counts": manifest["status_counts"],
                    "artifact_dir": str(args.out_dir),
                },
                indent=2,
            )
        )
        return 0 if not manifest["status_counts"].get("inconclusive") else 2
    if argv and argv[0] == "run-dynamic-trigger-qwenpaw-l2":
        parser = build_qwenpaw_l2_run_parser()
        args = parser.parse_args(argv[1:])
        manifest = run_qwenpaw_l2(
            QwenPawL2RunRequest(
                campaign=args.campaign,
                out_dir=args.out_dir,
                attempts=args.attempts,
                timeout=args.timeout,
                build_timeout=args.build_timeout,
                candidate_id=args.candidate_id,
                build_dir=args.build_dir,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": manifest["campaign_id"],
                    "candidate_count": manifest["candidate_count"],
                    "status_counts": manifest["status_counts"],
                    "artifact_dir": str(args.out_dir),
                },
                indent=2,
            )
        )
        return 0 if not manifest["status_counts"].get("inconclusive") else 2
    if argv and argv[0] == "run-dynamic-trigger-hermes-agent-l2":
        parser = build_hermes_agent_l2_run_parser()
        args = parser.parse_args(argv[1:])
        manifest = run_hermes_agent_l2(
            HermesAgentL2RunRequest(
                campaign=args.campaign,
                out_dir=args.out_dir,
                attempts=args.attempts,
                timeout=args.timeout,
                build_timeout=args.build_timeout,
                candidate_id=args.candidate_id,
                build_dir=args.build_dir,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": manifest["campaign_id"],
                    "candidate_count": manifest["candidate_count"],
                    "status_counts": manifest["status_counts"],
                    "artifact_dir": str(args.out_dir),
                },
                indent=2,
            )
        )
        return 0 if not manifest["status_counts"].get("inconclusive") else 2
    if argv and argv[0] == "run-dynamic-trigger-nanobot-l2":
        parser = build_nanobot_l2_run_parser()
        args = parser.parse_args(argv[1:])
        manifest = run_nanobot_l2(
            NanobotL2RunRequest(
                campaign=args.campaign,
                out_dir=args.out_dir,
                attempts=args.attempts,
                timeout=args.timeout,
                build_timeout=args.build_timeout,
                candidate_id=args.candidate_id,
                build_dir=args.build_dir,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": manifest["campaign_id"],
                    "candidate_count": manifest["candidate_count"],
                    "status_counts": manifest["status_counts"],
                    "artifact_dir": str(args.out_dir),
                },
                indent=2,
            )
        )
        return 0 if not manifest["status_counts"].get("inconclusive") else 2
    if argv and argv[0] == "run-dynamic-trigger-source-revised-native-l2":
        parser = build_source_revised_native_l2_run_parser()
        args = parser.parse_args(argv[1:])
        manifest = run_source_revised_native_l2(
            SourceRevisedNativeL2RunRequest(
                out_dir=args.out_dir,
                attempts=args.attempts,
                timeout=args.timeout,
                build_timeout=args.build_timeout,
                build_dir=args.build_dir,
                all_reports=args.all,
                project=args.project,
                report_id=args.report_id,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": manifest["campaign_id"],
                    "report_count": manifest["report_count"],
                    "status_counts": manifest["status_counts"],
                    "evidence_scope": manifest["evidence_scope"],
                    "canonical_accounting_affected": manifest[
                        "canonical_accounting_affected"
                    ],
                    "artifact_dir": str(args.out_dir),
                },
                indent=2,
            )
        )
        return 0 if "inconclusive" not in manifest["status_counts"] else 2
    if argv and argv[0] == "generate-adapter-qualification":
        parser = build_qualification_generate_parser()
        args = parser.parse_args(argv[1:])
        campaign = generate_adapter_qualification(
            QualificationGenerationRequest(args.source_campaign, args.out_dir)
        )
        print(
            json.dumps(
                {
                    "campaign_id": campaign.campaign_id,
                    "families": len(campaign.cases),
                    "artifact_dir": str(campaign.root),
                },
                indent=2,
            )
        )
        return 0
    if argv and argv[0] == "run-environment-smoke":
        parser = build_environment_smoke_parser()
        args = parser.parse_args(argv[1:])
        manifest = run_environment_smoke(
            EnvironmentSmokeRequest(
                out_dir=args.out_dir,
                projects=args.projects or (
                    "AstrBot",
                    "QwenPaw",
                    "chatgpt-on-wechat",
                    "droidclaw",
                    "lettabot",
                    "mercury-agent",
                    "nanobot",
                    "nanoclaw",
                    "openclaw",
                    "openclaw-cn",
                    "hermes-agent",
                ),
                setup_timeout=args.setup_timeout,
                launch_timeout=args.launch_timeout,
                require_all_confirmed=args.require_all_confirmed,
            )
        )
        print(json.dumps(manifest, indent=2))
        if manifest.get("truth_gate") == "all-launch-confirmed-required":
            return 2
        return 0 if manifest["expected_outcome"] else 2
    if argv and argv[0] == "expand-adapter-qualification":
        parser = build_qualification_expansion_parser()
        args = parser.parse_args(argv[1:])
        campaign = generate_adapter_qualification_expansion(
            QualificationExpansionRequest(
                args.source_campaign,
                args.qualification_campaign,
                args.out_dir,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": campaign.campaign_id,
                    "cases": len(campaign.cases),
                    "families": len({tuple(case["selection"]["family_key"]) for case in campaign.cases}),
                    "artifact_dir": str(campaign.root),
                },
                indent=2,
            )
        )
        return 0
    if argv and argv[0] == "run-adapter-qualification":
        parser = build_qualification_run_parser()
        args = parser.parse_args(argv[1:])
        run = run_adapter_qualification(
            QualificationRunRequest(args.campaign, args.attempts, args.jobs, args.engine)
        )
        print(
            json.dumps(
                {
                    "campaign_id": run.campaign_id,
                    "qualification_counts": dict(run.qualification_counts),
                    "forced_path_counts": dict(run.forced_path_counts),
                    "live_triggerability_counts": dict(run.live_triggerability_counts),
                    "artifact_dir": str(run.artifact_dir),
                },
                indent=2,
            )
        )
        expected = len(run.results)
        return 0 if expected and run.qualification_counts.get("qualified") == expected else 2
    if argv and argv[0] == "run-exploratory-triggerability":
        parser = build_live_triggerability_parser()
        args = parser.parse_args(argv[1:])
        rows = run_exploratory_triggerability(args.campaign)
        print(json.dumps({"records": len(rows), "outcome": "not-run"}, indent=2))
        return 0
    if argv and argv[0] == "run-hermes-qualification-smoke":
        parser = build_hermes_qualification_smoke_parser()
        args = parser.parse_args(argv[1:])
        run = run_hermes_qualification_smoke(
            args.campaign,
            args.out_dir,
            engine=args.engine,
            attempts=args.attempts,
        )
        print(
            json.dumps(
                {
                    "campaign_id": run.campaign_id,
                    "qualification_counts": dict(run.qualification_counts),
                    "forced_path_counts": dict(run.forced_path_counts),
                    "live_triggerability_counts": dict(run.live_triggerability_counts),
                    "artifact_dir": str(run.artifact_dir),
                },
                indent=2,
            )
        )
        return 0 if run.qualification_counts == {"qualified": 1} else 2
    if argv and argv[0] == "render-adapter-qualification-images":
        parser = build_qualification_recipe_parser()
        args = parser.parse_args(argv[1:])
        manifest = render_qualification_image_recipes(args.campaign, args.engine)
        print(json.dumps({"projects": len(manifest["projects"]), "engine": args.engine}, indent=2))
        return 0
    if argv and argv[0] == "prebuild-qualification-containers":
        parser = build_qualification_prebuild_parser()
        args = parser.parse_args(argv[1:])
        result = prebuild_qualification_containers(
            args.campaign, args.engine, project=args.project
        )
        print(
            json.dumps(
                {
                    "build_phase": "pre-analysis",
                    "definitions": len(result["manifest"]["projects"]),
                    "builds": [
                        {"project": row["project"], "image": row["image"]}
                        for row in result["builds"]
                    ],
                },
                indent=2,
            )
        )
        return 0
    if argv and argv[0] == "build-adapter-qualification-image":
        parser = build_qualification_image_parser()
        args = parser.parse_args(argv[1:])
        engine = resolve_oci_engine(args.engine)
        result = build_qualification_image(args.campaign, args.project, engine)
        print(
            json.dumps(
                {
                    "project": result["project"],
                    "image": result["image"],
                    "image_id": result["image_id"],
                },
                indent=2,
            )
        )
        return 0
    if argv and argv[0] == "run-production-like-smoke":
        parser = build_production_smoke_parser()
        args = parser.parse_args(argv[1:])
        run = run_production_like_smoke(
            ProductionLikeSmokeRequest(
                out_dir=args.out_dir,
                claude_model=args.claude_model,
                claude_base_url=args.claude_base_url,
                claude_credential_env=args.claude_credential_env,
                attempts=args.attempts,
                timeout_seconds=args.timeout,
                design_timeout_seconds=args.design_timeout,
                max_turns=args.max_turns,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": run.campaign_id,
                    "case_id": run.case_id,
                    "disposition": run.disposition,
                    "native_outcome": run.native_outcome,
                    "e2e_outcome": run.e2e_outcome,
                    "artifact_dir": str(run.artifact_dir),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0 if run.disposition == "prompt-to-sink-confirmed" else 2
    if argv and argv[0] == "audit-ground-truth":
        parser = build_gt_audit_parser()
        args = parser.parse_args(argv[1:])
        audit = audit_ground_truth(GroundTruthAuditRequest(args.out_dir))
        print(
            json.dumps(
                {
                    "audit_id": audit.audit_id,
                    "reports": len(audit.reports),
                    "counts": dict(audit.counts),
                    "artifact_dir": str(audit.root),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    if argv and argv[0] == "generate-ground-truth":
        parser = build_gt_generate_parser()
        args = parser.parse_args(argv[1:])
        campaign = generate_ground_truth_campaign(
            GroundTruthGenerationRequest(
                args.audit,
                args.out_dir,
                args.model,
                args.base_url,
                args.api_key_env,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": campaign.campaign_id,
                    "eligible_cases": len(campaign.cases),
                    "workbook_reports": len(campaign.accounting),
                    "artifact_dir": str(campaign.root),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    if argv and argv[0] == "review-ground-truth":
        parser = build_gt_review_parser()
        args = parser.parse_args(argv[1:])
        review = review_ground_truth_campaign(
            GroundTruthReviewRequest(
                args.campaign,
                args.model,
                args.base_url,
                args.api_key_env,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": review.campaign_id,
                    "approved": review.approved,
                    "rejected": review.rejected,
                    "artifact_dir": str(review.artifact_dir),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0 if review.rejected == 0 else 2
    if argv and argv[0] == "run-ground-truth":
        parser = build_gt_run_parser()
        args = parser.parse_args(argv[1:])
        run = run_ground_truth_campaign(
            GroundTruthRunRequest(args.campaign, args.attempts, args.jobs)
        )
        print(
            json.dumps(
                {
                    "campaign_id": run.campaign_id,
                    "support_counts": dict(run.support_counts),
                    "outcome_counts": dict(run.outcome_counts),
                    "artifact_dir": str(run.artifact_dir),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    if argv and argv[0] == "generate-covered":
        parser = build_generate_parser()
        args = parser.parse_args(argv[1:])
        campaign = generate_covered_campaign(
            CampaignGenerationRequest(
                coverage_root=args.coverage_root,
                out_dir=args.out_dir,
                model=args.model,
                base_url=args.base_url,
                api_key_env=args.api_key_env,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": campaign.campaign_id,
                    "candidate_ids": len(campaign.target_candidate_ids),
                    "cases": len(campaign.cases),
                    "execution_groups": len(campaign.execution_groups),
                    "artifact_dir": str(campaign.root),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    if argv and argv[0] == "audit-gt-tool-triggerability":
        parser = build_triggerability_parser()
        args = parser.parse_args(argv[1:])
        report = audit_ground_truth_tool_triggerability(
            TriggerabilityRequest(args.campaign, args.out_dir, args.jobs)
        )
        print(
            json.dumps(
                {
                    "campaign_id": report["campaign_id"],
                    "target_reports": report["target_reports"],
                    "disposition_counts": report["disposition_counts"],
                    "live_prompt_selection": report["live_prompt_selection"],
                    "artifact_dir": report["artifact_dir"],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0 if not report["disposition_counts"].get("inconclusive") else 2
    if argv and argv[0] == "provision-drivers":
        parser = build_provision_parser()
        args = parser.parse_args(argv[1:])
        campaign_manifest = args.campaign / "manifest.json"
        if campaign_manifest.is_file() and json.loads(
            campaign_manifest.read_text(encoding="utf-8")
        ).get("campaign_id") == "runtime-dynamic-trigger-all-candidates-v1":
            if args.check_only:
                parser.error("dynamic-trigger provisioning requires installation preflight")
            report = provision_dynamic_drivers(args.campaign)
        else:
            report = provision_drivers(
                ProvisionRequest(args.campaign, install=not args.check_only)
            )
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0 if report["ready"] else 2
    if argv and argv[0] == "upgrade-covered-v3":
        parser = build_upgrade_parser()
        args = parser.parse_args(argv[1:])
        campaign = upgrade_covered_campaign(
            CampaignUpgradeRequest(args.source_campaign, args.out_dir)
        )
        print(
            json.dumps(
                {
                    "campaign_id": campaign.campaign_id,
                    "candidate_ids": len(campaign.target_candidate_ids),
                    "cases": len(campaign.cases),
                    "execution_groups": len(campaign.execution_groups),
                    "artifact_dir": str(campaign.root),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    if argv and argv[0] == "run-campaign":
        parser = build_campaign_parser()
        args = parser.parse_args(argv[1:])
        run = run_campaign(
            CampaignRunRequest(
                campaign_dir=args.campaign,
                attempts=args.attempts,
                jobs=args.jobs,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": run.campaign_id,
                    "disposition_counts": dict(run.disposition_counts),
                    "artifact_dir": str(run.artifact_dir),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    if argv and argv[0] == "run-agent-runtime-validation":
        parser = build_agent_runtime_parser()
        args = parser.parse_args(argv[1:])
        run = run_agent_runtime_validation(
            AgentRuntimeValidationRequest(
                coverage_root=args.coverage_root,
                candidate_id=args.candidate_id,
                out_dir=args.out_dir,
                controller=args.controller,
                model=args.model,
                base_url=args.base_url,
                api_key_env=args.api_key_env,
                max_iterations=args.max_iterations,
                confirmation_attempts=args.confirmation_attempts,
                timeout_seconds=args.timeout,
            )
        )
        print(
            json.dumps(
                {
                    "campaign_id": run.campaign_id,
                    "candidate_id": run.candidate_id,
                    "verdict": run.verdict,
                    "artifact_dir": str(run.artifact_dir),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0 if run.verdict == "runtime-confirmed" else 2
    parser = build_parser()
    args = parser.parse_args(argv)
    prompt = _read_prompt(args, parser)
    request = ValidationRequest(
        project_id=args.project,
        report_name=args.report,
        prompt=prompt,
        attempts=args.attempts,
        timeout_seconds=args.timeout,
        model=args.model,
        base_url=args.base_url,
        api_key_env=args.api_key_env,
        out_dir=args.out_dir,
    )
    run = validate_prompt(request)
    print(
        json.dumps(
            {
                "run_id": run.run_id,
                "verdict": run.verdict,
                "reason": run.reason,
                "artifact_dir": str(run.artifact_dir),
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    if run.verdict == NOT_TRIGGERED:
        return 1
    if run.verdict == INCONCLUSIVE:
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValidationError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

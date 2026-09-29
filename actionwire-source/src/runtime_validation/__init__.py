"""Runtime validation for prompt-triggered LLM agent security issues."""

from .contracts import (
    INCONCLUSIVE,
    NOT_TRIGGERED,
    TRIGGERED,
    ValidationError,
    ValidationRequest,
    ValidationRun,
)
from .campaign_contracts import (
    CampaignDefinition,
    CampaignGenerationRequest,
    CampaignRun,
    CampaignRunRequest,
    CaseRun,
    CaseValidationRequest,
)
from .upgrade import CampaignUpgradeRequest
from .provision import ProvisionRequest
from .triggerability import TriggerabilityRequest
from .ground_truth_contracts import (
    GroundTruthAudit,
    GroundTruthAuditRequest,
    GroundTruthCampaignDefinition,
    GroundTruthCampaignRun,
    GroundTruthGenerationRequest,
    GroundTruthReview,
    GroundTruthReviewRequest,
    GroundTruthRunRequest,
)
from .propagation_contracts import (
    ProductionLikeSmokeRequest,
    ProductionLikeSmokeRun,
)
from .agent_contracts import AgentRuntimeValidationRequest
from .qualification_contracts import (
    QualificationCampaign,
    QualificationGenerationRequest,
    QualificationExpansionRequest,
    QualificationRun,
    QualificationRunRequest,
)


def validate_prompt(*args, **kwargs):
    """Lazily import the controller so injected instrumentation stays lightweight."""

    from .pipeline import validate_prompt as _validate_prompt

    return _validate_prompt(*args, **kwargs)


def generate_covered_campaign(*args, **kwargs):
    """Lazily generate the corrected-v2 strict-match replay campaign."""

    from .generation import generate_covered_campaign as _generate

    return _generate(*args, **kwargs)


def validate_case(*args, **kwargs):
    """Lazily validate one generated candidate replay case."""

    from .campaign import validate_case as _validate_case

    return _validate_case(*args, **kwargs)


def run_campaign(*args, **kwargs):
    """Lazily run a generated corrected-v2 campaign."""

    from .campaign import run_campaign as _run_campaign

    return _run_campaign(*args, **kwargs)


def upgrade_covered_campaign(*args, **kwargs):
    """Lazily upgrade the frozen corrected-v2 campaign to v3."""

    from .upgrade import upgrade_covered_campaign as _upgrade

    return _upgrade(*args, **kwargs)


def provision_drivers(*args, **kwargs):
    """Provision pinned TypeScript dependencies and report driver readiness."""

    from .provision import provision_drivers as _provision

    return _provision(*args, **kwargs)


def audit_ground_truth_tool_triggerability(*args, **kwargs):
    """Audit whether every targeted ground truth has a model-facing tool route."""

    from .triggerability import audit_ground_truth_tool_triggerability as _audit

    return _audit(*args, **kwargs)


def audit_ground_truth(*args, **kwargs):
    from .ground_truth_campaign import audit_ground_truth as _audit

    return _audit(*args, **kwargs)


def generate_ground_truth_campaign(*args, **kwargs):
    from .ground_truth_campaign import generate_ground_truth_campaign as _generate

    return _generate(*args, **kwargs)


def review_ground_truth_campaign(*args, **kwargs):
    from .ground_truth_campaign import review_ground_truth_campaign as _review

    return _review(*args, **kwargs)


def run_ground_truth_campaign(*args, **kwargs):
    from .ground_truth_campaign import run_ground_truth_campaign as _run

    return _run(*args, **kwargs)


def run_production_like_smoke(*args, **kwargs):
    from .production_like_smoke import run_production_like_smoke as _run

    return _run(*args, **kwargs)


def generate_adapter_qualification(*args, **kwargs):
    from .qualification_selection import generate_adapter_qualification as _generate

    return _generate(*args, **kwargs)


def generate_adapter_qualification_expansion(*args, **kwargs):
    from .qualification_selection import (
        generate_adapter_qualification_expansion as _generate,
    )

    return _generate(*args, **kwargs)


def run_adapter_qualification(*args, **kwargs):
    from .qualification_runner import run_adapter_qualification as _run

    return _run(*args, **kwargs)


def run_exploratory_triggerability(*args, **kwargs):
    from .qualification_runner import run_exploratory_triggerability as _run

    return _run(*args, **kwargs)


def render_qualification_image_recipes(*args, **kwargs):
    from .qualification_images import render_qualification_image_recipes as _render

    return _render(*args, **kwargs)


def build_adapter_qualification_image(*args, **kwargs):
    from .qualification_images import build_qualification_image as _build

    return _build(*args, **kwargs)


def prebuild_qualification_containers(*args, **kwargs):
    from .qualification_images import prebuild_qualification_containers as _prebuild

    return _prebuild(*args, **kwargs)


def run_hermes_qualification_smoke(*args, **kwargs):
    from .qualification_runner import run_hermes_qualification_smoke as _run

    return _run(*args, **kwargs)


def run_agent_runtime_validation(*args, **kwargs):
    """Lazily run the restricted agent-guided candidate campaign."""

    from .agent_campaign import run_agent_runtime_validation as _run

    return _run(*args, **kwargs)


__all__ = [
    "INCONCLUSIVE",
    "NOT_TRIGGERED",
    "TRIGGERED",
    "ValidationError",
    "ValidationRequest",
    "ValidationRun",
    "CampaignDefinition",
    "CampaignGenerationRequest",
    "CampaignRun",
    "CampaignRunRequest",
    "CaseRun",
    "CaseValidationRequest",
    "CampaignUpgradeRequest",
    "ProvisionRequest",
    "TriggerabilityRequest",
    "GroundTruthAudit",
    "GroundTruthAuditRequest",
    "GroundTruthCampaignDefinition",
    "GroundTruthCampaignRun",
    "GroundTruthGenerationRequest",
    "GroundTruthReview",
    "GroundTruthReviewRequest",
    "GroundTruthRunRequest",
    "ProductionLikeSmokeRequest",
    "ProductionLikeSmokeRun",
    "AgentRuntimeValidationRequest",
    "QualificationCampaign",
    "QualificationGenerationRequest",
    "QualificationExpansionRequest",
    "QualificationRun",
    "QualificationRunRequest",
    "generate_covered_campaign",
    "validate_case",
    "run_campaign",
    "upgrade_covered_campaign",
    "provision_drivers",
    "audit_ground_truth_tool_triggerability",
    "audit_ground_truth",
    "generate_ground_truth_campaign",
    "review_ground_truth_campaign",
    "run_ground_truth_campaign",
    "run_production_like_smoke",
    "generate_adapter_qualification",
    "generate_adapter_qualification_expansion",
    "run_adapter_qualification",
    "run_exploratory_triggerability",
    "render_qualification_image_recipes",
    "build_adapter_qualification_image",
    "prebuild_qualification_containers",
    "run_hermes_qualification_smoke",
    "run_agent_runtime_validation",
    "validate_prompt",
]

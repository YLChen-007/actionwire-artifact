"""Release-wide protocol identifiers for coverage comparison.

Coverage comparison deliberately advances every owned artifact, prompt, cache,
and chat receipt together.  Other subsystems (group oracle, semantic IR, and
runtime validation) retain their own independent versioning.
"""

PROTOCOL_VERSION = 7

COMPARISON_SCHEMA_VERSION = "coverage-comparison/v7"
ASSESSMENT_SCHEMA_VERSION = "coverage-requirement-assessment/v7"
CANDIDATE_SCHEMA_VERSION = "coverage-candidate/v7"
EXCLUSION_SCHEMA_VERSION = "coverage-comparison-exclusion/v7"
MANIFEST_SCHEMA_VERSION = "coverage-comparison-manifest/v7"
CHAT_SCHEMA_VERSION = "coverage-comparison-chat/v7"
AGENT_CHAT_SCHEMA_VERSION = "coverage-agent-chat/v7"
AGENT_AUDIT_SCHEMA_VERSION = "coverage-agent-audit/v7"
CHALLENGE_SCHEMA_VERSION = "coverage-requirement-challenge/v7"

CAPABILITY_PROPOSAL_SCHEMA_VERSION = "coverage-capability-requirement-proposal/v7"
CAPABILITY_ASSESSMENT_SCHEMA_VERSION = "coverage-capability-assessment/v7"
SOURCE_PROPOSAL_SCHEMA_VERSION = "coverage-source-requirement-proposal/v7"
SOURCE_ASSESSMENT_SCHEMA_VERSION = "coverage-source-requirement-assessment/v7"
LEARNED_REQUIREMENT_SCHEMA_VERSION = "coverage-learned-requirement/v7"
LEARNED_ASSESSMENT_SCHEMA_VERSION = "coverage-learned-assessment/v7"

SOURCE_VALIDATION_SCHEMA_VERSION = "coverage-candidate-source-validation/v7"
SOURCE_VALIDATION_CACHE_VERSION = "coverage-source-validation-cache/v7"
SOURCE_DISCOVERY_CACHE_VERSION = "coverage-source-requirement-cache/v7"
PRECISION_AUDIT_SCHEMA_VERSION = "coverage-precision-audit-sample/v7"

SAME_ORIGIN_SCHEMA_VERSION = "coverage-same-origin-witness/v7"
SAME_ORIGIN_EXCLUSION_VERSION = "coverage-same-origin-exclusion/v7"
SAME_ORIGIN_AUDIT_VERSION = "coverage-candidate-origin-audit/v7"

GT_AUDIT_SCHEMA_VERSION = "coverage-ground-truth-audit/v7"
GT_CHAT_SCHEMA_VERSION = "coverage-ground-truth-chat/v7"
GT_MANIFEST_SCHEMA_VERSION = "coverage-ground-truth-manifest/v7"
CORRECTION_DISPOSITION_SCHEMA_VERSION = "coverage-correction-disposition/v7"

COMPARISON_PROMPT_VERSION = "coverage-chain-comparison/v7"
CAPABILITY_PROMPT_VERSION = "coverage-capability-card-analysis/v7"
SOURCE_DISCOVERY_PROMPT_VERSION = "coverage-source-requirement-discovery/v7"
LEARNED_PROMPT_VERSION = "coverage-learned-invariant-comparison/v9"
SOURCE_VALIDATION_PROMPT_VERSION = "coverage-source-validation/v7"
GROUND_TRUTH_PROMPT_VERSION = "coverage-ground-truth-matching/v7"
OVERLAP_CONFLICT_POLICY_VERSION = "coverage-overlap-conflict-validation/v7"
EXACT_REPLAY_TRANSPORT_VERSION = "coverage-exact-prompt-replay/v7"
SOURCE_DISCOVERY_TRANSPORT_VERSION = "coverage-source-agent-discovery/v7"
SOURCE_VALIDATION_TRANSPORT_VERSION = "coverage-source-agent-validation/v7"
STRICT_MATCH_PROVENANCE_VERSION = "coverage-strict-match-provenance/v7"
MIGRATION_PROVENANCE_VERSION = "coverage-migration-provenance/v7"

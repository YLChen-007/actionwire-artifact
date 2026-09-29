"""Curated hierarchical-analysis profiles for exceptional compound gates.

Profiles are intentionally narrow. They are keyed by revision-independent source
symbols, never by generated catalog ordinals or revision-dependent gate IDs.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SourceSelection:
    """One exact project symbol included in a compound analysis."""

    file: str
    symbol: str


@dataclass(frozen=True)
class CompoundFragmentProfile:
    """One bounded source group analyzed before final composition."""

    fragment_id: str
    title: str
    focus: str
    check_ids: tuple[str, ...]
    policy_ids: tuple[str, ...] = ()
    selections: tuple[SourceSelection, ...] = ()


@dataclass(frozen=True)
class CompoundCheckProfile:
    """One decision-relevant child check required in the compound IR."""

    check_id: str
    fragment_id: str
    title: str
    op: str
    source: SourceSelection
    source_contains: str
    outcomes: tuple[tuple[str, str], ...]
    policy_refs: tuple[str, ...] = ()
    required_unresolved: tuple[str, ...] = ()
    reject_examples: tuple[tuple[str, str, str], ...] = ()


@dataclass(frozen=True)
class CompoundPolicyProfile:
    """One source policy table whose every entry must survive composition."""

    policy_id: str
    fragment_id: str
    title: str
    source: SourceSelection
    item_prefix: str


@dataclass(frozen=True)
class CompoundGateProfile:
    """Curated source and complete semantic contract for one compound gate."""

    profile_id: str
    qualified_function: str
    semantic_root: SourceSelection
    summary: str
    entry_check: str
    fragments: tuple[CompoundFragmentProfile, ...]
    checks: tuple[CompoundCheckProfile, ...]
    policies: tuple[CompoundPolicyProfile, ...]
    terminals: tuple[tuple[str, str], ...]
    default: str
    on_error: str
    opaque_boundaries: tuple[str, ...]
    forced_unresolved: tuple[str, ...]


APPROVAL_ROOT = SourceSelection("tools/approval.py", "check_all_command_guards")


CHECK_ALL_GUARDS_PROFILE = CompoundGateProfile(
    profile_id="hermes-check-all-guards/v2",
    qualified_function="tools.terminal_tool._check_all_guards",
    semantic_root=APPROVAL_ROOT,
    summary=(
        "Applies every ordered hardline, bypass, scanner, pattern, prior-approval, "
        "smart-review, and user-approval policy to a command."
    ),
    entry_check="C01",
    fragments=(
        CompoundFragmentProfile(
            fragment_id="F1",
            title="Invocation and environment bypasses",
            focus=(
                "Recover caller force routing, isolated-environment bypass, and the "
                "enforced allow/block/approval-required callsite outcomes."
            ),
            check_ids=("C01", "C02"),
            selections=(
                SourceSelection("tools/terminal_tool.py", "_get_approval_callback"),
            ),
        ),
        CompoundFragmentProfile(
            fragment_id="F2",
            title="Normalization and unconditional hardline policy",
            focus=(
                "Recover command normalization, first-match hardline behavior, every "
                "hardline policy entry, unconditional rejection, and error behavior."
            ),
            check_ids=("C03", "C04"),
            policy_ids=("P_HARDLINE",),
            selections=(
                SourceSelection("tools/approval.py", "_CMDPOS"),
                SourceSelection("tools/approval.py", "_RE_FLAGS"),
                SourceSelection("tools/approval.py", "HARDLINE_PATTERNS"),
                SourceSelection("tools/approval.py", "HARDLINE_PATTERNS_COMPILED"),
                SourceSelection(
                    "tools/approval.py", "_normalize_command_for_detection"
                ),
                SourceSelection("tools/ansi_strip.py", "strip_ansi"),
                SourceSelection("tools/approval.py", "detect_hardline_command"),
                SourceSelection("tools/approval.py", "_hardline_block_result"),
            ),
        ),
        CompoundFragmentProfile(
            fragment_id="F3",
            title="Configured and unattended bypass policy",
            focus=(
                "Recover approval-mode resolution, process/session YOLO and mode-off "
                "bypasses, execution-surface routing, and cron allow/block behavior."
            ),
            check_ids=("C05", "C06", "C07", "C08", "C09", "C10", "C11"),
            selections=(
                SourceSelection("tools/approval.py", "_normalize_approval_mode"),
                SourceSelection("tools/approval.py", "_get_approval_config"),
                SourceSelection("tools/approval.py", "_get_approval_mode"),
                SourceSelection("tools/approval.py", "_get_cron_approval_mode"),
                SourceSelection("tools/approval.py", "get_current_session_key"),
                SourceSelection("tools/approval.py", "is_session_yolo_enabled"),
                SourceSelection("tools/approval.py", "is_current_session_yolo_enabled"),
                SourceSelection("utils.py", "is_truthy_value"),
            ),
        ),
        CompoundFragmentProfile(
            fragment_id="F4",
            title="Tirith and built-in dangerous-pattern detection",
            focus=(
                "Recover Tirith enablement, exit and failure policy, finding rendering, "
                "built-in first-match detection, and every dangerous policy entry."
            ),
            check_ids=("C12", "C13", "C14", "C16"),
            policy_ids=("P_DANGEROUS",),
            selections=(
                SourceSelection("tools/approval.py", "_SSH_SENSITIVE_PATH"),
                SourceSelection("tools/approval.py", "_HERMES_ENV_PATH"),
                SourceSelection("tools/approval.py", "_PROJECT_ENV_PATH"),
                SourceSelection("tools/approval.py", "_PROJECT_CONFIG_PATH"),
                SourceSelection("tools/approval.py", "_SHELL_RC_FILES"),
                SourceSelection("tools/approval.py", "_CREDENTIAL_FILES"),
                SourceSelection("tools/approval.py", "_SENSITIVE_WRITE_TARGET"),
                SourceSelection("tools/approval.py", "_PROJECT_SENSITIVE_WRITE_TARGET"),
                SourceSelection("tools/approval.py", "_COMMAND_TAIL"),
                SourceSelection("tools/approval.py", "_RE_FLAGS"),
                SourceSelection("tools/approval.py", "DANGEROUS_PATTERNS"),
                SourceSelection("tools/approval.py", "DANGEROUS_PATTERNS_COMPILED"),
                SourceSelection("tools/approval.py", "detect_dangerous_command"),
                SourceSelection("tools/approval.py", "_format_tirith_description"),
                SourceSelection("tools/tirith_security.py", "_env_bool"),
                SourceSelection("tools/tirith_security.py", "_env_int"),
                SourceSelection("tools/tirith_security.py", "_load_security_config"),
                SourceSelection("tools/tirith_security.py", "_MAX_FINDINGS"),
                SourceSelection("tools/tirith_security.py", "_MAX_SUMMARY_LEN"),
                SourceSelection("tools/tirith_security.py", "check_command_security"),
            ),
        ),
        CompoundFragmentProfile(
            fragment_id="F5",
            title="Prior approvals, warning aggregation, and smart review",
            focus=(
                "Recover canonical/legacy approval-key derivation, Tirith and pattern "
                "approval matching, warning aggregation, smart review, and session effects."
            ),
            check_ids=("C15", "C17", "C18", "C19"),
            selections=(
                SourceSelection("tools/approval.py", "_legacy_pattern_key"),
                SourceSelection("tools/approval.py", "_PATTERN_KEY_ALIASES"),
                SourceSelection("tools/approval.py", "_approval_key_aliases"),
                SourceSelection("tools/approval.py", "is_approved"),
                SourceSelection("tools/approval.py", "_smart_approve"),
                SourceSelection("tools/approval.py", "approve_session"),
            ),
        ),
        CompoundFragmentProfile(
            fragment_id="F6",
            title="Gateway and CLI approval resolution",
            focus=(
                "Recover approval-surface routing, notification and timeout failures, "
                "all user choices, pending status, and persistence restrictions."
            ),
            check_ids=("C20", "C21", "C22", "C23", "C24", "C25", "C26"),
            selections=(
                SourceSelection("tools/approval.py", "_get_approval_timeout"),
                SourceSelection("tools/approval.py", "prompt_dangerous_approval"),
                SourceSelection("tools/approval.py", "submit_pending"),
                SourceSelection("tools/approval.py", "approve_permanent"),
                SourceSelection("tools/approval.py", "save_permanent_allowlist"),
            ),
        ),
    ),
    checks=(
        CompoundCheckProfile(
            "C01",
            "F1",
            "Caller force bypass",
            "allow-if",
            SourceSelection("tools/terminal_tool.py", "terminal_tool"),
            "if not force:",
            (("force-enabled", "T_ALLOW"), ("force-disabled", "C02")),
        ),
        CompoundCheckProfile(
            "C02",
            "F1",
            "Isolated-environment bypass",
            "allow-if",
            APPROVAL_ROOT,
            'if env_type in ("docker", "singularity", "modal", "daytona", "vercel_sandbox"):',
            (("isolated", "T_ALLOW"), ("host-capable", "C03")),
        ),
        CompoundCheckProfile(
            "C03",
            "F2",
            "Command normalization",
            "normalize",
            SourceSelection("tools/approval.py", "_normalize_command_for_detection"),
            "command = strip_ansi(command)",
            (("normalized", "C04"),),
        ),
        CompoundCheckProfile(
            "C04",
            "F2",
            "Unconditional hardline matcher",
            "block-if",
            APPROVAL_ROOT,
            "if is_hardline:",
            (("match", "T_BLOCK"), ("no-match", "C05")),
            policy_refs=("P_HARDLINE",),
            reject_examples=(
                (
                    "<recursive deletion of a protected root>",
                    "It matches an unconditional hardline deletion rule.",
                    "The environment is host-capable and force is disabled.",
                ),
                (
                    "<host shutdown command>",
                    "It matches an unconditional hardline shutdown rule.",
                    "The environment is host-capable and force is disabled.",
                ),
            ),
        ),
        CompoundCheckProfile(
            "C05",
            "F3",
            "Approval-mode resolution",
            "derive",
            SourceSelection("tools/approval.py", "_normalize_approval_mode"),
            "if isinstance(mode, bool):",
            (("resolved", "C06"),),
        ),
        CompoundCheckProfile(
            "C06",
            "F3",
            "Process YOLO bypass",
            "allow-if",
            APPROVAL_ROOT,
            'is_truthy_value(os.getenv("HERMES_YOLO_MODE"))',
            (("enabled", "T_ALLOW"), ("disabled", "C07")),
        ),
        CompoundCheckProfile(
            "C07",
            "F3",
            "Session YOLO bypass",
            "allow-if",
            APPROVAL_ROOT,
            "is_current_session_yolo_enabled()",
            (("enabled", "T_ALLOW"), ("disabled", "C08")),
        ),
        CompoundCheckProfile(
            "C08",
            "F3",
            "Approval-mode-off bypass",
            "allow-if",
            APPROVAL_ROOT,
            'approval_mode == "off"',
            (("enabled", "T_ALLOW"), ("disabled", "C09")),
        ),
        CompoundCheckProfile(
            "C09",
            "F3",
            "Execution-surface routing",
            "derive",
            APPROVAL_ROOT,
            "if not is_cli and not is_gateway and not is_ask:",
            (("interactive-or-ask", "C12"), ("noninteractive", "C10")),
        ),
        CompoundCheckProfile(
            "C10",
            "F3",
            "Noninteractive and cron policy",
            "allow-if",
            APPROVAL_ROOT,
            'if os.getenv("HERMES_CRON_SESSION"):',
            (
                ("not-cron", "T_ALLOW"),
                ("cron-approve", "T_ALLOW"),
                ("cron-deny", "C11"),
            ),
        ),
        CompoundCheckProfile(
            "C11",
            "F3",
            "Unattended cron dangerous-command denial",
            "block-if",
            APPROVAL_ROOT,
            "is_dangerous, _pk, description = detect_dangerous_command(command)",
            (("match", "T_BLOCK"), ("no-match", "T_ALLOW")),
            policy_refs=("P_DANGEROUS",),
            reject_examples=(
                (
                    "<dangerous unattended cron command>",
                    "It matches a dangerous policy rule and cron denial is configured.",
                    "The session is noninteractive cron with cron_mode deny.",
                ),
            ),
        ),
        CompoundCheckProfile(
            "C12",
            "F4",
            "Tirith enablement and import availability",
            "allow-if",
            APPROVAL_ROOT,
            "except ImportError:",
            (("disabled-or-missing", "C16"), ("enabled", "C13")),
        ),
        CompoundCheckProfile(
            "C13",
            "F4",
            "Tirith scan, exit-code, and failure policy",
            "unknown",
            SourceSelection("tools/tirith_security.py", "check_command_security"),
            "exit_code = result.returncode",
            (
                ("allow", "C16"),
                ("warn-or-block", "C14"),
                ("unexpected-error", "T_PROPAGATE"),
            ),
            required_unresolved=("external-policy:tirith-binary-matching-rules",),
        ),
        CompoundCheckProfile(
            "C14",
            "F4",
            "Tirith finding normalization and description",
            "derive",
            SourceSelection("tools/approval.py", "_format_tirith_description"),
            'findings = tirith_result.get("findings") or []',
            (("described", "C15"),),
        ),
        CompoundCheckProfile(
            "C15",
            "F5",
            "Prior approval for Tirith findings with canonical and legacy aliases",
            "allow-if",
            APPROVAL_ROOT,
            "if not is_approved(session_key, tirith_key):",
            (("approved", "C16"), ("unapproved-warning", "C16")),
        ),
        CompoundCheckProfile(
            "C16",
            "F4",
            "Built-in dangerous-command matcher",
            "derive",
            SourceSelection("tools/approval.py", "detect_dangerous_command"),
            "for pattern_re, description in DANGEROUS_PATTERNS_COMPILED:",
            (
                ("no-match", "C18"),
                ("match", "C17"),
                ("error", "T_PROPAGATE"),
            ),
            policy_refs=("P_DANGEROUS",),
        ),
        CompoundCheckProfile(
            "C17",
            "F5",
            "Prior approval for built-in patterns with canonical and legacy aliases",
            "allow-if",
            APPROVAL_ROOT,
            "if not is_approved(session_key, pattern_key):",
            (("approved", "C18"), ("unapproved-warning", "C18")),
        ),
        CompoundCheckProfile(
            "C18",
            "F5",
            "Warning aggregation and no-warning allow",
            "allow-if",
            APPROVAL_ROOT,
            "if not warnings:",
            (
                ("none", "T_ALLOW"),
                ("smart-mode", "C19"),
                ("manual-mode", "C20"),
            ),
        ),
        CompoundCheckProfile(
            "C19",
            "F5",
            "Smart approval review",
            "block-if",
            APPROVAL_ROOT,
            'if approval_mode == "smart":',
            (
                ("approve", "T_ALLOW"),
                ("deny", "T_BLOCK"),
                ("escalate", "C20"),
                ("error", "C20"),
            ),
            reject_examples=(
                (
                    "<warning-bearing command judged DENY>",
                    "Smart review returns DENY for the combined warnings.",
                    "Approval mode is smart.",
                ),
            ),
        ),
        CompoundCheckProfile(
            "C20",
            "F6",
            "Human-approval surface routing",
            "derive",
            APPROVAL_ROOT,
            "if is_gateway or is_ask:",
            (("gateway-or-ask", "C21"), ("cli", "C25")),
        ),
        CompoundCheckProfile(
            "C21",
            "F6",
            "Gateway callback availability",
            "prompt",
            APPROVAL_ROOT,
            "if notify_cb is not None:",
            (("callback", "C22"), ("no-callback", "T_APPROVAL_REQUIRED")),
        ),
        CompoundCheckProfile(
            "C22",
            "F6",
            "Gateway notification failure",
            "block-if",
            APPROVAL_ROOT,
            "notify_cb(approval_data)",
            (("notified", "C23"), ("notification-error", "T_BLOCK")),
            reject_examples=(
                (
                    "<warning-bearing gateway command>",
                    "The user notification callback fails.",
                    "A gateway callback is registered but raises an exception.",
                ),
            ),
        ),
        CompoundCheckProfile(
            "C23",
            "F6",
            "Gateway timeout and user decision",
            "block-if",
            APPROVAL_ROOT,
            'if not resolved or choice is None or choice == "deny":',
            (("timeout-or-deny", "T_BLOCK"), ("approved", "C24")),
            reject_examples=(
                (
                    "<warning-bearing gateway command>",
                    "Approval times out or the user denies it.",
                    "Gateway or ask-mode approval is required.",
                ),
            ),
        ),
        CompoundCheckProfile(
            "C24",
            "F6",
            "Gateway approval persistence",
            "constrain",
            APPROVAL_ROOT,
            'for key, _, is_tirith in warnings:\n                if choice == "session"',
            (("persisted-or-once", "T_ALLOW"),),
        ),
        CompoundCheckProfile(
            "C25",
            "F6",
            "CLI prompt and user decision",
            "block-if",
            SourceSelection("tools/approval.py", "prompt_dangerous_approval"),
            "if approval_callback is not None:",
            (("deny-or-error", "T_BLOCK"), ("approved", "C26")),
            reject_examples=(
                (
                    "<warning-bearing CLI command>",
                    "The prompt denies, times out, or its callback fails.",
                    "CLI approval is required.",
                ),
            ),
        ),
        CompoundCheckProfile(
            "C26",
            "F6",
            "CLI approval persistence",
            "constrain",
            APPROVAL_ROOT,
            'for key, _, is_tirith in warnings:\n        if choice == "session"',
            (("persisted-or-once", "T_ALLOW"),),
        ),
    ),
    policies=(
        CompoundPolicyProfile(
            "P_HARDLINE",
            "F2",
            "Unconditional hardline command patterns",
            SourceSelection("tools/approval.py", "HARDLINE_PATTERNS"),
            "H",
        ),
        CompoundPolicyProfile(
            "P_DANGEROUS",
            "F4",
            "Approvable dangerous-command patterns",
            SourceSelection("tools/approval.py", "DANGEROUS_PATTERNS"),
            "D",
        ),
    ),
    terminals=(
        ("T_ALLOW", "Allow command execution."),
        ("T_BLOCK", "Block command execution."),
        ("T_APPROVAL_REQUIRED", "Return a pending approval-required decision."),
        ("T_PROPAGATE", "Propagate an unexpected error to the caller."),
    ),
    default="Allow only after every reachable check reaches T_ALLOW.",
    on_error=(
        "Follow each child check's error rule; unexpected scanner and matcher errors "
        "propagate, while approval-channel failures block."
    ),
    opaque_boundaries=(
        "agent.auxiliary_client.call_llm provider, retry, and credential plumbing",
        "Tirith installation, download, and provenance-verification internals",
        "plugin approval hooks, which swallow observer failures",
        "gateway activity heartbeat and queue implementation details",
    ),
    forced_unresolved=("external-policy:tirith-binary-matching-rules",),
)


PROFILES = (CHECK_ALL_GUARDS_PROFILE,)


def find_compound_profile(
    qualified_function: str, *, project_id: str = "hermes-agent"
) -> CompoundGateProfile | None:
    """Return the one exact profile matching a resolved gate implementation."""

    if project_id != "hermes-agent":
        return None

    return next(
        (
            profile
            for profile in PROFILES
            if profile.qualified_function == qualified_function
        ),
        None,
    )

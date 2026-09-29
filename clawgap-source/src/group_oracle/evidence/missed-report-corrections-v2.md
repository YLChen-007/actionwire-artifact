# Source-backed post-hoc coverage corrections v2

This catalogue is ground-truth-informed corrective evidence. It is not part of the blind
baseline. Each claim is project-neutral and is supported by source at the pinned benchmark
revision; vulnerability-report text and report identifiers are intentionally excluded.

## astrbot-write-root-permission-separation

**A restricted file-write or file-edit authorization policy must use roots that grant write permission and must not reuse read-only plugin-skill roots merely because their paths are contained.**

Source anchors: `benchmark/python/AstrBot/astrbot/core/tools/computer_tools/fs.py:113-121,169-185` and the rollback binding in `design/AstrBot/astrbot-4.25.2-acceptance.json`.

## browser-eval-post-navigation-policy

**Browser evaluation that can change the main-frame location must validate the expression-derived or resulting destination against the same scheme, hostname, and IP policy required for direct navigation.**

Source anchors: `benchmark/python/hermes-agent/tools/browser_tool.py` browser evaluation dispatch and the direct-navigation URL policy in the same module.

## device-path-canonicalization

**A blocking-device denylist must canonicalize user-controlled paths, including home expansion and dot-segment normalization, before comparing device identities.**

Source anchor: `benchmark/python/hermes-agent/tools/file_tools.py:130,312`.

## code-execution-action-approval

**Model-controlled source code that is written and launched as a host process must pass a code-dependent action-approval decision before process creation.**

Source anchors: `benchmark/python/hermes-agent/tools/code_execution_tool.py` code write/launch path and `benchmark/python/hermes-agent/tools/approval.py:920` command-only guard.

## noninteractive-approval-routing

**A noninteractive batch or scheduled execution context must fail closed or route model-controlled dangerous commands through an explicit approval policy instead of defaulting to approved.**

Source anchor: `benchmark/python/hermes-agent/tools/approval.py:920-980`.

## dangerous-command-class-completeness

**A dangerous-command gate must cover every source-supported destructive command class before auto-approval; an incomplete pattern table must not be treated as complete authorization.**

Source anchor: `benchmark/python/hermes-agent/tools/approval.py:920-980` and its reachable dangerous-command pattern tables.

## droidclaw-shell-action-approval

**A model-selected adb shell action must require explicit user approval or a deny-by-default command policy before execution; a non-empty command check alone is not authorization.**

Source anchor: `benchmark/typescript/droidclaw/src/actions.ts:699-704`.

## subprocess-messaging-credential-isolation

**A restricted child-process environment must remove messaging and provider credential names from the inherited environment before launching model-controlled commands.**

Source anchor: `benchmark/python/hermes-agent/tools/environments/local.py:416` and the environment-key lists used by `_make_run_env`.

## delegated-subagent-capability-congruence

**A subagent type may be auto-approved as read-only only when the selected configuration's tool surface and permission mode are actually read-only and do not exceed the parent approval envelope.**

Source anchors: `benchmark/typescript/lettabot/vendor-source/letta-code-v0.19.5/src/permissions/checker.ts:688-757` and `src/agent/subagents/manager.ts:568-610` under the same benchmark root.

## jq-module-directive-semantics

**A jq safe-bin policy must reject or safely resolve include and import module directives before jq is auto-approved for host execution.**

Source anchor: `benchmark/typescript/openclaw/src/infra/exec-safe-bin-semantics.ts:24-30`.

## broadcast-mention-neutralization

**Untrusted outbound message content must neutralize platform broadcast mentions and must disable mention interpretation when the delivery API exposes such a companion capability.**

Source anchors: `benchmark/python/hermes-agent/gateway/platforms/slack.py:1169` and `tools/send_message_tool.py:1041` under the same benchmark root.

## matrix-html-all-route-sanitization

**Every route that emits Matrix custom HTML must neutralize raw HTML, event attributes, and dangerous URI schemes on the primary path, not only on an error fallback.**

Source anchors: `benchmark/python/hermes-agent/tools/send_message_tool.py:1399` and `gateway/platforms/matrix.py:2585` under the same benchmark root.

## post-interaction-navigation-validation

**After a browser click, double-click, or evaluated page action can navigate, the resulting destination must be revalidated before later browser access.**

Source anchors: `benchmark/typescript/openclaw-cn/src/browser/routes/agent.act.ts:79,257` and `src/browser/pw-tools-core.interactions.ts:257` under the same benchmark root.

## shell-wrapper-flag-normalization

**Inline-command extraction must recognize every supported cmd and PowerShell wrapper flag spelling before allowlist or durable-approval evaluation.**

Source anchors: `benchmark/typescript/openclaw/src/infra/shell-wrapper-resolution.ts:209-225` and `src/infra/shell-inline-command.ts:169-220` under the same benchmark root.

## jq-environment-builtin-semantics

**A jq safe-bin policy must reject jq programs that access the environment through `env` or `$ENV` before auto-approval.**

Source anchors: `benchmark/python/QwenPaw/src/qwenpaw/security/tool_guard/rules/dangerous_shell_commands.yaml:244-288`, the inherited-environment shell execution path in `benchmark/python/QwenPaw/src/qwenpaw/agents/tools/shell.py`, and `benchmark/typescript/openclaw/src/infra/exec-safe-bin-policy-validator.ts:33` with `src/infra/exec-safe-bin-semantics.ts:24-30` under the OpenClaw benchmark root.

## durable-approval-inner-payload-binding

**A durable allow-always approval for a shell wrapper must bind the complete normalized inner payload and must not persist trust for only the wrapper executable path.**

Source anchors: `benchmark/typescript/openclaw-cn/src/agents/bash-tools.exec.ts:1259` and `src/infra/exec-approvals-allowlist.ts:266,331` under the same benchmark root.

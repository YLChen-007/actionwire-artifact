# Hermes Prompt-Entry → Tool Static Inference Design

## Purpose and pipeline position

This module determines which model-callable tools may be exposed to each externally controlled prompt entry. It adds an upstream reachability filter to the existing pipeline:

```text
prompt entry → exposed tool → handler → sink → gate
```

The tool handler remains the root anchor for handler→sink call-chain construction. Prompt-entry inference does not replace or move that root: it joins an entry to an already enumerated handler and can then include or exclude that handler's downstream chains for a particular attacker entry.

“Prompt entry” means externally controlled text that reaches `AIAgent.run_conversation(...)` (or the one-shot wrapper that reaches it). Slash commands and other commands that bypass the LLM are not prompt entries.

## Source-code mechanism

Hermes does not bind a channel directly to handler functions. Binding happens through one `AIAgent` instance and two independent relations:

```text
PromptEntry ──constructs/uses──> AIAgent ──filters──> tool definitions
Toolset ──contains──> tool name ──registry.register──> handler
```

At construction, `AIAgent` passes `enabled_toolsets` and `disabled_toolsets` to `get_tool_definitions`, then derives `valid_tool_names` from the filtered definitions (`run_agent.py:1613-1626`). The model receives those definitions. Model-generated tool names outside `valid_tool_names` are rejected or repaired before dispatch (`run_agent.py:13494-13536`). Thus the `AIAgent` instance is the correct join point between a prompt entry and the registry.

Platform-facing entry code obtains enabled toolsets as follows:

- CLI: explicit `--toolsets` when supplied, otherwise `_get_platform_tools(config, "cli")`. The explicit argument is validated as a toolset name but does not pass through saved-platform restriction filtering; this permits CLI testing of `discord`/`discord_admin` with the required token.
- One-shot CLI: explicit `--toolsets`, otherwise the CLI profile.
- TUI/dashboard: `HERMES_TUI_TOOLSETS`, otherwise the CLI profile.
- Gateway: `_get_platform_tools(config, source.platform)`; the shared call site is expanded into one logical entry for every built-in `PLATFORMS` key.
- Cron: per-job override, otherwise the Cron profile, with `cronjob`, `messaging`, and `clarify` always disabled.
- API server: API-server profile.
- ACP/editor: `hermes-acp` plus dynamically loaded MCP toolsets.
- Feishu comment: the fixed `feishu_doc` and `feishu_drive` toolsets.

`toolsets.py` declares tool names and composite `includes`. `hermes_cli/platforms.py` maps each platform to a default composite. `hermes_cli/tools_config.py` implements configuration overrides, platform restrictions, default-off toolsets, non-configurable platform additions, and plugin extensions. Tool modules bind concrete names to handlers with `registry.register(...)`; plugin contexts use `register_tool(...)`; MCP and plugin factories may retain symbolic names until runtime.

## Analysis relations and states

The implementation materializes these logical relations:

```text
PromptEntry(
  entry_id, prompt_source, run_conversation_call,
  agent_constructor, platform_expr,
  enabled_toolsets_expr, disabled_toolsets_expr
)

EntryToolset(entry_id, toolset, selection_state)
ToolsetTool(toolset, tool_name)

RegisteredTool(
  tool_name, canonical_toolset, handler,
  check_fn, requires_env, registration_location
)

EntryTool(
  entry_id, tool_name, handler,
  selection_state, exposure_state, context_state
)
```

`EntryToolset` and `ToolsetTool` are represented in the long-form CSV by `selected_via_toolsets` and `toolset_evidence` rather than separate output files.

State meanings:

- `selection_state`: `default` for empty-configuration source defaults; `configurable` for conservative supported overrides; `dynamic` for a known plugin/MCP extension edge whose concrete names need runtime metadata; `unresolved` for a source expression that cannot be evaluated.
- `exposure_state`: `unconditional` when a registration has no availability predicate; `check_fn_conditional` when `check_fn` must pass; `unresolved` when registration or runtime metadata is unavailable.
- `context_state`: `satisfied`, `conditional`, `blocked`, or `unknown` for entry-local execution prerequisites.

The canonical security view is conservative: both `default` and `configurable` tools are potentially prompt-reachable. It does not claim that a runtime installation has credentials or that a particular user configuration enables every configurable tool.

## Hybrid static implementation

### CodeQL anchor query

[`get_prompt_entries.ql`](../../../src/ql/get_prompt_entries.ql) enumerates non-test:

- direct `run_conversation(...)` calls;
- the one-shot `chat(...)` wrapper;
- executor references, including `pool.submit(context.run, agent.run_conversation, prompt)`;
- all `AIAgent(...)` constructions.

It preserves prompt, platform, enabled/disabled expression text, enclosing function, location, and a coarse classification. The deterministic resolver performs cross-function ownership for persistent agents. Every discovered prompt call/reference is emitted; caller-defined and internal sites are classified explicitly, and unknown sites become `unresolved` rather than disappearing.

### Deterministic declaration resolver

[`infer_prompt_entry_tools.py`](debug/script/infer_prompt_entry_tools.py) parses Hermes source with Python's AST and never imports or executes Hermes modules. Its deliberately small evaluator accepts literals, containers, name references, list concatenation, `OrderedDict`, and `PlatformInfo`; all other expressions remain unknown.

The resolver expands `TOOLSETS.includes` recursively, derives source-default and conservative configurable profiles, applies platform restrictions/default-off behavior, subtracts entry-specific disabled toolsets, and expands the shared gateway call site into logical platform entries. Results are sorted before serialization for byte-identical regeneration.

### Registration and handler join

[`get_tool_registrations.ql`](../../../src/ql/get_tool_registrations.ql) extracts `registry.register(...)` and plugin `register_tool(...)` metadata: name, canonical toolset, handler expression, `check_fn`, `requires_env`, async flag, and source location.

Concrete names join by exact tool name to the existing 67-row handler-entry result. A tool referenced by a toolset but absent from that result is emitted as `handler_unresolved`. Plugin/MCP registrations with factory-provided names remain present in the raw registration CSV and are represented in the canonical relation by symbolic dynamic rows.

## Exposure and entry-local context

A selected concrete tool is considered exposed only through a registration. `check_fn` is not executed; its presence produces `check_fn_conditional`.

Known entry-local rules are modeled explicitly:

- The five Feishu document/drive handlers require the thread-local Lark client injected by the Feishu-comment path. Normal Feishu selects the same five tools through its platform profile, but their context is `blocked` unless another injection path is discovered. Feishu-comment has `satisfied` context.
- The five Yuanbao handlers are globally registered under `hermes-yuanbao`, but their `_check_yuanbao` requires either a Yuanbao session context or an active Yuanbao adapter in the same process. `gateway:yuanbao` satisfies both naturally. Standalone CLI can select their names through configuration but does not start the adapter, so it is not the preferred practical test witness.
- `send_message` is satisfied for normal gateway entries and conditional elsewhere because it needs gateway session/running state.
- `clarify` is satisfied for interactive CLI/one-shot/TUI profiles and blocked for constructors without a callback.
- Credential, environment, browser, terminal, Home Assistant, plugin, and MCP checks remain conditional or unknown.

Indirect tool mechanisms do not widen the originating profile:

- `execute_code` generates sandbox stubs only for `SANDBOX_ALLOWED_TOOLS ∩ enabled_tools` (`tools/code_execution_tool.py:148-161`).
- Delegation intersects requested child toolsets with the parent's effective capability set and removes blocked child toolsets (`tools/delegate_tool.py:921-956`). Background/delegated runs are classified as inherited/internal, not independent attacker entries.
- Dispatch rejects model-produced names outside `valid_tool_names` before handler invocation.

## Minimal prompt-entry testing policy

The testing objective is tool/toolset coverage, not entry coverage. A tool only needs one prompt-entry witness even when many entries can reach it. Entry selection uses this lexicographic policy:

1. Minimize the number of distinct prompt-entry types needed to cover all target tools/toolsets.
2. When multiple entries can trigger the same tool, prefer CLI because it is the simplest test harness.
3. Add a non-CLI entry only when CLI is platform-restricted or has a known blocked execution context.

For concrete static testing, a relation is considered test-triggerable when its handler is resolved, selection is `default` or `configurable`, exposure is unconditional or runtime-check conditional, and context is `satisfied` or `conditional`. A runtime-conditional row is usable only after the test environment supplies its credential/dependency/session prerequisites. `blocked`, `unknown`, dynamic-name, and handler-unresolved rows do not count as verified concrete coverage.

Under the current source model, the test plan favors a self-contained/natural execution context over a theoretically possible cross-entry call that requires another platform adapter to be active:

- CLI is the preferred witness for 57 of the 67 concrete handler tools.
- Feishu-comment covers five Feishu document/drive tools and supplies their otherwise-missing Lark client.
- Yuanbao gateway covers five globally registered Yuanbao tools whose availability check depends on the Yuanbao session/adapter. CLI selection alone is insufficient in a normal standalone CLI process.
- CLI + Feishu-comment + Yuanbao gateway therefore cover all 67 concrete handlers.
- Discord and Discord-admin do not require another entry type: saved CLI platform configuration rejects these Discord-scoped toolsets, but direct `cli.py --toolsets discord,discord_admin` passes them to `AIAgent`. Their `check_fn` requires `DISCORD_BOT_TOKEN`, and their factory handlers remain a runtime/manual obligation for the handler query.
- Spotify, MCP, and other plugin extensions do not require another prompt-entry type: configure them on CLI and enumerate their concrete runtime registrations before invoking them.

Thus the practical full entry set is CLI, Feishu-comment, and Yuanbao gateway. Discord, Spotify, MCP, and other plugin tests reuse CLI with explicit configuration.

## Outputs

All generated artifacts live under `design/hermes-agent/prompt-entry/debug/`:

- `prompt-entry-anchors.csv`: raw CodeQL prompt/construction anchors.
- `tool-registrations.csv`: raw CodeQL registration relations.
- `prompt-entries.csv`: classified and gateway-expanded prompt entries.
- `prompt-entry-tools.csv`: canonical long-form entry→tool→handler relation with all states and evidence.
- `prompt-entry-tool-matrix.csv`: readable tool-by-entry matrix.
- `prompt-entry-tool-coverage.md`: profile summary, witnesses, Feishu distinction, conditional/blocked/dynamic/unresolved cases.

## Reproduction and validation

Run against the benchmark CodeQL database:

```bash
bin/codeql query run --database=/root/codeql-home/dbs/hermes-bench-py-db \
  --additional-packs=src/ql -o /tmp/prompt-entries.bqrs src/ql/get_prompt_entries.ql
bin/codeql bqrs decode --format=csv /tmp/prompt-entries.bqrs \
  > design/hermes-agent/prompt-entry/debug/prompt-entry-anchors.csv

bin/codeql query run --database=/root/codeql-home/dbs/hermes-bench-py-db \
  --additional-packs=src/ql -o /tmp/tool-registrations.bqrs src/ql/get_tool_registrations.ql
bin/codeql bqrs decode --format=csv /tmp/tool-registrations.bqrs \
  > design/hermes-agent/prompt-entry/debug/tool-registrations.csv

python design/hermes-agent/prompt-entry/debug/script/infer_prompt_entry_tools.py \
  --project-root benchmark/python/hermes-agent \
  --prompt-anchors design/hermes-agent/prompt-entry/debug/prompt-entry-anchors.csv \
  --registrations design/hermes-agent/prompt-entry/debug/tool-registrations.csv \
  --handlers design/hermes-agent/handler-entry/debug/tool-handler-entries.csv \
  --out-dir design/hermes-agent/prompt-entry/debug
```

Then run focused tests and deterministic-output validation:

```bash
python design/hermes-agent/prompt-entry/debug/script/test_infer_prompt_entry_tools.py
python design/hermes-agent/prompt-entry/debug/script/infer_prompt_entry_tools.py \
  --project-root benchmark/python/hermes-agent \
  --prompt-anchors design/hermes-agent/prompt-entry/debug/prompt-entry-anchors.csv \
  --registrations design/hermes-agent/prompt-entry/debug/tool-registrations.csv \
  --handlers design/hermes-agent/handler-entry/debug/tool-handler-entries.csv \
  --out-dir design/hermes-agent/prompt-entry/debug --check
```

The resolver fails if any non-test prompt anchor is unresolved, any existing handler is absent from the joined result, CLI and TUI defaults differ, Cron exposes an excluded tool, Feishu-comment differs from its fixed five-tool set, or gateway expansion is incomplete.

## Static-analysis boundary

Exact point-in-time availability is intentionally out of scope. Runtime configuration files, environment variables, credentials, discovered plugins, and MCP server schemas are not executed. Their influence is preserved as configurable, conditional, dynamic, or unresolved state so consumers can distinguish “not selected” from “not statically knowable.”

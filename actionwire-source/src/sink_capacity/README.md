# src/sink_capacity — Sink API capability-card generator

> Governs code (see `docs-map.yaml`): `src/sink_capacity/*.py`.

Builds the **sink-API capability oracle** specified by
[`design/common/detection-method.md`](../../design/common/detection-method.md) § "Sink Capability Oracle": for every sink
API defined in [`src/ql/call/sinks_af.qll`](../ql/call/sinks_af.qll) `is_sink_af`, emit a
natural-language **capability card** (English) that describes *what the API can do* +
runnable example usage. Design rationale:
[`design/hermes-agent/sink/sink-design.md`](../../design/hermes-agent/sink/sink-design.md).

This step only **describes** capability (facts + examples). It does **not** mention gates,
checks, or "what should be validated" — matching `gate coverage ⊇ sink capability` is the
next step.

Newly generated cards use `sink-capability-card/v2`. The v2 contract separates the reusable
API ceiling from a chain's effective capability:

- `api_family` and exact `runtime` bind the stable `SCC-*` identity;
- `roles[].bindings[]` names exact API arguments/receiver fields and records whether each is
  caller-bindable;
- `facets[]` carries one conditional effect per activation predicate set;
- `library_guarantees[]` records restrictions the concrete runtime enforces;
- `defaults[]` records behavior active only when the corresponding role is omitted;
- `normative_authority` is always `capability-facts-only`. Ordinary capability facts cannot
  authorize a security requirement. Only the separately parsed source-owned approval
  `policy_contract` is normative.

Legacy migration classifies the known Node/TypeScript families (`node`, `javascript`,
OpenClaw/NanoClaw/Mercury/DroidClaw/LettaBot/CodeG/TinyClaw/LobsterAI) as TypeScript and the
remaining current library/project families as Python. Runtime identity cannot contain
`unspecified` or `unresolved`, preventing defaults from one runtime from being joined to another.

`effective_capability.derive_effective_capability_views()` joins semantic chains with v2
cards and field-flow rows using `(project, revision, chain_id)`. It emits exact role bindings,
authority, transforms, call-shape predicates, active defaults, guarantees, boundaries and
actual effects as `effective-capability-view/v1`.

## Pipeline

```
sinks_af.qll ──extract_sinks──▶ 48 SinkAPI records ──┐
                                                     ├─ doc_sources: introspect() sig/docstring (installed pkg)
                                                     │              fetch_and_cache_doc() local doc snapshot
                                                     │              project_source() locate internal wrapper def
                                                     ▼
             prompts.build_user ──▶ agent.run_agent (claude CLI, DeepSeek backend, reads source itself)
                                                     ▼
                                    generate ──▶ index.md + <slug>.md
```

The 48 records comprise all 46 AgentFuzz `is_sink` disjuncts plus the local `md.convert`
rendering sink and the project-specific `prompt_dangerous_approval` user-consent sink. The
extractor has explicit classifications for every disjunct; none should fall back to
`unclassified.*`.

| module | role |
|---|---|
| `extract_sinks.py` | depth-aware split of `is_sink_af` into top-level `or` disjuncts; rule table → `SinkAPI` |
| `doc_sources.py` | doc acquisition: `introspect()` (inspect signature+docstring+version); `fetch_and_cache_doc()`/`crawl_all()` — **crawl official docs once into a local snapshot (`api-docs-snapshots/`), then reuse from disk** (offline, reproducible); `project_source()` (locate internal wrapper `def`); `DOC_URLS`/`SECURITY_REFS` (provenance) |
| `agent.py` | **agent runner**: drives the `claude` CLI headless with a **DeepSeek** backend (Anthropic-compatible endpoint). It excludes user-level Claude settings so another configured provider cannot override that backend, pins Claude helper-model aliases to the selected DeepSeek model, and uses `--tools` to expose only Read/Grep/Glob. For project-internal sinks the agent **reads the implementation itself** and follows what it calls. No direct DeepSeek HTTP. |
| `card_contract.py` / `card_migration.py` | strict v2 parser/identity, all-card directory validation, deterministic 114-card migration ledger |
| `effective_capability.py` | project/revision-bound per-chain role/facet/authority view derivation |
| `prompts.py` | English v2 capability-card prompt (capability facts + examples only; no gates; reply is the card, no file writes) |
| `generate.py` / `main.py` | staged regeneration, atomic publication, identity migration, index table + one `<slug>.md` per API; CLI |
| `llm.py` | *legacy* direct-DeepSeek-HTTP chat client — superseded by `agent.py`, not used by default; it has no credential literal and reads only `DEEPSEEK_API_KEY` |

## Usage

```bash
cd ~/my-project/agent-research/clawgap

# crawl official docs once into the local snapshot (design/api-docs-snapshots/):
python3 -m src.sink_capacity.main --crawl-docs

# index table + deterministic v1→v2 migration of existing cards (no LLM, fast;
# refuses to publish a source-review placeholder for a new API):
python3 -m src.sink_capacity.main --no-llm

# generate all 48 English cards via claude-agent + DeepSeek (~1-1.5 min each):
python3 -m src.sink_capacity.main

# only specific sink APIs (by slug):
python3 -m src.sink_capacity.main --only subprocess.Popen supervisor.evaluate_runtime

# migrate all 114 current cards into an isolated staging directory:
python3 -m src.sink_capacity.main \
  --out src/sink_capacity/sink-capability-cards \
  --migrate-v2-staging /tmp/clawgap-sink-capability-cards-v2

# atomically migrate all shared/source-owned cards to v2 and regenerate every
# Python-generator-owned card:
python3 -m src.sink_capacity.main --full-regeneration
```

Output: `src/sink_capacity/sink-capability-cards/` — `index.md` (table of all
sink APIs) + one `<slug>.md` per API (filename = sink API id).

The generic benchmark pipeline maps each concrete sink callsite to exactly one terminal
`sink_constraint` containing the card path/digest and concrete call shape. This constraint is
separate from the three gate types and is never included in a gate-semantics prompt.

Deterministic APIs:

- `migrate_markdown_card_to_v2(markdown, path=...)` migrates one legacy card;
- `migrate_card_directory(source_dir, staging_dir)` migrates every current card and returns
  path-sorted identity migration rows;
- `migrate_card_directory_in_place(source_dir)` performs the same migration atomically with
  restore-on-failure;
- `generate.regenerate_all_cards(...)` stages and atomically publishes the Python generator's
  complete owned set;
- `derive_effective_capability_views(...)` returns exactly one project/revision-bound view per
  semantic chain.

Full regeneration writes `identity-migration.jsonl` and a digest-bound manifest only after all
114 cards validate as v2. It first deterministically migrates the complete shared directory,
preserving source-owned approval policy contracts, and then replaces Python-generator-owned
cards with source-backed regeneration results. TypeScript/project cards are migrated from their
existing source-owned content rather than deleted or replaced by empty scaffolds.

Effective-view authority uses the closed v15 vocabulary: `model-arbitrary`,
`model-component`, `model-basename`, `model-enum`, `internal-derived`, `operator-config`,
`provider-response`, and `fixed`. A confirmed caller-bindable origin defaults to
`model-arbitrary`; narrower field-flow authority overrides it. A selector key does not confer
authority over the selected stored value.

## JavaScript/TypeScript benchmark cards

The Python card generator continues to parse only `src/ql/call/sinks_af.qll`. TypeScript projects use the
independent pack at `src/ql-js/`. Its `call/sinks_af.qll` is one project-neutral catalog: sink recognition uses
module/API identity, receiver, literal action/payload and enclosing signatures, never an adapter predicate or a
source-file whitelist. Project models remain responsible for handler/source identity and constrained call/taint
bridges. A shared audit may therefore contain sinks unrelated to the active adapter; only handler-source-reachable
calls become chains and constraints. Legacy project-prefixed canonical IDs remain stable artifact keys.
Capability-card selection follows the same contract: it dispatches on sink label/call shape/enclosing signature,
not project identity, so a shared sink remains assemblable when another adapter reaches the same capability.

The audited terminal rules map directly to the Node and boundary cards in this directory:

- `node.child-process.md`, `node.fs.read.md`, `node.fs.write.md`, and `node.fs.delete.md`;
- `javascript.fetch.md`;
- `openclaw.browser-navigation.md`, `openclaw.delivery.md`, `openclaw.node-invoke.md`,
  `openclaw.gateway-rpc.md`, and `openclaw.external-tool-boundary.md`.

同一 `src/ql-js` facade 为 NanoClaw 的 15 个 source-bearing handler 选择 `nanoclaw.*.md` 语义能力卡，覆盖 agent
创建、消息/文件/card 投递、消息编辑/reaction、交互提问、任务读写生命周期、包安装和 MCP server 注册。报告 API
使用 `NanoClaw.<handler>`，物理 `writeMessageOut`/DB boundary 只作受 discriminator 和 consumer 约束的 witness。
GT primitive 继续选择 `node.fs.copy.md` 以及 `nanoclaw.approval-persistence.md`、
`nanoclaw.runtime-config-mutation.md`、`nanoclaw.approval-presentation.md`。SQL cards 只在 table/function identity 同时满足时使用；presentation card
只表示 core 已到达 capability-explicit channel DI boundary，不声称恢复排除实现内部的调用图。
NanoClaw 的 `node.fs.copy.md` 由 `fs` / `node:fs` module API 和 source/destination 参数位置选择，不使用
concrete source-file whitelist；project identity、handler reachability 与严格跨组件 bridge 仍在各自模型层约束。

LobsterAI 的 pinned browser SSRF witness 使用 `lobsterai.browser-navigation.md`。该卡只绑定 bundled OpenClaw
runtime 中经过完整、受约束 handler chain 到达的 Playwright `Page.goto` callsite，并把 `url` 记录为 controlled
facet；不会把普通同名 `goto` 调用映射为 browser-navigation constraint。

后续 TypeScript adapter 复用同一 facade，但能力卡按实际边界分开：TinyClaw 使用
`tinyclaw.external-agent-execution.md` 描述注册 CLI 子进程边界；Mercury 的常规 Node 原语复用 Node 卡，命令审批
回调使用 `mercury.command-approval.md`，未过滤的 AI SDK tool map 使用
`mercury.tool-capability-exposure.md`；DroidClaw 使用 15 张 `droidclaw.*.md` 卡把 19 个
handler 名称映射为设备输入、应用/URI 导航、剪贴板、截图、文件传输、ADB shell 与邮件编写能力，不使用通用
`Bun.spawnSync` 原语；LettaBot 使用 7 张 `lettabot.*.md` 卡描述 pinned Letta Code 的命令执行、文件读写/编辑、
文件枚举、内容搜索和子代理委派，前台/后台及文本/图片分支由 10 个 exact callsite 作 witness，报告不显示内部
`spawn`/`fs`/ripgrep 原语；本地 todo store 继续复用 Node file-read/file-write 卡。
CodeG 使用 `codeg.external-agent-execution.md` 描述五参数 `acpPrompt` 中 `blocks` 跨入 Rust ACP runtime 的
边界；Rust MCP tools 仅进入 out-of-language inventory，UI terminal/file/git/MCP transport actions 也只有在
真实 handler-source taint 可达时才能成为 constraint。

OpenClaw-CN fork 使用独立的 `openclaw-cn.browser-navigation.md`、
`openclaw-cn.browser-interaction.md`、`openclaw-cn.code-eval.md`、`openclaw-cn.delivery.md`、
`openclaw-cn.rpc.md` 和 `openclaw-cn.external-tool.md`。当前 GT concrete process/file/fetch sink 分别复用
`node.child-process.md`、`node.fs.write.md` 与 `javascript.fetch.md`；每个 callsite 只生成一个 constraint，
argv/options 或 path/content 等多个 controlled facet 合并在该记录中。sink shape 本身不要求
`openclaw-cn-ts` identity；fork card 只在该 sink 还满足 OpenClaw-CN handler-source reachability 和严格
receiver/action/payload/callback shape 时成为项目 constraint。

These cards are not synthesized from the Python QL disjunction parser. The OpenClaw pipeline
selects them from the concrete TypeScript call shape, stores their digest in
`sink-constraints.csv`, merges multiple controlled facets for one callsite, and rejects missing
or duplicate constraints. RPC/external cards are used only when execution has crossed the core
TypeScript analysis boundary.

## Approval policy contracts

`capability_class: user-consent` cards may contain an optional
`approval-policy-contract/v1` block when the surrounding source owns an explicit
dangerous-command approval policy. No other capability class may contain this block. Each
requirement must provide a unique policy ID, rule, applicability, security effect, and
non-empty examples. The parser leaves ordinary historical card YAML opaque; strict YAML
validation is activated only when a top-level `policy_contract` is present.

The Hermes `prompt_dangerous_approval` and Mercury `PermissionManager.askHandler` cards carry
the same four project-neutral effective-command policies. These normative entries do not
participate in ST identity. Group Oracle emits one digest-bound `capability-policy` evidence
record per card/policy pair and invalidates reuse when the card digest changes.

Backend: requires the `claude` CLI on PATH; it is driven headless against DeepSeek's
Anthropic-compatible endpoint (no direct DeepSeek HTTP). Env overrides:
`DEEPSEEK_API_KEY` / `DEEPSEEK_ANTHROPIC_BASE_URL` (default `https://api.deepseek.com/anthropic`) /
`DEEPSEEK_MODEL` (default `deepseek-v4-flash`) / `SINKCAP_CLAUDE_BIN`.
`--source-root` sets the tree the agent reads for project-internal sink APIs
(default `/root/my-project/agent-research/clawgap/benchmark/python/hermes-agent`; passed as
`--add-dir`).

The runner passes `--setting-sources project`, so repository settings/hooks remain active but
`~/.claude/settings.json` cannot silently replace `ANTHROPIC_BASE_URL` or the requested model.
It also disables session persistence to avoid unrelated title-generation requests.

## Re-running just the failures

`main` prints a JSON summary with `failed: [{slug, error}]`. Re-run those with
`--only <slug> ...`.

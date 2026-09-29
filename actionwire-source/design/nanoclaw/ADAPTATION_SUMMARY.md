# NanoClaw TypeScript 四阶段适配总结

共享 pipeline 顺序为 gates → call chains → gate semantics → call-chain semantics。所有已解析 handler
直接参与后续语义分析；本 adapter 的 handler/source/boundary、sink、gate 与 GT 口径保持不变。

## 项目身份与共享 pack

Registry 项目为 `nanoclaw` / adapter `nanoclaw-ts`，source language 为 `typescript`，CodeQL database language
为 `javascript`，query pack 为 `src/ql-js`。DB、输出和设计目录分别是 `codeql-db/nanoclaw-db`、
`output/nanoclaw`、`design/nanoclaw`。preflight 在查询前校验 DB primary language，并要求项目 identity 查询恰好
返回一条 adapter。

`src/ql-js/project/ProjectModel.qll` 是多项目 facade；OpenClaw 和 NanoClaw 分别位于
`OpenClawModel.qll` / `NanoClawModel.qll`。查询名、CSV columns、manifest v2 和后续语义 contract 保持共享，
Python 的 AST/DataFlow API 不进入 TypeScript pack。

项目 model 负责 handler/source/boundary identity；`call/sinks_af.qll` 同时维护 TypeScript primitive sink 和
NanoClaw 的 handler-named semantic sink。GT 验收仍核对原有 5 个 concrete primitive witness，而论文能力盘点另外
恢复 15 个本地 handler 的语义 sink。

共享 pack 另含由 `isOpenClawProject()` 与 exact OpenClaw path 双重约束的 synthetic two-vulnerability
sink/bridge fixture；NanoClaw identity 与源码路径均不能命中该规则，因此本 adapter 的结果不变。

## Handler、sink 与跨组件路径

NanoClaw identity 同时要求 MCP `registerTools` / `startMcpServer` 和 host delivery symbol。共享 facade 把
`projectToolHandler`（本地 taint root）、`projectToolBoundary`（无 source 的外部能力）和
`projectToolInventoryEntry` 明确分开。NanoClaw 的公开 inventory 只取本地 handler；SDK/MCP exposure 继续由
boundary predicate 审计。Handler 仅接受 literal `tool.name`、对应 object 的单参数 `handler(args)`，且
binding 必须实际进入同文件的 `registerTools([...])`。固定快照恢复 15 个注册 handler；dispatcher、未注册 object
和 tests 是 fixture 负例。

inventory 还恢复 18 个 Claude Agent SDK tool 和一个 `mcp__<configured-server>__*` boundary。SDK 名称必须来自
literal `TOOL_ALLOWLIST`，且同一 binding 必须 spread 到
`ClaudeProvider.query → sdkQuery(...).options.allowedTools`。动态 namespace 另外要求严格的
`Object.keys(this.mcpServers).map(mcpAllowPattern)` 转发、helper 的 `mcp__...__*` template shape，以及 runner 从
`config.mcpServers` 填充 runtime map；内置 `nanoclaw` server 不生成 wildcard duplicate。19 个 boundary 均不满足
`handlerSource`，所以不进入 Handler 分母、gate、sink、chain、constraint 或 Stage 5。

15 个 semantic sink 使用 `NC-ACTION-*` canonical ID，并按 handler 名称输出：

- agent/message：`create_agent`、`send_message`、`send_file`、`edit_message`、`add_reaction`；
- interaction：`ask_user_question`、`send_card`；
- scheduling：`schedule_task`、`list_tasks`、`cancel_task`、`pause_task`、`resume_task`、`update_task`；
- self modification：`install_packages`、`add_mcp_server`。

除了 `list_tasks` 的 `getInboundDb` 读取 boundary，其余 semantic sink 都选择 handler 内唯一的
`writeMessageOut` callsite；definition 同时约束 envelope `kind`、payload 的 literal `action`/`type`/`operation`，以及
host 的 exact `registerDeliveryAction` 或 `createChannelDeliveryAdapter` consumer。受控 facet 使用 `tool.action` 加
handler schema 中的目标、内容、路径、任务字段或 self-mod 参数。因此普通同名消息写入、错误 action registry 和无
downstream consumer 的请求不会被当作该语义能力。

原有四个 GT primitive sink family 继续保留：

- `NC-FILE-COPY`：两处 `fs.copyFileSync`，合并 `source-path` / `destination-path` facets；
- `NC-APPROVAL-PERSIST`：`pending_approvals` SQL template 约束下的 `Statement.run`；
- `NC-CONFIG-MUTATION`：`container_configs` SQL template 与 `updateContainerConfigJson` 约束下的 `Statement.run`；
- `NC-APPROVAL-PRESENT`：`requestApproval` 中 literal `chat-sdk` 的 `adapter.deliver` capability boundary。

`NC-FILE-COPY` 的 detector 按 Node API signature 建模：receiver 必须来自 `fs` / `node:fs` module import，callee
必须是 `copyFileSync`，且 source/destination 两个位置参数都存在；规则不绑定当前两个 witness 的 concrete file path。
因此新增 core callsite 可以自动复用该 sink definition，而普通对象上的同名方法仍不会命中。

GT 跨组件链只为经过审计的 action/kind/registry/payload shape 建边：`messages_out` handoff、A2A dynamic route、literal
`add_mcp_server` delivery registry、`pending_approvals` response、literal approval handler registry，以及
`ChannelDeliveryAdapter` boundary。`messages_out` 边还要求实际的
`deliverSessionMessages → drainSession → getDueOutboundMessages/deliverMessage` 消费路径；host 分流由
`msg.kind === 'system'` / `msg.channel_type === 'agent'` 的 AST literal 约束，config replay 必须通过
`mcp_servers` 参数和 `setDeliveryAdapter(createChannelDeliveryAdapter())` 注入形状。不存在通用 `.run`、
`.deliver`、`.handler` 名称闭包。

## Gate 和 TypeScript slice

The revision-pinned catalogue now requires the concrete model-facing handler source to reach
each checked operand as well as the terminal sink argument. Exact file/line/name membership is
not sufficient by itself; helper-only formals and unrelated branch checks are excluded before
ordered assembly. This is the TypeScript implementation of the SameOrigin contract used by
coverage comparison.

项目分支枚举 semantic-action 与 GT path 上的 inline early return/throw、helper call、`.filter` callback、
`realpathSync` transform 和 `requestApproval` consent gate。每个 candidate 同时绑定 tool、current sink witness 和 chain owner，随后由
通用 pipeline 以 callsite、checked expression、handler 和 sink 再关联。

TypeScript compiler bridge 支持 prefix/binary inline expression、filter callback element binding 和 library argument
binding。inline condition 的 actual-to-formal 状态为 `resolved`；`gate_uid` 继续由 normalized AST、lexical activation
与 enclosing owners 生成，行号、空白、注释和 revision 不参与 UID。当前 15 个 slices 均无 unresolved binding 或
slice failure。

## Revision-pinned GT

`inventory/nanoclaw-groundtruth-lock.json` 固定 4 个相对路径及 SHA-256。默认 generator 只验证 lock；只有显式
`--update-lock` 才接受 corpus 变化。项目 inventory 对 4 handlers、6 sinks、22 gates、9 cross-component edges 和
11 extraction records 逐条保存 provenance、原 anchor、current witness、status 和 mapping。

已审计的重定位包括 A2A copy `:140 → :138`、files filter `:348 → :280` 和多处 helper/transform anchor。2026-06-18
才加入的 optional A2A policy 为 `not-present`；target-inbox containment 与 workspace-root containment 为
`expected-missing`。6 条 sink reference 通过 API/capability/facet identity 归并到 5 个 concrete callsites；两份
报告的 pending-approval sink 复用一条 canonical definition。

Oracle matcher 只在 exact tool→current sink chain 上匹配 gate `(name,file,line)`。Function-kind GT 通过 selected
callsite 的 compiler slice 携带 helper definition，不使用全局同名 symbol。负 oracle 进一步区分
`destination-path:target-inbox` 与 `source-path:workspace-root`，所以源侧 containment 和 existence check 不会冒充修复。

## 测试与限制

```bash
python scripts/test_nanoclaw_gt_coverage.py
python scripts/test_ql.py --unit-only
python scripts/test_ql.py
python scripts/check_doc_drift.py --report
git diff --check
```

JavaScript fixtures 验证 project identity、15 个 registered object、15 个 semantic sink/chain、18 个 literal SDK
boundary、一个动态外部 MCP namespace、五个 GT sink callsites 和跨组件 chain；负例覆盖未转发/decoy allowlist、相似 SDK call、内置 namespace
duplicate、boundary source/chain、错误 action/kind、错误 registry literal、错误 SQL table 和普通 `.deliver`。
Python/Node tests 验证 registry、
capability cards、inline slice 稳定 UID、corpus
hash drift、rebase/not-present/expected-missing/duplicate mapping 和 exact-chain oracle。

当前静态输出包含 20 条 chain 与 20 条 sink constraint：15 条 semantic-action chain 加 5 条 GT primitive chain；
15 个 GateSlice 无 slice failure。

v1 不执行 live exploit，不分析 tests/setup/skills/scripts/third-party，也不把 Claude SDK builtin 或外部 MCP namespace
描述为 NanoClaw 本地实现。Stage 3/4 只能从 `DEEPSEEK_API_KEY` 获取 credential。
## Shared filter/transform detector contract

The TypeScript filter detector now dispatches through the common registered-project model and
supports guarded admission, reject-then-admit, and `Array.filter` results with same-origin
collection-to-sink evidence. NanoClaw's existing exact filter witness and line-pinned
`realpathSync` transform remain approved. Ordinary `resolve`, `normalize`, `trim`, or replacement
calls are only review candidates, so the refactor cannot promote a transform by name alone.
OpenClaw-CN's helper-owned filter signatures use a separate project-identity guard and therefore do
not alter NanoClaw candidates or eligible gates.
## Shared Mercury approval-sink isolation

The shared TypeScript catalog now recognizes Mercury's signature-constrained
`checkShellCommand(command) -> this.askHandler(...)` control-flow sink as `MA-COMMAND-APPROVAL`.
NanoClaw's pinned handlers do not reach that receiver/enclosing signature, and the accompanying gate admission
is guarded by `isMercuryAgentProject()`, so NanoClaw's semantic-action and approval contracts remain unchanged.

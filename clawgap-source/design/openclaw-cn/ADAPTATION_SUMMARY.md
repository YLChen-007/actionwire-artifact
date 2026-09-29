# OpenClaw-CN TypeScript 四阶段适配总结

共享 pipeline 顺序为 gates → call chains → gate semantics → call-chain semantics。所有已解析 handler
直接参与后续语义分析；下述 adapter 静态模型与 GT oracle 不变。

## 固定身份与共享 family facade

OpenClaw-CN 固定 upstream tag `v0.2.1` / peeled revision
`558f272e6c90e7e0c37644e505e161b91ef738f0`。registry 使用 project/adapter
`openclaw-cn` / `openclaw-cn-ts`，source language 为 `typescript`，CodeQL language 为 `javascript`，
query pack 为 `src/ql-js`；DB/output/design 分别是 `codeql-db/openclaw-cn-db`、`output/openclaw-cn`、
`design/openclaw-cn`。

共享 pack 中只有 handler/source/bridge 与 adapter identity 由项目 model 分派。Sink catalog 不读取 project
identity：同一个受约束的 Node、browser、RPC 或 callback signature 可在任意 TypeScript benchmark 中匹配；
历史 `OCCN-*` canonical ID 只为已生成 oracle/artifact 保持稳定。

共享 pack 另含由 `isOpenClawProject()` 与 exact OpenClaw path 双重约束的 synthetic two-vulnerability
sink/bridge fixture；OpenClaw-CN identity 与源码路径均不能命中该规则，因此本 adapter 的结果不变。

`OpenClawModel.qll` 提供 OpenClaw-family factory/object helper；`OpenClawCNModel.qll` 增加 fork identity、
scope 与 wrapper。upstream identity 明确排除 `clawdbot-tools.ts` discriminator，fork identity 同时要求
`createOpenClawCodingTools` 和两个 `createOpenClawTools` 实现。真实 DB preflight 因此只返回一条
`openclaw-cn,openclaw-cn-ts`。

核心范围为非测试 `src/**/*.ts`，排除 plugins、动态 channel tools 与 test helpers；
`extensions/feishu/src/outbound.ts`、`media.ts` 是 GT 所需的两个显式例外。source/GT lock 以相同规则计算
1722 个 source file 的 SHA-256 scope digest，apps/vendor/dist/scripts 不进入该 digest。

## Handler、sink 与跨组件路径

Handler model 复用 family 的 literal object 规则，加入 `createSubagentsTool` 与
`createClawdbotReadTool` wrapper。固定 DB 恢复 25 个唯一 tool name / 28 条 execute row；source 始终是第二个
`args`/`params` 参数。dispatcher、普通 execute、tests 和动态 plugin/channel tools 是 fixture 负例。

GT acceptance 覆盖 13 个 concrete witness；项目无关 sink query 同时保留该源码树内所有匹配的 production
callsite，不能再把共享 audit 的总行数误当成 OpenClaw-CN GT 分母：

- `OCCN-BROWSER-EVALUATE`：page/locator evaluate 的 function-text；
- `OCCN-BROWSER-INTERACTION`：locator click/dblclick 的 locator-ref；
- browser navigation：两个 page.goto、CDP `Target.createTarget` 和 `/json/new` URL；
- process spawn：gateway `spawnImpl`、PTY spawn 与 node-host child-process spawn；
- apply-patch callback 中的 fs write；
- Feishu `sendMediaFeishu` 内受约束的 remote-media fetch。

browser bridge 同时要求 literal route、client signature 与 runtime delegate；node bridge 要求
`node.invoke/system.run` payload；Feishu bridge 要求 direct delivery mode、outbound registry callback、
`mediaUrl` field 与 `sendMediaFeishu`。apply-patch 使用 `resolvePatchFileOps` callback position。普通同名
`run/send/invoke` 不建立边；普通 `fetch` 可作为共享 network sink 被审计，但只有项目 handler-source taint
可达时才形成 OpenClaw-CN chain/constraint。

## Gate 与 TypeScript slice

revision-pinned gate row 现在除 exact handler/source/sink identity 外，还必须以
`sourceReachesFunctionNode` 证明同一个 handler source 到达 exact checked operand；只证明 source 到 sink
不能再把 helper/config 检查当作 coverage gate。GT-slice 的 SameOrigin overlay 另行审计执行顺序，post-sink 与
mutually-exclusive branch check 不进入 `covered`/`wrong-check`。

OpenClaw-CN gate catalogue 每行先证明 exact tool handler、第二形参 source、controlled sink facet、taint bridge 与
structural sink path。它覆盖 inline early return/throw、helper call/definition、URL/allowlist decision、normalizer、
encoding、callback/RPC 后 policy 与 exec consent/allow-always 决策。

route callback 和 local helper 会被 structural path 用 literal boundary hop 压缩；pipeline 只对已经携带相同
handler_file/tool_name/sink identity 的 OpenClaw-CN catalogue row 放宽 hop-string membership，未绑定的全局同名
symbol不能进入 chain。`new URL` 用 `NewExpr`，`skillAllow` 用 VariableDeclarator initializer，
`assertMediaNotDataUrl` 记录 selected-chain 调用 witness。当前共享-catalog 静态运行有 62 条 eligible catalog
gate row 且 GateSlice failure 为 0；行号、注释和空白不进入 `gate_uid`。

Stage 4 对模型响应执行 claim-preserving normalization：只移除与 step operation 不相容的可选
reject/bypass example，以及无法由同 step evidence 逐字证明的非 matcher 引文；source-defined matcher/policy
仍保持 exact-substring fail-closed contract。

## Revision-pinned GT oracle

项目不修改 `groundtruth` symlink 或 8 份 JSON。lock 固定每份相对路径、SHA-256、source scope digest 与原始总计：
8 handlers、43 extraction records、69 gates、15 sinks、21 cross-component edges。inventory 每条保存原对象、
原 anchor、current witness、anchor/mapping status、canonical sink、capability 与 controlled facet。

15 条 sink ref 映射到 13 个 concrete callsite。64 条非缺失 gate ref 分为 exact-chain、protected-sibling 与
defective-control；5 条为 expected-missing。GHSA-536/qmwg direct-navigation control 只在 direct-navigation
chain 上提供 sibling evidence，不覆盖 click/evaluate act；expected-missing matcher禁止
`assertBrowserNavigationAllowed` 或 SSRF helper 被挂到 vulnerable act/Feishu chain。

当前固定 DB 静态 acceptance：25 unique tool names / 28 handler rows；共享 sink audit 440 callsites；GT 为
13/13 concrete witness、15/15 sink ref、64/64 present/protected/defective gate ref、5/5 expected-missing。
handler-source reachability 生成 40 structural chains、36 unique constraints、162 chain-gate rows、18 条
zero-gate chain，slice failure 为 0；其中 13 chains / 13 constraints 是 revision-pinned GT exact witnesses，
其余发现保留在共享 audit 中。所有生成的 `debug/*.md` 首段由 generator 自动写仓库根目录完整命令。

共享 catalog 改变了 Stage 4/5 输入，旧 14-chain semantic baseline 与 digest 已失效。设置
`DEEPSEEK_API_KEY` 后需重新运行两次 `python -m src.pipeline --project openclaw-cn all` 才能建立新的 semantic
复用/digest 基线；本次静态验收不把旧记录冒充为新结果。

## 回归与限制

```bash
python scripts/test_openclaw_cn_gt_coverage.py
python scripts/test_ql.py --unit-only
python scripts/test_ql.py
python scripts/check_doc_drift.py --report
git diff --check
```

JavaScript fixtures验证 fork/upstream identity互斥、25/28 handler、严格 sink shape与 dispatcher/plugin/test
handler negatives，并验证 shared sink 在错误 project identity 下仍可被审计但不能形成该项目 handler chain；Python
tests验证 source/GT hash、15→13 mapping、64/5 gate分类、protected sibling、唯一 constraint
和 exact-chain matcher。Stage 3/4只读取 `DEEPSEEK_API_KEY`。v1不执行 live exploit，也不声称覆盖所有 extension、
动态插件、apps 或 prompt-entry reachability。
## Shared filter/transform detector contract

The TypeScript filter query now runs over every registered `projectToolHandler` model and supports
guarded `push/add/set`, reject-then-admit, and `Array.filter` results, with source-to-checked and
collection-to-canonical-sink proof. Transform eligibility uses exact project/file signatures;
OpenClaw-CN retains `normalizeToolParams`, the cron normalizers, `resolvePatchPath`, and
`assertSandboxPath`. Generic name matches are review-only. A zero filter count is accepted only
when all revision-pinned canonical witnesses are `confirmed-zero` in the zero-gate audit.

OpenClaw-CN additionally owns three exact filter signatures in
`src/ql-js/call/openclaw_cn_filters.qll`; the upstream OpenClaw predicate remains separately guarded.
They bind the LLM-controlled second handler argument to: (1) `parsePatchText`'s validated hunk
admission before the `resolvePatchFileOps` callback write, (2) `parseEnvPairs` before the named
`runParams.env` object enters `node.invoke`, and (3) the `exec`/`nodes` RPC environment re-entry at
`handleInvoke`, where `sanitizeEnv` conditionally admits request entries before node-host `spawn`.
The two RPC witnesses share the same `sanitizeEnv` callsite, so the four raw rows form three distinct
filter UIDs. Every row requires `isOpenClawCNProject()`, an `openClawCNToolHandler`, exact reviewed
helper bodies, same-origin source flow, and a canonical sink path; similarly named helpers in other
projects cannot match. The sanitizer signature binds the admitted assignment specifically to the
`Object.entries(overrides)` loop, excluding the separate `process.env` base-environment loop.
## Shared Mercury approval-sink isolation

The shared TypeScript catalog now recognizes Mercury's signature-constrained
`checkShellCommand(command) -> this.askHandler(...)` control-flow sink as `MA-COMMAND-APPROVAL`.
OpenClaw CN's pinned handlers do not reach that receiver/enclosing signature, and the accompanying gate admission
is guarded by `isMercuryAgentProject()`, so the fork's sink, chain, and gate contracts remain unchanged.

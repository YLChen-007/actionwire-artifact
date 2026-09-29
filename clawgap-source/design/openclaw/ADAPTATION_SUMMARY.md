# OpenClaw TypeScript 四阶段适配总结

共享 pipeline 顺序为 gates → call chains → gate semantics → call-chain semantics。所有已解析 handler
直接参与后续语义分析；本文件下述 TypeScript adapter、sink 与 gate 静态事实不变。

## 固定身份与语言边界

项目 registry 使用 `openclaw` / `openclaw-ts`，source language 为 `typescript`，CodeQL extractor language
为 `javascript`，query pack 为 `src/ql-js`。DB 是 `codeql-db/openclaw-db`，输出是 `output/openclaw`。
CodeQL runner 在执行 query 前读取 DB metadata 并要求 primary language 恰为 `javascript`；Python benchmarks
继续显式使用 `python` / `src/ql`。aggregate pipeline manifest 使用 language-neutral
`clawgap-benchmark-pipeline/v3`，读取旧 aggregate 时保留已有 stage 后升级。

`src/ql-js/project/ProjectModel.qll` 现为共享 facade，项目细节分别落在各项目 model。Handler identity、source 与
跨组件 bridge 仍由 project model 约束；`src/ql-js/call/sinks_af.qll` 则是项目无关的 TypeScript sink catalog，
只按 module/API、receiver、literal action、payload field 与 enclosing signature 识别危险能力。历史 `OC-*` 等
canonical ID 仅作为生成物兼容键，不再代表项目 dispatch，也不要求 `isOpenClawProject()` 才能匹配。

核心 scope predicate 接受 `src/**/*.ts`，并窄化接受源码中实际存在的 bundled browser tool
`extensions/browser/src/**/*.ts`；仍排除 `*.test.ts`、`*.spec.ts`、test helpers、其他 extensions 与
plugin/channel 动态工具。第三方包与 apps/Swift 只进入 GT inventory，不伪造跨语言调用链。固定
`v2026.2.1` 快照没有 bundled browser extension；其 detector contract 由隔离的 synthetic fixture 验证，
不得计入 revision-pinned coverage。
`scripts/build_openclaw_two_vul_synthetic.py` 可从固定快照生成完整 source-level derivative，并在输出根写入
`SYNTHETIC_DERIVATIVE.json`；该派生源只用于检测回归，不改变 registry、固定 DB、GT lock 或论文分母。

## TypeScript CodeQL 模型

Python 的 `CallNode`、`AttrNode` 与 Python dataflow API 没有复用。`src/ql-js` 依赖
`codeql/javascript-all` 并输出与 pipeline 相同的 CSV contract。

Handler model 恢复 factory object literal 的 tool name，并对 read/write/edit 的 audited wrapper 做实例化映射。
`toToolDefinitions` dispatcher、任意同名 `execute`、tests 和动态 plugin tools 是负例。调用/taint模型包含：

- direct call 与 callback position；
- audited `runExecProcess → spawnWithFallback → spawnAndWaitForSpawn → spawnImpl`；
- apply-patch parser 到 Node fs facets；
- web fetch/search helper 链；
- literal `node.invoke` / gateway method、browser `/tabs/open`、message delivery 和外部 coding-tool 边界；
- object/array container、property read、argument→formal、normalizer 与闭包 payload builder 的窄 taint step。

Sink rules 位于 `src/ql-js/call/sinks_af.qll`，每个 disjunct 有 canonical identity、capability、boundary 和受控
facet，并用 `source:` 注释指回对应 ground-truth JSON。多个报告复用同一 canonical rule 时可列出多个 JSON；
若规则是同一 handler/capability 的完整 sibling，而报告的最小 D5 witness 是另一原语，则注释必须显式说明，
不能伪称该 exact sink 出现在报告中。实现覆盖 process spawn、network egress、file read/write/delete、browser
navigation、delivery、node/gateway RPC 与排除实现的 coding-tool boundary；不使用无约束的通用 `execute`、
`run` 或 `invoke` 名称匹配。
Synthetic Chrome MCP `client.callTool` 使用独立的 `openclaw.chrome-mcp-rpc.md` capability card，受控 facet
只取 `arguments` payload；它不会复用 gateway-method card，也不会把任意同名 client call 扩成 sink。

Gate detector 在同源 taint-valid handler→sink path 上实现 dominance、collection admission filter 与 transform。
支配检查针对当前函数内 sink 或真正通向 sink 的首个下沉 callsite，不采用 caller-closure “存在即 GATED”。
Gateway receiver 的 `authorizeGatewayMethod(req.method, ...)` 通过 method/payload 明确的 RPC bridge 作为
pre-handler gate；其他无同一参数/继续路径证据的 universal hook 不附着。

静态 candidate 与 GateSlice catalog 的 join 使用 callsite identity 加 checked expression。CodeQL 对长
`toString()` 值产生的 `prefix ... suffix` 缩写会与 TypeScript AST 完整文本做受约束的首尾匹配；同一 callsite
的多个参数仍保持不同 UID。未解析到 catalog UID 的 candidate 不进入 `chain-gates.csv` 的 eligible 序列，
避免空 UID 造成 gate sequence 缺口或绕过 semantic completeness 门禁。

## TypeScript GateSlice backend

The shared dominance query now makes the paper's SameOrigin relation explicit at the
checked-value endpoint: the same model-facing handler source must reach both the gate operand and
the terminal controlled sink argument. OpenClaw's generic gate rows already used
`sourceReachesFunctionNode`, so this tightening documents and preserves their existing proof;
helper-only or post-sink checks remain ineligible.

`typescript_bridge.mjs` 使用仓库固定的 TypeScript compiler API，通过 JSON stdin/stdout 返回 callsite、checked
expression、enclosing function、condition/branch effect、局部派生、helper definition 和 actual→formal binding。
GateSlice schema 保持 v1，只把 `project.language` 写为 `typescript`。`gate_uid` 使用 normalized AST、lexical
activation、enclosing function 与嵌套 callback 的 outer factory/wrapper owner stack，不含 revision、行号、
空白或注释；行移动测试验证 UID 保持稳定，双 factory fixture 验证同名 `execute` callsite 不会合并。

## GT inventory 与 oracle

`design/openclaw/inventory/` 不写入 groundtruth symlink。lock 保存全部 86 个相对路径、SHA-256 与每报告 sink
计数，总计 159 条。每条记录保存原始 name/kind/location/problematic_parameter/evidence、所有可解析 anchor、
current witness、anchor/mapping status、canonical sink、capability、facet、boundary 和排除原因。

canonical 去重键是当前 API identity、危险能力、受控参数角色和边界类型；同一 `spawnImpl` 被多个报告引用时
复用定义，但每个 GT record 保留独立 provenance。Oracle 只纳入 current/rebased core witness、core tool handler、
LLM source 与支持 capability 同时成立的 48 条记录。当前 matcher 验证 handler→sink、current witness 或明确边界、
existing gate/expected-missing 名称语义，以及每个 concrete sink 唯一 constraint；缺失控制不能由无关 gate 冒充。

项目级 D5 anchor matcher 对 `kind: function` 额外要求固定快照仍存在该函数符号。函数 body evidence 偶然出现在
另一函数中不能把 later-only helper 标成 `rebased`；`kind: adhoc` 仍要求 exact evidence 命中，不能用相似 body
跨函数或跨链冒充当前 gate。

## 测试与复现

```bash
python scripts/test_ql.py --unit-only
python scripts/test_openclaw_gt_coverage.py
python -m unittest src.pipeline.tests.test_pipeline \
  src.gate_semantics.tests.test_typescript_slicer
python scripts/check_doc_drift.py --report
git diff --check
```

`scripts/test_ql.py` 顺序运行 Python 与 JavaScript fixtures，完整模式编译两个 production packs 并顺序执行
六个 Python benchmark 加 OpenClaw acceptance，避免同库锁冲突。Stage 3/4 需要调用 LLM；credential 只来自
`DEEPSEEK_API_KEY`，不会进入配置、命令、日志或生成物。OpenAI-compatible transport 使用单请求 SSE 增量读取
长 JSON 响应，避免代理 idle timeout；provider reasoning 被显式关闭，因为 GateSemanticIR 只消费最终 JSON、
不保存隐藏思维 token。transport 仍不提供工具，并兼容非流式 JSON provider response。

## v1 限制

该适配不执行 live exploit，也不声称覆盖 extensions、Swift、动态插件或 prompt-entry reachability。RPC/callback
boundary 证明的是核心 handler 把受控参数交给某项明确能力；它不代表已恢复排除组件内部的全部调用图。

## 当前验收结果

共享 sink query 当前审计 393 个 production callsite；固定 DB 静态阶段产出 27 个 handler、31 个 eligible
gate、39 条 structural chain、35 个 concrete sink constraint、83 条 eligible chain-gate row 和 17 条
zero-gate chain，slice failure 为 0。`node-pty.spawn` 使用项目无关的 Node process card mapping。共享 catalog
改变了 Stage 4/5 输入，旧 38-chain semantic baseline 与 digest 已失效，重新运行 `all` 前不引用其复用率。

锁定 GT inventory 为 86 reports / 159 sink references / 48 checks；固定静态输出上的 revision-pinned
acceptance 为 48/48 PASS，slice failure 为 0，35 个 concrete sink constraint 均满足唯一性要求。
Python/JavaScript fixture 和两个 production pack 编译已通过。
Hermes full baseline 仍要求本地提供被 `.gitignore` 排除的 `design/hermes-agent/groundtruth/new-vuls` 外部语料；
当前 Nanobot full acceptance 另有 6 个既存失败，集中为 `web.py:118/162/181` 的 3 个 Python `httpx`
sink/chain 缺失（constraint 与 structural-chain 各一项），不属于 OpenClaw TypeScript pack，本适配未改动该
Python sink model。

`design/openclaw/groundtruth/new-vuls/` 的项目级 D5 renderer 逐条输出 6 handlers、7 sinks 和 59 gates。
它复用 locked inventory 的 revision/scope 决策：later-only、excluded boundary 和不具备受支持危险能力链的条目
完整入账，但不进入 detector recall 分母；same-tool 当前链上的同名 gate 仅标为 `candidate-only`。
当前 D5 acceptance 为 5/5 eligible sinks、7/7 eligible existing gates、0 eligible gaps。
## Shared filter/transform detector contract

The TypeScript filter query now runs over every registered `projectToolHandler` model and supports
guarded `push/add/set`, reject-then-admit, and `Array.filter` results, with source-to-checked and
collection-to-canonical-sink proof. The transform query is signature-driven: OpenClaw keeps the
exact `normalizeToolParams`, cron normalizers, sandbox/apply-patch helpers, and
`buildDockerExecArgs` signatures and their existing bridges. Generic `trim`, `replace`,
`replaceAll`, `resolve`, and `normalize` calls are review-only and cannot change eligible counts.
An audited zero is valid only after every canonical witness is recorded as `confirmed-zero`.

OpenClaw additionally has three revision-pinned helper-owned filter signatures in
`src/ql-js/call/openclaw_filters.qll`. A row is emitted only when the registered handler source
reaches the exact helper argument, the helper has the reviewed conditional-admission body, and its
result reaches the named canonical sink:

- `apply_patch`: `args.input -> applyPatch(input) -> parsePatchText(input)`, whose validated
  `parseOneHunk` results are admitted to `hunks` before `writeFile`/`rm`;
- `nodes`: `args.env -> parseEnvPairs(params.env)`, whose string and `KEY=VALUE` checks precede
  insertion into the `node.invoke` `system.run` environment;
- `exec` and `nodes`: the RPC-carried tool environment re-enters `handleInvoke` as `params.env`,
  then `sanitizeEnv(params.env)` rejects blocked entries before `spawn(..., { env })`.

The helper call `sanitizeEnv(undefined)` is not source-derived and is excluded. Likewise,
configuration/system-PATH normalization, output collections, and similarly named helpers do not
qualify without the same handler-source and helper-output-to-sink evidence.

The OpenClaw-CN filter signatures are implemented in a separately project-guarded predicate;
OpenClaw fixtures assert that those fork-only rows remain absent, so the upstream rows and counts
are unchanged.
## Shared Mercury approval-sink isolation

The shared TypeScript catalog now recognizes Mercury's signature-constrained
`checkShellCommand(command) -> this.askHandler(...)` control-flow sink as `MA-COMMAND-APPROVAL`.
OpenClaw's pinned handlers do not reach that receiver/enclosing signature, and the accompanying gate admission
is guarded by `isMercuryAgentProject()`, so OpenClaw sink, chain, and gate contracts remain unchanged.

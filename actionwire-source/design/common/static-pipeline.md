# 通用静态分析流水线与接口契约

> 上级设计：[`design/整体设计.md`](../整体设计.md)。
>
> 本文是 [`docs-map.yaml`](../../docs-map.yaml) 中 `python-benchmark-pipeline` 与
> `handler-specifications` 的 spec owner，管辖 `src/projects/**`、`src/pipeline/**`、项目模型查询和共享
> handler-specification extractor。Gate/sink 的项目级算法细节仍由对应专题设计维护。

## 1. 职责与边界

通用静态流水线把不同语言、不同项目的 source tree 转换为统一的 revision-bound 结构与语义产物：

```text
ProjectSpec + benchmark source + handler inventory
  → project preflight
  → structural gate/call-chain artifacts
  → per-gate semantic IR
  → ordered call-chain semantic IR
```

Tool Handler Specification 是该流程的**补充预处理输入**：它描述模型看到的工具接口并连接 concrete handler，
但不产生 gate oracle、不改变 handler root，也不作为第五个 static stage。

执行顺序必须区分两种前置条件：`src.pipeline all` 只要求 registered handler inventory，不会调用
`src.handler_specifications`；handler specification 可以独立提前生成，但必须在 HC/HT 对齐以及任何需要
model-facing schema 的 capability/coverage consumer 之前完成并通过校验。

所有阶段遵守：

- project、revision、source language、CodeQL language 和 query pack 必须显式绑定；
- 不能通过 import、执行或安装 benchmark package 推断静态定义；
- unsupported AST、source drift、adapter ambiguity 和 schema mismatch 必须 fail closed；
- 生成物包含 repository-root reproduction command、输入 digest 和 deterministic identity；
- partial/unknown 状态保留，不能用上一 revision 的结果静默填充。

## 2. Project Registry 与多语言路由

`src.projects.ProjectSpec` 登记每个项目的：

- project ID、source root、analysis revision 和 output root；
- `source_language`、`codeql_language` 和 `query_pack`；
- CodeQL database、project model/adapter 与 extraction exclusions；
- design/GT 路径、semantic profiles 和不含秘密的 LLM 配置。

Python 项目使用 Python extractor、CodeQL `python` database 和 `src/ql`；TypeScript 项目使用
`source_language=typescript`、CodeQL `javascript` database 和 `src/ql-js`。CLI 可以做单次显式 override，但
`--all` 只消费 registry。

### 2.1 Preflight

在任何 stage 写出产物前：

1. 解析 registry 与 override 后的 source、revision、DB 和 query pack；
2. 使用 `codeql resolve database --format=json` 校验 DB 语言；
3. 验证 project adapter/query 唯一存在；
4. 验证 source root、handler inventory 和已声明输入；
5. 构建完整 staging plan，避免中途失败留下部分新产物。

DB 语言不符、query 缺失、adapter 多义、registered source 缺失或未登记 benchmark project 均使 run 失败。

## 3. 四阶段公共接口

从仓库根目录运行：

```bash
python -m src.pipeline --project chatgpt-on-wechat infer-gates
python -m src.pipeline --project chatgpt-on-wechat infer-call-chains
python -m src.pipeline --project chatgpt-on-wechat infer-gate-semantics
python -m src.pipeline --project chatgpt-on-wechat infer-call-chain-semantics
```

`all` 等价于以上固定顺序。标准输出为：

```text
output/<project>/
  ├── static/gates/
  ├── static/call-chains/
  ├── gate-semantics/
  ├── call-chain-semantics/
  └── pipeline-manifest.json
```

Hermes Agent 保留 registered `output/hermes`。Stage 1/2 的 manifest schema 分别为
`clawgap-pipeline-gates/v2` 和 `clawgap-pipeline-call-chains/v2`，并记录 source/CodeQL language、revision、
query/adapter identity、generation command 和输入 digest。

Gate slicing 按 `source_language` 选择 `PythonGateSlicer` 或 `TypeScriptGateSlicer`；其它语言值必须明确拒绝，
不能回退到启发式文本切片。

## 4. Tool Handler Specification

### 4.1 输入、处理和输出

```text
src.projects.ProjectSpec
        +
design/<project>/handler-entry/debug/tool-handler-entries.csv
        +
revision-pinned benchmark source
        │
        ▼
Python AST adapter / TypeScript Compiler-API adapter
        │  静态解析，不 import/执行 benchmark package
        ▼
按 tool_name 分组 handler → schema/evidence/runtime-rule validation
        │
        ▼
<ProjectSpec.output_root>/handler-specifications/
  ├── tool-handler-specifications.json
  └── tool-handler-specifications.md
```

公共入口为：

```bash
python -m src.handler_specifications --project <project-id>
python -m src.handler_specifications --all
```

单项目模式允许覆盖 source、handler inventory、revision 和 output directory；覆盖 source 时必须同时显式提供
revision。`--all` 先验证全部 registered project，再逐文件 atomic replace。旧 Hermes generator 仅作为兼容
launcher，canonical artifact 不再写入其旧 debug 目录。

### 4.2 `clawgap/tool-handler-specifications/v2`

规范化逻辑契约如下。Resolved `function` 严格只有 `name`、`description`、`parameters`；外部 runtime/SDK 才能
提供定义时必须为 `null`。

```jsonc
{
  "schema_version": "clawgap/tool-handler-specifications/v2",
  "project": {
    "id": "<registered project id>",
    "source_language": "python | typescript",
    "codeql_language": "python | javascript",
    "analysis_revision": "<ProjectSpec.analysis_revision>",
    "source_root": "<registered or overridden source root>",
    "output_root": "<ProjectSpec.output_root>"
  },
  "reproduction_command": "<complete repository-root command>",
  "inputs": {
    "handler_inventory": {
      "path": "<tool-handler-entries.csv>",
      "sha256": "<sha256>",
      "rows": 0
    },
    "source_files": [
      {"path": "<consumed source file>", "sha256": "<sha256>"}
    ]
  },
  "counts": {
    "handler_rows": 0,
    "unique_tools": 0,
    "resolved": 0,
    "unresolved": 0
  },
  "tools": [
    {
      "tool_name": "<canonical tool name>",
      "interface_kind": "function-tool | mcp-tool | structured-output-action | external-tool-boundary | dynamic-mcp-boundary",
      "handlers": [
        {
          "tool_name": "<inventory tool name>",
          "form": "<registration/wrapper shape>",
          "handler_func": "<concrete function or method>",
          "file": "<source-relative file>",
          "line": 1,
          "forwarded_body": "<optional one-hop body evidence>"
        }
      ],
      "function": {
        "name": "<same value as tool_name>",
        "description": "<model-facing description>",
        "parameters": {"type": "object", "properties": {}}
      },
      "runtime_rules": [
        {
          "rule_id": "<stable rule id>",
          "condition": {"<runtime/config selector>": "<value>"},
          "source": {"file": "<source file>", "line": 1},
          "effect": "<deterministic function change>",
          "affected_fields": ["<JSON pointer>"]
        }
      ],
      "resolution": {
        "status": "resolved | unresolved",
        "reason_code": "<required when unresolved>",
        "reason": "<source-backed explanation>"
      },
      "evidence": [
        {
          "kind": "<definition/wrapper evidence kind>",
          "file": "<source file>",
          "line": 1,
          "sha256": "<sha256>",
          "detail": "<optional AST/provenance detail>"
        }
      ]
    }
  ]
}
```

### 4.3 提取与校验不变量

1. `tool-handler-entries.csv` 是 handler universe。相同 `tool_name` 的 wrapper/handler 行合并成一个 tool record，
   但 `handlers[]` 全部保留并稳定排序。
2. Canonical function 使用源码声明的默认定义；配置、平台或 backend 变体进入 source-backed `runtime_rules`，
   不复制 tool record。
3. Python adapter 只解释 registration、decorator、class/dataclass metadata、property、signature、annotation、
   default 和 docstring 的安全 AST 子集。
4. TypeScript adapter 只通过已有 compiler API 解释 literal object、local import、MCP declaration、TypeBox、Zod
   和 structured-output schema。
5. Unsupported call/AST expression 必须携带 file、line 和 AST shape fail closed，禁止 import 或执行 benchmark。
6. Runtime/SDK-owned interface 显式 unresolved；DroidClaw 的 action object 是 `structured-output-action`，不能伪装
   为 function tool。
7. Project revision、handler CSV 和所有消费的 source file 均绑定 SHA-256；相同输入生成字节一致的 JSON/Markdown。
8. 测试要求 registry source roots 与 `benchmark/python`、`benchmark/typescript` 下的 active project 一一对应。

当前 revision-pinned acceptance baseline 保留为 12 个项目、316 条 handler row、309 个 unique tool、301 个
resolved specification 和 8 个 unresolved boundary。LobsterAI、CodeG、TinyClaw 已退出 active registry，其
snapshot 与历史设计仍保留但不进入 `--all` denominator。

实现与兼容行为见 [`src/handler_specifications/README.md`](../../src/handler_specifications/README.md)。

## 5. Gate Semantic IR

### 5.1 Slice 与受限源码研究

静态 gate stage 为每个 callsite-bound gate 提供：

- stable gate/value identity、checked expression 和 actual→formal binding；
- callsite condition、branch effect、完整 gate function；
- outcome-relevant helper、constant、configuration 和 source spans；
- `source→gate` flow、unresolved dependency 和 revision digest。

输入不包含 sink capability 或漏洞标签，避免模型从预期结论反推 gate 语义。默认 stateful Agent SDK 只开放
`Read`、`Grep`、`Glob` 与只读 LSP definition/reference/symbol/type/implementation；Bash、网络、写入、rename、
formatting 和 code action 不暴露。`PreToolUse` 对 file-oriented tool/LSP 参数执行 resolved-root 校验，拒绝绝对
路径、`..`、URI 和 symlink root escape。CLI transport 只是显式 fallback。

Session、tool trace、source evidence、model/prompt version、usage 和 raw response 写入 audit sidecar；下游只消费
validated `semantic.json`。

### 5.2 V1：普通 gate

`GateSemanticIRV1` 包含 compact summary、有序 semantic atoms、default/error behavior、稳定输入输出 value identity、
由当前 gate 自身证明的 rejection example，以及 source-proven bypass example。普通允许输入、推测性漏洞和 whole-chain
sink impact 不能作为 bypass。

单 gate 使用 gate-entry isolation：假定执行已经到达当前 gate。上游 feature switch、先前 return 和 sibling
activation 只进入 slice/audit；当前函数中决定 checked value 的 normalization/derivation、gate 内部分支和直接消费
gate result 的 caller branch 仍必须进入语义。

Regex/glob/allowlist/denylist/policy-table matcher 的 `source_rules` 必须是 evidence span 的连续源码子串。Compiled
matcher 引用 pattern table 时，pipeline 确定性附加同文件 assignment dependency closure。仅高度相似的机械抄写
漂移可由 source span 校正；语义遗漏仍拒绝。正常产品流程只调用一次模型；`--debug-fidelity-review` 才运行第二次
review，并跳过 repository reuse。

### 5.3 Inline、V2 与 V3

- `if not x or not y: return` 等无 validation call 的 early exit 作为一个 `inline-condition` composite gate；
  lookup/constructor 只是 derivation，不冒充 predicate。
- Hermes `_check_all_guards` 使用 qualified-function profile 和 `GateSemanticIRV2`，完整保留 child checks、hardline/
  dangerous-pattern rules、配置/状态例外和 transition；外部 Tirith rules 未解析时整体保持 `partial`。
- Policy/external-decision gate 使用 source-profile-checked `GateSemanticIRV3`。LLM compact IR 只进 audit；确定性 checker
  从 AST 恢复 control flow、derived values、完整 policy、outcome、state effect、dependency 和 completeness。
- 依赖外部 LLM decision 的 `_smart_approve` 等 profile 必须保持 `partial`，不能因 prompt 已知标为 complete。

已有 artifact 可通过 `python -m src.gate_semantics.checker --write` 做无模型升级；正常 semantic pipeline 已内置
checker。详细 contract 见
[`gate-fte-design.md`](../hermes-agent/gate/gate-fte-design.md)。

### 5.4 Identity、repository 与 token accounting

当前 catalog 按 `gate_id` 排序给出一基 `gate_number`，ordinal 只用于阅读与 `--gate-number N` 选择。持久 identity
使用不含 revision、行列和 ordinal 的 `gate_uid`，artifact 位于：

```text
output/<project>/gate-semantics/repository/<gate_uid>/
  ├── semantic.json
  ├── audit.json
  └── chat.json
```

同 UID 的 `content_digest` 未变且通过当前 validator 时复用，不调用模型；digest 改变则重新生成。Catalog 新增/
删除不会清理历史 repository entry。Usage 分开记录 uncached input、cache creation、cache read、output 和 total；
manifest 只累加本 run 实际 model calls，无 provider usage 的旧 artifact 标记 unavailable，不估算为零。

## 6. Call-Chain Semantic Assembly

整链阶段选择唯一 structural handler/sink chain，从 `chain-gates.csv` 收集 exact chain 上全部 `confirmed` 和
`branch-confirmed` gate，排除 `needs-review`，按 callsite identity 去重并按执行顺序内嵌 per-gate semantic IR。

关键不变量：

- `gates[]` 是 ordered sequence，不构造跨 gate control-flow graph；
- branch-local gate 保留 locality，不能写成全局必经；
- handler/sink identity 与 source/value binding 必须自包含；
- unresolved union 和 aggregate status 由成员 IR 确定性汇总；
- 每个 concrete sink point 附加恰好一个 terminal `sink_constraint`；
- terminal capability 不进入 `gates[]`；
- stage 4 组装全部 taint-valid chain，允许 `gates: []`，不按预判 impact 裁剪。

Gate stage 只写 `gate-semantics/`；chain stage 从 persistent repository 读取 selected gate，只写
`call-chain-semantics/`，不复制 run-local gate input。详细 contract 见
[`call-chain-semantics-design.md`](../hermes-agent/call-chain/call-chain-semantics-design.md)。

## 7. Zero-Gate Cross-Project Audit

Filter/transform metrics 必须对每个 revision-pinned handler-source-path-sink witness 做审计：

- Python filter 支持 reject-and-continue admission，但要求 same-origin collection→sink proof；
- legacy argument/admission shape 与 dynamic bridge 必须窄绑定，不能变成 generic name match；
- Python transform 只接受 exact project signature；
- TypeScript filter 经过 registered project model；transform eligibility 由 exact project/file signature 驱动；
- generic replacement、trim、resolve、normalization 保持 review-only。

只有生成的 `clawgap-zero-gate-audit/v1` manifest 把全部 witness 分类为 `confirmed-zero` 时，零检测才是可解释的
结果；缺 source、adapter 或 flow evidence 时必须保留 unknown/gap。

## 8. 相关文档

- 方法与 gate 判定：[`detection-method.md`](detection-method.md)
- 跨项目对齐和 Group Oracle：[`cross-project-oracle.md`](cross-project-oracle.md)
- Candidate 准入：[`filter-candidates.md`](filter-candidates.md)
- Pipeline implementation：`src/pipeline/`、`src/projects/`

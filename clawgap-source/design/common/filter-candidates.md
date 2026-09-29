# Canonical Candidate 过滤与准入流程

> 上级设计：[`design/整体设计.md`](../整体设计.md)。
>
> 本文是 [`docs-map.yaml`](../../docs-map.yaml) 中 `coverage-comparison` 的公共 spec owner，管辖 v15 的
> requirement authority、field-sensitive flow、member applicability、source promotion 和 generic/training 分区。
> 实现级接口与 artifact schema 同时由
> [`src/coverage_comparison/README.md`](../../src/coverage_comparison/README.md) 维护。

独立实验入口 `python -m src.coverage_comparison.scoped_ablation` 可以只对冻结训练表的 43 个 eligible 报告运行
两种单 Oracle Coverage Decision；实际推导集合是这些报告绑定的 56 条去重链，不扩展到同组的其他链。
Group-only 使用已准入的 group-origin CR 和 4 个 exact-member training fallback，屏蔽 Card 中的 policy contract，
不混入 source-derived/learned CR；Capability-only 使用相同目标 IR 和冻结 Card（含其显式契约），不输入 Group 规则或 fallback。
新实验独立冻结输入/实现/prompt，真实调用模型；GT 不进入推导，只在候选冻结后的独立匹配阶段出现。
空 Group requirement 集确定性记录为 no-requirements；操作错误记录为 inconclusive，不能冒充漏报或命中。
该入口输出阶段性 Coverage Decision 和逐报告匹配，不执行目标漏洞，不替换 canonical 发布或源码验证准入。
修复 Capability 输出格式约束时，可显式指定 `--reuse-group-from` 保留本轮已完成的 Group 调用；必须逐项验证
同一43例/链/Group规则/model设置、逐字相同的Group和GT prompt并重新校验原始响应。新目录记录继承来源与新调用数，
不得用该选项混入旧 canonical 结论；每轮保存实际实现源码。

本文记录当前 `canonical-trained-detector/v15` 如何从上游候选中降低误报，并说明大模型、CodeQL、源码验证和确定性准入各自负责什么。本文描述的是当前活动产物；数字应以
`output/cross-project/coverage-comparison/manifest.json` 为准。

从仓库根目录复核当前快照：

```bash
python -m src.coverage_comparison --all --replay-only

jq '.counts | {
  precision_input_candidates,
  provisional_candidates,
  generic_candidates,
  training_regression_candidates,
  training_fallbacks,
  vulnerability_clusters,
  member_applicability,
  member_decisions,
  field_flow_witnesses,
  field_flow_exclusions,
  unvalidated_canonical_candidates
}' output/cross-project/coverage-comparison/manifest.json
```

## 1. 当前结果与术语

当前快照包含：

| 项目 | 数量 | 含义 |
|---|---:|---|
| Precision输入 | 1,139 | 进入完整审计分区的历史/上游candidate记录 |
| Structural chains | 603 | 当前跨项目结构链总数，用于结构 partition |
| Eligible comparisons | 485 | 进入 requirement/member comparison 的链 |
| Admitted CR | 120 | 通过规范证据门禁的 project-neutral requirement |
| Capability hypotheses | 461 | 仅描述能力或待验证规则的审计记录 |
| CR/member pairs | 358 | 独立执行 member applicability 的边 |
| Provisional candidates | 96 | 经过上游投影、尚未完成最终generic准入的候选 |
| Generic candidates | 78 | 未来held-out唯一允许读取的最终chain-level候选 |
| Vulnerability clusters | 74 | 按根因聚合后的人工复核单位 |
| Training overlay | 82 | 78条generic加4条training-only fallback |
| Field-flow witnesses | 150 | exact field→sink-role 正向证明 |
| Field-flow exclusions/absence | 283 | 排除项和 absence-not-proof 审计 |
| Generic training diagnostic | 38/43 | 只使用generic集合的训练集诊断，不是blind recall |
| Training regression | 43/43 | 使用training overlay的训练回归结果 |

`CR-*`与`CAND-*`不是同一种对象：

```text
CR-*   = project-neutral的安全requirement
CAND-* = 某个CR在某个project/revision/chain上的未覆盖实例
```

例如：

```text
CR-00e3c3f4a588e4d6
  + AstrBot
  + C-8df14601b06c
  + missing-check
  → CAND-b03da667a40c095d
```

该candidate属于最初1,139条审计记录，并通过全部门禁成为最终78条generic candidates之一。

## 2. 总体判断模型

一个candidate进入generic集合前必须回答三个不同问题：

```text
1. 这条安全规则应不应该存在？
   → Normative Evidence Resolver

2. 模型控制的具体字段能否到达危险sink role？
   → CodeQL field flow，或hash-bound source-validation field flow

3. 当前gate是否完整实现了这条规则？
   → gate semantic comparison + source validation
```

三类问题不能互相替代：

- Capability Card能说明API“可以做什么”，但不能独立发明“必须检查什么”。
- CodeQL能证明字段到达sink参数，但不能独立证明自然语言policy合理，也不能完整判断gate语义是否充分。
- 大模型能提出和解释安全语义，但不能仅凭模型投票进入generic集合。

整体流程为：

```text
上游chain、gate、sink和Capability Card
  → LLM/人工提出requirement或source judgement
  → 规范证据解析
  → 精确field→sink-role证明
  → member-level applicability
  → gate coverage与source validation
  → 确定性candidate准入
  → root-cause聚合与generic/training分区
```

Requirement有两类入口但只有一个canonical CR空间：Group Oracle从HSG observed gates和group-scoped registry evidence
产出group requirement；Coverage Comparison的canonical source analysis可以从`explicit-source-policy`或versioned
`learned-invariant`提出/细化source-derived CR。后者不回写Group Oracle artifact。全部provenance都先规范化为
`canonical-requirement/v7`，再经过同一normative resolver、member applicability、field/role和source-promotion门禁。

## 3. 大模型提供什么

### 3.1 Requirement proposal

Group Oracle或source analysis可以提出结构化安全规则：

```json
{
  "rule": "必须满足的安全规则",
  "applicability": "规则何时适用",
  "controlled_facet": "模型控制的字段或能力",
  "security_effect": "规则防止的安全影响",
  "enforcement_stage": "检查应发生的阶段",
  "evidence_ids": ["EV-..."]
}
```

模型的作用是把分散在handler、gate、sink、策略代码和修复记录中的语义整理为project-neutral requirement。稳定的CR/CAND ID由确定性代码生成，不由模型生成。

### 3.2 Gate语义比较

模型结合gate semantic IR和源码判断现有检查属于：

```text
covered
wrong-check
missing-check
not-applicable
unknown
```

CodeQL可以枚举gate、调用关系和受控参数，但“检查路径包含关系”是否等价于“保证principal唯一隔离”属于安全语义判断，不能仅凭通用数据流查询决定。

### 3.3 Source validation judgement

Provisional candidate可以进入受限源码审查，返回：

```json
{
  "verdict": "confirmed-uncovered",
  "controlled_flow": "confirmed",
  "sink_reachability": "confirmed",
  "gate_coverage": "uncovered",
  "source_research_complete": true,
  "uncertainties": [],
  "operational_error": null,
  "source_evidence": []
}
```

每条source evidence必须绑定源码相对路径、行范围、exact excerpt、角色和SHA-256。允许的典型角色包括：

```text
handler
controlled-value
gate
sink
policy
impact
```

历史source validation可能使用大模型或只读source agent；当前v15 refresh只复用digest-bound结果，manifest记录：

```text
v15_live_model_calls = 0
v15_source_agent_calls = 0
```

## 4. 规范依据过滤

Requirement必须由至少一种规范authority支持：

| Authority | 来源 | 约束 |
|---|---|---|
| `explicit-source-policy` | 源码、测试或配置中的明确安全边界 | exact excerpt、路径、行号和SHA-256 |
| `fixed-delta` | revision-bound修复/acceptance contract | exact HC/ST适用范围和source digest |
| `standard` | 仓库固定的标准文本 | exact quote和SHA-256 |
| `documentation` | 仓库固定的项目文档 | exact quote和SHA-256 |
| `learned-invariant` | versioned learned catalog | 精确route、applicability contract和training标签 |
| `capability-policy` | source-owned versioned policy contract | card digest、schema version和policy ID |

普通Capability Card只描述事实能力，例如“fetch可向caller-selected URL发请求”。它不能单独授权“必须阻止私网URL”的requirement。只有显式`policy_contract`是例外。

Resolver验证：

```text
authority kind合法
∧ evidence ID存在
∧ exact quote完整
∧ SHA-256匹配
∧ schema version匹配
∧ applicability contract完整
∧ upstream状态完整
```

没有规范authority时输出：

```text
status = non-normative
reason = ordinary capability facts cannot authorize a requirement
```

当前1,139条审计分区中，955条被归为`non-normative-capability-hypothesis`。它们保留在审计产物中，但不进入generic候选。

## 5. Field-sensitive静态证明

### 5.1 CodeQL证明的内容

Python和TypeScript查询从精确模型字段读取开始：

```text
tool schema field
→ handler property read
→ assignment/argument/parameter/return
→ allowed transform或显式bridge
→ exact sink argument role
```

例如：

```text
args.url     → destination-url
args.env     → environment
args.cwd     → working-directory
args.command → command
args.path    → path
```

禁止把以下关系当作field flow：

```text
整个args对象 → 每个property
map key → stored value
selector/task_id → selected record contents
同名变量 → 自动传播
sibling argument → 其他sink role
path → environment
session_id/selector → command
config/provider response → model-controlled
```

跨RPC、IPC、queue或plugin registry默认不传播；只有项目绑定bridge可以加入。OpenClaw-CN Feishu桥只允许：

```text
args.media
→ runMessageAction.params
→ handleSendAction读取media
→ Feishu fetch destination-url
```

它不传播整个`args`，也不把`path`、`filePath`或其他同名字段视为media。

### 5.2 CodeQL不能证明的内容

CodeQL通常不能单独证明：

- 某条自然语言安全策略本身是否合理；
- 某个gate在业务语义上是否完整；
- 某个principal/workspace关系是否构成真实安全边界；
- 漏洞是否在实际部署条件下可利用；
- 项目维护者是否认可该规则为预期policy。

因此不能把最终candidate描述为“全部经CodeQL形式化证明”。

### 5.3 两种field-flow witness

当前150条field-flow witness由两类证明组成：

| Proof kind | 数量 | 来源 |
|---|---:|---|
| `codeql-direct` | 5 | CodeQL局部直接数据流 |
| `codeql-interprocedural` | 65 | CodeQL跨函数数据流 |
| `codeql-explicit-bridge` | 2 | CodeQL项目绑定bridge |
| `source-validation-cited-field-flow` | 78 | source validation引用的完整hash-bound源码证据 |

Source-validation witness只有在以下条件全部满足时才可提升：

```text
verdict == confirmed-uncovered
controlled_flow == confirmed
sink_reachability == confirmed
source_research_complete == true
uncertainties为空
operational_error为空
handler/controlled-value/sink证据完整
所有源码SHA-256匹配
field与sink role兼容
```

这类记录属于高约束静态源码证据，但仍不是CodeQL独立证明。

## 6. Effective Capability View与Member Applicability

HSG保留共享HC/ST语义分组，但Group requirement不再自动应用到全部member chains。每条chain从Capability Card v2和field-flow派生Effective Capability View，记录：

```text
实际controlled roles
value authority
transforms
active/inactive facets
library guarantees和runtime defaults
```

随后对每个`(HSG, requirement, member chain)`执行：

```text
Normative requirement
∧ required sink role匹配
∧ exact field-flow witness
∧ value authority满足
∧ capability facet激活
∧ boundary匹配
∧ actual effect可达
∧ call-shape predicate满足
```

结果分为：

```text
applicable
not-applicable
unknown
upstream-incomplete
```

只有`applicable`可以继续生成generic candidate；`unknown`和`upstream-incomplete` fail closed。

当前358个CR/member pairs的分区为：

| Decision | 数量 |
|---|---:|
| `applicable` | 95 |
| `unknown` | 180 |
| `upstream-incomplete` | 83 |

相对前一版本，有8条旧canonical candidates因缺少完整member applicability被移出generic，并写入`member-applicability-removals.jsonl`；没有静默删除。

## 7. Candidate source validation与最终准入

### 7.1 Source routing与evidence packet

Canonical source analysis是coverage pipeline内置的requirement synthesis和promotion阶段。默认风险路由预算为64条
chain，固定权重为SameOrigin改变`+100`、无primary candidate`+80`、learned routing`+60`、partial IR`+40`、
partial Group Oracle`+30`、高风险terminal capability`+20`。冻结的training source-regression chain先保留在预算
内但不改变分数；随后每项目最多先取3条，再按全局`(score desc, project, chain_id)`补足。

`--canonical-source-scope all`定义485-chain的新detector execution，因此只能随新的detector freeze发布。Router
weights、training regression set、selected/excluded rows全部写入manifest。

Packet source validation可以处理任意provenance的CR。V15只复用source hash、研究完整状态和精确field/role仍然
成立的旧validation。`source-validation-evidence-packet/v1`绑定：

- handler、controlled field/value与ordered structural hops；
- gate/sink spans、SameOrigin和连续pre-sink coverage；
- exact-chain value/guard search；
- 全部引用源码的SHA-256。

一次no-tool判断必须返回完整source verdict或`needs-deep`。Deep agent只能读取packet声明的源码文件，最多8 turns、
16 tool calls，不提供broad Glob或workspace-symbol search。它必须证明handler input、SameOrigin、sink reachability、
真实security boundary、protected asset、concrete effect和uncovered gate。Invalid packet只能进入受限deep fallback，
不能直接产生survivor；数据库、队列等non-source structural resource可保留anchor，但不能伪装为source evidence。

剩余Wrong-Check按chain共享evidence packet，每批最多4条。Complete-oracle Missing-Check按whole-chain density选择，
每批最多4条，直到`needs-source-validation + source-unknown + operational-failure < 150`。无法形成合法verdict的批次
写入独立failure sidecar与unknown validation，不能阻塞其它chain，也不能成为confirmed或false-positive证据。

### 7.2 Deterministic precision contract

Source promotion前还执行以下确定性门禁：

- `Recommended`/`should`等非规范建议不能成为canonical finding；
- SameOrigin必须绑定requirement约束的精确sink role；
- 同chain且rule、applicability、effect、failure mode、gates相同的candidate合并provenance；
- 影响必须由model-facing flow直接到达，不能依赖另一browser/process compromise；
- 合取requirement的每个子句都要有源码支持；
- content/environment/working-directory requirement必须绑定同一handler-controlled role；
- 普通hardening rule没有concrete policy/protected-asset evidence时不能仅凭Capability Card晋升；
- 更完整的resolved-path/symlink requirement可以subsumed较窄规则，但要保留replacement identity。

每条输入candidate的`confirmed | needs-source-validation | recommendation-only | facet-not-controlled |
role-not-controlled | policy-evidence-missing | duplicate | subsumed | impact-not-model-reachable |
requirement-overbroad | source-rejected`终态写入`candidate-filter-dispositions.jsonl`。Partial Group Oracle的
applicability未完成时必须为`upstream-incomplete`。

完成member applicability后，candidate仍必须具有完整source validation。最终generic只接受：

```text
verdict = confirmed-uncovered
```

其他结果的处理：

```text
covered            → 原candidate不成立
not-applicable     → 从canonical移除
source-rejected    → 从canonical移除并保留原因
unknown            → fail closed，不进入canonical
operational-failure→ 单独审计，不冒充误报或确认结果
```

当前1,139条审计记录的终态分区为：

| Disposition | 数量 |
|---|---:|
| `confirmed` | 78 |
| `non-normative-capability-hypothesis` | 955 |
| `upstream-incomplete` | 90 |
| `member-upstream-incomplete` | 6 |
| `member-unknown` | 2 |
| `impact-not-model-reachable` | 3 |
| `source-rejected` | 4 |
| `requirement-overbroad` | 1 |

这些disposition构成完整审计分区，不能把所有非`confirmed`记录统称为false positive。例如`unknown`和`upstream-incomplete`表示证据不足，而不是已经证明安全。

## 8. AstrBot实例

`CR-00e3c3f4a588e4d6`要求per-principal workspace由完整principal identity派生，不能使用可能碰撞的有损规范化值。对应generic candidate为：

```text
CAND-b03da667a40c095d
project = AstrBot
chain = C-8df14601b06c
failure_mode = missing-check
```

### 8.1 大模型/源码审查给出的语义

```text
不同UMO可被normalize_umo_for_workspace折叠成相同key
→ _workspace_root使用该key
→ allowed roots包含该workspace
→ containment gate只检查path位于root内
→ file_path.open读取实际文件
```

Source evidence分别绑定：

- `normalize_umo_for_workspace`的有损规范化；
- `_workspace_root`和`_read_allowed_roots`的policy；
- `_is_path_within_allowed_roots`的实际检查；
- `FileReadTool.call`的模型控制path；
- `_probe_local_file`的file read sink。

### 8.2 静态证据与确定性准入

该实例当前使用：

```text
witness_id = FFW-520e45dd2e8e9ffe
proof_kind = source-validation-cited-field-flow
field = path
sink_role = path
value_authority = model-arbitrary
transforms = normalize, strip
```

它不是CodeQL witness。确定性resolver验证源码路径、行范围、excerpt和SHA-256，并生成：

```text
required_sink_roles = [path]
required_effect = file-read
required_boundary = host-filesystem-to-model
call_shape_predicates = [file-read-active]
```

Member Applicability的role、authority、facet、boundary、effect和call shape全部匹配，source validation同时满足：

```text
controlled_flow = confirmed
sink_reachability = confirmed
gate_coverage = uncovered
source_research_complete = true
uncertainties = []
```

因此该candidate进入最终generic集合。这里机械验证的是证据身份、字段/role和准入合同；“UMO碰撞构成跨principal disclosure”仍包含模型/源码审查的安全语义判断。

## 9. Generic、Training与人工复核

活动输出严格分离：

```text
candidates.jsonl
  = generic-candidates.jsonl
  = 78条，held-out允许读取

training-regression-candidates.jsonl
  = 78 generic + 4 fallback
  = 82条，只用于training regression
```

78条chain-level candidates按：

```text
project
+ actual effect sink
+ normalized invariant
+ patch locus
```

聚合为74个`vulnerability-clusters.jsonl`根因簇。人工precision复核应优先按74个clusters检查，而不是重复审查同一根因对应的多条chain。

Runtime training consumer显式读取overlay中的61个strict-match candidate ID，覆盖43个report和76个reference；
generic/held-out consumer只能读取byte-identical的`candidates.jsonl`或`generic-candidates.jsonl`。4条旧member repair
只在`generic-freeze-lock.json`写完后加载，用于恢复5个training report，不得进入generic或held-out输入。

### 9.1 Identity、freeze与版本迁移

`coverage-candidate/v7`只绑定CR：

```text
hash(coverage-candidate/v7, HSG, project, revision, chain, CR,
     failure_mode, sorted(gate_ids))
```

旧`R-*`、`CAPR-*`、`SR-*`、`LIR-*`与`CAND-*`通过identity migration映射到当前CR/CAND；runtime和GT audit只能
读取稳定CR/CAND identity。`generic-freeze-lock.json`在读取training fallback registry之前绑定v15 implementation、
Capability Card v2、field-flow QL、CR normalization、router、learned catalog、prompts、12个project revision、
coverage inputs、43个training GT及其SHA-256。

V14至V9的只读快照位于`output/cross-project/archive/coverage-comparison-v*/`；v8、v7和v6分别保存在其明确
archive root，v7由annotated tag `coverage-v7-pre-migration-20260822`锚定。Migration仅用于provenance/rollback，
活动代码不得导入旧pipeline。

`confirmed-uncovered`的准确含义是：

> 具有完整、revision-bound源码证据支持，且满足当前准入合同的高置信静态candidate。

它不等同于形式化证明、人工确认或运行时成功利用。进一步降低误报可以优先：

1. 将更多`source-validation-cited-field-flow`补成独立CodeQL witness；
2. 对74个根因簇做分层人工抽样；
3. 对高影响簇补充runtime exploit/control验证；
4. 将验证后的通用规则回填为source-owned policy或精确QL fixture，而不是report-specific特例。

## 10. 主要审计产物

| 产物 | 用途 |
|---|---|
| `candidate-filter-dispositions.jsonl` | 全部1,139条记录的终态分区 |
| `canonical-requirements.jsonl` | 活动CR及规范证据 |
| `normative-evidence-resolutions.jsonl` | requirement是否具备规范authority |
| `requirement-applicability-contracts.jsonl` | 机器可执行的准入合同 |
| `effective-capability-views.jsonl` | 每条chain的实际能力、roles和authority |
| `field-flow-witnesses.jsonl` | field→sink role正向证明 |
| `field-flow-exclusions.jsonl` | 不成立或证据不足的数据流审计 |
| `member-applicability.jsonl` | 每个CR/member pair的独立判定 |
| `member-applicability-removals.jsonl` | 旧candidate的证据化移除记录 |
| `generic-candidate-validations.jsonl` | 78条generic的source validation |
| `generic-candidates.jsonl` | held-out允许读取的generic集合 |
| `training-regression-candidates.jsonl` | training-only overlay |
| `vulnerability-clusters.jsonl` | 根因聚合结果 |
| `generic-freeze-lock.json` | generic产物与实现SHA-256绑定 |

## 11. 声明边界

- 当前43个GT参与过learned catalog、policy contract和回归选择，因此43/43只能称为training recall。
- Generic的38/43是训练集诊断，不是blind recall。
- Synthetic-inclusive 46/46包含3个显式source transplant，只能称为detectability diagnostic。
- `unknown`、`upstream-incomplete`和`operational-failure`不能被计作已确认误报。
- Future held-out evaluation只能读取`candidates.jsonl`或byte-identical的`generic-candidates.jsonl`。

## 12. 相关文档

- 检测不变量与SameOrigin：[`detection-method.md`](detection-method.md)
- HC/ST/HSG requirement来源：[`cross-project-oracle.md`](cross-project-oracle.md)
- Runtime consumer与replay边界：[`runtime-validation.md`](runtime-validation.md)

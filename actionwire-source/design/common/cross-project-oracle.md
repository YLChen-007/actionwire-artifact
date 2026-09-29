# 跨项目类型对齐与 Group Oracle

> 上级设计：[`design/整体设计.md`](../整体设计.md)。
>
> 本文是 [`docs-map.yaml`](../../docs-map.yaml) 中 `handler-type-alignment`、`sink-type-alignment` 和
> `group-oracle` 的 spec owner，定义 HC/HT、ST、HSG 与 requirement evidence 的公共契约。

## 1. 目标与阶段关系

跨项目阶段把 project-specific handler 和 sink 表达转换为可比较、可迁移但不丢失 concrete provenance 的对象：

```text
resolved handler specifications
  → Handler Criterion (HC) + Handler Type leaf (HT)

handler-rooted semantic chains + terminal capability
  → global Sink Type (ST)

actual reachable member
  → Handler-Sink Group HSG = (HC, ST)

HSG members + observed gates + normative evidence
  → project-neutral requirements
```

公开 group axis 是 `(HC, ST)`。`HT` 用于保留 user-visible leaf intent 和 trace metadata，不直接拆分共享
requirement。只有实际可达、具有合法 semantic/capability binding 的 member 进入 HSG；不会构造 HC×ST 笛卡尔积。

## 2. Handler 类型对齐

从仓库根运行：

```bash
python -m src.handler_type_alignment --all
```

### 2.1 输入与禁止信息

对齐直接消费全部 resolved handler specification，不按 security impact 预筛选。Prompt 只含 declared intent、
parameter roles 和同 parent sibling context，禁止输入 sink identity、capability class、gate semantics 或 impact verdict，
避免用后续安全结论污染 handler taxonomy。

Runtime/SDK-owned unresolved interface 不伪造类型，写入显式 exclusion/boundary audit。

### 2.2 Parent 与 leaf identity

系统使用两个 content-addressed identity：

```text
HC-* = hash(operation_family, resource_family, effect)
HT-* = hash(intent_family, operation_family, resource_family, effect)
```

- `HC-*` 是共享 oracle 的 parent criterion；
- `HT-*` 是精确 user-visible action leaf；
- required parameter 的命名、数量和 wrapper 拆分只形成 role signature，不自动拆分相同行为；
- browser click/key/navigation/scroll/type、repository issue/commit/PR 和 device app/service/key/playback 等明确
  不同 intent 保持独立 HT，即使共享 HC。

`handler-type-catalog/v4` 的 `criteria[]` 列出 child type、representative 和全部 assigned members；`types[]` 为
每个 leaf 标明唯一 `handler_criterion_id`。`handler-type-mapping/v2` 同时记录 parent 和 leaf。

### 2.3 Seed、proposal 与 reconciliation

NanoBot 的 resolved handler 先按 primary user-visible intent 和 closed operation/resource/effect vocabulary 形成
frozen leaf anchors。其它项目按 project batch canonicalize；相同 normalized intent 若得到不同 axis tuple，必须在
一次 order-independent interaction 中从已观察 tuple 选择唯一结果，一次 repair 后仍冲突则整次 run 失败。

无 sibling anchor 的 target 使用按 sorted member identity 生成的临时 `HP-*` proposal，不提前分配最终 HT。
Proposal batch 最多 8 个 source，只能在同一 HC 的 complete sibling index 中选择 best match 或 `distinct`。
Proposal edge connected component 需要 joint adjudication，拒绝 asymmetric、non-transitive 或跨 parent merge。

只剩一个 member 的 leaf 由同 parent sibling independent challenger 审计；若 parent 没有其它 leaf，则确定性记录
`no-sibling-candidate`，不调用模型。Singleton audit 要求 complete sibling coverage 或明确 boundary，不能为了达到
比例目标强迫合并。

### 2.4 Project-neutral normalization

在 proposal/type ID 前，受测 normalization table 只统一由接口封装造成的 alias，例如：

- message payload/destination variant；
- file/document/artifact read；
- single/batch browser-command wrapper；
- scheduled-task state control；
- skill lifecycle mode。

该表同步统一 operation/effect axis，但不合并明确不同的 browser action、repository object creation 和 device action。

### 2.5 输出

```text
output/cross-project/handler-types/
  ├── catalog.json
  ├── mappings.jsonl
  ├── criterion-support.jsonl
  ├── handler-oracle-inheritance.jsonl
  ├── singleton-audit.jsonl
  ├── capability-observations.jsonl
  ├── manifest.json
  └── alignment.md
```

对齐完成后才按 exact project/tool/sink join 生成 capability observations；该 sidecar 不改变 handler membership，
`no-reachable-sink` 也不等于 no-security-impact。当前文档保留的 v3 deterministic projection 为 98 个 criterion、
37 个 singleton criterion 和 144 个 leaf；live v4 记录实际结果但不以这些数值强迫模型合并。

实现说明见 [`src/handler_type_alignment/README.md`](../../src/handler_type_alignment/README.md)。

## 3. Sink 类型对齐

从仓库根运行：

```bash
python -m src.sink_type_alignment --all
```

### 3.1 Eligible chain 与 terminal accounting

对齐消费被 handler-impact 保留且成功组装为 `call-chain-semantic-ir/v3` 的 chain。Complete/partial IR 均可进入，
semantic IR hard limit 为 64,000 estimated tokens，完整输入不得截断。

- `potential-impact` 与 `unknown` chain 形成 security `(HC, ST)` group；
- 双模型确认的 `no-security-impact` chain 形成 `(HC, no-security-impact)` terminal accounting group，并标记
  `downstream_oracle_eligible=false`；
- semantic assembly failure、handler specification unresolved 或 HC mapping 缺失写入 `excluded-chains.jsonl`。

公开 handler axis 是 HC；HT 只保留 trace metadata。

### 3.2 输入连接与一致性

任何模型请求前，loader 校验：

- handler catalog/mapping schema、project 与 revision；
- structural chain、semantic IR 与 manifest path/digest；
- terminal sink constraint 和 capability-card SHA-256；
- exact `(project, tool_name)` handler mapping，或 concrete handler function/file/line fallback。

连接冲突、多义或无法解释时整次 run 失败。同一 `(project, HC, sink_id)` 的多条 chain 只有在 capability card、
controlled argument、call shape 和 constraint 完全一致时才可合并 assessment；最终仍为每条 eligible chain 生成
mapping。同一 revision-bound concrete sink 从多个 HC 可达时必须共用一个全局 ST；原始 constraint/card 不一致则
fail closed。

### 3.3 Global ST identity

NanoBot reachable sink 先 batch-cluster 为 frozen global ST anchors，并记录每个 ST 已观察 HC。External target 在其
HC 内只看到已关联 anchor；无 seed 的 HC 从空 catalog 开始。未匹配 group 使用 sorted member 派生临时 `SP-*`
proposal，再以最多 8 个 source 的 batch 与 complete concise global catalog 比较。Proposed-match connected component
需要 joint adjudication。

活动 catalog 的 external ST 也是 content-bound frozen anchor：完整 target input digest 未变时复用；HC 改变但
`(project, revision, sink_id, constraint, card)` 相同时按 concrete-sink semantic digest 复用。其它输入变化重新判定。

`ST-*` identity 只包含：

- capability family/facets；
- model-controlled semantic roles；
- implicit-default facets；
- project-neutral call-shape family。

API/library name、project、language、HC/HT、label 和 prose 不进入 identity。Fixed 与 model-controlled destination、
shell string 与 direct argv，以及会改变 redirect/path/environment/authentication/parsing/dispatch 能力的 default 必须
分开；async/library/wrapper 语法差异本身不拆分。

Approval equivalence 依据语义而非 API 名：例如 command、user-decision 和 return-control 等价时可共享 ST，但
process execution、approval persistence 和 presentation-only sink 必须分离。

### 3.4 安全与输出

Card、call shape 和描述作为 untrusted data；模型不开放 tools。每次 interaction 最多一次 schema repair，仍无效则
失败且不替换上一版产物。Credential-shaped substring 在 transport/audit persistence 前统一 redact。

```text
output/cross-project/sink-types/
  ├── catalog.json
  ├── mappings.jsonl
  ├── assessments.jsonl
  ├── excluded-chains.jsonl
  ├── handler-sink-groups.jsonl
  ├── identity-reuse.jsonl
  ├── manifest.json
  ├── alignment.md
  └── repository/*/chat.json
```

全部产物在 sibling staging directory 校验后 atomic publish；Markdown 开头包含完整 repository-root generation
command。Credential 只从 `DEEPSEEK_API_KEY` 读取。默认只 replay byte-identical complete prompt；`--fresh` 禁用
replay。

实现说明见 [`src/sink_type_alignment/README.md`](../../src/sink_type_alignment/README.md)。

## 4. HC/ST Group Oracle

从仓库根运行：

```bash
python -m src.group_oracle --all
```

### 4.1 Group identity 与输入验证

该阶段只处理 `downstream_oracle_eligible=true` 的 security group。公开 key 是 `(HC, ST)`，稳定 input identity 复用
`HSG-*`。No-security-impact group 写入 `excluded-groups.jsonl`，不进入模型。

首个请求前，loader 从 sink mappings 重建 exact chain membership，并要求与 `handler-sink-groups.jsonl` 完全一致；
同时校验 handler/sink catalog、mapping schema、project revision、semantic IR、sink constraint、capability card、
manual evidence path/quote/SHA-256 和所有 manifest digest。

### 4.2 Deterministic seed 与 peer comparison

每个 HSG 确定性选择 seed：

1. NanoBot-seeded ST 优先选择最小 `chain_id` 的 complete NanoBot chain；
2. 否则选择字典序第一个 complete `(project, chain_id)`；
3. 全组均 partial 时才选择第一个 partial chain。

Seed-profile prompt 接收完整 ordered semantic IR、HC/ST criterion、完整 capability card 和适用 pinned evidence，
输出 project-neutral policy atoms 与 provisional requirements。Seed 不可信也不完整，observed gate 只产生 hypothesis。

Gate-derived candidate 的被检查主体必须在输入 IR 中有明确模型来源（可包含已记录的转换）；整体 `args`
绑定到多个 gate、同名变量或 helper 的 `params` 名称不能替代字段来源。配置可作为比较基准或适用条件，
不要求该配置本身由模型控制。普通非空/类型/格式检查不自动成为安全 requirement；来源不明的主体不得凭空补边。

其余 chain 始终与同一 frozen seed profile 比较；peer 不能看到之前 peer 的 proposal。每个 request 最多 8 条 chain，
受 96,000 estimated input-token hard limit；单条 IR 超限在 transport 前失败，不截断。

### 4.3 Evidence authority

Requirement 的 evidence 分为：

| Evidence | 作用 |
|---|---|
| `documentation` | repository-pinned 明确产品/安全契约 |
| `standard` | 固定标准文本与适用 scope |
| `fixed-delta` | revision-bound 修复或 acceptance contract |
| `capability-policy` | source-owned、versioned capability policy contract |
| ordinary `capability-card` | 仅说明事实能力，不能独立批准 requirement |

`oracle-evidence-registry/v1` 要求 source path、SHA-256、locator、exact quote、supported claim 和 HC/ST applicability。
Generator 不做 live research。

`group-wide` 表示可在该 HC/ST 下以项目中立方式表达，不要求适用条件在全部 member 上同时成立。
带 normative evidence 的成员条件策略（例如启用域名 blocklist 时对模型 URL 的限制）可以成为 requirement，
但必须保留配置、被检查主体和效果边界；不能因 seed 不含该策略或 helper 名称仅见于一个项目而直接拒绝，
也不能把该策略无条件推广给其他 member。策略关闭、异常处理和明确豁免保留为适用范围或 enforcement limit，
不得由生成器擅自升级成更严格的 fail-closed 保证。

本节列出的是 **Group Oracle evidence registry** 可直接消费的 authority。下游 Coverage Comparison 还可以把
`explicit-source-policy` 和 versioned `learned-invariant` 规范化为 source/learned-derived CR；它们不回写或伪装成
Group Oracle requirement，必须在 canonical resolver 中独立验证 source digest、适用性与 policy basis。两条路径最终
共享“普通 Capability Card 不能独立创造义务”的门禁。

Seed profiling 后，只有具有 applicable normative evidence 的 group 执行 evidence-extension prompt。它可以从
documentation、standard、fixed-delta 或 capability-policy 提出 zero-gate requirement；每条 proposal 必须引用允许的
`EV-*`，绑定 deterministic seed 且 `origin_gate_ids=[]`。普通 capability card 不进入该 pass。

### 4.4 Proposal validation 与 identity

Gate-derived seed/peer proposal 必须引用 exact origin gate；zero-gate member 不能凭 capability fact 发明义务。
所有 proposal 收齐后按 semantic dimension 分区，再在 complete concise index 与适用 evidence 中选择
`add`、`already-covered` 或 `reject`。`add` 必须引用 normative `EV-*`。

Duplicate edge 形成 connected component 后 joint adjudicate，消除 asymmetric/non-transitive relation。超 8 node 的
component 使用 lossless ID-preserving recursive summary，audit subject 包含 component ordinal。

```text
RP-* = hash(group, origin chain/gate, normalized proposal semantics)
R-*  = hash(dimension, rule, applicability)
```

API、project、handler 和 gate name 不进入最终 requirement identity。

### 4.5 Reuse、checkpoint 与发布

完整 group 复用还需匹配 `construction_policy_sha256`（seed/peer/evidence/assessment/component/summary/repair
提示内容的摘要）。旧版本缺少该指纹或规则已变化时重新推导，不能绕过更新的来源和条件适用性要求。
`--fresh` 同时禁用 exact-prompt replay、完整 group snapshot 复用和 requirement continuity。
当前 seed/peer candidate 与 continuity proposal 内容 ID 相同时，合并必须同时保留规范 `origin_evidence_ids`
并使用 evidence-origin wire contract，不能只合并 chain/gate。任何强制保留项失去规范来源时立即失败，不能产生
`reject` 却标注“Preserved”的静默丢失结果。

可重复指定 `--group-id HSG-*`，仅推导所选完整组及其全部成员。部分运行必须写入独立目录；禁止覆盖 canonical
目录或包含未选组的已有产物。Manifest 的 `selection_scope` 明确选择范围与完整上游分母，普通 counts 仅描述
本次实际输出，不把两组结果标为129组完成。

G06/G25 的模型 URL gate 定向修订使用独立的
`src/group_oracle/oracle-evidence-registry-url-gates.json`，其四条 documentation evidence 绑定
`evidence/model-origin-url-policies.md` 的精确引文与哈希，不修改原始抽样、baseline registry 或 corrected-v2 注册表。
此修订基于已审阅输入/策略，不是重新报告盲测结果；能力卡仍无独立规范授权。

定向 gate 保留验证使用 `--observed-gates-only`：规范证据仍用于评审，但不执行独立的 zero-gate evidence-extension，
不继承 zero-gate continuity，且最终 requirement 必须有 observed origin gate。该模式与 correction-ledger injection
互斥，并参与整体复用身份；它不宣称能用规则机械补全缺失的字段数据流。G25 原有 remote-image scheme/address
目标也必须在修补独立 blocklist 目标时保留，不能以策略加载错误放行覆盖另一阶段的 DNS/address 拒绝。
该模式在发布前对已接纳候选执行一次跨 dimension 的全组 policy consolidation：输入完整 member IR、规范合同
和当前 clusters，要求精确划分所有已接纳 proposal ID；不得增加新来源或能力卡授权。规范的例外、条件和失败分支
必须在最终规则集合中共同成立，防止某条宽泛否定抵消同组另一条已保留的豁免。此步骤纳入 token 上限、审计及复用指纹。

`--gate-qualification` 可提供经审阅的模型来源准入文件。文件必须精确覆盖本次全部 group/member，绑定 revision、
原始完整 semantic IR 哈希、qualified gate UID 和输入 JSON Pointer 的精确值；漂移或缺成员时失败。
仅在 `--observed-gates-only` 模式应用：构造过滤后的推导视图及 value bindings，保留全部成员和原始上游文件，
在 manifest 保存准入文件哈希、原始哈希与被排除 UID。验证器只接受合格来源 UID；该机制执行已有审阅结果，
不声称从任意自然语言记录自动证明 taint。G06/G25 定向文件来自本会话明确来源的 URL gate；未知 helper 引用不补猜。

只有 HSG member refs、HC/ST、每条 semantic IR 和 applicable evidence IDs 全部相同时才 content-bound reuse 完整
oracle/proposal/assessment/chat。扩展 HSG 的旧 requirement 只有在 origin chain、gate UID 和 current evidence 仍有效
时才能 continuity-preserve。

Live interaction 同步 fsync 到 output sibling 的 redacted noncanonical checkpoint；中断 rerun 可恢复，成功 atomic
publish 后删除。Checkpoint 不是 canonical artifact，也不能绕过 byte-identical prompt validation。Manifest 把
provider-reported usage/covered live calls 与 deterministic full-run token estimate 分开记录。

输出为：

```text
output/cross-project/group-oracles/
  ├── oracles.jsonl
  ├── seed-profiles.jsonl
  ├── proposals.jsonl
  ├── proposal-assessments.jsonl
  ├── excluded-groups.jsonl
  ├── evidence-index.json
  ├── manifest.json
  ├── oracle-index.md
  └── repository/<stage>/<subject>/chat.json
```

实现与 post-hoc corrected-v2 边界见 [`src/group_oracle/README.md`](../../src/group_oracle/README.md)。

## 5. 下游接口

Coverage comparison 只能把 evidence-authorized requirement 与具体 HSG member 连接。它必须再次验证 exact source field、
sink role、capability family、boundary、effect 和 call-shape applicability；Group Oracle 的 group-level requirement 不能
自动投影到全部 members。完整准入见 [`filter-candidates.md`](filter-candidates.md)。

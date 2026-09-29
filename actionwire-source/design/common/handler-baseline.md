# Blind Claude Code Per-Handler Baseline

> 上级设计：[`design/整体设计.md`](../整体设计.md)。
>
> 本文是 [`docs-map.yaml`](../../docs-map.yaml) 中 `claude-handler-baseline` 的 spec owner，定义 blind universe、
> isolation、freeze、ground-truth adjudication、precision-first policy 与结果声明边界。

## 1. 目的与独立性

该 baseline 为 agent 提供一个不复用 ClawGap call-chain、gate、Capability Card、Group Oracle 或 candidate 产物的
对照实验。Agent 直接从 concrete handler inventory row 和目标项目源码发现 model-controlled input、handler-rooted
path、terminal sink、security requirement 与 gate defect。

它与 ClawGap detector 独立：

- ClawGap 的静态产物、设计、paper、GT 和其它 benchmark project 对 trial 不可见；
- 每个 handler row 是独立 trial，多 concrete entry 的同名工具不能合并；
- baseline finding 不能反向修改 canonical detector、oracle 或 freeze；
- GT-handler-conditioned 结果只度量“已给定正确 handler root”后的恢复能力。

实现入口见 [`src/handler_baseline/README.md`](../../src/handler_baseline/README.md)。

## 2. Full Blind Universe

从仓库根运行：

```bash
python -m src.handler_baseline --all --workers 4 --timeout 3600
```

Trial universe 是 12 个 registered project 的
`design/<project>/handler-entry/debug/tool-handler-entries.csv` 全部行。当前冻结记录为 316 条 handler-entry row、
309 个 project-scoped unique tool name。不能按 tool name 合并，否则 QwenPaw、OpenClaw 等多 concrete entry 工具会
丢失 handler-root path。

`--inventory-only` 只预览 universe；`--only HB-*` 用于 focused smoke，必须写入 `focused/<trial-id>/`，不能生成或
冒充 full-corpus freeze。

## 3. Trial Isolation

每个 trial 使用全新 Claude Code process，通过 DeepSeek Anthropic-compatible endpoint 固定
`deepseek-v4-flash`，不允许 fallback model。Bubblewrap 只把目标 project source 以 read-only `/workspace` 挂载，
使用临时 HOME；以下内容不可见：

- `design/`、`output/` 和 paper；
- Git metadata 与其它 benchmark project；
- ground truth、ClawGap detector/oracle artifact；
- 用户 Claude settings 与指向 repository 外部的 symlink。

Agent 只开放 `Read`、`Grep`、`Glob`，输入只含 exact handler inventory row。Prompt 使用论文中的 coverage
invariant，但要求 agent 自己从源码恢复：

```text
model-controlled input
  → concrete handler root
  → reachable terminal sink/capability
  → relevant pre-sink gates
  → capability gap / no finding / unknown
```

存在 relevant gate 但联合语义覆盖不足为 `wrong-check`；applicable requirement 没有 relevant gate 为
`missing-check`；source、call shape、capability 或 gate 证据不足输出 `unknown`。`no-finding` 必须给出 source-backed
negative evidence。

Finding 的 `HBF-*` identity 由 runner 对 validated normalized record 确定性计算，模型不产生可信 identity 或计数。

## 4. Artifact、Resume 与 Usage

Per-trial `trial.json` 在 terminal status 后 atomic write。Resume 只有在以下身份全部不变时复用：

- source tree digest 与 handler inventory；
- model、Claude version 和 timeout；
- system/user/repair prompt；
- response JSON schema。

完整 run 发布：

```text
output/cross-project/claude-handler-baseline/
  ├── inventory.jsonl
  ├── trials.jsonl
  ├── findings.jsonl
  ├── manifest.json
  ├── blind-freeze.json
  └── baseline-results.md
```

Markdown 开头由 generator 写入完整 repository-root reproduction command。

Transport 按 call 记录 uncached input、cache creation input、cache read input、output、total input 和 total tokens；
initial analysis 与最多一次 schema repair 分开记录。Timeout/failure 无 usage 时标记 unavailable，不按 0 计，也不换算
USD。Detection 与 post-hoc adjudication token 分开报告。

## 5. Ground-Truth Audit

Ground truth 只能在 `blind-freeze.json` 验证 canonical artifact digest 后读取：

```bash
python -m src.handler_baseline --all --ground-truth-only --timeout 900
```

Audit 从 `design/*/groundtruth/new-vuls` 发现 JSON-authoritative report，并纳入 LettaBot Markdown-only fallback；
Mercury JSON-only 和 OpenClaw stale report-name 通过 normalized report identity 处理。

候选先限定到同 project 与 exact handler root，再由独立 non-agentic adjudication 检查：

1. controlled value；
2. security requirement；
3. gate defect；
4. sink capability/argument/effect；
5. handler-rooted path；
6. revision/source compatibility。

共享 handler、sink 或 capability family 不构成 match。模型 match 只生成 manual-review template；只有
`ground-truth-manual-reviews.jsonl` 中带 source-backed reason 的 `confirm` 才进入 strict numerator。

## 6. GT-Handler-Conditioned Experiment

只评估 curated GT 所属 handler 时运行：

```bash
python -m src.handler_baseline --all --ground-truth-handlers --workers 4 --timeout 3600
```

Controller 读取 46 个 report 的 D5 handler binding，当前记录为 48 个 report-handler binding：22 个 exact、25 个
source-confirmed drift、1 个 Markdown fallback，去重后是 11 个 project 的 26 个 `HB-*` trial。Ambiguous/unmapped
binding 在调用 Claude 前 fail closed。

`ground-truth-handler-scope.json` 冻结 GT hash、original handler definition、current source digest、mapping decision/
evidence 和 exact `GT/report-handler → HB-*` 关系，但该文件不进入 Bubblewrap。默认输出：

```text
output/cross-project/claude-handler-baseline-ground-truth-handlers/
```

这是 ground-truth-conditioned、label-blind 的 handler recall 实验，不能用于声明 316-handler universe 的 precision
或 discovery rate。Post-hoc positive match 必须逐项确认 revision、handler root、controlled input、reachable path、
sink role/effect、requirement、gate defect、failure mode 和 trigger mechanism；一个 finding 最多匹配一个 report。

## 7. Precision-First Policy

保留 legacy `all-findings` artifact 的同时，可运行：

```bash
python -m src.handler_baseline --all --ground-truth-handlers \
  --report-policy most-credible-vulnerabilities \
  --workers 4 --timeout 3600
```

每个 handler 只允许 0–2 个 `high` confidence vulnerability，rank 从 1 连续编号，不能用 medium/low 补足第二项。
每项必须以源码同时证明：

- model-controlled input 与 handler-rooted reachability；
- default/documented configuration 下的 realistic precondition；
- protected asset/trust boundary；
- 超出 intended/equivalent capability 的 unauthorized delta；
- 全部 relevant gate 的 precise defect；
- concrete trigger 到 terminal sink security effect。

同 controlled input、requirement、gate defect、sink effect 和 path 仅 payload spelling 不同的记录按 invariant identity
去重。Intended capability、相同授权条件下显式开放的 equivalent capability、generic hardening、unproven policy
preference 和 speculative reachability 不能报告为 vulnerability；证据不足输出 `unknown`。

独立输出为：

```text
output/cross-project/claude-handler-baseline-credible-vulnerabilities-ground-truth-handlers/
  └── vulnerabilities.jsonl
```

当前 46-report/26-handler binding graph 在 per-handler capacity=2 且一个 finding 最多匹配一个 report 时，maximum
bipartite assignment 是 34，因此 strict recall 结构上限为 34/46（73.9%），必须与 observed recall 一并报告。

## 8. Precision-First Adjudication

Blind freeze 后以同一 policy 运行：

```bash
python -m src.handler_baseline --all --ground-truth-handlers \
  --report-policy most-credible-vulnerabilities \
  --ground-truth-only --timeout 900
```

除九 facet match template 外，还生成 `vulnerability-manual-review-template.jsonl`。完成的
`vulnerability-manual-reviews.jsonl` 必须把每项标为 `tp|fp|duplicate|unknown`，给出 source anchors，并可记录复现
旧 FP 的 canonical ID。Report 分开给出 conditioned validity、pending review、旧 FP recurrence、strict match、token
cost，以及保留的 legacy 49 raw findings / 45 TP / 6 FP ledger 对比。

Validity 与 recall 均只描述 GT-handler-conditioned sample，不能外推为 full-inventory blind precision。

## 9. 声明边界

- Full blind experiment 的 denominator 是 handler rows，不是 unique tool name。
- Focused run、failed trial 或未完成 manual review 不能进入 full-corpus结果。
- GT-conditioned recall 不等于工具发现率；precision-first validity 不等于全量 precision。
- Agent 输出是待校验 finding；确定性 identity、freeze 和 manual source review 才决定统计归属。
- Baseline 结果不能用于修改已冻结 detector 或作为 Group Oracle 的规范 evidence。

## 10. 相关文档

- 顶层证据边界：[`design/整体设计.md`](../整体设计.md)
- Canonical candidate 准入：[`filter-candidates.md`](filter-candidates.md)
- Runtime replay：[`runtime-validation.md`](runtime-validation.md)

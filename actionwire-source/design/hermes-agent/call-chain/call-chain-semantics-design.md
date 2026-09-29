# Hermes Ordered Call-Chain Gate Semantics

> 管辖代码（见仓库根 `docs-map.yaml`）：`src/call_chain_semantics/**`。
>
> 本阶段不再调用 LLM 组合 gate，也不构造跨 gate control-flow graph。它确定性地收集 exact chain 上全部
> eligible detector gate semantic，并以数组顺序表示执行顺序。
>
> Artifact ownership is strict: `src.gate_semantics` owns `output/hermes/gate-semantics/`; this stage only reads
> its per-gate `semantic.json` files and owns `output/hermes/call-chain-semantics/`.

## 1. 定义与边界

一条 call chain 的 detected checking semantics 定义为：

```text
CallChainDetectedSemantics
  = ordered exact-chain GateSemanticIR records
  + chain-local callsite and static-verdict metadata
  + cross-gate value identity
  + unresolved/status aggregation
```

gate 之间只有单向顺序：

```text
gate[0] → gate[1] → ... → gate[n-1] → selected sink boundary
```

每个 gate 内部仍可有 allow/block/error/branch 等语义；这些逻辑属于原样内嵌的 `GateSemanticIRV1/V2/V3`，不在
call-chain 层复制成第二张图。`branch-confirmed` 只表示该 gate 位于一个可选分支，保存在 gate wrapper 的
`static_verdict`，不会把它升级为全局必经 gate。

本结果的完整性只相对于当前 QL detector、exact structural chain 和 verdict policy：

- 包含 `confirmed` / `branch-confirmed`；
- 排除 `needs-review`；
- 不从 owning function、GT 描述或背景知识补入 detector 未返回的条件；
- 不含 sink capability、漏洞、修复或 Batch Runner runtime conclusion。

## 2. 首个测试链

ground-truth JSON 只提供 handler 与 sink endpoint。二者唯一选择：

```text
C-54eabf84fd
_handle_terminal → terminal_tool → _check_all_guards →
check_all_command_guards → prompt_dangerous_approval
```

当前 `chain-gates.csv` 对该 exact chain 有 6 行、6 个 callsite；排除一个 `needs-review` 后，
执行顺序为：

| order | catalog | gate UID | gate ID | callsite | verdict |
|---:|---:|---|---|---|---|
| 1 | #86 | `GU1fa2875abdb086501469` | `G475abe7e64c3215f` | `isinstance` at `tools/terminal_tool.py:1670` | `confirmed` |
| 2 | #35 | `GU28d514fd6039494a3b6b` | `G1ef41a32dc9cd89c` | inline foreground-timeout condition at `tools/terminal_tool.py:1714` | `confirmed` |
| 3 | #224 | `GU493ad03cb5f7e4a187d1` | `Gc3e3e517e07d8993` | `_foreground_background_guidance` at `tools/terminal_tool.py:1726` | `confirmed` |
| 4 | #178 | `GUeda4a1fd7829e594f0bd` | `Ga0ad79ab3d2e66d7` | `detect_hardline_command` at `tools/approval.py:937` | `confirmed` |
| 5 | #228 | `GU19218c5493665821bde0` | `Gc54219160ab446b7` | `_smart_approve` at `tools/approval.py:1020` | `branch-confirmed` |

#210 `_check_all_guards` 不是该 selected sink 的 eligible detector row，不能因结构链经过该函数就强制注入。
#178/#228 也不能被另一个 record 吸收；当前设计不存在 cross-gate absorption。

`tools/approval.py:920` 是函数定义行，不是 gate location。line 954 的 CLI/gateway/ask 条件来自环境变量而非
LLM-controlled `command`，不满足 source→gate 同源污点条件；它不进入本 detected-gate sequence。

## 3. `CallChainSliceV2`

assembler 的中间 slice 包含：

- revision、chain ID、完整 structural call chain 与 ordered calls；
- handler、selected sink invocation boundary；
- ordered `selected_gates`，含 current catalog number、persistent gate UID、semantic gate ID/name、qualified
  function、callsite 和 verdict；
- 与 selection 同序的完整 `gate_semantics`；
- chain-wide value binding；
- per-gate unresolved union 与 aggregate status。

slice 不再含：

- `absorbed_gates`；
- `composition_requirements`；
- semantic atom refs、terminal 或 branch-bypass edge；
- chain-stage LLM prompt/input。

## 4. `CallChainSemanticIRV2`

最终 `semantic.json` 的字段为：

```json
{
  "schema_version": "call-chain-semantic-ir/v2",
  "chain_id": "C-54eabf84fd",
  "handler": {},
  "sink": {},
  "values": [],
  "summary": "Collects 5 detected gate semantics in call-chain order before prompt_dangerous_approval.",
  "gates": [
    {
      "gate_number": 86,
      "gate_uid": "GU1fa2875abdb086501469",
      "gate_name": "isinstance",
      "callsite": "tools/terminal_tool.py:1670",
      "static_verdict": "confirmed",
      "semantic": {
        "gate_id": "G475abe7e64c3215f"
      }
    }
  ],
  "unresolved": ["external-decision:auxiliary-llm-approval-response"],
  "status": "partial"
}
```

`gates[]` 的数组顺序是唯一 authoritative cross-gate relation。`gate_number` 是当前 catalog 的显示编号，
`gate_uid` 是跨 detector/catalog 变化的 repository identity。wrapper 只增加 chain-local metadata；
`semantic` 是对应 per-gate IR 的逐字段深拷贝，不能总结、改写或删减。保留 `static_verdict` 非常重要：没有它，
下游会把 #228 `branch-confirmed` 错当作全局必经检查。

下列 V1 字段已删除：

- `composition`；
- `absorbed_gates`；
- `reach_sink_summary`；
- `terminals`；
- `boundary_excluded_refs`；
- `reach_sink_facts`。

`summary` 由 assembler 确定性生成，不使用 LLM。`unresolved` 是所有 gate 显式 dependency 与普通 V1
`unknown` atom 的并集；任一 gate 为 `partial` 时 chain 也为 `partial`。当前结果只因 #228 V3 的
`external-decision:auxiliary-llm-approval-response` 为 `partial`；#178/#224 的 source policy inventory 已完整恢复。
这里的 `complete` 只表示 selected gate semantic 没有 unresolved dependency，不表示 detector 找到了源码中的
每个条件或不存在漏洞。

## 5. Sink boundary

通用 Python benchmark 使用 V3：sink boundary 不再只是 slice 截止位置，而是一个独立、必需的
`sink_constraint`。`gates[]` 只允许 dominance/filter/transform gate，绝不插入 sink invocation；每条
结构链恰好附加一个 constraint，即使 `gates[]` 为空也生成完整记录。V2 Hermes wrapper 继续兼容旧 artifact，
V3 则增加 `{project.id, project.revision}` envelope、terminal constraint 的 controlled argument/call shape/
capability-card digest，并允许 zero-gate missing-check chains。

Pipeline 集成使用 `call-chain-semantics-manifest/v3`：为完整 structural chain CSV 中的每条 taint-valid chain
组装 semantic record，不经过 handler-impact 预筛选。manifest 记录 structural chain、semantic record、
zero-gate chain 与 assembly failure 数，确保每条输入 chain 都有成功记录或显式失败原因。

call-chain 只收集 selected sink invocation 之前的 gate。例：

```python
approval = check_command(command)
if not approval["approved"]:
    return

choice = prompt_dangerous_approval(command)  # selected sink boundary

if choice == "approve":
    approve_session(command)                 # post-sink behavior
return build_approval_result(choice)         # post-sink behavior
```

`approve_session` 和 `build_approval_result` 位于 sink invocation 之后，不能作为 pre-sink gate 收进当前 chain。
V1 用 `boundary_excluded_refs` 事后标记；V2 不再保留该字段。正确做法是：

1. static chain/slicer 在 sink invocation 截止；
2. 只选择 sink 前的 callsite gate；
3. 若一个候选 semantic 跨越 boundary，先拆成 pre-sink/post-sink record，不能把混合 record 交给 assembler。

当前五个 selected gate 都在 sink 前，不需要 exclusion metadata。

## 6. 确定性实现

模块职责：

- `main.py`：CLI、参数验证和完整 reproduction command；
- `assembler.py`：endpoint resolution、exact-chain gate selection、dedup/order、value/unresolved/status；
- `contracts.py`：构造 V2 wrapper、verbatim equality、order/metadata/status/size validation；
- `pipeline.py`：从 canonical gate store 读取 per-gate result、确定性 assembly、artifact/audit/manifest；
- `render.py`：按数组顺序生成 `chain-index.md`；
- `schemas/`：`CallChainSliceV2` 与 `CallChainSemanticIRV2`。
- `v3.py`：从每条完整结构链确定性组装 `CallChainSemanticIRV3`，不做 impact filtering，并校验 gate
  顺序、唯一 sink constraint、空 gate 数组、排除 provenance 与 unresolved/status 传播；不调用 chain-stage LLM。

流程为：

```text
GT handler/sink
  → unique structural chain
  → exact-chain confirmed/branch-confirmed rows
  → callsite/gate-UID deduplication
  → execution ordering
  → load `repository/<gate_uid>/semantic.json`
  → deterministic gates[] wrappers
  → union unresolved/status
  → semantic + audit + manifest + Markdown index
```

没有 `prompts.py`、chain-stage model call、JSON repair 或 raw chain response。call-chain CLI 不接受 model、timeout
或 gate detector input；如果某个 per-gate semantic 缺失，它直接失败并列出应先生成的 canonical artifact，不能在
call-chain output 下隐式创建 `gate-inputs/`。

assembler 不读取 run-local `gate-semantics.jsonl` 来寻找 selected gate。它用 current catalog 将 ordinal/callsite
映射为 `gate_uid`，然后直接读取：

```text
output/hermes/gate-semantics/
  gate-index.csv
  repository/
    GU1fa2875abdb086501469/semantic.json
    GUeda4a1fd7829e594f0bd/semantic.json
    GU493ad03cb5f7e4a187d1/semantic.json
    GU19218c5493665821bde0/semantic.json
```

这样单 gate 调试运行只需更新自己的 `repository/<gate_uid>/semantic.json`，call-chain 阶段始终消费各 gate 的独立最终
结果，不依赖某一次运行恰好包含哪些 records 的 aggregate JSONL。

## 7. Validation and audit

validator 要求：

- exact-chain selected gate UID 唯一，semantic gate ID 与顺序完全一致；
- wrapper 的 catalog number/name/callsite/verdict 与 selection 完全相等；
- `semantic` 与输入 per-gate IR 逐字段相等；
- 只允许 `confirmed` / `branch-confirmed`；
- handler、sink、values、summary、unresolved、status 都是确定性值；
- self-contained IR 不超过 64,000 estimated tokens；当前 retained corpus 的最大记录约为 33,104 tokens。

assembler 接受 V1/V2/V3 并逐字段原样内嵌。V3 的 `inputs[0].id` 作为 checked command binding；V3 内部
activation/check/outcome 只描述该 gate 本身，不能提升成 cross-gate composition graph。对本测试链还应断言
#178 含 12 条 hardline rules、#224 含 11 条 foreground rules、#228 保留 unresolved external decision，且最终
chain status 为 `partial`。

audit 只保存 assembly provenance：revision、assembly version、input/semantic digest、selected gate UIDs/IDs、被排除
的 GT 字段名、estimated tokens 和成功/失败状态。它不再保存 chain model、prompt version、raw/repaired response。
manifest 将 `composition_failures` 改为 `assembly_failures`。

## 8. 运行与产物

从仓库根先生成所需的 per-gate semantics（也可以运行不带 selector 的完整 gate catalog）：

```bash
python -m src.gate_semantics.main \
  --gate-number 86 --gate-number 35 --gate-number 224 \
  --gate-number 178 --gate-number 228 \
  --model deepseek-v4-flash
```

`main` 在每次 LLM extraction 后自动执行 source-profile checker。若这些 canonical gate 已由旧版 pipeline
生成，可不重复调用模型，直接升级并验证：

```bash
python -m src.gate_semantics.checker \
  --gate-number 86 --gate-number 35 --gate-number 224 \
  --gate-number 178 --gate-number 228 \
  --write
```

随后纯确定性生成 call-chain semantics：

```bash
python -m src.call_chain_semantics.main
```

两个默认 output root 为：

- `output/hermes/gate-semantics/`：catalog、aggregate JSONL 以及每个 gate 的
  `repository/<gate_uid>/{slice,semantic,audit,chat}.json`；
- `output/hermes/call-chain-semantics/`：`chain-slices.jsonl`、`call-chain-semantics.jsonl`、
  `call-chain-semantics-audit.jsonl`、`manifest.json`、`chain-index.md` 和
  `selected/C-54eabf84fd/{slice,semantic,audit}.json`。

call-chain `semantic.json` 是后续 checking-coverage inference 所需的产品。`slice.json` 保存 assembler 输入快照，
`audit.json` 保存 digest、revision 和验证状态；二者对正常下游不是必需输入，但保留用于复现、排错和证明
`semantic.json` 来自哪些 exact gate artifacts。call-chain output 不再复制任何 gate artifact。

`chain-index.md` 开头必须由 generator 写入从仓库根执行的完整命令。测试覆盖 unique chain、exact detector
inventory、五 gate order、UID repository lookup、`needs-review` exclusion、verbatim semantic embedding、`branch-confirmed` preservation、
unresolved/status propagation、size limit、无旧 graph 字段以及全工件重建。

Hermes V2 compatibility tests 从 canonical
`design/hermes-agent/groundtruth/new-vuls/` 读取 endpoint fixture；旧拼写 `groudtruth/` 不再是有效路径。通用 V3
测试继续使用临时结构链和 sink-constraint fixture，因此不会依赖或改写 canonical semantic output。

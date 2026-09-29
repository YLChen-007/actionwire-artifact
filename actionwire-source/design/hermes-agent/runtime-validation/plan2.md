# Hermes Agent 由 LLM Agent 指挥的 candidate 运行时验证方案

## 1. 目标与核心原则

本方案描述一条 candidate-centric 运行时验证流水线：由一个 Controller LLM Agent 指挥整个验证过程。它根据 `src/coverage_comparison` 产出的 candidate、call chain、gate 与 sink 信息选择插桩点，构造 prompt 和 mock provider tool call，启动隔离的 Hermes Agent 目标进程，读取结构化插桩证据，并根据确定性 evaluator 的反馈多轮修订，最后结束该 candidate 的验证。

核心原则是：

```text
LLM agent 指挥实验；
确定性代码拥有权限并给出 verdict。
```

也就是：

```text
LLM controls the experiment.
Code controls authority and verdict.
```

LLM 可以选择下一步动作、提出插桩计划、修改 prompt/tool arguments/fixture、观察反馈并继续迭代；但插桩实现、目标进程启动、sandbox、trace 收集、最终成功/失败判定都必须由受限 Python harness 完成。LLM 不能输出任意 Python/TypeScript 代码，不能直接执行 shell，不能修改 Hermes 源码，也不能自行宣布 candidate 验证成功。

## 2. 与 AgentFuzz 的关系

AgentFuzz 的有效结构是：

```text
LLM 生成 seed prompt
  -> 目标 agent 真实运行
  -> tracer 收集 call/branch/oracle 日志
  -> LLM 或约束求解器变异输入
  -> 继续运行
  -> 确定性代码匹配 runtime oracle
```

AgentFuzz 中 LLM 负责 seed prompt、semantic mutation、mutator scheduling 和相似度打分；约束求解器负责 variable mutation；目标执行和 trace 收集由确定性代码完成；最终 success 主要由 `sink@file:line` 的 runtime 日志匹配决定。

本方案沿用该反馈循环，但扩大 LLM 的指挥范围：

```text
AgentFuzz:
  LLM 主要 mutate prompt

本方案:
  LLM 选择 candidate 视角下的插桩计划
  + 构造 prompt / tool call / fixture
  + 读取结构化 trace feedback
  + 指挥多轮修订
```

同时替换 AgentFuzz 的弱证据模型：

| AgentFuzz 信号 | 本方案用途 | 本方案限制 |
|---|---|---|
| target chain 中某函数出现 | 仅搜索反馈 | 不能作为 verdict |
| branch locals 出现 | 仅 gate/路径反馈 | 必须绑定 input 与 return |
| `sink@file:line` 命中 | 仅搜索反馈 | 必须绑定 controlled value 与 ordered sequence |
| sink 后继续执行真实效果 | 不采用 | effect 前记录并 raise |
| prompt 输出看起来成功 | 不采用 | 必须由 events/transcripts 判定 |

因此本方案是 **LLM-guided search + deterministic runtime oracle**，不是 LLM 自由验证。

## 3. 总体流程

```text
Controller LLM
  |
  | list_candidates / get_candidate
  v
candidate bundle
  |- candidate requirement
  |- call chain slice
  |- handler / gates / sink
  |- tool schema
  |- bounded source excerpts
  |
  | list_anchor_catalog / search_source / read_source
  v
LLM 选择插桩点与 value relation
  |
  | propose_instrumentation / propose_plan
  v
deterministic compiler
  |
  | validate anchors / source hashes / tool schema / sink policy
  v
instrumentation.json
provider-script.json
fixture manifest
launch config
  |
  | run_pair / run_trial
  v
isolated Hermes Agent process
  |
  | -z prompt
  | loopback mock provider
  | registry dispatch
  | handler
  | gate
  | propagation
  | sink
  | pre-effect interceptor
  v
events.jsonl + provider transcript
  |
  | collect_trace / evaluate_trial
  v
deterministic verdict / structured feedback
  |
  | revise_plan or finalize_result
  v
下一轮或最终 candidate result
```

## 4. Controller LLM 与 target mock provider 的区别

本方案有两个逻辑上分离的模型，不能混淆。

### 4.1 Controller LLM

Controller LLM 使用 DeepSeek 或其他 OpenAI-compatible provider，在目标进程外运行。它负责：

- 阅读选中的 candidate；
- 根据 call chain、gate 和 sink 选择插桩点；
- 构造 exploit/control prompt；
- 设计 mock provider 返回的 tool call；
- 选择 fixture 与 launch profile；
- 读取结构化 trace 摘要；
- 根据失败前缀修订计划；
- 调用 finalize 结束实验。

Controller LLM 不拥有 shell、Docker socket、host write、credential read、arbitrary Python execution、arbitrary command execution 或任意 repo 路径访问权限。

### 4.2 Target model

Hermes Agent 进程内的模型使用 loopback mock OpenAI-compatible provider。它只返回 Controller 计划中经过 schema 校验的 tool call。目标路径仍然是：

```text
Hermes provider request
  -> mock response
  -> Hermes tool-call parsing
  -> ToolRegistry.dispatch
  -> handler
  -> gate
  -> sink
```

该实验不测量 live model 在自然语言下是否主动选择工具。每个结果必须记录：

```json
{
  "target_provider": "mock",
  "selection_mode": "mocked-provider-forced-tool-call",
  "live_prompt_triggerability": "not-tested",
  "effect_execution": "intercepted-before-effect"
}
```

未来若测试自然语言 prompt 诱导 live model 选择工具，应使用真实 target provider，并作为独立 campaign 发布，不能与 forced-tool 结果混合。

## 5. 给 LLM Agent 提供受限工具接口

不能只靠一段 prompt 告诉 LLM“请完成验证”。流程和权限必须由工具接口与 Python 状态机强制约束。系统 prompt 只作为操作说明，不作为安全边界。

推荐工具面：

```text
list_candidates
get_candidate
search_source
read_source
list_anchor_catalog
list_tool_schema
list_fixture_catalog
propose_instrumentation
propose_plan
compile_plan
configure_mock_provider
run_pair
run_trial
collect_trace
evaluate_trial
revise_plan
stop_target
finalize_result
```

可以有两种实现载体：

1. OpenAI-compatible tool calling：Controller LLM 返回 JSON action，Python orchestrator 执行。
2. MCP server：泛化现有 `src/runtime_validation/lab_mcp_server.py`，提供相同受限工具面。

第一版建议先实现 Python JSON action loop，便于测试和集成；MCP 形态可在稳定后复用同一工具实现。

## 6. 工具接口设计

### 6.1 `list_candidates`

输入：

```json
{
  "project": "hermes-agent",
  "filters": {
    "failure_mode": "wrong-check"
  }
}
```

输出候选摘要：

```json
{
  "candidates": [
    {
      "candidate_id": "CAND-...",
      "chain_id": "C-...",
      "handler_tool": "browser_snapshot",
      "sink_api": "_run_browser_command",
      "failure_mode": "missing-check",
      "requirement": "..."
    }
  ]
}
```

### 6.2 `get_candidate`

输入：

```json
{
  "candidate_id": "CAND-..."
}
```

输出 candidate bundle，包括 candidate record、requirement/trigger goal、semantic handler、call-chain slice、gate records、sink constraint、controlled argument、tool schema、bounded source excerpts、fixture candidates 和 launch profiles。

LLM 不接收整个 repository，只接收与 candidate 绑定的有限上下文。

### 6.3 `list_anchor_catalog`

LLM 不应直接填写任意 `file + function + line`，而应从 deterministic compiler 生成的 anchor catalog 中选择 `anchor_id`。

示例输出：

```json
{
  "anchors": [
    {
      "anchor_id": "A-registry-dispatch",
      "kind": "registry-dispatch",
      "file": "tools/registry.py",
      "function": "ToolRegistry.dispatch",
      "mandatory": true
    },
    {
      "anchor_id": "A-handler-browser-snapshot",
      "kind": "handler-argument",
      "file": "tools/browser_tool.py",
      "function": "browser_snapshot",
      "argument_paths": ["full", "task_id", "user_task"],
      "mandatory": true
    },
    {
      "anchor_id": "G-device-block",
      "kind": "gate-input-return",
      "file": "tools/file_tools.py",
      "function": "_is_blocked_device",
      "argument_paths": ["filepath"],
      "mandatory": false
    },
    {
      "anchor_id": "S-browser-command",
      "kind": "internal-sink",
      "file": "tools/browser_tool.py",
      "function": "_run_browser_command",
      "line": 2282,
      "mandatory": true
    }
  ]
}
```

anchor catalog 来源包括 coverage candidate、semantic IR、call-chain slice、source AST、gate semantics 和已审核 runtime 边界 catalog。

### 6.4 `search_source` / `read_source`

受限规则：

- 只能访问 candidate source binding 内的文件；
- 每次返回有限行数和有限字符数；
- 禁止 credential；
- 禁止跳出 pinned source root；
- 所有请求与响应写入 controller transcript；
- 不提供 shell grep，而是安全的服务端搜索。

### 6.5 `propose_instrumentation`

LLM 输出 declarative plan：

```json
{
  "action": "propose_instrumentation",
  "candidate_id": "CAND-...",
  "selected_anchor_ids": [
    "A-prompt-received",
    "A-provider-tool-call",
    "A-registry-dispatch",
    "A-handler-browser-snapshot",
    "S-browser-command"
  ],
  "diagnostic_anchor_ids": [
    "P-browser-session-state"
  ],
  "value_bindings": [
    {
      "source": "tool_argument",
      "argument_path": ["task_id"],
      "relation": "equals",
      "value_id": "VAL-..."
    }
  ],
  "sink_policy": {
    "interceptor": "browser-fixture-boundary",
    "policy": "record-and-raise-before-effect"
  }
}
```

LLM 只能选择 `anchor_id` 和封闭 relation/value binding。anchor 背后的路径、函数、行号、hash 和插桩方式由系统维护。

### 6.6 `compile_plan`

Python compiler 验证：

1. mandatory anchors 是否齐全；
2. anchor 是否属于该 candidate；
3. source hash 是否匹配；
4. argument path 是否合法；
5. relation 是否适合值类型；
6. sink family 是否有 interceptor；
7. fixture 是否安全；
8. tool name 与 tool schema 是否匹配；
9. exploit/control 是否有有效 differential；
10. 是否可能执行未拦截 effect。

合法输出 `plan_id`、`plan_hash`、`instrumentation.json`、`provider-script.json`、fixture manifest 和 launch config。非法输出结构化错误，供 Controller LLM 修订。

### 6.7 `run_pair` / `run_trial`

输入：

```json
{
  "plan_id": "PLAN-...",
  "roles": ["exploit", "control"]
}
```

Runner 自动执行：

```text
1. 创建 disposable HERMES_HOME
2. 创建 disposable workspace/state
3. 准备 fixture
4. 启动 loopback mock provider
5. 注入 PYTHONPATH sitecustomize
6. 启动 Hermes one-shot 进程
7. 收集 events.jsonl
8. 收集 provider transcript
9. process-group cleanup
10. sandbox/cleanup canary
```

LLM 不直接构造 Hermes 命令。它最多选择白名单 launch profile，例如 `oneshot-file-toolset`、`oneshot-code-toolset`、`oneshot-browser-fixture` 或 `scripted-approval-required`。

### 6.8 `collect_trace`

返回给 LLM 的是 bounded structured summary，不是完整原始日志：

```json
{
  "trial_id": "T-...",
  "role": "exploit",
  "process_status": "completed",
  "provider_calls": 1,
  "progress": [
    {"stage": "prompt_received", "matched": true},
    {"stage": "provider_tool_call", "matched": true},
    {"stage": "registry_dispatch", "matched": true},
    {"stage": "handler_argument", "matched": true},
    {"stage": "gate_input", "matched": false},
    {"stage": "sink_argument", "matched": false},
    {"stage": "sink_intercepted", "matched": false}
  ],
  "failure_hint": "handler received task_id, but browser command sink was not reached",
  "event_count": 18
}
```

可允许 LLM 请求少量 event details，但必须限长、redact，并写入 transcript。

### 6.9 `evaluate_trial`

deterministic evaluator 输出：

```json
{
  "evaluation_id": "EV-...",
  "verdict": "inconclusive",
  "reason": "controlled value reached handler but not sink",
  "matched_sequence": [
    "prompt_received",
    "provider_tool_call",
    "registry_dispatch",
    "handler_argument"
  ],
  "required_sequence": [
    "prompt_received",
    "provider_tool_call",
    "registry_dispatch",
    "handler_argument",
    "sink_argument",
    "sink_intercepted"
  ],
  "healthy": true,
  "control_result": "healthy-negative"
}
```

LLM 可以读取该结果并决定下一轮，但不能改写 verdict。

### 6.10 `finalize_result`

`finalize_result` 不接受 LLM 手工填写任意 verdict。它必须绑定 `candidate_id`、`plan_hash`、`evaluation_id` 和 confirmation trial IDs；orchestrator 再从 deterministic evaluator 读取最终结果。这样可以防止 LLM 仅凭文本输出或局部 trace 声称成功。

## 7. 插桩点选择

插桩位置必须从 verdict 需要的证据倒推，而不是 trace 全仓库函数。

### 7.1 固定必选锚点

所有 Hermes trials 必须观察：

| 阶段 | 位置 | 方式 |
|---|---|---|
| prompt | `hermes_cli/oneshot.py::run_oneshot` 的 `prompt` | call trace |
| provider request | loopback provider server | transcript |
| provider tool call | loopback provider response | transcript |
| registry dispatch | `tools/registry.py::ToolRegistry.dispatch` | call trace |
| terminal effect | sink family primitive/fixture boundary | wrapper |

Controller LLM 不能删除这些 mandatory anchors。

### 7.2 candidate 语义锚点

来自 semantic IR 的 handler、controlled argument、candidate gates、semantic sink、call-chain propagation 和 capability fixture boundary。对 `wrong-check` candidate，`candidate.gate_ids` 对应的 gate input/return 也是 mandatory。

### 7.3 诊断可选锚点

当 trace 只到达 handler 或 gate 而未到 sink 时，LLM 可提议增加 normalization helper、command builder、browser bridge、message adapter 或 state reader/writer。这些点必须来自 anchor catalog，并标记为 diagnostic。

### 7.4 terminal effect 边界

最终必须落到能阻断危险效果的位置：

| sink family | interceptor |
|---|---|
| process | `subprocess.Popen/run`、`os.system` 等 wrapper |
| filesystem | `open`、`Path.open/read_text/write_text`、delete/rename wrapper |
| network | socket/HTTP client wrapper |
| browser | fake browser bridge / CDP or CLI boundary |
| messaging | local messaging fixture |
| code eval | `eval/exec` 或 sandbox runner boundary |
| persistent state | DB/file state fixture boundary |

internal function 出现不等于 terminal effect。例如 `_run_browser_command` 被调用后，还应继续到 browser fixture 或外部效果边界，除非该 internal invocation 本身就是经审核的 effect boundary。

### 7.5 LLM 权限边界

LLM 可以：

- 在 anchor catalog 中选择 diagnostic propagation；
- 确认 controlled argument 是 `args.path`、`task_id` 还是其他字段；
- 选择适合的 relation；
- 根据失败反馈增加下一个观察点；
- 修改 fixture 或 mock tool arguments。

LLM 不可以：

- 删除 mandatory anchors；
- 发明未在 catalog 中的函数；
- 提交任意表达式；
- 修改 source；
- 绕过 interceptor。

### 7.6 missing-check 与 wrong-check 的规则

`missing-check` 通常没有相关 gate，LLM 不应发明 gate。它应选择 prompt、provider、registry dispatch、handler controlled argument、propagation、sink 和 terminal interceptor。若为诊断添加附近 gate，必须标记 `diagnostic_only: true`，不能作为 candidate oracle 的必要 gate。

`wrong-check` 已给出 relevant gates，gate input/return 为 mandatory。验证重点是 exploit value 通过 gate 但仍到达 sink，而 control 被阻止或出现安全 differential。

## 8. 插桩实现方式

采用不改 benchmark 源码的进程内注入：

```text
Runner 写入 instrumentation.json
  -> 创建 overlay/sitecustomize.py
  -> 设置 PYTHONPATH=<overlay>:<hermes-root>
  -> 启动 Hermes -z prompt
```

Python 自动导入 `sitecustomize.py`，它加载 per-trial instrumentation 配置并安装 `sys.settrace`、`threading.settrace`、terminal primitive wrappers 和 event writer。

函数输入用 call event；函数返回用 return event；if/branch 用 line event；外部效果用 wrapper。read_file 家族可观察：

```text
run_oneshot(prompt)
ToolRegistry.dispatch(name,args)
_handle_read_file(args)
read_file_tool(path,...)
_is_blocked_device(filepath)
ShellFileOperations.read_file(path)
_exec(command)
BaseEnvironment.execute(command)
_run_bash(command)
subprocess.Popen(payload)
```

不能使用 basename+line 的弱匹配。必须绑定 absolute source root、repo-relative path、qualified function、optional line 和 source SHA-256。terminal wrapper 还要检查 call stack 中是否存在 expected sink anchor，避免把无关 `Popen` 或 `open` 误判为 candidate sink。

每个事件携带：

```text
campaign_id
candidate_id
plan_hash
trial_id
attempt
role
correlation_id
value_id
sequence
pid
thread_id
monotonic_ns
```

evaluator 只允许同一 trial/role/correlation/value identity 下的 ordered sequence 通过。匹配 sink 后必须记录 sink arguments、验证 relation、记录 `sink_intercepted`，并在 effect 前 raise。

## 9. LLM 控制状态机

Python orchestrator 必须强制以下状态：

```text
IDLE
  -> CANDIDATE_SELECTED
  -> CONTEXT_INSPECTED
  -> PLAN_PROPOSED
  -> PLAN_COMPILED
  -> TRIAL_RUNNING
  -> TRACE_COLLECTED
  -> EVALUATED
  -> PLAN_REVISED | CONFIRMING | FINALIZED
```

非法转移直接拒绝，例如：

```text
未 compile 就 run
未 run 就 evaluate
未 evaluate 就 finalize
confirmation 阶段继续 semantic revise
```

即使 candidate 文本中包含 prompt injection，LLM 也没有能力跳过状态机或越权调用工具。

## 10. 多轮迭代策略

一个 candidate 允许最多 `max_iterations` 轮探索：

1. LLM 提出或修订 plan；
2. compiler 校验；
3. runner 分别执行 exploit/control；
4. evaluator 输出 progress prefix 与失败原因；
5. LLM 根据反馈修订。

当出现一个健康 plan 后，锁定 `plan_hash`，执行 `confirmation_attempts` 次确认，不允许继续语义修订。基础设施重试单独计数，不消耗 semantic negative budget。

反馈示例：

```text
prompt_received: yes
provider_request: yes
provider_tool_call: yes
registry_dispatch: yes
handler_argument: yes
gate_result: yes
sink_argument: no
sink_intercepted: no
```

LLM 可根据原因调整：

| 观察 | 下一轮动作 |
|---|---|
| provider 未收到请求 | 修 launch/provider config |
| registry 未 dispatch | 修 tool schema/toolset |
| handler args 不匹配 | 修 argument path/tool args |
| gate return 不符 | 修 exploit/control differential |
| handler 后停止 | 增加下一个 propagation anchor |
| sink args 不匹配 | 修 relation/transform |
| control 也触发 unsafe effect | 更换 control 或 fixture |

结束条件：

- 多次确认通过：`runtime-confirmed`；
- 健康 plan 多次未触发 candidate differential：`not-reproduced`；
- provider/instrumentation/source/control 失败：`inconclusive`；
- 无模型面、无安全 fixture、无 launch mode：`unsupported`；
- immutable runtime 或依赖缺失：`blocked`；
- LLM 预算耗尽：`inconclusive` 或单独 `controller-budget-exhausted`。

## 11. verdict 仍由确定性代码给出

LLM 不给最终 verdict，因为它可能把 handler reached 当成成功、把 stdout 文本当成功、忽略 control failure、误读 gate return、编造不存在事件，或把 sink-only hit 当成 candidate confirmed。

最终判定必须读取：

```text
events.jsonl
provider transcript
control result
process lifecycle
source/hash binding
sandbox and cleanup canaries
```

`runtime-confirmed` 需要：

1. prompt/provider transcript hash 匹配；
2. mock response 解码为 reviewed tool call；
3. Hermes 真实 registry dispatch；
4. handler 收到 intended controlled value；
5. gate input/result 符合 missing/wrong-check 语义；
6. value 或 approved transform 到达 sink args；
7. effect 执行前被拦截；
8. control 为 healthy negative 或更早安全阻断；
9. events 在同一 correlation/value identity 下有序；
10. source、instrumentation、sandbox、cleanup 全部通过。

## 12. Controller system prompt 约束

可以使用如下提示词作为操作说明，但安全边界仍由工具接口和状态机保证：

```text
You are the ClawGap runtime-validation controller.

Your job:
1. inspect the selected candidate;
2. choose source-bound anchors from the catalog;
3. build a safe exploit/control plan;
4. run isolated trials through the provided tools;
5. read deterministic feedback;
6. revise the plan when needed;
7. finalize only the verifier-produced result.

Hard rules:
- Select anchors only by anchor_id.
- Never claim success from text output.
- Never treat a handler-only or sink-only hit as confirmation.
- Missing-check candidates have no mandatory gate.
- Wrong-check candidates must observe cited gate input and return.
- Every dangerous effect must be intercepted.
- Mock-provider mode does not test live model selection.
- Use finalize_result only with the evaluation_id returned by evaluate_trial.
```

## 13. 安全与可复现性要求

工具面必须做到：

```text
无 shell
无 Docker socket
无 host write
无 credential read
无 arbitrary Python
无 arbitrary command
无任意 source path
```

LLM 想做的每件事都映射到受限接口：

| 意图 | 实际接口 |
|---|---|
| 启动 Hermes | `run_trial(plan_id)` |
| 选择插桩点 | `anchor_id` |
| 修改 provider 返回 | schema-bound provider script |
| 读源码 | bounded `read_source` |
| 搜索源码 | source-root-confined `search_source` |
| 结束实验 | `finalize_result(evaluation_id)` |

每个 trial 使用 new process group、disposable `HERMES_HOME`、disposable workspace/state、per-trial `events.jsonl`、per-trial provider transcript、read-only target source/interpreter、loopback-only provider network、无 inherited credentials，并执行 active cleanup canary。

建议 artifact 目录：

```text
output/cross-project/runtime-agent-validation-v1/
  manifest.json
  cohort.jsonl
  candidate-results.jsonl
  campaign-summary.md
  <candidate-id>/
    intake.json
    controller/turn-0001.json
    plans/<plan-hash>/
      plan.json
      instrumentation.json
      provider-script.json
      fixture-manifest.json
      compile-result.json
    trials/<trial-id>/
      exploit/
        command.json
        events.jsonl
        provider-transcript.jsonl
        stdout.log
        stderr.log
        result.json
      control/
        ...
    result.json
```

Controller transcript 必须记录每轮 action、输入输出、selected anchor IDs、plan hash、trace summary、evaluator result 和 finalize decision。凭证值不得持久化，发布前必须进行 credential scan。

## 14. 推荐实现模块

第一版可以不立即实现 MCP，先用 Python controller：

```text
src/runtime_validation/agent_campaign.py
src/runtime_validation/agent_controller.py
src/runtime_validation/agent_lab.py
src/runtime_validation/agent_candidate_intake.py
src/runtime_validation/agent_plan_compiler.py
src/runtime_validation/agent_instrumentation.py
src/runtime_validation/agent_provider.py
src/runtime_validation/agent_runner.py
src/runtime_validation/agent_evaluator.py
```

使用形态：

```python
controller = AgentController(
    model="deepseek-v4-flash",
    base_url="https://api.deepseek.com/v1",
    credential_env="DEEPSEEK_API_KEY",
)

lab = RuntimeAgentLab(
    project="hermes-agent",
    coverage_root=Path("output/cross-project/coverage-comparison"),
)

for candidate in cohort:
    session = lab.new_session(candidate)
    result = controller.run(session, max_iterations=6)
```

`RuntimeAgentLab` 提供上述受限工具；`AgentController` 只调用这些工具，不拥有额外权限。

## 15. 最小测试

实现时至少覆盖：

1. candidate intake 和 source hash drift；
2. anchor catalog 只包含 candidate-bound anchors；
3. mandatory anchors 不可删除；
4. LLM 提交未知 anchor 时 compile fail closed；
5. wrong-check 缺 gate 时 compile fail closed；
6. missing-check 中 diagnostic gate 不进入 verdict；
7. provider transcript drift；
8. tool schema mismatch；
9. handler reached 但 sink 未到；
10. gate return 不符合 expected differential；
11. exploit/control confirmation；
12. LLM 无法在未 evaluate 时 finalize；
13. LLM 无法提交任意命令或代码；
14. per-trial log 隔离；
15. process group cleanup；
16. credential redaction；
17. controller budget exhaustion 不产生负面 verdict。

## 16. 结论

该方案可以实现为：

```text
LLM agent 指挥 candidate 验证
  -> 选择 source-bound 插桩点
  -> 配置 mock provider 和 fixture
  -> 调用 runner 启动隔离 Hermes Agent
  -> 读取结构化 trace feedback
  -> 多轮修订
  -> deterministic evaluator 给出最终结果
```

但它必须保持两条硬边界：

```text
1. LLM 只能通过受限工具指挥实验；
2. 最终 verdict 只能来自确定性 runtime evidence。
```

这样才能同时获得 LLM agent 的探索能力和 ClawGap 运行时验证的可复现、安全、抗误报证据契约。

## 17. v1 实现边界与 smoke 入口

当前实现先落地一个可运行的 Hermes pilot，而不是一次性泛化全部 candidate family：

```text
src/runtime_validation/agent_candidate_intake.py
src/runtime_validation/agent_controller.py
src/runtime_validation/agent_lab.py
src/runtime_validation/agent_provider.py
src/runtime_validation/agent_campaign.py
src/runtime_validation/agent_target_launcher.py
src/runtime_validation/inject/agent_sitecustomize.py
```

已实现：

- 只读 join `coverage-comparison` candidate、comparison row、Hermes semantic IR 和 source SHA-256；
- candidate 与 comparison 必须使用 coverage v7 contract；candidate 的 `CR-*`
  `requirement_id` 和 canonical provenance 必须一致，低版本 coverage row
  fail closed，不能通过历史 campaign fallback 重建；
- candidate-bound anchor catalog 与 mandatory anchor 校验；
- restricted JSON action loop 和 inspect -> plan -> compile -> run -> evaluate -> finalize 状态机；
- bounded `search_source` / `read_source`；
- declarative plan compiler 与封闭 value relation；
- loopback OpenAI-compatible mock provider；
- Bubblewrap、new process group、disposable `HERMES_HOME`/workspace；
- config-driven `sys.settrace` 插桩与 `Popen` effect-before-interception；
- instrumentation startup error 与 disposable workspace cleanup canary；
- deterministic ordered exploit/control evaluator；
- finalize 必须绑定 evaluator-produced `evaluation_id`。

v1 pilot 只支持 `_handle_read_file -> file_ops.read_file` family，并使用已审核的
`/dev/./zero` exploit 与 `/dev/zero` control differential。其他 Hermes candidate 在 intake
或 compile 阶段 fail closed，不能宣称 negative；待新增对应 anchor/interceptor/fixture family
后再扩展。

coverage precision v14 发布后，pilot intake 只接受 source-confirmed canonical candidates。
主 smoke candidate `CAND-925c9d1319c3ccbd` 保持不变；missing-check fail-closed 回归改绑定当前
canonical 的 `CAND-3e313ae3b7496e18`，用于证明 read-file handler 中尚未实现的 candidate family
仍在 compile 阶段返回 unsupported，而不是从已降级为 `needs-source-validation` 的历史 ID 读取。

无外部 Controller LLM 凭证的确定性 smoke：

```bash
python -m src.runtime_validation run-agent-runtime-validation \
  --coverage-root output/cross-project/coverage-comparison \
  --candidate-id CAND-925c9d1319c3ccbd \
  --out-dir output/cross-project/runtime-agent-validation-v1/scripted \
  --controller scripted-pilot \
  --confirmation-attempts 1 \
  --timeout 60
```

外部 Controller LLM 模式使用：

```bash
python -m src.runtime_validation run-agent-runtime-validation \
  --coverage-root output/cross-project/coverage-comparison \
  --candidate-id CAND-925c9d1319c3ccbd \
  --out-dir output/cross-project/runtime-agent-validation-v1/live \
  --controller openai-compatible \
  --model deepseek-v4-flash \
  --base-url https://api.deepseek.com/v1 \
  --api-key-env DEEPSEEK_API_KEY \
  --confirmation-attempts 1 \
  --timeout 60
```

两种模式的 target provider 都是 mock。结果只能解释为
`forced-tool-candidate-path-propagation`，且 dangerous process effect 已在创建前拦截；
不能解释为 live prompt jailbreak 或 live model tool selection 成功。

# 三类 Gate 与终端 Sink Constraint 的检测方案（详细）

> 管辖代码（见 `docs-map.yaml`）：`src/ql/get_gates.ql`、`src/ql/gate/GateShapes.qll`、
> `src/ql/fte_filter.ql`、`src/ql/call/filter_gates.qll`、`src/ql/fte_transform.ql`、`src/ql/get_sinks.ql`、
> `src/ql/get_handler_to_sink.ql`、`src/ql/tests/` 与 `scripts/test_ql.py`。
>
> 对应公共方法 [`design/common/detection-method.md`](../../common/detection-method.md) §「Gate 类型」。工具调用链上的检查点（gate）按**作用机制**
> 分三类：**① 支配型 · ② filter 型 · ③ transform 型**。原④能力约束不再是 gate，而是每个
> concrete sink callsite 唯一对应的终端 `sink_constraint`。本文给出三类 gate 的**检测细节**
> （CodeQL 签名、人工签名/参数表、Source 锚点、静态/LLM 边界、切片接口）。
>
> 统一原则：「**gate 在不在**」尽量静态判定；判不准的语义处（③ 哪个函数算净化）
> **人工指定签名/参数表**兜住，不猜、不靠 LLM 检测；「**gate 覆盖够不够**」（覆盖域 < 能力域）统一交 LLM。
> ②③属**数据流型 gate**（不支配 sink 调用），合称 **FT 家族**。sink call 本身即使其结果影响后续
> control flow，也不能进入 `gates[]`；它只作为独立能力约束出现。

---

## 0. 三类总览与 sink constraint（检测手段 · 静态/LLM 分工）

| 类型 | 作用对象 | 静态定位签名 | 判不准处如何兜 | is-gate 谁判 | 覆盖够不够谁判 |
|---|---|---|---|---|---|
| **① 支配型** | 控制流 + 污点值 | `ConditionBlock.controls(sink 调用)` 抽校验调用 **∧ 同源污点穿过 gate**（`t→*g ∧ t→*sinkArg`） | —（结构确定） | 静态 | LLM |
| **② filter 型** | 集合成员 | 条件支配「污点值写入集合」且集合→sinkArg | —（结构确定，高精度） | 静态 | LLM |
| **③ transform 型** | 值内容 | 污点**穿过**函数 f，且 f ∈ **人工净化签名表** | **人工净化签名表** | 静态（查表） | LLM |
| **终端 sink constraint（非 gate）** | sink API/callsite/受控实参 | 每个 taint-valid concrete sink callsite | sink capability card | 静态映射；缺卡失败 | 不进入 gate LLM |

**三类共享一条必要条件——gate 必被「来自 Source 的同源污点」穿过**（§1.1）：不碰攻击者可控数据的支配条件
不是本模型的 gate。① `get_gates.ql` 现已并入 (A)(B) 控制支配 + **(C) 同源污点穿过**（并含 (A′) 旁路开关
透明化，见 §2），1674 条控制流候选按 §1.1 分级为 confirmed / needs-review；② `fte_filter.ql` 已内建同源污点。
②③ 的数据流识别见 §3–4；终端 constraint 见 §5。

---

## 1. 公共基座：Source→sinkArg 污点路径（无 sanitizer）

**①②③ 三类 gate**和终端 sink constraint 建立在同一条污点路径上：`t(工具参数 Source) →* sinkArg(sinkSensitiveNode 选中的安全敏感值)`。

### 1.0 当前分析基线

- CodeQL DB：`codeql-db/hermes-agent-db`。
- DB source root：`benchmark/python/hermes-agent`。
- sink 枚举：`src/ql/get_sinks.ql`；当前 DB 产出 701 个去重 callsite，规范化结果见
  `design/hermes-agent/sink/debug/script/sink-points.csv`。
- 重建 DB 后先运行 `python design/hermes-agent/sink/debug/script/process_sink_data.py`，再用该批 sink
  中间数据驱动 handler→sink 与 gate 分析，避免混用旧 xclaw DB 的行号和覆盖结论。

- **Source 锚点** = `d5_param_extraction`（工具 handler 的参数入口，见 skill
  `cyl-agent-cve-analysis-enhance-d5-gate-extract-params`）。
- **Sink 敏感值** = `sinkSensitiveNode(sink, node, role)` 选中的节点。`is_sink_af` 只标定
  callsite；共享谓词再按 `url` / `rpc-payload` / `argument` / `receiver` 选值。普通 HTTP
  `get/post` 只取第 0 个位置实参或具名 `url`，`request(method, url, ...)` 只取第 1 个
  位置实参或具名 `url`；所有 sink family 都必须显式登记 capability-bearing 节点，不存在
  “任意实参/receiver”fallback。process 取 command/argv 与精确 process control，code/SQL/template/
  path/approval 取语义参数，loader/extraction/navigation 取 URL/repository，delivery 取 content/payload。
  `rpc-payload` 必须是精确审计例外；当前登记 ManagedModal、poco 两个 client 的三个 internal callsite、
  Hermes Camofox `_post(..., json=body)`，以及 nanobot 三个 fixed/configured-provider search
  `client.get(..., params=query)` callsite。GT-backed `prompt_dangerous_approval` 只取 `command` arg 0。
- **实现**：复用 `existworks/AgentFuzz/ql/get_dataflow_str_constraint.ql` 的
  `TaintTracking::localTaint(ccn, sink_ccn.getArg(i))`，跨函数处升级为 `TaintTracking::Global<Cfg>`。

### 1.0.1 handler→sink 链也必须 source→sink 有效

`get_handler_to_sink.ql` 不再只输出 `r_calls(handler, sink, d)` 的纯调用图可达链；它同时要求**当前
handler 的非 `self`/`cls` 形参**能污点到达该 sink 的实参或方法接收者。这样 Step-3 的
`handler-sink-chains.csv` 表示「source→sink taint-valid call chain」，而不是「handler 运行过程中碰巧可调用到
某 sink」。

- **Source**：当前 `handler` 的参数入口（排除 `self`/`cls`，避免把对象状态误作用户输入）。
- **SinkArg/receiver**：普通 sink 调用取实参；`path.read_text()` / `target.exists()` 这类 receiver sink 取
  属性调用接收者。
- **语义 sink label**：已建模 callable 通过 `asyncio.to_thread` 执行时，`get_sinks.ql` 与
  `get_handler_to_sink.ql` 输出 callable 方法名而非 `to_thread`；例如 Firecrawl 输出 `scrape`，保证 sink
  inventory、taint-valid chain 与 GT method-name 口径一致。
- **附加流步**：与 `get_gates.ql` 保持一致，复用路径/字符串规范化、parser/lookup 派生值、tuple/list 解包、
  以及 `cha_calls`/`delivery_bridge` 的 arg→param 桥。
- **落盘执行桥**：对 `with open(P, "w") as f: f.write(t)` 后在**同一 handler** 内执行
  `subprocess.Popen(..., P)` 的结构，把 source→`write` 内容与「同一路径被执行」连接为有效
  handler→sink 语义。匹配同时要求 write receiver 是该 `with open` 的 handle、open 为写模式、Popen
  路径变量定义与 open 路径共享同一非空文件名 literal；不把任意同函数 file-write 和 Popen 粗略相连。
  该桥覆盖 `execute_code(code)` 将 `code` 写入 `script.py` 后以 `_script_path` 启动本地 Python 的情况；
  普通 source→sinkArg 污点无法覆盖它，因为 `_script_path` 来自 `tmpdir` 而不是 `code`。
- **效果**：`skill_view -> load_env -> get_hermes_home -> active_path.read_text@hermes_constants.py:84`
  这类配置路径读取虽然 call graph 可达，但 `active_path` 不从 `name` 等 handler 输入派生，故不再作为有效
  handler→sink 链报告；后续 `chain-gates.csv` / coverage 报告只在 taint-valid 链集合上做 gate 标注。

> **关键工程决定：跑「无 sanitizer」的污点**。若把净化函数登记为 CodeQL `sanitizer`，污点会在那里
> **被切断**，就看不到完整路径了。FTE 要的相反——**保留整条路径**，再把路径上的节点**分类**为
> filter / transform / capability。故污点配置只做**可达性**，不注册任何 sanitizer；gate 识别是路径上的
> **节点分类器**。

### 1.1 gate 必被污点穿过（三类共同的必要条件）

漏洞模型是「检查点覆盖域 < sink 能力域」，两个域都是**同一个被污染值的状态集合**。因此一个条件要成为
本模型的 gate，前提是**它检查/改写的正是那股流向 sink 的攻击者可控数据**。形式化为**同源必要条件**，两种结构：

- **check 形态**（① 支配 / ② filter）：`t →* g`（污点到达 gate 被测操作数 g）**且** `t →* sinkArg`（同一 Source 到达 sink 实参）——同源。
- **transform 形态**（③ transform）：污点**穿过** gate 函数（`t →* gate_in ∧ gate_out →* sinkArg`）。

`t` 必须是当前模型面对的 concrete handler 参数，不能再用“任意 on-chain helper formal”近似。helper 参数只有在
handler-rooted global flow 或项目绑定 dispatch bridge 证明后才能到达 `g`。这一区分会排除两类历史误绑定：例如
browser helper 的固定 `command/result` 虽同时影响临时文件名和 fallback 判断，却不是 `browser_back(task_id)` 的模型
source；以及 delivery helper 在下游发送返回后检查 `result`，不能保护已经发生的 `open(media_path)` sink。
QwenPaw 是显式 pre-handler 特例：只允许 adapter 固定的 `tool_call.input` field 到 concrete tool-handler parameter
映射，不允许按 `tool_input`/`args` 名称做通用 helper-source 推断。

**不满足即不是 gate**：`if config.enabled:` / `if self.is_admin:` / `if len(results)>0:` 这类支配了 sink
但不碰污点值的条件，无论怎么判都约束不了攻击者对 sink 的影响，**不计入 gate**。这正是 ① 若只做控制支配
（不加同源污点）会吐 1674 条候选的根因——绝大多数是与污点无关的支配条件。

#### 1.1.1 v15 字段级 source→sink role 证明

SameOrigin 的 `t` 从 v15 起不是整个 `args`/`params` 容器，而是 concrete handler source 上的常量字段读取，
例如 `args.get("url")`、`args["path"]` 或 TypeScript `args.command`。字段读取值随后可以穿过赋值、实参到形参、
返回值和显式 transform，但必须最终到达 sink catalog 声明的**精确 role**。map key 不污染 map value，整个对象不
自动污染所有 property，同名变量、sibling argument、selector 与被选内容也不构成传播。operator config、provider
response 或内部派生值分别标记 `operator-config`、`provider-response`、`internal-derived`，不得冒充
`model-arbitrary`。

Python `src/ql/field_flow/FieldFlow.qll` 与 TypeScript/JavaScript
`src/ql-js/field_flow/FieldFlow.qll` 只提供字段读取和窄桥 primitive；生产 witness/exclusion 查询分别为两套 pack
中的 `get_field_flow*.ql`。跨 RPC/IPC 只有项目 adapter 或 fixture 明确登记的 arg→param bridge 才可传播，不能按
函数名、变量名或“看起来像 RPC”推断。测试同时覆盖显式桥 positive 与无桥 negative，以及 map-key、whole-object、
same-name、sibling、selector、config/provider 七类误传播控制。

OpenClaw-CN 的 message→Feishu 链由独立 `get_project_field_bridges.ql` 消费项目绑定桥：只允许 handler `args`
以同一对象身份进入 `runMessageAction.params` 后，在 `handleSendAction` 精确读取 `media` 字段，并最终绑定到
`OCCN-FEISHU-MEDIA-FETCH` 的 URL role。该规则不传播整个 `args`，也不把 `path`、`filePath`、selector 或同名
局部变量视为 `media`。

QL CSV 不能直接作为 coverage 输入。`field-flow-chain-binding/v1` 必须用 project、handler name/file/line 与
sink file/line/column/role 唯一绑定 revision、chain、handler 和 sink ID；零匹配或多匹配 fail closed。
`src.coverage_comparison.field_flow_conversion` 随后输出 `field-flow-witness/v1` 与
`field-flow-exclusion/v1`，包含 `value_authority`、transform、`proof_kind`、typed path nodes 及所有引用源码的
SHA-256。`explicit-bridge` proof 若 path 中没有 bridge node 也必须拒绝。

**一个例外（不套此必要条件）**：**策略开关 / 配置门**（`if not force:`、`approval_mode == "yolo"`、
`_global_allow_private_urls`）检查的是**配置/标志而非污点值**，控制的是「**要不要启用检查**」而非「检查污点值」，
属**旁路面（bypass surface）**、另走 bypass 分析，不要求污点穿过、也不归入 ①②③。

**实现口径（污点召回的现实约束）**：本库连**调用图**都需 `cha_calls`/`getServiceHandle`/`delivery_bridge` 桥才连通，
**数据流**同样会因未建模的容器/跨组件步而 under-taint。故必要条件**分级实施**、不一刀切丢弃：
(A)(B) 控制支配 → 出**候选**；(C) 同源污点穿过 → **确认**真 gate；污点不确定（未建模步）→ 标 `needs-review` 而非静默丢。
另有一类**分支局部同源 gate**：条件不全局支配 sink-ward 调用，但 gate 块能前向到达该调用、且守的是早退阻断出口；
这类只保护自身所在分支，标 `branch-confirmed`，语义弱于严格 `confirmed`。
污点用**无 sanitizer 过近似** + **复用上述桥**：CodeQL 污点走的是库内建 type-tracking 调用图（`resolveCall`），
解析不到运行期注入的服务句柄（`env.execute`/`file_ops.*`），库又不接受外部调用图；故把 `cha_calls`/`delivery_bridge`
桥当 **`isAdditionalFlowStep`** 注入（每条桥接调用补 arg→param 边，含 self 偏移/kwarg 对应），让 s 腿穿过服务句柄
到达真 `subprocess.Popen`（`get_gates.ql` `bridgeTaintStep`，实测把 72 条 needs-review 翻 confirmed）。对
`len(x)`/`isinstance(x)`/`type(x)` 这类**污点通常不传播的派生检查**，按「tested 表达式**派生自**污点值」处理
（局部数据依赖），避免因不传播而误杀真 gate。`checkedGateNode` 同时把**函数实参**与**方法接收者**作为被检查值：
`is_valid_namespace(namespace)` 查实参，`skill_md.exists()` / `path.is_dir()` 查接收者。`derivedValueStep` 还窄补
parser/normalizer/lookup 的「输入 → 返回值/解包目标」：如 `namespace, bare = parse_qualified_name(name)`、
`name.split(...)`、`pm.find_plugin_skill(name)`，使从同一 source 派生出的检查值能与 sinkArg 连通。

### 1.2 跨项目 adapter 的 source、运行期边与 gate provenance

通用查询不按目录名猜项目。`src/ql/project/ProjectModel.qll` 先用项目独有的源码形状选择 adapter，pipeline
preflight 要求每个 DB **恰好命中一个** adapter；随后 `projectToolHandler`、`projectHandlerSourceParameter`、
`projectAdditionalCallEdge`、`projectPreHandlerGate` 与 `projectAdditionalSink` 为共享 handler→sink/gate 查询提供
最窄项目差异。registry 中的 revision/source/DB 仍是分析身份的单一事实源，adapter 不能用相似类名跨项目扩根。

当前新增三个 adapter 的边界如下：

| Adapter | Concrete root / source | 运行期与污点补边 | Gate / sink 特例 |
|---|---|---|---|
| QwenPaw `6d1e936…` | 只取 `_create_toolkit` 的 `tool_functions` 字典真实引用的 builtin 函数；source 为除 `self/cls` 外的形参 | `asyncio.to_thread(_execute_subprocess_sync, arg...)` 建 callback edge，并把 callback 后的实参逐位映射到 callback 形参 | `_decide_guard_action` 中对同一 `tool_input` 的 `guard(...)` 在 concrete handler dispatch **之前**执行；以 `[pre-handler]` provenance 输出 `confirmed`，owner 保留 concrete handler |
| nanobot `337c460…` | 只取 `nanobot/agent/tools/` 下 concrete `Tool` subclass 的 `execute(...)`；排除抽象 `Tool.execute`，source 排除 `self/cls/kwargs` | 不扩张到 registry/universal dispatcher；普通调用边足够时不增加 project bridge | `create_subprocess_exec`/`create_subprocess_shell` 各自形成 `process-spawn` terminal constraint，不作为 gate |
| poco-agent `7a61cb9…` | 只取 `channel_runtime.py`、`memory.py` 中 `@tool("...")` 的 nested function；tool name 取 decorator 字符串，source 只取 `args` | 把注入的 `runtime_client`/`memory_client` 调用窄连到对应 client method；补 dict/list/tuple value→container；instance method 的位置实参跳过 `self`，具名实参按同名形参连接 | `client.post` 与 `client.request` 是 project-scoped network sinks，分别映射 httpx capability card |

QwenPaw 的 pre-handler guard 是 §1.1 同源原则的**显式执行序例外形状**，不是跳过同源验证：adapter 同时固定
被检查值为 dispatch 使用的 `tool_input`，并把行绑定到 concrete handler owner。`static_stages._attach_chain_gates`
只对带 `[pre-handler]` 的行按 handler owner 挂链，不要求 guard 文件伪装成 handler→sink hop；其他 gate 仍必须
同时满足 hop file 与 owner 约束。这样保留真实执行顺序，又不虚构“handler 调用了 guard”的正向调用边。

具名实参桥统一使用 `callee.getFunction().getArgByName(name)`。不能用 `getArg(_)` 枚举后按名字过滤：该 API
只覆盖位置形参，会漏 poco `search_memories(self, *, query)` 这类 keyword-only parameter。该映射在
`call/call.qll`、`get_handler_to_sink.ql`、`get_gates.ql` 与 `fte_transform.ql` 保持一致，保证结构链、gate 同源
确认和 transform 判定不会使用三套不同的跨边语义。

对应 fixture 是 `src/ql/tests/qwenpaw_project_model/`、`nanobot_project_model/` 与
`poco_agent_project_model/`：

- QwenPaw 断言字典中三类 concrete handler/name/source、pre-handler gate，以及 shell `to_thread` callback edge；
- nanobot 断言 concrete `ExecTool`/`ReadFileTool` root、source 与 process/file sink，同时不把 abstract base 当 root；
- poco 断言两个 `@tool` root、两条 injected-client edge，并要求普通 payload 与 keyword-only `query` 经 JSON
  container 到达精确审计的 `post:json` / `request:json` `rpc-payload`；factory、HTTP control-plane 和
  无关 method 不能成为 tool root。`sink_sensitive_nodes` fixture 另覆盖 HTTP URL 位置、固定 URL+污染
  body 负例、ManagedModal/Camofox payload 例外、process/code/path/extraction/browser/delivery family，
  以及 `prompt_dangerous_approval(command, ...)` 的 GT-backed arg-0 mapping；timeout、encoding、globals、
  task id、branch、filter 与 header 等非 capability 参数必须保持为负例。
  OpenClaw 同一 TypeScript fixture source tree 由两个测试查询共享；`scripts/test_ql.py` 显式使用
  `--threads=1`，避免两个 extraction job 竞争同一临时 test database。

这些 fixture 是 adapter **形状回归**；revision-pinned GT acceptance 另由各项目 oracle 验证 report inventory、
handler→sink、existing/missing gate 与每 sink 一个 constraint。fixture 编译通过不能替代 fixed-DB acceptance。

---

## 2. ① 支配型 —— 控制依赖支配 ∧ 同源污点穿过

在 handler→sink 链的每个函数 F 里，找**支配「F 内通往 sink 的下沉调用 cs」**的条件块，抽其中/流入其中
的校验调用 = gate **候选**；**再要求该候选被同源污点穿过（§1.1）才是真 gate**。(A)(B)(C) 三者缺一不可。
若条件不全局支配 `cs`，但条件块能前向到达 `cs`、守的是早退阻断出口、且检查值与 sinkArg 同源，则作为
`branch-confirmed` 输出，用来表达「只覆盖该分支」的真 gate。

```ql
// (A) cb 支配 cs（sink-ward 调用）—— 控制支配，得候选；(A′) 硬编码旁路开关 `bypassFlagName`(force) / 存在守卫
//     `isPresenceGuardOfArg`(`if workdir:`) 命中时**透明化**；(A″) 简单 for 迭代器 `isLoopGuardBeforeSink`
//     （守卫在 `for x in xs` 体内、sink 在循环后）也透明化——三者都要求内层 cb 守**阻断出口**（return/raise，
//     短路 or 链用 `ifThenBlocksExit` 在 If AST 层判），产出 `[bypass:]`/`[opt-guard:]`/`[loop:]` 标签
cb.controls(cs.getBasicBlock(), _) and cb.getScope() = F.getFunction()
// (B) 校验调用 vc（(B1)(B2) **统一 AST 包含**，非 BB 相等）：(B1) vc 在 cb 测试子树里 `if check(x):`/`if not
//     check(x):`；(B2) 赋值后再判 `x=check(); if <expr(x)>:`——被测表达式**派生自** x。AST 包含覆盖 `not check(x)`
//     （调用落 cb 前驱块）、`if not x["k"]:`/`if x.attr:`——旧的 BB 相等会漏（terminal `if not isinstance(command,str):`）
//     (B2) 用 **SSA def-use**（`EssaVariable`：`ev` 的定义 = 本次赋值的 target flow node ∧ `use = ev.getASourceUse()`）
//     绑定「cb 测试里的 use 确由 vc 这次赋值产生」，**不能只按同名变量匹配**——否则**变量复用**会跨接：`_patch_skill` 里
//     `err` 被 `check_A()`/`_validate_content_size()` 反复赋值，按变量名会把后者@737 接到**前面**那个 `if err:`@700
//     （它支配 `read_text`@709），谎报「_validate 守卫了 read()」，gate 反在 sink 之后。SSA 只认本次赋值真正流到的 use。
//     B1/B2 都不能用「与 ConditionBlock 同 basic block」替代 AST 关系：同块只证明执行邻近，不证明 call 返回值
//     决定条件。B1 只取 condition AST 中不被另一个 call 包住的最外层 call；B2 use 不能只是另一个 predicate
//     call 的实参/接收者。mapping `get`/`setdefault` 是 value projection，不作为 B2 predicate。
//     tuple/list unpacking 仍逐 target 做 SSA 绑定：`ok, detail = check(x); if ok:` 保留 `check`，不能因移除 BB
//     fallback 丢掉 `detect_hardline_command` 这类真实 validator。
// (B3) 无 call 的 inline early-exit：`if not repo or not pr_number: return`
//     完整 If test 是一个 composite gate；then 必须直接 return/raise、condition CFG 必须前向可达 sink-ward call，
//     且至少一个 operand 与 sinkArg 通过同一 Source t 连通。gate location 取 test span，而非上游 lookup location。
// (C) 同源污点穿过（★必要条件，非后置步骤）：
//     ∃ Source t（= d5_param_extraction），t →* vc 的被检查值 g（实参或方法接收者）∧ t →* cs 通往的 sinkArg
// (A-branch) 分支局部：not cb.controls(cs) ∧ gateBlockReachesSink(cb,cs) ∧ cb 守 return/raise ∧ (C)
//     产出 guard_kind `[branch-local]` + taint_verdict=`branch-confirmed`
```

### 2.1 QL 回归测试门禁

`get_gates.ql` 把可独立验证的 (B1)/(B2)/(B3) 结构边界放在
`src/ql/gate/GateShapes.qll`，生产查询与 fixture 测试导入同一份 predicate，避免测试复制实现。当前
`src/ql/tests/get_gates_shapes/` 覆盖：

- `if check(value)` 的直接条件调用；
- `result = check(value); if result` 的 SSA 赋值后判定；
- `matched, detail = check(value); if matched` 的 tuple unpack；
- `dict.get` 值投影后由完整 call-free truthiness 条件形成 composite inline gate；
- `Path(value).is_file()` 只认外层 `is_file`，不认构造器 `Path`；
- `has_binary_extension(resolve(value))` 只认外层 predicate，不认内层 producer。

`src/ql/qlpack.yml` 声明 `extractor: python`，使 `codeql test run` 能为 fixture 创建临时数据库。任何
`.ql`、`.qll` 或 pack metadata 改动，收尾前必须从仓库根目录执行：

```bash
python scripts/test_ql.py
```

该命令先运行全部 CodeQL fixture（含 QwenPaw/nanobot/poco-agent 的 project-model 正负例）和
`src.projects` 中 12 个 active project 的 baseline/GT renderer 单元测试，再编译
`src/ql/*.ql` 的全部生产查询，最后在固定 `hermes-agent-db` 上重新运行 handler/sink、dominance、transform 和
handler-entry 查询，把临时 D5 per-item 结果与 `call-chain/baseline/d5-covered-items-v1.json` 做单调集合回归；
随后分别在固定 CowAgent、AstrBot、QwenPaw、nanobot 与 poco-agent DB 上重建 generic pipeline stage 1/2，
并对注册的 TypeScript 项目执行各自的 revision-pinned acceptance oracle。LobsterAI、CodeG 和
TinyClaw 退役后不再进入 source-dependent runner；它们的 `src/ql-js/tests/` fixture 作为历史 shape
regression 保留，不表示 active benchmark membership。Hermes 当前批准下限为
handler 9、sink 12、eligible gate 74；新增覆盖允许通过，丢失任一已批准 item 或把 gate 降为
`needs-review` 会失败。完整过程只写临时目录，不重写 canonical debug artifacts。

`.claude/settings.json` 另通过 `scripts/ql_baseline_hook.py` 在 Claude Write/Edit/MultiEdit 修改 `.ql`、`.qll` 或
`qlpack.yml` 后记录 session-scoped QL-dirty marker，并在本轮 Stop 时至多触发一次 active-project full-DB regression
suite；成功消费 marker，失败保留 marker 并以 blocking hook result 反馈给 agent，使修复后的下一次 Stop 自动重试。
`--unit-only` 只运行 fixture 和 fast comparator，供开发中的快速迭代，不能作为最终验证。改变检测行为时必须
同步增加或修改最小 Python fixture、测试 `.ql` 和 `.expected`；compile smoke test 与 checked-in CSV smoke
test 都不能替代 full-DB 结果断言。

- **(C) 是必要条件、与 ② filter 同级，不是「步骤 5 的事后确认」**。`fte_filter.ql` 早已内建同源污点
  （被 check 的 x == 被准入进集合的 x + 集合→sinkArg 可达）；① 也必须如此——**`get_gates.ql` 现已并入 (C)**
  （`GateTaintConfig` 无-sanitizer `TaintTracking::Global` + `sameOriginTaint`），把纯控制支配与分支局部候选
  按 §1.1 分级为 **confirmed / branch-confirmed / needs-review**：真阳性（`is_safe_url(url)` / `_is_blocked_device(path)` /
  `validate_within_dir(...)` / `check_execute_code_guard(code)` 都检查污点值）一个不掉，去重 gate 函数从 164
  塌到数十个有意义集合，覆盖率变真实精度（逐条见 `debug/v2-taintC-before-after-report.md`）。
- **分支局部同源 gate**：`branchLocalGateCandidate` 不取代严格 (A)，只在 `cb` 不全局支配 `cs`、但 `cb`
  能前向到达 `cs` 且守早退出口时启用；同源污点连通后输出 `branch-confirmed`。典型：`skill_view` 中
  `if ":" in name:` 分支内 `namespace, bare = parse_qualified_name(name)`，随后
  `if not is_valid_namespace(namespace): return`。对插件链 `_serve_plugin_skill -> read_text@769`，该 gate 严格支配并
  报 `confirmed`；对本地 fall-through `skill_md.read_text@1017`，它只覆盖冒号分支并报 `branch-confirmed`。
- **选择来源（selection provenance）也属于同源**：`skill_view` 的 `name` 先决定 `skill_md` 路径，文件内容再经
  `_parse_frontmatter(content)` 产生 `parsed_frontmatter`，其 `platforms` / `name` 决定平台和禁用策略 gate，最后
  同一路径下的 `target_file.read_text()` 才是 sink。标准值污点不会把「被选择的路径接收者」自动连到
  `read_text()` 返回内容，因此 `get_gates.ql` 仅对 `tools/skills_tool.py::skill_view` 的两个 `read_text` 补
  路径接收者→读取结果边，并补 `_parse_frontmatter` 实参→返回值与
  `parsed_frontmatter.get("name", ...)` 接收者→结果边。后者只是 metadata projection，不单独输出为 gate；
  真正输出的是随后支配 sink 的 `skill_matches_platform` / `_is_skill_disabled`。
- 命中示例：`_is_blocked_device`、`check_execute_code_guard`、`validate_within_dir`、审批
  `if not approval["approved"]: return` 等（见 `gate-candidate-coverage.md`）。
- **策略开关不算 ①，但要「透明化」不能挡住内层真 gate**：`if not force:`、`approval_mode` 等检查配置/标志、
  非污点值（§1.1 例外），其**本身**归 bypass 面、不作为 ① 的 gate。但它们常**包住**真正的数据-检查点
  （terminal：`if not force: approval=_check_all_guards(command); if not approval["approved"]: return`），
  若严格支配就把内层 gate 一起埋掉（`force=True` 直达 sink → 内层条件不支配 sink → 整条 no-candidate）。
  故 `get_gates.ql` 落地 **(A′) 旁路透明化**：维护一张**硬编码旁路开关名表** `bypassFlagName`（首版 `force`，
  可增补 `approval_mode` / `_allow_private_urls`），当外层条件命中该表、且内层条件 `cb` 守着**阻断出口**
  （`guardsBlockingExit`：早退 `return`/`raise`）时，把外层当**透明**、视 `cb` 支配 sink-ward 调用，让
  `_check_all_guards` 这类内层 gate 浮出。产出 `guard_kind` 标 `[bypass:<flag>]`，(C) 同源污点仍照常分级：
  外层 `force` 旁路本身另由 bypass-surface 分析报为「覆盖域 < 能力域（旁路轴）」发现（§8 落地顺序 4）。
- **(A′) 也透明化「被校验参数的存在守卫」**（`isPresenceGuardOfArg`）：外层测试是**裸 Name `x`**（`if workdir:`）或
  `not x`（无 call/比较/下标）、**且 `x` 正是内层校验调用 vc 的实参**时透明化，让内层 gate 浮出。典型：
  `if workdir: err=_validate_workdir(workdir); if err: return`——`workdir` falsy 时跳过校验，但该参数此时**也未被使用**，
  故 `_validate_workdir` 仍是覆盖 `workdir` 的**完整 gate**，不该被存在守卫埋掉。**关键约束「x 是 vc 的实参」不可省**：
  否则退化成「任意 `if x:` 都透明」→ 候选爆炸（实测无此约束时 1762→4015、opt-guard 2253 条噪声）。与 `force` 区别：
  它非已知安全旁路，另标 `[opt-guard:<x>]`（下游再判是否安全相关，不默认作 bypass 发现）；内层 cb 仍须守**阻断出口**。
- **(A″) 简单 for 迭代器透明化（loop-aggregate 守卫）**（`isLoopGuardBeforeSink`）：`for x in xs: if bad(x): return`
  ——守卫在**逐项循环体内**、sink 在**循环之后**（`web_extract`：`for _url in urls: if _PREFIX_RE.search(_url)…: return`
  然后 `provider.extract(safe_urls)`；`patch_tool`：`for _p in _paths: if _check_sensitive_path(_p): return` 然后 subprocess）。
  纯基本块支配抓不到：for 的「迭代耗尽」出边直达 sink、**旁路**该条件 → `cb.controls(sink,_)=NO`（实测 `diag_web_extract.ql`
  P2=NO，同块 in-loop 语句 P3=YES）。但语义上「逐项都过守卫、任一失败即 return 退出，才能走出循环到 sink」== 该守卫覆盖 sink。
  故把**简单迭代器**（单 `Name` 目标）当透明：守卫 `cb` 在循环体内（`getParentNode+` 达该 `For`）∧ sink-ward `cs` 在循环外同作用域
  ∧ 守着阻断出口 → 认定支配，标 `[loop:<x>]`。**收紧（仿 opt-guard，避免爆炸）：vc 的实参就是循环变量 `x`**——守的正是被迭代项；
  实测 +28 条、只落 `web_extract`/`patch_tool` 两个真实 loop-aggregate 点，无噪声。**注意阻断出口判定**：短路 `or` 链
  `if A or B or …: return` 里**没有单一 ConditionBlock 支配 return**（return 从任一 operand-true 可达），按块的
  `guardsBlockingExit(cb)` 会漏（web_extract 四路 or 即此，实测 Q4=NO）；故补 `ifThenBlocksExit`：改在 **If AST 层**判
  （cb 是某 If 测试的子表达式、该 If then-body `getStmt` **直接**含 `Return`/`Raise`）。
- **(A′)(A″) 透明分支必须叠加「gate 前向可达 sink-ward 调用」约束**（`gateBlockReachesSink(cb, cs)` =
  `cb.getASuccessor+() = cs.getBasicBlock()`）：透明化只解除「`cb` 不严格支配 `cs`」这**一条负约束**
  （`not cb.controls(cs,_)`），但该负约束对「`cb` 在 `cs` **之后**」与「`cb` 在 `cs` 之前、被可选外层守卫包住」
  **一视同仁**——会把 **sink 之后、另一分支上的无关早退 gate** 误配为覆盖该 sink。实测 `skill_view`：collision-scan
  循环里的 `read_text`@1065 被**文件读分支**里 `if has_traversal_component(file_path):`@1197（其外层 `if file_path and
  skill_dir:` 是 `file_path` 的存在守卫 → opt-guard）误配，而 1197 在 1065 **之后**、属另一分支，实为无关。加此**正**向
  可达约束（gate 块能沿 CFG 后继到达 `cs`）即排除；严格支配 (A) 天然满足（支配 ⟹ 可达），故只加在 (A′)(A″)。
  （注：**递归/回退**路径上「行号更大的 gate 守着行号更小的 sink」是合法的——gate 支配的是回退调用 `cs`（如
  `_run_browser_command` 的 `if fallback_reason: _run_chrome_fallback_command()`），后者经递归再入到达该 sink；
  这不违反可达约束，属 join 把它显示在更短的直达见证链上，非误报。）
- **嵌套子 gate**：外层 gate 函数（`check_all_command_guards`/`is_safe_url`）内部还有子校验
  （`detect_dangerous_command`/`_is_blocked_ip`）。通用递归仍由 LLM 读 gate 函数体识别，CodeQL 用
  `r_calls` 导出切片；但可对已审计、结构稳定且能精确约束的 helper 增加静态子结果。当前窄例外是
  `skill_view`：只有父 `skill_matches_platform` / `_is_skill_disabled` 已满足同源污点并支配 linked-file sink 时，
  才分别输出 `current.startswith(mapped)`、`name in platform_disabled` 和
  `name in skills_cfg.get("disabled", [])`。子结果保留真实 `gate_file/line`，同时使用链上父调用的
  `in_func=skill_view` 挂链；这不是「父函数一命中就无条件枚举其全部内部条件」。

- **GT 覆盖比对规则——「父 gate 命中 ⇒ 子 gate 覆盖」（nested-in-gate + 调用层级）**：检测器只需 located
  到**父 gate 函数**，则其体内/体下的子 gate 视为**已覆盖**，记 `nested-in-gate(L{k})`，`k` = 父 gate 函数到子
  gate 的 **in-scope 调用跳数**（`L0` = 子 gate 是父 gate**自身函数体**内的 inline 条件；`Lk` = 子 gate 是父 gate
  经 `k` 跳 `inscope_calls` 到达的函数）。**判定前置条件**（避免虚假覆盖）：① 父 gate 必须**真在 identified 集合**里
  （反例 `_is_blocked_ip`：其唯一父 `is_safe_url` 未被检测器识别 → 不算 nested、仍 no-candidate）；② 子 gate 必须
  **在 DB 里有真实调用路径**（层级一律以 **DB**（`src.zip` 快照）为准、用 `diag_nesting.ql` 的 `min(reachAt)` 算，
  勿以当前磁盘源码 grep——二者可能漂移）。
  实测层级：`skill-name absolute-or-drive` ⊂ `_skill_lookup_path_error` = **L0**；`_match_host_against_rule` ⊂
  `check_website_access`、`_is_blocked_device_path` ⊂ `_is_blocked_device`、approval 子检测器
  （`detect_*`/`_check_sudo_stdin_guard`/`check_command_security`）⊂ `check_all_command_guards` = 各 **L1**（逐条见
  `debug/taintC-per-gate.csv` 的 `nested-in-gate` 行）。层级用 `min(reachAt)` 有界递归算（见 `debug` 报告 §4.4）。

- **GT 匹配须按 (file+条件行) 而非 callee token 对齐**：检测器用**被调 callee 名**标 gate（`search`/`isinstance`/
  `is_absolute`…），adhoc GT 用**语义名**（"secret-in-url precheck"…）。若匹配器按 callee token 且把 generic 名
  （`search`）纳入停用词，会把**真命中误判为 no-candidate**（实例：`browser_navigate secret-in-url precheck` 实为
  gate_fn=`search`、confirmed）。对齐口径：按「同 file + 同条件 callsite/行」匹配，不靠 callee 名字面。

---

## 3. ② filter 型 —— 条件支配的集合准入（纯静态，高精度）

**定义**：一个条件 `cb` 支配一次「把（被污染的）元素写入集合 `C`」的写入 `W`，`C` 数据流到 sinkArg。
产出「过滤后数据流」。cb 里的校验调用 = filter-gate。

跨项目实现位于 `call/filter_gates.qll`。除条件 true 分支内的直接 `append/add/extend/insert` 和字典写入外，
它还识别同一 `for` 迭代中「校验失败 `continue`，随后准入」的隐式 false 分支。准入对象可由被测元素或字段经
简单 `get`/`strip` 等局部规范化派生。新增的派生/失败后准入形态必须同时证明：handler Source 到达被测值、
被测值与准入值同源、准入后的 collection 到达 capability-bearing sink node。Poco-Agent
`_extract_messages` 因此产生 `role` 与 `content` 两个 `isinstance` gate；无关 response-format collection
不满足 collection→sink 证明。为避免在扩展时丢失既有结果，旧版「顶层 If 测试参数 + 同变量准入」形态按
原谓词精确保留，而不是对所有同变量写入放宽。已知的 browser fallback response-formatting callsite 被明确
排除。QwenPaw 的两条动态 archive/search witness 与 Hermes 的三个 subprocess-environment admission
callsite 使用 revision-pinned source bridge；bridge 同时绑定项目、文件、行号与函数名，不能按同名函数扩张。

```ql
predicate fteFilter(ConditionBlock cb, CallNode gateCall, ControlFlowNode W, CallNode sink) {
  is_sink_af(sink) and
  ( W.(CallNode).getFunction().(AttrNode).getName() in ["append", "add", "extend", "update"]
      or W instanceof SubscriptStoreNode ) and         // W = 集合/字典写入
  cb.controls(W.getBasicBlock(), _) and                 // 条件支配写入
  taintedFromParam(writtenValue(W)) and                 // 写入值被工具参数污染
  DataFlow::localFlow(collectionOf(W), sinkArgNode(sink)) and  // 集合 → sinkArg
  gateCall.getBasicBlock() = cb                          // 条件里的校验调用 = filter-gate
}
```

**真实命中**：
- web_extract：`if not async_is_safe_url(url): ssrf_blocked.append() else: safe_urls.append(url)`
  （`safe_urls`@973 → `provider.extract(safe_urls)`@1037）。
- `_make_run_env`：`elif k not in _HERMES_PROVIDER_ENV_BLOCKLIST …: run_env[k]=v`（@380 →
  `Popen(env=run_env)`）。

**为什么纯静态就够（is-gate）**：「有条件地把污点值放进流向 sink 的容器」在语义上**就是**过滤，这个结构
fixture 与 source bridge 另外验证 response-format/unrelated collection 不进入 sink-bound 准入结果。故
**filter 的存在性不需要 LLM**；
LLM 只接手「准入规则够不够」（如只按初始 URL 判 SSRF、不管重定向）。

TypeScript 的通用准入形态位于 `src/ql-js/call/collection_filters.qll`；OpenClaw 的跨函数/RPC
精确形态位于 `src/ql-js/call/openclaw_filters.qll`。后者以 helper callsite 作为 gate owner，并同时要求：
`apply_patch` 的 LLM `args.input` 到达 `parsePatchText` 且其 validated hunk collection 到达文件 sink；
`nodes` 的 LLM `args.env` 到达 `parseEnvPairs` 且返回字典进入 `node.invoke system.run`；以及 `exec`/`nodes`
的工具 env 跨 RPC 到达 `handleInvoke.params.env`，再经 `sanitizeEnv` 的 blocked-key/prefix 准入后成为
`spawn` 的 `options.env`。`sanitizeEnv(undefined)`、配置/系统 PATH 规范化、输出集合或仅同名 helper
均不满足同源证明，不计入 filter。

查询候选输出到 `debug/gate-filter.csv`，并由
`debug/script/render_recall_result.py` 与 dominance、transform 结果合并。若当前 GT 快照没有
`gt_type=filter` 行，综合报告把 filter recall 明确记为 N/A，同时仍展示查询实际产出的候选数；候选数不是
GT 分母，不能用来虚构 recall。

---

## 4. ③ transform 型 —— 同源污点穿过「人工净化签名表」

**定义**：来自同一 handler Source 的污点**穿过**一个改写返回值的调用 `g = f(...t...)`，且 `g` 继续流向
sinkArg。产出「净化后数据流」。`src/ql/fte_transform.ql` 实现两个角色：

- `sink-transform`：`source →* transform_in ∧ transform_out →* sinkArg`；
- `guard-normalizer`：`source →* transform_in ∧ transform_out →* checkUse`，同时原始同源
  `source →* sinkArg`，用于 `_strip_quotes` / `_normalize_command_for_detection` 这类只给后续检查提供规范化值的 gate。

**为什么必须人工指定**：「污点穿过一个调用」**必然过产生**（`str()`/`join`/`f"{x}"`/`logger.info` 都穿过），
静态判不出「是净化还是无害管道」；而这一判定语义性强、LLM 也不稳。**故采用人工维护的净化签名表**——
判不准就不猜，直接列。CodeQL 只做机械匹配：`同源污点穿过 ∧ f ∈ 签名表`。单凭 `str.replace` / `re.sub`
不能证明是安全变换，因此泛化原语只输出 `needs-review`，不能升级为 `confirmed`。

```ql
predicate sinkTransform(FunctionObject root, CallNode f, CallNode sink) {
  transformRoot(root) and transformSink(sink) and
  isSanitizerSig(f) and                                  // f ∈ 人工净化签名表
  exists(DataFlow::Node source, DataFlow::Node tin, DataFlow::Node tout, DataFlow::Node sinkArg |
    rootParamSource(root, source) and
    transformInputNode(f, tin) and transformOutputNode(f, tout) and sinkArgNode(sink, sinkArg) and
    TransformFlow::flow(source, tin) and TransformFlow::flow(tout, sinkArg)
  )
}
```

**当前人工净化签名表（随项目增补）**：

- **高置信标准 API**：`html.escape` / `_html_escape`、`markupsafe.escape`、`shlex.quote`；
- **Matrix**：`_pre_sanitize_matrix_markdown`、`_sanitize_matrix_html`、`_sanitize_link_url`、
  `_markdown_to_html_fallback`；
- **Slack**：`format_message`（实体占位、控制字符转义、占位恢复由父 transform 统一拥有）；
- **shell / command**：`_transform_sudo_command`、`_wrap_command`、`_escape_shell_arg`、
  `_strip_quotes`、`_normalize_command_for_detection`；
- **URL / path / pagination**：`normalize_url_for_request`、`_rewrite_loopback_url_for_camofox`、
  `normalize_read_pagination`、`_expand_path`。
- **Python project signatures**：ChatGPT-on-WeChat
  `agent/tools/read/read.py::Read._resolve_path`（只批准 `Read.execute` 中到 `open` 的 path flow，排除
  Edit/Write 同名 helper）、Nanobot
  `nanobot/agent/tools/filesystem.py::_resolve_path`（输出经 `_resolve` 返回到 filesystem sink），以及
  QwenPaw `src/qwenpaw/agents/tools/shell.py::_collapse_embedded_newlines`（输出到同步/异步 subprocess sink）。
- **TypeScript exact signatures**：OpenClaw/OpenClaw-CN 的 `normalizeToolParams`、
  `normalizeCronJobCreate/Patch`、`resolvePatchPath`、`assertSandboxPath`，OpenClaw
  `buildDockerExecArgs`，NanoClaw `realpathSync`，以及 Mercury Agent 精确文件/行绑定的 filesystem
  `resolve` 与 `splitShellSegments`。DroidClaw 保留三条 source/effect 精确桥。

TypeScript 查询对所有 `projectToolHandler` model 使用同一入口，而不是只在少数 project branch 中运行。
`trim`、`toLowerCase`、`replace/replaceAll`、普通 `resolve`/`normalize` 只产生 `needs-review`；普通
`path.resolve`、换行规范化、输出过滤或函数名以 `normalize`/`sanitize` 开头都不能仅凭名字成为 confirmed gate。
LettaBot 的 line-ending `replace` 因而仍不进入 eligible catalogue。

审计后允许真实零：零表示 pinned revision 的每条 canonical handler-source-path-sink witness 都没有上述结构或
批准签名，而不等同于「查询没有返回行」。`clawgap-zero-gate-audit/v1` 将 raw rows、eligible UID 和逐 witness
`detected`/`detector-gap`/`confirmed-zero` 结论分开；`needs-review` 永远不计入 paper table。
OpenClaw-CN 的 filter 审计将 callback-owned apply-patch write、named `runParams.env` 和 RPC re-entry
`sanitizeEnv` 四条 source-to-sink witness 绑定到三个 eligible UID；其余 36 条 canonical witness 保持
`confirmed-zero`，且 audit generator 的 strict mode 要求不存在 unresolved detector gap。

**污点实现约束**：

- Source 使用现有 d5 handler 形参模型；当前 DB 的 `send_message_tool` 注册有漂移，查询显式补该根以覆盖 Matrix/Slack GT。
- Sink 统一使用 `sinkSensitiveNode`：HTTP 只追踪 URL，精确审计的内部 RPC 可追踪 payload；
  其余 family 也必须显式选择 command/code/query/path/receiver/content 等 capability-bearing 节点。
  Matrix/Slack 等真实出站发送调用已纳入 `is_sink_af`，transform 查询不再维护独立 sink 或
  sinkArg fallback。
- 复用 `cha_calls` / `delivery_bridge` 的 arg→param 桥；对人工审计的 Matrix Markdown 管道，窄补
  `_markdown_to_html` / `_build_text_message_content` 返回值、返回字典 payload mutation、`re.sub` replacement callback
  capture，以及 `_sanitize_link_url` 经 placeholder 容器进入 `_markdown_to_html_fallback` 的父 transform summary。
- tuple/list 解包、路径字符串方法、Markdown `convert` 等派生值继续按无-sanitizer 污点传播。

**GT 归属与输出**：检测器只需命中已确认父 transform，父函数内部的 inline pass / parser callback 记
`nested-in-transform`；只有直接/父归属的 `confirmed` 计入 recall，`needs-review` 不计。候选输出
`debug/transform-candidates.csv`；每行同时保留 transform 定义位置 (`transform_file/line`) 与实际调用位置
(`transform_call_file/line`)，供 call-chain coverage 把 transform 精确挂到包含该调用的链上函数。
`debug/script/render_transform_coverage.py` 生成逐 GT coverage，随后
`debug/script/render_recall_result.py` 将已实现的 dominance、filter、transform 三类检测结果合并为
`debug/gate-coverage-combined.md`。两份生成器都在 Markdown 开头记录从仓库根目录执行的完整命令及全部
输入/输出参数，确保 debug 报告可复现。`taintC-per-gate.csv` 的
`(json, gate_name)` 必须与当前 authoritative JSON 精确一致；Matrix 回归测试同时校验名称顺序与
`EXACT_EXPECTATIONS` 覆盖，防止名称漂移静默退化为 `no-candidate`。

Matrix fallback 的 `_sanitize_link_url` / `_markdown_to_html_fallback` 只在 `markdown` import 失败时生效，
因此即使同源输入和输出均连到 `send_message_event`，也输出较弱的 `branch-confirmed`，不表示覆盖正常
`Markdown.convert` 路径。当前 `send(content) -> format_message -> truncate_message -> chunk ->
_markdown_to_html(text)` 的 helper-return/list-iteration 边由一条仅限 Matrix 文件和参数名的审计 summary
补齐；当前版本改为在 `send()` 内联构造 `msg_content`，故两条 fallback transform 的输出再由仅限 Matrix
文件、精确函数名和 `send_message_event` content 实参的审计 summary 补到 sink。报告生成器还会把 GT
中 fix-added、但当前源码未定义的父
transform 标为 `absent-in-source`，避免把不存在的修复 gate 计作检测器漏报。

> 现有 `getStrFuncName()=["split","index","rindex"]` 是给模糊测试找边界的窄表，**不是净化表**；
> transform 签名是面向 sanitizer/normalizer 的人工表；命中且满足同源穿过才定为 transform-gate。覆盖域
> （净化规则）仍由 LLM 读 f 实现抽取，再判是否 < sink 能力域。

---

## 5. 终端 `sink_constraint`（非 gate）

**定义**：一个 concrete sink callsite 就是一项能力约束。它记录 sink ID/API/location、被 Source 控制的
实参、capability class、完整 call shape，以及 capability card 的路径和 SHA-256。多个结构链可以共享同一
sink point，但 `sink-constraints.csv` 对该点必须恰好一行；缺少卡映射是显式失败。

典型能力字段仍可从 sink call shape 和能力卡读出：

| sink 类型 | 需约束的参数 | 安全值 | 不安全 = 发现 |
|---|---|---|---|
| `subprocess.Popen/run/call` | `shell` | `False`（或不传） | `shell=True`（如 `transcription_tools.py:1236`） |
| `subprocess.*` | `env` | 受限环境（`_make_run_env` 产出） | 直传外部 `env` |
| `httpx/requests .get/.post` | `follow_redirects` / `allow_redirects` | `False` 或经校验 | `follow_redirects=True`（`vision_tools.py:203/1288`）→ SSRF-via-redirect |
| `open`/file sink | 路径根约束 | 限定在 base dir 内 | 无根约束（多与 ①/② 协同） |

- `shell=True`、`allow_redirects=True` 等是 sink 的具体能力形态，不是额外 gate；
- `gates[]` 切片显式排除任何 `is_sink_af(gateCall)`；
- Gate LLM prompt 保持 sink-free，constraint 仅在 Stage 4 的 `CallChainSemanticIRV3` 附加；
- 没有 eligible gate 的链仍产生 `gates: []` + 一个有效 `sink_constraint`，从而显式保留 missing-check 路径。

---

## 6. 静态 / LLM 分界表（三类 + terminal constraint）

| 判定 | ① 支配 | ② filter | ③ transform | terminal constraint | 手段 |
|---|---|---|---|---|---|
| 污点路径 `param→sinkArg` 存在 | —(控制依赖) | 静态 | 静态 | 静态 | `TaintTracking::Global`（无 sanitizer） |
| 「这里是 gate」 | 静态(`controls`) | 静态(高精度) | 静态(**查净化签名表**) | 非 gate；每 sink point 恰好一个 | §2–5 |
| gate 校验函数/callsite 定位 | 静态 | 静态 | 静态 | sink API/callsite | — |
| 嵌套子 gate | **LLM 读函数体** | — | — | — | §2 |
| **覆盖域是什么** | LLM | LLM | LLM | capability card | 读规则 |
| **覆盖域 < 能力域（漏洞）** | LLM | LLM | LLM | 下游比较输入 | gate IR + constraint |

---

## 7. CodeQL → LLM 单 Gate 语义接口（已实现）

本阶段只回答「这个 gate 本身做什么检查/变换」，不在同一次 LLM 调用中做整链组合或 sink-capability
包含关系判断。实现位于 `src/gate_semantics/`，入口为 `python -m src.gate_semantics.main`；LLM transport
默认使用 `claude-agent-sdk` 的 stateful `ClaudeSDKClient`，并为每个 gate 建立一段可多轮研究、可审计的
独立会话。`Read`、`Grep`、`Glob` 三个既有只读工具继续保留，同时通过 MCP 加入只读 LSP 导航；旧的
`src.sink_capacity.agent.run_agent` Claude CLI 路径保留为 `--agent-transport cli` fallback，不参与 LSP。
coverage source validation 的 packet-constrained deep fallback 复用同一 runner，但显式传入 digest-bound
`allowed_source_files`、`max_turns=8` 与 `max_tool_calls=16`；该模式移除 `Glob` 和
`lsp_workspace_symbols`，其余 file-oriented tool 只能访问 packet 声明的源码文件。

### 7.1 输入候选与边界

候选 contract 与源语言无关，`run_pipeline` 从项目 query pack 消费三类检测器输出：

- dominance：只纳入 `confirmed`、`branch-confirmed`；
- filter：结构已经证明「条件控制元素准入」，按 confirmed 纳入；
- transform：只纳入 `confirmed`、`branch-confirmed`；
- 所有 `needs-review` 都排除，不能让 LLM 把未确认候选升级成真实 gate。

同一 callsite 因多个 sink 行重复时，按稳定 `gate_uid` 去重，sink/chain 引用只留在 audit，不进入 LLM
prompt。`get_gates.ql` 输出准确的 checked expression、位置、Source 参数和条件；`fte_filter.ql` 输出被条件
准入的确切元素；`fte_transform.ql` 输出由同源污点证明的 transform input（包括 receiver 或非首实参），
下游不再猜「第一个实参就是被检查值」。

无调用的复合 truthiness gate 使用 synthetic `gate_fn=inline-condition`。CodeQL 输出结构 marker 和完整
test span，Python slicer 再从当前 revision 恢复 exact source；`checked_value.expression` 保存完整条件，
`checked_value.components` 按短路求值顺序保存 operand，局部赋值闭包以 `local-derivation` source chunk 提供。
这些 lookup/constructor 只解释值从哪里来，不能被 LLM 写成独立 block/pass gate。例如
`delivery.get(...) → extra.get("repo")/extra.get("pr_number") → if not repo or not pr_number` 的唯一 gate
位置是完整 If test；语义 atom 分别描述两个 falsey rejection，并保留 Python `or` 的短路顺序。

调用型 gate 也必须对 checked argument 或 method receiver 做当前函数内的有界向后赋值闭包，
不能因为 gate AST 是 `Call` 就丢掉输入构造。闭包保留源码顺序和条件重赋值的控制语句，
同时排除无关局部语句。例如 `local_path.is_file()` 的 slice 必须包含：

```python
resolved_url = video_url
if resolved_url.startswith("file://"):
    resolved_url = resolved_url[len("file://"):]
local_path = Path(os.path.expanduser(resolved_url))
```

这三段都标记为 context-only `local-derivation`：它们可以支撑 `derive` atom，但构造阶段的分支、
异常或 helper 不是所选 `is_file` gate 自身的 reject/on-error 行为。局部闭包最多跟踪 24 个符号、
16 个 source chunk；触发上限时必须记录 `local-derivation-*-budget` unresolved 而不是静默截断。

普通 predicate 的输出默认表述为 `boolean branch decision`，不预设每个 false 都是 block。
只有当所选 semantic unit 自身终止、拒绝或丢弃 checked value 时才可以生成 `block-if`/
`drop-if` 和 rejection example。如果 false 只进入 `elif`、sibling predicate、fallback 或后续检查，
它是 local branch miss：路由写入 `default`，不吸收后续 gate 的算法，也不伪造 rejection example。
对由 `Path(...)` 局部构造可证明的 `exists/is_dir/is_file` 调用，若项目只声明 Python 版本范围而
没有锁定具体 runtime，slice 记录 `library-contract:pathlib.Path.<method>@supported-python-version-unpinned`。
LLM 只能输出跨支持版本的可携行语义；不得猜测 errno/异常抑制表，必须用 `unknown` atom 和
`status: partial` 保留这个版本化依赖，直到后续加入对应 runtime 的确定性 profile。

每个 gate 的语义边界统一采用 **gate-entry isolation**：假定执行已经到达所选 gate，不把上游 feature
switch、先前 early return、sibling gate 或其它 reachability constraint 写入 `semantic.json`。这些信息仍可
留在 `slice.json` 的 `callsite.activation` 供 debug/audit，但缺失 activation 不是语义错误，reviewer 发现把它
混入 gate semantics 时反而必须删除。这个假定不丢弃 checked-value construction：当前函数内决定 gate 实际
输入的 derivation/normalization、gate 内部分支，以及直接消费 gate result 的 caller branch 仍属于语义范围。
因此 #11 不需要恢复 shell-linter 分支的进入条件；#20 不需要恢复先前 write 是否成功，但仍必须保留
`path = self._expand_path(path)`。

产品流程中的普通 gate 只执行一次语义生成；`local-derivation`、`unresolved_symbols` 或 exact matcher 不再自动
触发第二次 LLM 调用。第一次返回仍须满足完整 contract：局部构造顺序、sibling/fallback 边界、
false-versus-reject 与未解析 library 声明由主 prompt 约束；regex matcher 的 exact source-rule assignment closure
由 pipeline 在第一次返回上确定性附加并验证，不依赖第二个模型调用。只有逐 gate 调试显式传入
`--debug-fidelity-review` 时，才追加一次 boundary/fidelity reviewer。reviewer 同时获取原 GateSlice 和第一版
GateAnalysisResponse，输出完整的更正后 response；debug 运行跳过 repository reuse，确保选中的 gate 确实重新
执行 analyze + review。两次原始返回都保存在 audit/chat；普通生成或 debug review 的结构错误仍可进入既有
bounded contract-only repair，但 repair 不得发明新语义。

`GateSliceV1` 是 agent 的初始上下文，不是源码信息边界。普通生成和可选 debug fidelity review 都可以在
`unresolved_symbols` 为空时继续研究源码。默认 SDK 会话优先使用 LSP 的 definition、references、symbols、
type-definition 与 implementation 来解析语义关系，再用 `Read` 读取精确返回范围；`Grep`/`Glob` 仍用于
字符串配置键、regex/policy table、反射和 LSP 找不到的符号。slice 的 `project.language`
决定 `lsp_init` language：Hermes 启动 Python/Pyright，OpenClaw 启动 TypeScript server，两者都
受 resolved `project.source_root` 约束。

**TypeScript GateSlice backend。** `run_pipeline(..., source_language=...)` 只接受 `python` 或
`typescript`，分别路由到 `PythonGateSlicer` 和 `TypeScriptGateSlicer`。TypeScript backend 通过
`typescript_bridge.mjs` 调用固定的 TypeScript compiler API；bridge 拒绝 `source_root` escape，
按 CodeQL file/line/column、gate name 和 checked hint 定位 call/inline expression，恢复 condition、
branch effects、lexical activation、checked receiver/argument、有界 local derivation 和可证明的
actual→formal binding。它以规范化 TypeScript AST 构造坐标无关的 `gate_uid`，并复用
`GateSliceV1`/`source_bundle`/`unresolved_symbols` contract；binding 或 source witness 无法证明时必须
显式记录 unresolved，不能默认补全。嵌套的同名 `execute` callback 还把不含坐标的 outer factory/wrapper
lexical owner stack 纳入 UID，避免 read/write 等独立 tool callsite 因相同局部 AST 被错误合并。
LobsterAI policy catalog 需要切片 prompt 中的 inline string literal；bridge 将 string-literal-like AST 作为
checked-expression candidate，并以 `resolved` inline binding 输出。移动该 literal 的行号不会改变 normalized-AST
`gate_uid`。
OpenClaw 的 `src/ql-js` 已实现 dominance/filter/transform 三类
生产查询；候选仍须同时具备相同 handler source 到 checked value 与 concrete sink argument 的 taint witness。
revision-pinned fixture/GT acceptance 同时覆盖 ordinary `execute`、dispatcher、plugin/test 负例以及
zero-gate chain，避免把 caller closure 中出现过的检查误记为当前链 gate。

TypeScript bridge 还解析相对 `.js` import 到 snapshot 内对应 `.ts` helper definition，使 cron 等跨文件
normalizer 的 source bundle 包含真实函数体。若模型逐字引用了 authoritative slice 文件中的 source rule、但
evidence 行号偏移，validator 只在该精确字符串于 slice 文件中唯一出现时重定位 evidence；不存在或多处匹配时
仍 fail closed，不把近似/臆造规则改写成源码。

LSP MCP bridge 固定为 `@theupsider/lsp-mcp@1.3.2`；Python 固定 Pyright 1.1.408，TypeScript 固定
`typescript-language-server` 5.3.0 与兼容的 TypeScript 5.9.3。Node 依赖由
`src/gate_semantics/lsp/package-lock.json` 固定，Python 依赖由
`src/gate_semantics/requirements.txt` 固定。MCP 环境显式加入 pinned `node_modules/.bin` 与
`NODE_PATH`，不能依赖用户 shell 中偶然存在但缺少 TypeScript runtime 的 language server。允许给模型的
LSP inventory 只有 `lsp_init`、definition、
references、document/workspace symbols、diagnostics、type definition、implementation 和 health。
rename、formatting、code action 等写能力即使 bridge 本身实现也不会暴露；Bash、网络和所有文件写工具同样
禁止。显式 `--no-lsp` 只关闭 MCP，绝不移除 `Read`、`Grep`、`Glob`。

源码研究由 SDK `PreToolUse` hook 强制限制在 resolved `project.source_root`：它检查 `Read.file_path`、
`Grep/Glob.path`、`lsp_init.root` 和所有 file-oriented LSP 参数，解析相对路径、`file://` URI、`..` 与
symlink 后拒绝任何 root escape。这个 hook 不移除 `Read`、`Grep`、`Glob`，也不依赖模型遵循 prompt；
普通 gate extraction 保持上述完整只读工具集合。packet-constrained source validation 额外要求解析后的
file path 精确属于 packet allowlist，并在 PreToolUse policy check 超过 16 次时拒绝后续调用；LSP init root
仍必须等于 source root。所有 allowlist/limit denial 与 checked-call count 写入 `packet_constraints` audit。
拒绝记录写入 `agent_session.source_root_policy.denials`。研究同时受 `--max-turns` 预算约束。工具补充的每个 semantic atom 必须在
audit evidence 中引用准确的源码相对路径和行号；证据位于原 slice span 之外时另记入
`source_research.additional_evidence`。SDK 还把 session ID、MCP connection status、每轮结构化 tool
call/result、模型与 stderr tail 写入 audit 的 `agent_session`，而 `semantic.json` 不含这些运行元数据。
预算内仍不能解析的 outcome-affecting dependency 必须保留为 `unknown` + `status: partial`。

为便于逐 gate 调试，每个 repository entry 的 `chat.json` 保存 analyze/repair 调用以及显式启用的 debug review 收到的完整 system/user
prompt、assistant 原始回复，以及 SDK session 中按真实顺序出现的 assistant text、tool-use 和 tool-result
事件；同时记录 gate/revision/model/prompt version。API key、provider credential 不进入该文件。audit 继续只留
精简 tool trace，不重复嵌入完整 prompt；`semantic.json` 仍是唯一给下游使用的语义产物。即使某个 gate
分析失败，也写包含失败 exchange 的 chat 文件，便于区分 transport、tool、contract 与语义错误。

每次 SDK `ResultMessage` 的 provider `usage` 原样保留在 turn result，并规范化为 per-gate `llm_usage`：
`input_tokens`、`cache_creation_input_tokens`、`cache_read_input_tokens`、`output_tokens`、三类输入之和
`total_input_tokens` 以及总和 `total_tokens`。该字段同时写入 `audit.json`、`chat.json` 和精简
`agent_session.token_usage`。CLI fallback 改用 `--output-format json` 读取同一 usage，而不是从 prompt 字符数估算。
manifest 的 `agent.debug_fidelity_review` 明确记录是否启用第二次调试调用；`llm_usage`/`counts.llm_*_tokens`
只累计本次真实执行的 model calls，包括失败调用，明确排除
digest 命中而复用的 artifact；因此第二次完全复用运行的消费为 0。旧 artifact 无法追溯 provider usage 时写
`provider_reported: false` 和零值，不伪造估算 token。

每个 `GateSliceV1` 输入包含：

- line/revision/ordinal 无关的 repository key `gate_uid`、revision-aware 的 semantic `gate_id`，以及 checked
  input `V...`、decision/transformed output `D.../V...`；
- exact call expression、checked expression 与 actual→formal binding；
- gate mode、静态 verdict、callsite condition、true/false branch effect；
- 可解析时的完整 project gate function；
- 与规则相关的嵌套 helper、policy constant、table、import/config 线索和 source digest；
- Source symbol 与 `t→g` 信息；无法静态解析的依赖显式列入 `unresolved_symbols`；
- **不含** sink label、sink capability、漏洞、修复或预期安全义务。

对于 library/inline predicate，切片只展开精确条件，不复制整个 handler；否则一个普通 `isinstance` 会把
数千行无关逻辑带入 prompt。project gate 函数则完整保留，并从 gate function 与 callsite condition
最多递归两层收集相关依赖。

#### 7.1.1 `_check_all_guards` compound profile

全 catalog 的 gate-only closure 审计表明，只有 `tools.terminal_tool._check_all_guards` 是由多个独立安全
策略组成、不能可靠地用通用两层切片压成一个 IR 的极端 gate。实现不按会随输入重排的 `gate_number`
或随 revision 改变的 `gate_id` 特判，而按 resolved qualified function 匹配
`tools.terminal_tool._check_all_guards`，并确认语义根为
`tools.approval.check_all_command_guards`。profile 定义在 `src/gate_semantics/compound_profiles.py`。

该 profile 用显式 symbol allowlist 取代任意递归展开。共享输入包含 caller 的 `if not force`、四行 wrapper
和完整 orchestrator；其余 source 按六个 audit-only fragment 分组：

1. caller force 与隔离环境 bypass；
2. command normalize、`HARDLINE_PATTERNS` 与不可绕过的 hardline block；
3. approval mode、process/session YOLO、noninteractive/cron 默认；
4. Tirith config/exit/failure policy、`DANGEROUS_PATTERNS` 与 finding aggregation；
5. session/permanent prior approval 与 `_smart_approve` 的 prompt、approve/deny/escalate；
6. gateway/CLI notify、pending、timeout、deny、approve 与 persistence scope。

profile 明确把通用 `call_llm` provider/retry/credential plumbing、Tirith 下载/安装、plugin observer hook、
gateway heartbeat/queue 细节当作 opaque operational boundary；这些实现体不能因为名字可解析就进入语义
prompt。外部 Tirith binary 的实际 matching rules 没有随 Python source 提供，固定记录为
`external-policy:tirith-binary-matching-rules`，因此最终 IR 必须含 `unknown` atom 且 `status: partial`。

分析采用两级调用：先分别生成六个最多 12 条 rule、目标 250–600、硬上限 1,200-token 的 source-grounded
fragment；再把 fragment 与完整 profile inventory 合成自包含 `GateSemanticIRV2`。最终 `semantic.json` 包含
26 个按真实分支连接的 child check、12 条 hardline policy rule、47 条 dangerous-pattern policy rule、四个
terminal outcome、每个 child 的 input/output、error behavior、policy reference、reject example 与 unresolved。
fragment 仍只用于审计和降低单次 source prompt 复杂度，任何后续整链推理所需的语义都不能只留在 audit。

profile 从当前 AST 按 source symbol 定位全部 26 个 check anchor，并直接解析两个 policy table 的每个 tuple；
validator 要求 child ID/operation/outcome/policy reference、policy entry ID/顺序以及 28 个 evidence unit 全部精确
覆盖。任何 child、policy entry 或 anchor 缺失都会使本 gate 分析失败，不能以 summary 替代或静默退回通用
递归切片。这样既恢复通用深度 2 截断掉的 Tirith/config/approval 行为，也避免 `_smart_approve → call_llm`
和 browser/installer 一类无关 dependency explosion。

LLM 负责每个 child/policy 的自然语言 `summary`、`input`、`output`、`rule` 与 `on_error`；profile 负责从
source AST 确定 inventory、operation、transition、policy reference、无执行性的 symbolic reject example 和
evidence anchor。pipeline 在校验前只归一化这些 profile-owned 结构字段，不修改 LLM 的语义 prose；因此模型把
evidence 分组或把 example 写成 shorthand 不需要再调用 LLM 修格式，但少了 child/policy 或语义字段仍会失败。
`unresolved` 同样来自已解析 source inventory；当前只有外部 Tirith binary matching policy，不能把已提供的
approval state、alias mapping、CLI callback contract 或刻意 opaque 的 provider plumbing 误报为缺失语义。

该 compound profile 只决定 **被 detector 独立选中为该 callsite gate 时** 如何完整表示其 per-gate
semantic。它不授权 call-chain assembler 因结构链经过 `_check_all_guards` 就强制注入该 gate，也不授权用它
吸收 exact-chain detector 返回的 nested callsite gate；整链 inventory 仍以 `chain-gates.csv` 为准。

### 7.2 `GateSemanticIRV1`

LLM 返回下面的 compact IR；受控英文只陈述 source-proven behavior：

```json
{
  "gate_id": "G123",
  "mode": "predicate",
  "input": "V7: candidate URL string",
  "output": "D123: pass/block decision; V7 remains unchanged",
  "summary": "Determines whether a URL target is permitted by normalizing its host, resolving all addresses, and rejecting prohibited destination classes.",
  "steps": [
    {
      "id": "S1",
      "op": "normalize",
      "rule": "Parse the URL, lowercase its hostname, and remove the hostname trailing dot."
    },
    {
      "id": "S2",
      "op": "block-if",
      "rule": "The normalized hostname is empty or belongs to the blocked-hostname set."
    },
    {
      "id": "S3",
      "op": "block-if",
      "rule": "Any resolved address is private or internal.",
      "unless": "Private-address access is enabled."
    }
  ],
  "default": "pass",
  "on_error": "block",
  "reject_examples": [
    {
      "input": "http://127.0.0.1/admin",
      "precondition": "Private-address access is disabled.",
      "rejected_by": "S3",
      "reason": "The hostname resolves to a blocked loopback address."
    }
  ],
  "bypass_examples": [],
  "status": "complete"
}
```

字段和压缩约束：

- `summary` 是至多 35 words 的一句话，说明 gate 的安全功能；
- `steps` 按执行/判断顺序排列，ID 必须为连续 `S1...S8`，每条 `rule` 至多 25 words；
- 依赖 regex/glob/allowlist/denylist/policy table 的 step 可带 `source_rules`，逐项保存能复现匹配的 exact
  source substring；若 compiled matcher 引用 pattern table，两者都必须原样保存，不能只写自然语言摘要；
- operation 只能是 `derive`、`normalize`、`allow-if`、`block-if`、`admit-if`、`drop-if`、
  `transform`、`constrain`、`prompt`、`unknown`；
- `default` 与 `on_error` 不得丢失 fail-open/fail-closed；配置/平台/状态例外写入 `when`/`unless`；
- `input`/`output` 必须以切片给出的稳定 value ID 开头，供后续 ordered call-chain aggregation 对齐值身份；
- 普通单 gate 仍以 200–300 serialized tokens 为优选紧凑目标，但完整 `semantic.json` 的硬上限为
  2,000 tokens。硬上限统计整个 compact `GateSemanticIRV1` JSON（包括 ID、input/output、summary、全部
  steps（包括 `source_rules`）、default、on_error、reject_examples、bypass_examples 和 status），不统计 `slice.json`、evidence 或
  `audit.json`。
  完整性优先于优选目标；不能为了压缩合并不同拒绝类别，或删除 checked input、派生过程、例外与错误行为。

#### 7.2.1 compound `GateSemanticIRV2`

普通 gate 继续使用 V1。只有 profile 明确标记的 compound gate 使用 V2，且仍写入同一个 `semantic.json` 和
`gate-semantics.jsonl`。V2 不是八个阶段的 summary，而是 gate 自身完整的 micro control-flow graph；若它被
某条 call chain 选中，整份 IR 作为一个 ordered gate wrapper 的 `semantic` 原样内嵌：

- `entry` 指向第一个 `Cxx` child check；每个 child 的 `outcomes` 指向另一个 child 或 `T_ALLOW`、`T_BLOCK`、
  `T_APPROVAL_REQUIRED`、`T_PROPAGATE`；
- `checks` 保存全部 decision-relevant normalize、bypass、predicate、scanner、prior approval、smart review、
  prompt、timeout、failure 与 persistence semantics；
- `policies` 保存 matcher 使用的每条自然语言 policy rule；多个 child 用 `policy_refs` 复用同一张表；
- source span、digest、raw response 仍只在 slice/audit；普通 V1 matcher 的 regex/policy 原文是例外，必须
  进入对应 step 的 `source_rules`。V2 的自然语言检查逻辑、例外、policy inventory 和 error outcome 必须
  全部存在其 semantic；
- compound IR 目标 4,000–6,500 serialized tokens，硬上限 8,000。当前 catalog 只有这一例，30-gate chain
  即使包含它仍远小于常用模型 context；这里完整性优先，且其 8,000-token 上限独立于普通 gate 的
  2,000-token 上限。

#### 7.2.2 source-profile-checked `GateSemanticIRV3`

V1 适合单一、紧凑且没有大 policy inventory 的 gate；V2 只用于 `_check_all_guards` 这种 compound
orchestrator。对「表面步骤很少，但结果依赖精确 matcher 表、gate-internal control flow、外部 decision 或状态副作用」
的 gate，单靠 V1 prose 不能保证从 `semantic.json` 恢复 decision-relevant source behavior。因此 pipeline 在
普通 LLM extraction 之后运行 `behavior_checker.py`：若 qualified function 命中确定性 source profile，就把
最终产物升级为 `GateSemanticIRV3`，并把原始 LLM IR 放入 audit 的
`semantic_check.original_semantic_ir`。

V3 是 gate-local control structure，不是 cross-gate graph，包含：

- `inputs`：checked value、callsite context，以及会改变结果的 external response value；
- `activation`：gate 何时实际被调用/跳过，以及每个 activation outcome；
- `derived_values`：稳定 value ID、全部 `sources`、精确 operations 和使用它的 check；多输入派生值不能压成
  单一 `from`；
- `checks`：每个 check 的 reads、operation、rule、policy refs、outcomes、error behavior 和 source-proven
  reject examples；
- `policies`：原样保存 source 中每条 matcher/prompt rule、flags、match semantics 和 terminal outcome；
- `outcomes`、`state_effects`、`dependencies`：区分 pass/block/pending/not-evaluated、持久状态修改及
  outcome-affecting external dependency；
- `completeness`：分别声明 control-flow、policy、context、dependency 和 overall 的 complete/partial。

当前 Hermes profiles 是：

- `detect_hardline_command`：12 条 regex policy、container backend activation 和 scoped normalization；
- `_foreground_background_guidance`：background activation、只供 help/version exception 使用的 normalization、
  1 条 wrapper、2 条 ampersand、8 条 long-lived regex rule；blocking regex 读取 raw command；
- `_smart_approve`：warnings/mode activation、完整 auxiliary-review prompt policy、APPROVE-before-DENY substring
  precedence、session approval effect，以及 unresolved auxiliary LLM response。

profile 直接从当前 source AST 解析 policy 内容，并断言预期 inventory；source shape 或 rule count 改变会使
检查失败，不会静默沿用旧语义。V3 validator 还检查 value/policy/outcome/state-effect 引用、ID 唯一性、
dependency 与 completeness/status 一致性、与 source profile 逐字段相等及 8,000-token 上限。没有 profile 的
简单 gate 继续保留 V1；checker 不把任意未建模 gate 冒充为 behavior-complete。

### 7.3 拒绝与绕过样例

`reject_examples` 最多两个，并优先覆盖不同的拒绝规则类别。每个样例必须：

- 是 supplied source 能证明会被**当前 gate 自身**拒绝的 literal/symbolic input；
- `rejected_by` 精确引用现有 `block-if` 或 `drop-if` atom；
- `reason` 至多 20 words；依赖配置、平台或先前状态时显式写 `precondition`；
- 不包含可执行 exploit payload，不从通用安全知识猜测，不把 downstream gate 的拒绝算到当前 gate。

只有一种拒绝类别时只给一个样例。非拒绝 transform 或 passive constraint 返回空数组。未解析依赖会改变
结果时不生成无法证明的样例，并输出 `unknown` atom 与 `status: partial`。

当 verdict 由外部服务或 LLM reviewer 非确定性决定时，即使 prompt 给了 approve/deny 规则，也不能声称某个
具体 command 必然被拒绝；这种 gate 的 `reject_examples` 必须为空。只有 source 自身能保证某类输入落入
`block-if`/`drop-if` 时才允许给 concrete example。等价的 default 与 exception outcome 应合并为最少 atom，
但不能合并结果不同的 approve、deny、escalate 分支。

`bypass_examples` 是必需数组，允许 0–5 个元素；它只表示输入**通过当前 gate，却规避了该 gate 在 source 中
体现的安全意图，并可能产生 source-supported local security impact**。普通安全输入通过 gate 不是 bypass。
每个样例必须：

- `passed_by` 精确引用当前 IR 的 `allow-if` 或 `admit-if` atom；
- `input` 是 literal 或 symbolic input，`reason` 至多 20 words；
- `potential_security_impact` 至多 25 words，只陈述 callsite 附近 source 可以证明的潜在影响；
- 配置、平台、并发、先前状态或 TOCTOU 条件写入可选 `precondition`；
- 不从通用安全知识猜测，不输出 executable exploit payload，不把 downstream sink capability 或 whole-chain
  vulnerability conclusion 填入单 gate IR。

若 source 不能证明绕过，必须输出空数组。transform gate 同样输出空数组；其不完整变换若将来需要表达，使用
独立的 transform-fidelity contract，而不把普通变换输入伪装成 bypass。比如 containment helper 只校验
`target_file.resolve()`、但 callsite 随后读取原始 `target_file` 时，可以在 source 证明存在检查与使用分离的
前提下给 symbolic symlink-race 样例；若 source 不存在这种分离，则不能生成该样例。

reviewer 必须逐一审计 fail-open `allow-if`、default 与 error route：若 policy/config failure 能让原本应被
source policy 阻断的 symbolic input 到达紧邻 consumer，就必须给出 bypass example。`normalize`、`load policy`
或 `validate` 不能作为黑盒摘要；所有会改变匹配结果的大小写、scheme/path 截断、prefix/suffix 处理、无效项
跳过、precedence 与 deduplication 都必须存在于 compact atom。每个 supplied `unresolved_symbols` 项要么由
project-source evidence 明确解析，要么保留 `unknown` 与 `status: partial`；模型常识不能代替 external library
contract 的源码证据。

### 7.4 验证与 audit sidecar

程序在接受响应前验证字段集合、稳定 ID、mode、atom 顺序/数量、word/token limits，以及每个
`rejected_by` 是否指向 rejecting atom，以及 `passed_by` 是否指向 allow/admit atom。每个 atom 必须有独立
evidence range；evidence file 必须是 source root 内的规范化相对路径，行号不能越过真实文件。transform
不能伪造拒绝或绕过样例。若 step 含 `source_rules`，validator 逐项要求去除外围空白后的字符串确实是同一
step 某个 evidence span 的连续原文；regex matcher 的 fidelity review 还要求最终至少存在一条 exact
source rule，避免模型只留下概括性 prose。若模型提交的条目与某个完整 evidence span 的字符相似度至少
0.98、但有漏逗号等抄写漂移，pipeline 可确定性替换为该完整 source span；低相似度、截断或错误定义仍失败。
对于 `_NAME.search/match/fullmatch(...)` 形态，pipeline 还从同 step 已引用的 evidence 中解析 `_NAME` 的
top-level assignment 及其引用的同文件 assignment closure，并以源码顺序确定性附加完整定义；未引用对应
evidence 时不能附加，仍由 fidelity review 补查。
失败响应只允许一次
source-preserving JSON repair。

LLM extraction 成功后，pipeline 总是调用 `check_and_upgrade_semantic`。普通 V1 或 compound V2 没有匹配
profile 时保持原 schema；已 profile 的 policy/external-decision gate 必须得到通过 source checker 的 V3，
否则该 gate generation 失败。对已有 canonical artifacts 可独立检查和升级：

```bash
python -m src.gate_semantics.checker \
  --gate-number 95 --gate-number 197 --gate-number 245 --gate-number 249 \
  --write
```

不带 `--write` 只报告 `verified`、`recovered`、`not-profiled` 或 `failed`；带 `--write` 才替换 profiled
`semantic.json`、更新 `audit.json`、aggregate JSONL、manifest，并写
`semantic-check-report.json`。`recovered` 不是 LLM 失败：它表示 legacy IR 不能完整恢复 source behavior，最终
V3 已由确定性 profile 修复。

面向后续 deterministic call-chain aggregation 的 `gate-semantics.jsonl` 只含 compact IR。下列审计信息放在
`gate-semantics-audit.jsonl`/`gate-slices.jsonl`，不进入整链 semantic：

- source bundle、per-chunk digest 与整 slice digest；
- project revision、model、prompt version、unresolved symbols；
- step→source evidence、chain refs、所有原始/repair responses 与 validation errors。

compound gate 另外在 audit 保存 profile ID、六个 fragment 的 compact result/证据/raw responses、26 个
check anchor、两张 policy source inventory、opaque boundary、forced unresolved，以及 composer 的 raw/repair
记录。相应自然语言 child/policy semantics 则完整写入 `semantic.json`/`gate-semantics.jsonl`。

V3 gate 的 audit 另外保存 checker/version/profile ID、source coverage units、legacy findings 和原始 LLM IR；
下游仍只读最终 `semantic.json`，不依赖这些审计字段。对已升级 artifact 重复执行 `checker --write` 时，audit
保留第一次 recovery 的 `original_semantic_ir`/findings，并把本次幂等验证写入 `latest_verification`，不能用
“当前已相等”的 verified record 覆盖原始恢复证据。

`manifest.json` 保存输入/输出路径、计数、失败明细、source bundle digest、catalog/selection mapping 和从
仓库根目录可重放的完整 `generation_command`。默认模型为 `deepseek-v4-flash`。每次运行先对完整去重集合按
稳定 `gate_id` 排序并分配从 1 开始的 `gate_number`，然后才应用任何选择器；相同 revision 和 detector inputs
下，`--gate-number 4` 不会因 `--max-gates` 或其他选择而漂移。

`gate_number` 只用于当前 catalog 的人类阅读与 `--gate-number` 选择；持久化索引是 `gate_uid`。UID 由 project、
module、enclosing function、mode、qualified function 及去除坐标后的 gate/checked/callsite AST 计算，不含 revision、
行列、ordinal、verdict 或 sink provenance。同 helper 的不同 callsite 因 enclosing/context 不同得到不同 UID。
repository 路径固定为 `output/hermes/gate-semantics/repository/<gate_uid>/`，包含 `slice.json`、`semantic.json`、
`audit.json`、`chat.json`。

`content_digest` 对影响语义的 binding、branch effect、source chunk 内容、unresolved dependency 和 compound
profile 求 hash，但排除 revision、行列、ordinal、generated value ID 和 detector provenance。相同 UID 且 digest
未变时，pipeline 重新执行当前 contract/evidence/source-rule checker 后直接复用，不调用 LLM；digest 改变或
stored contract 不再通过时重新生成。detector 新增/删除只改变当前 catalog：仍存在的 UID 可复用，已消失 UID
保留在 repository 但不出现在 `gate-index.csv`。manifest 分别记录 `reused_semantics`、`generated_semantics`、
`migrated_semantics`、`stale_semantics`、`invalidated_semantics`。digest 变更或 contract 失效时，旧结果先移入
`repository/<gate_uid>/stale/<old-digest>/`，确保重新生成失败后下游不会误读旧 `semantic.json`。首次升级会从旧 `selected/NNNN-G.../` 按 current gate/content identity
迁移兼容 artifact；旧目录只作兼容数据，不再是 canonical lookup。

无论选择几个 gate，程序都会输出完整 `gate-index.csv` 与 `gate-index.md`。CSV 保存 ordinal、ID、mode、静态
verdict、函数/调用点、checked expression、actual→formal binding 和 unresolved count；Markdown 开头自动写
完整生成命令，并给出单 gate 调试命令。只构造全部输入而不调用 LLM：

```bash
python -m src.gate_semantics.main --build-slices-only
```

独立分析第 4 个 gate：

```bash
python -m src.gate_semantics.main --gate-number 4
```

若要调试第二次 boundary/fidelity reviewer：

```bash
python -m src.gate_semantics.main --gate-number 4 --debug-fidelity-review
```

该 flag 不是产品批量生成选项；默认命令对每个普通 gate 只发起一次分析调用。compound profile 自身的
fragment/composer 多调用属于其完整语义生成算法，不是这里的 debug reviewer。

canonical output root 仍包含完整 catalog；本次 `gate-slices.jsonl`、`gate-semantics.jsonl` 和 audit JSONL
只含 #4，同时在该行 `gate_uid` 对应的 `repository/<gate_uid>/` 下写四个 artifact，可直接比较输入切片、
compact IR、证据 sidecar 与完整 chat。可重复 `--gate-number` 选择多个 ordinal；zero、重复或越界编号会明确报错。

先安装固定的 SDK 与 MCP bridge（从仓库根目录）：

```bash
python -m pip install -r src/gate_semantics/requirements.txt
npm ci --prefix src/gate_semantics/lsp
```

真实启动 Pyright 和 TypeScript language server、覆盖 init/health/definition/references、document/workspace
symbols、diagnostics、type-definition 与 implementation 的集成测试：

```bash
python -m unittest src.gate_semantics.tests.test_lsp_integration -v
```

完整 gate suite 还会验证只读 tool inventory、write-tool exclusion、相对/绝对/URI/`..`/symlink root escape、
hook denial audit、SDK lifecycle 和 CLI/no-LSP fallback：

```bash
python -m unittest discover -s src/gate_semantics/tests -v
```

完整运行会逐 gate 创建独立 Claude Agent SDK/LSP 会话：

```bash
python -m src.gate_semantics.main
```

临时关闭 LSP、但保留 `Read`/`Grep`/`Glob`：

```bash
python -m src.gate_semantics.main --no-lsp
```

若 SDK/MCP 环境不可用，可显式使用旧 CLI transport：

```bash
python -m src.gate_semantics.main --agent-transport cli
```

默认输出目录是 `output/hermes/gate-semantics/`。这是 gate artifact 的唯一 ownership root；
`src.call_chain_semantics` 根据 current catalog 的 `gate_uid` 直接读取各个
`repository/<gate_uid>/semantic.json`，不会在自己的 output 下重新生成或复制 gate。顶层
`gate-semantics.jsonl` 仍是当前 gate run 的批量结果，不能代替这些独立 reusable artifacts。测试用 fake runner 覆盖 contract、repair、
evidence、安全边界和 30-gate rendering budget；涉及 DNS、配置、prompt 或外部状态的 gate 若做动态校验，
必须 mock dependency，禁止真实网络或副作用。

### 7.5 后续阶段边界

`src/call_chain_semantics/` 已实现确定性 V3 聚合：按 exact structural chain 收集 canonical per-gate IR，
按执行顺序逐字段内嵌并聚合 value identity、unresolved 和 status，再附加该链终点唯一的
`sink_constraint`。它不构造第二张 control-flow graph，也不调用 chain-stage LLM；约束中携带
capability-card path/digest，但覆盖域对比仍由后续消费者完成。本阶段不会把 `t→sinkArg`、sink 能力或
漏洞结论泄漏进单 gate 语义 prompt。

---

## 8. 落地顺序

1. **② filter 检测器**（§3）：纯静态、高精度、零 LLM，先覆盖 web_extract / `_make_run_env` 两个 GT。
2. **终端 sink constraint**（§5）：为每个 concrete sink callsite 生成唯一能力约束，记录受控参数、
   call shape 与 capability-card path/digest；它不是 gate，不进入 `gates[]`。
3. **③ transform**（§4）：`fte_transform.ql` 已实现人工净化签名表（标准 API + hermes 自定义）+ 同源污点穿过；
   泛化 `replace/sub` 留在 `needs-review`，Matrix callback/container 仅用审计后的窄 summary 补流。
4. **① 支配型**：`get_gates.ql` 已并入 (A)(B) 控制支配 + **(C) 同源污点穿过**、**分支局部 `branch-confirmed`**、
   **方法接收者检查值**与 parser/lookup 派生污点步、**(A′) 旁路开关透明化**
   （硬编码 `bypassFlagName`，首版 `force`，回收被 `if not force:` 埋掉的 terminal 审批 gate）、**卡点2 CHA 桥注入
   污点**（`isAdditionalFlowStep` 复用 `cha_calls`/`delivery_bridge` 补 arg→param，s 腿穿服务句柄到真 Popen，72 条
   needs-review 翻 confirmed、GT dominance needs-review 1→0）。**待办**：`bypassFlagName` 增补
   （`approval_mode`/`_allow_private_urls`）；嵌套子 gate 交 LLM 读函数体识别；正面的 bypass-surface 检测器
   （把 `force` 报为覆盖<能力）；收紧 (B) 到 predicate-like 去 confirmed 噪声。
5. **公共**：Source 用 `d5_param_extraction`；污点用无-sanitizer 的 `TaintTracking::Global`。
6. **跨组件**：`delivery_bridge` 放宽根到 d5 handler 后，同套 ②③ gate 检测器在网关/插件链上复用；
   平台发送端的伴随缓解字段归入终点 sink constraint，不作为第四类 gate。

> **一句话**：三类 gate 中，① 靠控制依赖支配、② 靠条件+集合写入——都**纯静态高精度**；
> ③ 靠**人工净化签名表**。每条链的终点能力由独立 `sink_constraint` 表达；「gate 覆盖域 < sink 能力域」
> 的最终判定统一交后续语义消费者。

TypeScript backend 复用同一三类 gate/constraint contract，但由 `src/ql-js` 项目 facade 分派。compiler bridge
现可对 inline prefix/binary condition、`.filter` callback element 和 library primitive argument 生成 resolved
binding；normalized-AST `gate_uid` 仍不含行号、空白或注释。NanoClaw 的 target-inbox 与 workspace-root 缺失控制
按 sink facet 和 exact chain 进入负 oracle，不能由源侧 `isPathInside` 或 `existsSync` 冒充。

Python fixture 另包含 empirical-ineligible 的 Nanobot login-shell synthetic regression：它要求生产 sink
predicate 识别 `ExecTool.execute` 内的 `asyncio.create_subprocess_exec`，并同时锁定 `HOME`、`-l`、`-c`
以及缺失 `--noprofile`/`--norc` 的源码形态。完整派生源码上的 Stage 2 还必须把 handler 参数
`command` 绑定为 sink argument；只有函数可达而缺少 `command→sink` 证据不算通过。该 fixture 只证明
detector 对移植缺陷形态的支持，不改变 revision-pinned gate baseline 或 empirical denominator。

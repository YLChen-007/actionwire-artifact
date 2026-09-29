# Hermes Call Chain 构建方案（CodeQL，预处理阶段）

> 管辖代码（见 `docs-map.yaml`）：`src/ql/call/call.qll`、`src/ql/call/sinks_af.qll`、`src/ql/util/util.qll`。
>
> 目标：为「工具调用语义不一致」检测的**预处理阶段**产出工件——从每个工具的 **handler
> 入口**出发，沿调用图（含 CHA/points-to 增强）走到人工指定的 sink 点，得到
> `工具 → 工具函数 → 多态分发 → 检查门 → sink` 的 call chain，供下游 LLM 抽取
> 「检查门语义 / sink 语义」并做一致性比对。
>
> 适用项目：`hermes-agent`（Python）。工具链：**CodeQL**。
> 实现参考 `related-work/sourcecode/AgentFuzz`（`src/ql/call/call.qll`、`src/ql/util/util.qll`、
> `src/ql/get_callchain_and_location.ql`）。

---

## 0. 在整体方案中的位置

```
整体数据流:  prompt → llm → tool → 解析命令 → 过滤(检查门) → 执行(sink)
                              └──────────── 本文负责的静态段 ────────────┘

本文产出:    handler (root) ──调用图(CHA 增强)──▶ sink callsite
             每条链路上每个 hop 带 file:line，作为下一步 LLM 阅读的输入
```

与 goclaw 版同形，差异只在**语言/工具**（Go+CHA → Python+CodeQL）与 **多态穿透手段**
（Go 的 `callgraph/cha` → CodeQL 的 CHA 风格 QL 边 + 内建 points-to）。

---

## 1. 总体流程

| 阶段 | 名称 | 手段 | 产出 |
|---|---|---|---|
| P1 | 枚举工具入口（root） | `is_tool_handler` 解析 `registry.register(handler=...)` | 62 个 handler `FunctionObject` |
| P2 | 标定 sink | 移植 AgentFuzz `is_sink` + 补 hermes 文件 sink，按 Cmd/Path/Network/Other 分类 | `is_sink` / `sink_category` |
| P3 | 构建调用图 | AgentFuzz 边 + 内建 `FunctionInvocation` + **类型约束 `cha_calls`**（self 层次 + 服务句柄桥）+ 审批 import-alias 桥 | `calls` / `inscope_calls` |
| P4 | 路径搜索 | depth `1..8` 内 (handler, depth, callee) 自由变量绑定 + `print_callchain` 重构 witness | `call_chains` 表 |

全部静态完成，**不运行 hermes**。CodeQL DB：`~/my-project/agent-research/clawgap/codeql-db/hermes-agent-db`
（`bin/codeql database create -l python`，`LGTM_INDEX_FILTERS` 排除 `.venv`/`node_modules`）。

---

## 2. 输入 / 输出

**输入：** hermes 源码 + CodeQL python DB。

**输出（`clawgap/output/hermes/`）：**
- `callchain.csv`：CodeQL 原始结果（每行一条 root→sink witness）。
- `call_chains.json`：解析成 goclaw 风格 schema：
  ```json
  {
    "tool_handler": "_handle_terminal",
    "tool_file": "tools/terminal_tool.py",
    "tool_line": 2667,
    "depth": 4,
    "sink_category": "Cmd",
    "sink_location": "subprocess.Popen@.../local.py$$603:...",
    "call_chain": "4#_handle_terminal@terminal_tool.py->terminal_tool@...->...->subprocess.Popen@local.py:603"
  }
  ```
- `run_summary.md`：链路条数、按 sink 分类计数、ground-truth 召回自检。

---

## 3. P1：枚举工具入口（`is_tool_handler`）

锚点：`registry.register(name=..., handler=<X>, ...)`（`tools/registry.py`）。识别两种 handler 形态：

1. **具名函数** `handler=_handle_terminal`：
   `reg.getArgByName("handler").(NameNode).getId() = f.getName()` 且与 register 调用同文件。
2. **lambda 包裹** `handler=lambda args, **kw: execute_code(...)`：
   `reg.getArgByName("handler").getNode() = lam`（`Lambda`），取 lambda 体内被调具名函数
   `inner.getScope() = lam.getInnerScope()` 作为 root（捕获 execute_code / web_search_tool /
   web_extract_tool / delegate_task / read_terminal_tool）。

> 工厂闭包 `handler=_make_handler(...)` / MCP `_make_tool_handler(...)` 暂不展开
> （对标 goclaw 对 MCP `BridgeTool` 的单独建模）。

**坑：** `registry.register` 的 object 必须是 `registry`（`AttrNode.getObject().toString() = "registry"`）；
root 必须过位置黑名单（排除 `tests/`，否则 `tests/.../test_tool_search.py` 的 `_handler` 漏进来）。

---

## 4. P2：Sink（移植 AgentFuzz + 补 hermes 文件 sink）

`is_sink_af` 当前包含 AgentFuzz `is_sink` 的全部 46 个顶层 disjunct，并保留本项目新增的
`md.convert` rendering sink 与 `prompt_dangerous_approval` approval-policy sink，共 48 个顶层
disjunct。迁移完整性由 sink debug 回归测试按谓词结构校验。
`get_handler_to_sink.ql` 与 `get_sinks.ql` 对传给 `asyncio.to_thread` 的已建模 callable 使用同一语义
method label；例如 Firecrawl 的 `to_thread(client.scrape, ...)` 输出 `scrape`，而不是 `to_thread`。

`is_sink_af` 只回答“这是否为 sink callsite”；污点终点由共享
`sinkSensitiveNode(sink, node, role)` 选择。该谓词没有“任意实参/receiver”fallback；新增 sink family
时必须同时登记其 capability-bearing 节点：

- `requests.get/post(url, ...)` 的 `url` 是第 0 个位置实参或具名 `url`；
- `requests.request(method, url, ...)` 及已建模 httpx/session `request` 的 `url` 是第 1 个
  位置实参或具名 `url`；`get` 仍使用第 0 个实参；
- process family 只取 command/argv 与能改变执行能力的精确 process control；code、SQL、template、
  filesystem-path 和 approval family 取其语义首参/具名参数。GT-backed
  `prompt_dangerous_approval(command, ...)` 因而只取第 0 个 `command`；
- `AsyncWebCrawler.arun`、Firecrawl/Exa/Parallel extraction 与浏览器导航取 URL；
  `AsyncHtmlLoader`/`WebBaseLoader.load()` 反查构造时的 URL，`GitLoader` 只取
  `repo_path`/`clone_url`，不取 branch、filter 或 loader receiver；
- path 方法只取携带路径的 receiver；Matrix/Slack/Mattermost 等 delivery primitive 只取 content/
  payload，其中 `chat_postMessage(**kwargs)` 精确取 `**kwargs` aggregate；
- 内部 RPC 的 body 只能由项目、文件、scope、call shape 和具名参数共同限定的
  `rpc-payload` 例外开启。当前例外是 `ManagedModalEnvironment._request(..., json=...)`、
  poco-agent 两个 client 的三个 internal callsite、Hermes Camofox `_post(..., json=body)`，以及 nanobot
  三个 search-provider `client.get(..., params=query)` callsite。后者的 URL 是固定/配置 endpoint，
  handler-controlled search query 由 `params` 承载；映射精确限定项目、文件、scope、receiver 和 method。

因此 TTS 的 `text → json=payload → requests.post` 不构成 URL/SSRF 链；只有 handler 输入到达
`base_url`/`endpoint` 时才能产生该 HTTP sink 链。`get_handler_to_sink.ql`、`get_gates.ql`、
`fte_filter.ql` 与 `fte_transform.ql` 统一消费该谓词，避免结构链、dominance、filter 和
transform 对 sinkArg 使用不同口径。

`is_sink` 拆成四个分类谓词（`sink_category` 用于输出归类）：

| 类别 | 谓词 | 覆盖 |
|---|---|---|
| Cmd | `is_cmd_sink` | `subprocess.Popen` / `subprocess.run` / `os.system` / ShellTool / PythonREPL / get_ipython（移植自 AgentFuzz） |
| Network | `is_net_sink` | `requests.*` / httpx Client / aiohttp ClientSession / AsyncWebCrawler / WebBaseLoader（移植） |
| Other | `is_other_sink` | `eval` / `exec` / cursor·session·connection.execute / SQLDatabaseChain / jinja / GitLoader（移植） |
| **Path** | `is_path_sink` | **新增**：`open` / `Path.read_text/write_text/...` / `os.remove/rename/...` |

> hermes 主 sink 是 `subprocess.Popen`（Cmd）——terminal/read_file/write_file/execute_code 全汇聚于此。
> Path 类登记备用（hermes 工具层基本走 shell，少有直接 `open()`）。

`prompt_dangerous_approval` 是一个有意保留的策略型例外：它不是进程执行 primitive，而是
`Tool-Action-Approval-Gate` 报告所选择的用户同意 sink。匹配限定为
`tools/approval.py` 中 `check_all_command_guards()` 内的 bare-name call，避免把同文件
`check_dangerous_command()` 中的旧调用一并分类。这样，batch runner 跳过审批交互的问题仍能以
handler→approval-sink 的链路表达，同时不会把所有同名调用扩成全局 sink。

---

## 5. P3：调用图（类型约束 CHA 是关键）

移植 AgentFuzz 的边：`FunctionInvocation`（内建 points-to）、`method_calls`（同类 `self.`）、
`direct_calls`（同作用域/builtin）、`module_calls`（同模块类方法）、`add_calls`（Process target 特例）。

**实测：纯 AgentFuzz 图 recall 不足。** terminal/read_file/write_file 都断在
`env.execute()`（变量上的跨类多态调用，points-to 解析不到工厂/缓存返回的环境实例）——
诊断显示这三个工具到达 0 个 sink。故按用户决定**接回 CHA**（先 AgentFuzz、不足再 CHA）。

**坑：朴素「按名 CHA」会爆炸。** 最初把 `obj.m()` 连到「任意同名方法 m」→ 全程序过连通
（连 feishu 评论工具 `_handle_add_comment` 都"到达" `subprocess.Popen`），因为 `execute`/`run`/`get`
等常见名把所有调用者经 `BaseEnvironment.execute` 连到命令 sink。**根因是 receiver 无类型约束**，
而 CodeQL 这版 `ControlFlowNode` 无可用的 receiver points-to。

**最终 `cha_calls`（双重类型约束，对标 AgentFuzz 自己的硬编码桥 `add_calls`）：**
- **(A) self 层次分发**：`self.m()` 仅连到 caller 所在**类层次**内（子类 override / 父类）名为 m
  的方法。精确覆盖 `BaseEnvironment.execute` 内 `self._run_bash()` → `LocalEnvironment._run_bash`。
- **(B) 服务句柄桥**：`env.m()` / `self.env.m()` / `file_ops.m()` 连到任意类中名为 m 的方法。
  约束在 **receiver 名**（`getServiceHandle()` 白名单 `env/environment/_env/file_ops/_file_ops`，
  这些是 hermes 工具层从工厂/缓存取到的服务对象）。覆盖 `terminal_tool` 内 `env.execute()`
  和 `ShellFileOperations._exec` 内 `self.env.execute()`、`write_file_tool` 内 `file_ops.write_file()`。
  receiver 名很具体 → 不会像「任意 X.execute()」那样全连通。

**审批 import-alias 桥。** `tools/terminal_tool.py` 把
`tools.approval.check_all_command_guards` 导入为 `_check_all_guards_impl`，随后
`_check_all_guards()` 通过该 alias 调用。当前 DB 的内建 `FunctionInvocation` 没有恢复这条边，
而 `direct_calls` 又要求 call 名等于 callee 名且通常同作用域，导致 terminal handler 到
`prompt_dangerous_approval` 的链断开。`approval_alias_bridge` 同时限定 caller
`_check_all_guards`、call `_check_all_guards_impl`、callee `check_all_command_guards` 及两端文件，
并接入 `calls` 和 `calls_cn`，分别保证可达性搜索与 witness 重构；不采用全局同名 alias 扩边。
在 `hermes-agent-db` 上重跑 `get_handler_to_sink.ql` 后只新增 1 条 approval-sink 链：
`_handle_terminal → terminal_tool → _check_all_guards → check_all_command_guards →
prompt_dangerous_approval`（depth 4）。

**实测效果**：terminal/read_file/write_file/patch/execute_code 全部到达 `subprocess.Popen@local.py:603`，
而 feishu/kanban/homeassistant 等工具产出 **0 条 Cmd 链**（无爆炸），eval ~18s。

**规模/精度抑制（除上述类型约束外）：**
1. **in-scope 收缩**：递归只走 `inscope_calls`（caller、callee 都过位置黑名单），把图从全程序
   收缩到核心代码（~900 函数）——也是**性能与磁盘 spill 的关键优化**。
2. **深度上限** `getDepthLimit() = [2..8]`（terminal→Popen 4 跳；文件工具链经 file_ops/_exec/env 约 7 跳）。
3. **位置黑名单**：排除 `tests/`、vendored、文档站点。

> 演进：新增工具若引入新的服务句柄名，在 `getServiceHandle()` 补充即可；若仍有虚假链，可把
> (B) 进一步收紧到 callee 所属类的层次（如 `BaseEnvironment`/`ShellFileOperations`）。算法可插拔，
> `Source` 只依赖 `calls`/`is_sink`。

---

## 6. P4：路径搜索（`Source`）

```ql
class Source extends PyFunctionObject {
  Source() {
    is_tool_handler(this) and          // root = 工具入口
    depth = [1..8] and
    r_calls(this, callee, depth) and   // depth 跳内到达
    is_sink(callee) and                // sink callsite
    isIncludeLocation2(this...)        // root 在 scope 内
  }
  string getPathStr() { ... }          // depth#mid@file->...->sink@file:loc
}
```

- 每个 `Source` 是 (handler, sink-callnode, depth) 三元组；`getPathStr()` 用 `find_mid` 重构链路串。
- 同一 (root, sink) 可能在多个 depth 命中 → 后处理按 (tool, sink_callsite) 取最小 depth 去重。

主查询 `get_callchain_and_location.ql` 选出
`tool_handler / tool_file / tool_line / depth / sink_category / sink_location / call_chain`。

---

## 7. 运行步骤

```bash
# 0. 建库（一次；已排除 .venv/node_modules）
LGTM_INDEX_FILTERS=$'exclude:.venv\nexclude:node_modules' \
  bin/codeql database create ~/my-project/agent-research/clawgap/codeql-db/hermes-agent-db \
  -l python -s /root/my-project/agent-research/clawgap/benchmark/python/hermes-agent --overwrite

# 1. 安装 pack 依赖
cd clawgap/src/ql && bin/codeql pack install

# 2. 跑查询（TMPDIR 指向有空间的盘；本机根 fs 满，用 tmpfs）
TMPDIR=/run/user/0/cqtmp bin/codeql query run \
  --database=~/my-project/agent-research/clawgap/codeql-db/hermes-agent-db \
  --output=/run/user/0/callchain.bqrs --threads=4 get_callchain_and_location.ql
bin/codeql bqrs decode --format=csv /run/user/0/callchain.bqrs > clawgap/output/hermes/callchain.csv

# 3. 解析成 JSON + 自检
python3 clawgap/output/hermes/parse_callchains.py
```

> **环境注意**：本机根文件系统当前 100% 满；CodeQL 评估 scratch 与输出需用 `TMPDIR` 重定向到
> 有空间的文件系统（tmpfs `/run/user/0` 或 `/mnt/d`）。in-scope 收缩后 scratch 很小（~数十 KB）。

---

## 8. 自检（Ground Truth）— 实测结果

全量运行（62 handler，depth 1..8，eval ~18s）：**231 条去重链（792 原始），30 个工具出链**。
按 sink 分类：Cmd 45 / Path 147 / Network 39 / Other 0。**Sink 召回 4/5**：

| 工具 | 期望 sink callsite | 命中 | 实际 |
|---|---|---|---|
| terminal | `subprocess.Popen` @ `local.py:603` | ✅ d=4 | `_handle_terminal→terminal_tool→BaseEnvironment.execute→LocalEnvironment._run_bash→Popen` |
| read_file | `subprocess.Popen` @ `local.py:603`（经 shell） | ✅ d=6 | 经 `file_ops.read_file→_exec→env.execute→…` |
| write_file | `subprocess.Popen` @ `local.py:603`（经 shell） | ✅ d=6 | 经 `file_ops.write_file→_atomic_write→_exec→env.execute→…` |
| execute_code | `subprocess.Popen` @ `local.py:413` / `code_execution_tool.py:1094` | ✅ d=4 / d=1 | 远端路径经多态穿透；本地路径用 `code→write(script.py)→Popen(_script_path)` 落盘执行桥 |
| web_search | `httpx`/`requests`（Network） | ❌ | lambda root 命中，但只到达 Path `open`；网络 sink 未命中 |

**唯一未命中（web_search → Network）是 sink 定义问题，非调用图问题**：AgentFuzz 的 httpx/requests
sink 模式针对 langchain 式用法（`with httpx.Client()`/特定注解），不匹配 hermes 经 backend/client
对象出网的写法。属第一步「sink 先用 call.qll」的预期缺口，列入后续（§9）。

**精度（无爆炸）**：feishu/kanban/homeassistant 等非命令工具产出 **0 条 Cmd 链**；到达 Cmd sink 的
工具均为命令相关（terminal/read_file/write_file/patch/search_files/browser_*/tts/execute_code）。

指标：**Sink 召回**为主；**Gate 弱覆盖**为辅（检查门函数是否出现在某 hop）。结果在 `output/hermes/run_summary.md`。

### 8.1 当前 D5 JSON 覆盖报告

`debug/script/render_d5_chain_coverage.py` 将已有 `chain-gates.csv`、显式辅助桥、handler 清单与 gate
元数据映射回 `design/hermes-agent/groundtruth/new-vuls/*.json`。默认只读取该目录的 9 个 JSON：共
9 条 handler-entry、12 条 sink、100 条 gate，合计 121 个 GT item；不再把根目录旧 JSON 或
`Issue-220/8033/8034/8035` 的历史 snapshot 行混入当前覆盖率。

```bash
python design/hermes-agent/call-chain/debug/script/render_d5_chain_coverage.py
```

生成 `debug/d5-chain-coverage.md`、`d5-chain-coverage.csv`、`d5-chain-coverage-items.csv`，并从当前 JSON
刷新 `d5-gt-items-snapshot.csv`。Markdown 开头自动记录带全部参数的仓库根目录生成命令。显式命名为
`missing`、`lacking` 或 `absent` 的 required-but-absent gate 不能由缺陷点上的偶然候选覆盖；当同版本
元数据将其标成 `absent-in-source` 时，该 gate 保留在完整 GT 分母，但从 supported/evaluable gate
分母排除。若某报告有 gate GT、匹配 chain、但 supported gate 分母为 0，摘要明确显示
`no-supported-gates`，避免把 `0/0` 写成 `supported-full`。JSON 始终是 item 集合的权威来源；当前生成
计数及 metadata 漂移数以 `debug/d5-chain-coverage.md` 顶部摘要为准。

dominance gate 的父子覆盖默认由当前源码自动推导，不再要求为每个报告手工列子 gate：renderer
先把 detector 的 `confirmed` / `branch-confirmed` 候选限制在已经匹配 handler 与 sink 的同一条 chain，
再从候选 callee 的源码函数出发，对有定义、可解析的本地/import 调用做最多 6 跳的有界搜索。GT
location 所在函数（`kind=function` 时优先采用 GT 名称/证据中明确出现的函数定义）若在该子树内，
就显式记为 `nested-in-gate(L{k})`；`L0` 表示父 gate 自身函数体内的 inline gate，`Lk` 表示经过
`k` 条正常调用边。`return imported_alias(...)` 这种纯转发 wrapper 作为 0 成本 alias 边，因此
terminal 的 `_check_all_guards → _check_all_guards_impl/check_all_command_guards` 不人为增加层级。
每条自动命中都在 item notes/debug trace 中记录 parent、child 与 source subtree path。
`taintC-per-gate.csv` 的旧式 parent reason 只作为源码解析不到时的兼容 fallback；它不能把未确认、
不同 sink 或不同 chain 的父 candidate 扩散到子 gate。

`d5-chain-coverage.md` 的 Ground-Truth Items 表另列 `Verdict`：它显示实际覆盖该 GT gate 的 detector
candidate verdict，并与 `chain-gates-coverage.md` 使用同一标记（`✅ confirmed`、`🔷
branch-confirmed`）。同一 GT gate 若在不同匹配链上由两类 candidate 覆盖，两类 verdict 都按固定顺序
列出；handler、sink、unsupported/uncovered gate 没有选中 gate candidate，故该列留空。
`nested-in-gate(L{k})` 命中继承并显示同链上被选中的父 gate candidate verdict，而不是为子 gate
虚构新的 detector verdict。

报告前部的 `Detector Verdict Distribution` 以一条 GT gate item 为计数单位，按该 item 的完整
`detector_verdict` 值统计数量及其占全部 GT gate 的比例。同一 gate 在多条 chain 上匹配时仍只计一次；
若同时聚合出 `confirmed; branch-confirmed`，该组合是独立分布值；未选中 detector candidate 的
uncovered、unsupported 或 absent-in-source gate 统一列为 `No matched detector verdict`。分布总数
必须与报告的 GT gate 总数一致。

Hermes 的通用 handler→sink 清单与摘要现在和其他 benchmark 使用同一 pipeline canonical 契约。
项目内 `debug/script/count_detected_call_chains.py` 只固定 project ID 与 CLI 路径，校验、刷新和渲染实现由
`design/common/call_chain_report.py` 统一提供。默认调用校验
`output/hermes/static/call-chains/{handler-sink-chains.csv,manifest.json}`，`--refresh` 时先顺序运行
`infer-gates` 与 `infer-call-chains`，再生成 `debug/handler-sink-chains.csv` 和
`debug/handler-sink-coverage.md`。canonical CSV 以唯一 `chain_id` 为行身份，并在摘要中将 canonical
链、去重结构 `call_chain` 与 concrete sink 分开计数。`render_chain_gates_coverage.py` 不再默认拥有
`handler-sink-coverage.md`；只有调用方显式传入 `--handler-sink-out` 时才生成旧式摘要，以保留临时目录
回归兼容性而避免覆盖通用报告。

### 8.2 Hermes D5 单调回归基线

`baseline/d5-covered-items-v1.json` 固化 revision
`04439ac77f08915b4886bc3c79165a9538af6219` 上已经证明覆盖的 **95** 个 GT item：handler **9**、
sink **12**、eligible gate **74**。基线单位是
`(json_id, item_kind, item_index)`，同时用 normalized GT metadata SHA-256 绑定 item 的名称、类型与位置。
它不固化 chain ID、CSV 行序、debug trace 或 Markdown 文本，因此新增 chain/gate 和覆盖提升不会失败；但任一
已批准 item 变成 uncovered、handler/sink provenance 降级，或 gate 不再由 `confirmed` /
`branch-confirmed` candidate 覆盖时必须失败。`needs-review` 不能满足 gate 基线。当前 7 个 uncovered gate 和
19 个 unsupported gate 继续留在 D5 报告中，但不作为已覆盖事实写入基线。

只检查已有 per-item CSV：

```bash
python scripts/test_hermes_d5_baseline.py \
  --items-csv design/hermes-agent/call-chain/debug/d5-chain-coverage-items.csv
```

完整回归命令不读取 canonical `chain-gates.csv` 当作新 QL 结果，而是在临时目录依次运行
`get_handler_to_sink.ql`、`get_gates.ql`、`fte_transform.ql` 和 `get_tool_handlers.ql`，再调用
`render_chain_gates_coverage.py --rebuild-chain-gates` 与 `render_d5_chain_coverage.py`，最后做集合包含检查：

```text
current eligible covered GT items ⊇ approved baseline items
```

```bash
python scripts/test_hermes_d5_baseline.py
```

所有 CSV/Markdown 写入 `mkdtemp` 目录，正常运行后自动删除，不覆盖 `debug/` 下的 canonical 生成物；调试时可加
`--keep-temp` 保留证据。基线测试本身没有自动更新模式：GT、revision 或批准覆盖集合改变时，必须显式审查
`d5-chain-coverage-items.csv` 差异并创建新版本 baseline，不能在测试失败时自动接受当前结果。

`.claude/settings.json` 的 `PostToolUse` hook 在 Claude 使用 Write/Edit/MultiEdit 修改
`src/ql/**/*.ql`、`src/ql/**/*.qll` 或 `src/ql/qlpack.yml` 后，只写入按 Claude session 隔离的 QL-dirty
marker；同一轮无论修改工具调用多少次，`Stop` hook 都只执行一次完整临时目录回归。成功后 marker 被消费；
失败返回 blocking exit code 2、保留 marker 并把具体缺失 item 反馈给 agent，使修复后的下一次 Stop 自动重试。
该 hook 依次执行本节 Hermes D5 baseline，以及 CowAgent、AstrBot、QwenPaw、nanobot、poco-agent 的
revision-pinned GT regression；任一项目失败都保留 marker。
其他编辑器/agent 不共享 Claude hook，因此最终统一门禁仍是 `python scripts/test_ql.py`。

---

## 9. 边界与后续

通用接口位于 `src/projects/`、`src/pipeline/` 与 `src/ql/project/ProjectModel.qll`。Hermes adapter 继续使用
`04439ac77f08915b4886bc3c79165a9538af6219` 作为分析 revision，保留既有 handler/sink、gate identity/order
和 `output/hermes` 路径。新项目通过 adapter 提供 concrete handler、tool name、source parameter、窄动态边、
registration metadata、location policy 与可选 sink extension；`get_project_model.ql` preflight 必须只选中一个
adapter。chain ID 只依赖 project/revision、ordered qualified hops、handler source 和 terminal sink point，
不依赖 checkout 绝对路径。

AstrBot adapter 还为 `ComputerBooter` component dispatch 和 `to_thread` callback 提供窄边。nested `_run`
只允许 lexical owner 调用，并通过 closure capture step 传播 owner parameter；这同时抑制 Python points-to/
`module_calls` 把同模块所有 `_run` 混为一体的虚假链。fixture 必须断言 filesystem/shell/python callback
各自只连自己的 owner。AstrBot GT full regression 进一步要求 6 个 current file sink 的 handler→sink recall、
187/192 两个 path gate、每 sink point 一个 capability constraint，以及 hardlink/inode missing control 不被伪造。

QwenPaw adapter 对 Windows shell 路径另补一条严格限定的 `asyncio.to_thread` callback edge：caller、callback
必须同在 `src/qwenpaw/agents/tools/shell.py`，调用 callee 必须是 `to_thread`，且 callback 必须由第 0 个实参按
函数名引用。仅有调用边不足以保留 handler 参数到 sink 的 taint；`projectBridgeTaintStep` 因而把
`to_thread(callback, arg1, arg2, ...)` 的第 `i+1` 个实参逐位连接到 callback 的第 `i` 个形参。该 bridge 只在
`qwenToThreadCallbackEdge` 已成立时启用，不泛化到无关 callback 或其他项目。

nanobot 与 poco-agent 使用直接 handler/source 模型：nanobot root 为 concrete `Tool.execute`，poco root 为
两个指定 factory 文件中的 `@tool` 函数。poco 的 injected client edge 同时支持跳过 `self` 的位置实参和
`getArgByName` keyword-only 对齐，并把 payload value 连到 dict/list/tuple container；`client.post` 与
`client.request` 分别在 channel runtime/memory 中作为 project sink。三个 adapter 均有 positive/negative
CodeQL fixture、revision-pinned GT oracle 与 fixed-DB runner，并已接入 `python scripts/test_ql.py` 和 Stop hook。

- **web 网络 sink（最优先）**：补 hermes 实际出网写法的 Network sink（backend/client 对象上的
  `httpx`/`requests`），让 web_search/web_extract/各外部 API 工具的 Network 链补全（当前 4/5 的唯一缺口）。
- 本文只产出 call chain（结构），不在 CodeQL 查询内抽语义或比对。下游实现见
  [`call-chain-semantics-design.md`](call-chain-semantics-design.md)：它消费 per-gate semantic IR，生成
  sink-invocation-bounded `CallChainSemanticIRV1`，仍不做 sink capability 或漏洞判断。
- 工厂闭包 / MCP 动态工具（`_make_handler`/`_make_tool_handler`）单独建模，不在主流程展开。
- sink 继续扩展：`_spawn_subprocess` 包装层、`aiohttp`、模板/反序列化/DB（Other）。
- 服务句柄桥 `getServiceHandle()` 随新工具按需补名；必要时把 (B) 收紧到 callee 类层次。
- 多语言统一（goclaw 已有 Go 版；TS/Java/C++ 另文）。

---

## 附：与 goclaw 方案的对应

| goclaw（Go/CHA） | hermes（Python/CodeQL） |
|---|---|
| `Tool` 接口 + `Execute` 方法 | `registry.register(handler=...)` 的 handler（具名 + lambda） |
| `callgraph/cha` 全程序图（用类层次类型） | `calls` 启发式 + 内建 points-to + **类型约束 `cha_calls`**（self 层次 + 服务句柄桥） |
| 人工 `sinks.yaml` | `is_sink` 四分类谓词（移植 AgentFuzz + 补文件 sink） |
| BFS root→sink witness | `r_calls` depth 搜索（自由变量绑定）+ `print_callchain` 重构 |
| barrier（暂不启用） | in-scope 收缩 + 深度上限 + **服务句柄白名单**（控 CHA 虚假边/防爆炸） |
| `ExecuteWithContext` 跨工具污染（CHA 类型已界定） | `env.execute()` 多态分发：Go-CHA 有类型；CodeQL 无 receiver points-to，故用服务句柄名定向桥 |

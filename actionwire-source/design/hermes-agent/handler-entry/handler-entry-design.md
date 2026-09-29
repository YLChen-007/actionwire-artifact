# Plan: 用 CodeQL 枚举 hermes-agent 所有工具 handler 入口并做 ground-truth 覆盖测试

## Context（为什么做这件事）

整体研究（[`design/整体设计.md`](../../整体设计.md)；公共方法见
[`design/common/detection-method.md`](../../common/detection-method.md)）要检测「工具调用检查点覆盖不足」漏洞，
预处理第一步 **P1** 是
枚举 call-chain 的 root anchor —— 即**每个工具自己的 handler 入口**（不是统一 dispatch 点）。
本任务只做 P1 的一个可验证切片：**找出 hermes-agent 中所有工具 handler 入口**，并用
`design/hermes-agent/groundtruth/new-vuls/*.json` 的 `d5_tool_handler_entry` 字段验证枚举是否覆盖全部
已知入口；当前输入为 9 个 JSON、10 条 handler-entry，不能覆盖的要给原因。

关键事实（已核实）：
- hermes 所有内置工具在 import 期通过 `registry.register(name=..., handler=...)` 自注册
  （`tools/registry.py`，`ToolEntry`）。`handler=` 就是 root anchor。
- `handler=` 有三种写法：① 具名函数 `handler=_handle_terminal`；② lambda 转发
  `handler=lambda args,**kw: execute_code(...)`（benchmark 树 35 处）；③ 工厂
  `handler=_make_handler(discord_core)` / MCP `_make_tool_handler(...)`。
- benchmark 树 `tools/` 下有 77 个 `registry.register(`，全树 95 个。
- **已有基础设施可复用**：`src/ql/call/call.qll:70` 的 `is_tool_handler` 已实现形态①②；
  `src/ql/util/util.qll` 的 `isIncludeLocation2` 用相对路径黑名单（tests/venv/site-packages），
  **与源码树绝对路径无关**，可直接用于 benchmark DB。`src/ql/qlpack.yml` = `clawgap-callchain` pack。
- **缺口**：现有 `src/ql/get_callchain_and_location.ql` 只输出「能到达 sink」的 handler，没有
  「枚举全部 handler 入口」的查询 —— 这正是本任务要补的。

## 与 prompt-entry 分析的边界

本模块产出的 handler 集合继续作为 call-chain root 的单一事实源。上游
`design/hermes-agent/prompt-entry/prompt-entry-design.md` 另行推断
`prompt entry → exposed tool → handler`，并按精确工具名连接本模块的 67 个 handler。
prompt-entry 映射只用于按入口过滤可达 handler，不把 call-chain root 上移到 `run_conversation`
或统一 dispatch 点。工具集引用但本 CSV 缺失的名字必须标为 `handler_unresolved`；插件/MCP
工厂注册则保留为 dynamic，不能当作“工具不存在”。

### Ground truth（来自 `groundtruth/new-vuls/` 的 9 个 JSON、10 条 `d5_tool_handler_entry`，去重后 7 个工具）

| # | tool name | GT anchor 函数 | is_tool_handler 形态 |
|---|-----------|----------------|----------------------|
| 1 | `skill_view` | `_skill_view_with_bump`（体内 `skill_view`） | 形态① 具名 |
| 2 | `send_message` | `send_message_tool` | 形态① 具名 |
| 3 | `browser_console` | `browser_console` | 形态② lambda 体 |
| 4 | `browser_snapshot` | `browser_snapshot` | 形态② lambda 体 |
| 5 | `terminal` | `_handle_terminal`（一条 GT 锚在体内 `terminal_tool`） | 形态① 具名（+1-hop 体） |
| 6 | `read_file` | `_handle_read_file`（reached_via 提到 `read_file_tool`） | 形态① 具名 |
| 7 | `execute_code` | `execute_code` | 形态② lambda 体 |

注：GT JSON 的 `location` 行号来自各自的受影响/分析 commit（如 terminal 1761、2576、2675），
与当前 benchmark HEAD 不必一致。故**匹配只按
(tool name + 函数标识)，不按行号**。

## 决策（已与用户确认）

- **DB**：在 **benchmark 树**重建：`~/my-project/agent-research/clawgap/benchmark/python/hermes-agent`
  （项目 CLAUDE.md/README 指定的测试目录）。不复用已有的 xclaw DB。
- **枚举范围**：沿用 `is_tool_handler` 的**具名 + lambda 两形态**，并对具名 wrapper 补出 1-hop
  工具体（覆盖 `terminal_tool` 这类体内锚点）。工厂/MCP 形态（`_make_handler`/`_make_tool_handler`）
  作为**已知限制**写明，不在本次解析范围（不影响 7/7 GT 工具覆盖）。

## 实施步骤

### 1. 构建 benchmark 树的 CodeQL DB
```bash
cd /root/my-project/agent-research/clawgap
export LGTM_INDEX_FILTERS=$'exclude:**/.venv/**\nexclude:**/node_modules/**\nexclude:**/site-packages/**'
bin/codeql database create codeql-db/hermes-agent-db \
  --language=python --threads=4 --ram=6000 --overwrite \
  --source-root=/root/my-project/agent-research/clawgap/benchmark/python/hermes-agent
```
（Python 无需 build。若 `LGTM_INDEX_FILTERS` 的 `**` 报错，则去掉 filters 直接建库——`isIncludeLocation2`
会在查询层兜底排除 tests/venv。）

### 2. 新增枚举查询 `src/ql/get_tool_handlers.ql`（复用现有 pack）
复用 `is_tool_handler` / `is_register_call`，**不带 sink 可达约束**，输出全部 handler 入口。
关键点：
- 主体：`is_tool_handler(handler)` + `isIncludeLocation2(handler.getFunction().getLocation())`。
- 补一个小 helper 取注册工具名：同一 `is_register_call` 的 `reg.getArgByName("name").getNode().(StrConst)`
  的文本（`name="terminal"` → `terminal`），并把它与 handler 配对（按 `reg` 与 handler 同文件 + handler
  名出现在该 reg 的 `handler=` 实参里，复用 `is_tool_handler` 内已有的配对条件）。
- 标注形态：`named`（形态①命中）/ `lambda-body`（形态②命中）。
- **1-hop 工具体增强**：对形态①的 wrapper，额外 select 其体内直接调用的、定义在工程内的具名函数
  （`FunctionInvocation`/`calls` 一跳），作为 `forwarded_body` 列——使 `_handle_terminal→terminal_tool`、
  `_handle_read_file→read_file_tool`、`_skill_view_with_bump→skill_view` 显式出现。
- select 列：`tool_name, form, handler_func, file, line, forwarded_body`。

> 形态②（lambda）已直接产出工具体（`execute_code`/`web_extract_tool`/`browser_navigate`/
> `browser_console`），无需再补。

### 3. 运行并导出 CSV
```bash
bin/codeql query run --database=codeql-db/hermes-agent-db \
  -o /tmp/tool-handlers.bqrs src/ql/get_tool_handlers.ql
bin/codeql bqrs decode --format=csv /tmp/tool-handlers.bqrs \
  > design/hermes-agent/handler-entry/debug/tool-handler-entries.csv
```
预期约 60+ 行（设计文档 `call_chain_hermes.md` 记为 62 个 handler）。

### 4. 比对 ground truth，生成覆盖报告
`debug/script/process_handler_entry_data.py` 从 `groundtruth/new-vuls/*.json` 加载 10 条 GT entry，
并与第 2 步 CSV 逐一匹配（按工具名 + 函数标识，忽略行号）：
- 命中 `handler_func` 或 `forwarded_body` 即 COVERED；
- 输出每条 GT JSON → 匹配到的 CSV 行（含 benchmark 树实际 file:line）+ 状态。

当前实测：**10/10 GT entry、7/7 工具覆盖**。其中 9 条命中 `handler_func`；锚在
`terminal_tool` 的 1 条经 `_handle_terminal` 行的 `forwarded_body` 命中。

### 5. 写产出物
镜像 `design/openclaw/` 的布局，落在 `design/hermes-agent/`：
- `debug/tool-handler-entries.csv` —— 全部 handler 入口枚举（§3 产出）。
- `debug/entry-ground-truth-coverage.csv` —— 10 条 GT entry 的结构化匹配结果。
- `debug/entry-ground-truth-coverage.md` —— 7 个工具 + 9 个 JSON 的覆盖表 + 结论（10/10）+ 行号差异说明。
- `README.md`（更新现有那份）—— DB 构建命令、查询说明、复现步骤、**已知限制**：
  1. 工厂/MCP handler（`_make_handler` discord、`_make_tool_handler` MCP 动态注册）未解析；
  2. `is_register_call` 要求接收者字面名为 `registry`，别名注册不命中；
  3. 行号按 commit 漂移，匹配按 (name+函数) 标识。

## 关键文件
- **查询** `src/ql/get_tool_handlers.ql`（在 `clawgap-callchain` pack 内，`import call.call`）。
- **生成器** `design/hermes-agent/handler-entry/debug/script/process_handler_entry_data.py`；默认 GT 路径为
  `design/hermes-agent/groundtruth/new-vuls`，运行命令会自动写入 Markdown 报告开头。
- **复用不改** `src/ql/call/call.qll`（`is_tool_handler`/`is_register_call`）、`src/ql/util/util.qll`
  （`isIncludeLocation2`）、`src/ql/qlpack.yml`。
- **产出** `design/hermes-agent/handler-entry/debug/tool-handler-entries.csv`、
  `entry-ground-truth-coverage.csv`、`entry-ground-truth-coverage.md`。
- **DB** `codeql-db/hermes-agent-db`（benchmark 源根）。

## 模型可见工具规范提取

共享实现与完整契约已迁到 [`src/handler_specifications/README.md`](../../../src/handler_specifications/README.md)。
Hermes 的 `debug/tool-handler-entries.csv` 仍是工具集合单一事实源；规范输出的 canonical 位置改为
`output/hermes/handler-specifications/tool-handler-specifications.{json,md}`，不再写入本 `debug/` 目录。
仓库根目录命令为 `python -m src.handler_specifications --project hermes-agent`；旧生成脚本仅保留为兼容
launcher，并生成与新命令相同的 v2 内容。

Hermes 适配器仍以 `registry.get_definitions()` 最终交给模型的 function shape 为准：注册名覆盖 schema 内的
`name`，`parameters` 按 `tools/schema_sanitizer.py` 的确定性规则归一化。每个 handler 只保留一个 canonical
record；`execute_code`、`browser_navigate`、`cronjob` 和 `terminal` 的配置相关文本用 source-backed
`runtime_rules` 表达，不展开成重复工具记录。canonical `execute_code` 使用全部七个 sandbox tool 和
`project` mode；`cronjob`/`terminal` 分别使用 `~/.hermes` 与 600 秒的源码默认值。

真实快照测试要求 67 行全部一对一解析、function name 与 CodeQL tool name 一致、所有 parameters 均为可
JSON 序列化的 object schema，并验证动态规则的代表性 materialization 和两次生成的字节确定性。emoji、
toolset、check function 等不参与模型选择的 registry metadata 不进入规范。

Project adapter 的 handler contract 不能只覆盖静态字典或 decorator。若项目先由 backend method 返回 callable
集合、再循环传给 toolkit 注册（QwenPaw 的 `list_memory_tools() → register_tool_function()`），必须同时约束
provider 的返回形态与 consumer 的注册形态，并枚举每个 concrete backend implementation。共享 tool name 不得
把不同实现合并成一个虚构 handler；以 `backend-profile` metadata 标出 default/optional activation。只被内部
调用但未从 provider 返回的 helper 必须是负例。revision-pinned full-DB regression 还应按
`tool_name + handler_func + file` 固定 required handler identity，避免 raw GT 只覆盖部分工具时漏检仍然通过。

GT section 校验默认保持严格：每个扫描到的 JSON 都必须包含 `d5_tool_handler_entry` list。只有项目的
revision-pinned oracle 已明确说明部分报告不属于 model-facing handler 范围时，项目 launcher 才可显式传
`--allow-missing-ground-truth-sections`。此模式会分别报告有/无该 section 的文件数和缺失文件名；缺失 section
不生成覆盖行，也不能用相似 handler 补造 ground truth。若有效 GT entry 总数为零，报告写
`0/0 (n/a)`，而不是 100% coverage。项目还必须用独立的 revision-pinned structural oracle 检查真实 handler
集合，避免 `0/0` 让损坏的 adapter 空通过。

## 验证（end-to-end）
1. DB 建库成功：`codeql database create` 退出 0，`codeql-database.yml` 的 `sourceLocationPrefix`
   指向 benchmark 树。
2. 查询可编译可运行：`codeql query run` 无错误，CSV 含 `terminal/read_file/skill_view/send_message/
   execute_code/browser_console/browser_snapshot` 全部 7 个 GT 工具名。
3. 覆盖：`entry-ground-truth-coverage.md` 中 10 条 entry 全部 COVERED；若任一 NOT-COVERED，给出原因
   （形态不支持 / 注册接收者非 `registry` / 工具确不存在于 benchmark 树等）。
4. 抽样人工核对：对 `terminal` 与 `browser_console` 各打开 benchmark 树对应 file:line，确认
   CSV 行指向真实 `registry.register(...)` 与 handler 定义。

---

# 步骤 3：验证 d5_tool_handler_entry → d5_sink_points 是否同一条 call chain

## Context（为什么做这件事）
步骤 1 枚举了 handler 入口（`is_tool_handler`），步骤 2 迁移并验证了 sink（`is_sink_af`）。步骤 3 是
把二者连起来：对 `groundtruth/new-vuls/` 的 9 个 JSON（10 条 handler-entry、20 条 sink point），验证其
**d5_tool_handler_entry 到 d5_sink_points 是否落在同一条调用链**（root=handler → … → sink）。handler
与 sink 在单个 JSON 内不预设一对一关系。这是整体方案 P1「root→sink call chain」预处理段的收口，
直接复用 AgentFuzz 的链路机制（clawgap `call.qll` 已增强：CHA 桥 + 服务句柄桥）。

## 已确认的可复用资产
- `src/ql/call/call.qll`：`is_tool_handler`（root）、`r_calls`/`inscope_calls`/`calls`（含 `cha_calls`
  多态桥 + `getServiceHandle`=env/file_ops 服务句柄桥）、`find_mid`/`print_callchain`/`get_sink_location`。
- `src/ql/call/sinks_af.qll`：`is_sink_af`（步骤 2 迁移的 AgentFuzz sink）。
- `src/ql/get_callchain_and_location.ql`：**现成模板**，已是 `is_tool_handler(h) ∧ r_calls(h,sink,d) ∧
  is_sink(sink)`；步骤 3 只需把 sink 谓词换成 `is_sink_af`。
- DB：复用步骤 2 的 `/root/codeql-home/dbs/hermes-xclaw-af-db`（xclaw 源树，handler 与 sink 同在其中）。

## 实施步骤
### 1. 新增查询 `src/ql/get_handler_to_sink.ql`（镜像 get_callchain_and_location.ql，sink→is_sink_af）
```
import call.call
import call.sinks_af
import util.util
from FunctionObject handler, int d, CallNode sink
where is_tool_handler(handler) and isIncludeLocation2(handler.getFunction().getLocation())
  and d = [1 .. 8] and r_calls(handler, sink, d) and is_sink_af(sink)
select handler.getName(), <handler file:line>, d as depth,
       sink 标签(file:line via get_sink_location), print_callchain(handler, sink, d)
```
> 深度 8 足以覆盖最长内进程链（terminal: `_handle_terminal→terminal_tool→[env.execute cha 桥]→
> execute→_run_bash→subprocess.Popen` ≈5 跳；Matrix: `send_message_tool→_send_matrix→session.put` 3 跳）。
> 若某已知对未出现，临时上调 `util.util` 的 `getDepthLimit()` 上界复跑（属共享改动，仅在必要时）。

### 2. 运行并导出 `design/hermes-agent/handler-sink-chain/handler-sink-chains.csv`
```bash
bin/codeql query run --database=/root/codeql-home/dbs/hermes-xclaw-af-db \
  --additional-packs=src/ql -o /tmp/h2s.bqrs src/ql/get_handler_to_sink.ql
bin/codeql bqrs decode --format=csv /tmp/h2s.bqrs > design/hermes-agent/handler-sink-chain/handler-sink-chains.csv
```
（join 较重：67 handler × is_sink_af 1216 sink × 深度 8；`inscope_calls` 已把图收缩到核心代码。若过慢，
回退为「按 d5 对的定向可达查询」——按当前 9 个 JSON 内声明的 handler/sink 关系检查 `r_calls` 可达。）

### 3. 逐 JSON 验证 9 个 GT 记录集合
匹配口径同前：**按 (handler 函数名 + sink file+调用形态) 匹配，忽略行号**。root 取 `is_tool_handler`
登记的 handler（形态①=wrapper 如 `_handle_terminal`，形态②=lambda 体如 `browser_console`/`execute_code`）；
d5 若把锚放在工具体（如 `terminal_tool`），它是同链上的中间 hop。

预判（待跑实证）：
| JSON | root handler | sink | 链路性质 | 预判 |
|---|---|---|---|---|
| 220 / Issue-220 skill-view | `_skill_view_with_bump` | `read_text`@skills_tool.py | 同文件 | 连通 |
| 38035 matrix | `send_message_tool` | `session.put`@send_message_tool.py(_send_matrix) | 同文件 | 连通 |
| GHSA browser-eval | `browser_console` / `browser_snapshot` | `_run_browser_command(eval/snapshot)`@browser_tool.py | 同文件、同 task session | 连通 |
| 762f7e97 / 6a320e8b / fd335a4e | `_handle_terminal` | `subprocess.Popen`@environments/local.py | env.execute 服务句柄+CHA 桥 | 连通 |
| Code-Execution | `execute_code` | `subprocess.Popen`@code_execution_tool.py | 同文件 | 连通 |
| Device-Blocking | `_handle_read_file` | 当前 JSON 的 `d5_sink_points` | file_ops 服务句柄 | 连通性待报告验证 |
| Discord-Mention | `send_message_tool` | `chat_postMessage`@gateway/platforms/slack.py；`_api_post`/`session.post`@plugins/platforms/mattermost | 跨模块 tools→gateway/plugins（疑跨进程投递） | **风险** |

### 4. 处理未连通对（NOT-CONNECTED 的根因分析）
对预判「风险」或实测未出现的对：(a) 先上调深度复跑；(b) 仍缺则归因——
- **同进程多态分发未桥接**（如 send_message→DeliveryRouter→platform.send）：在 `getServiceHandle()`
  补投递/平台句柄名，或加一条定向 `cha` 桥（与既有 env/file_ops 桥同法），复跑；
- **真跨进程边界**（gateway 作为独立 runtime 投递）：记为「跨进程，不在单进程 call-graph 范围」——
  这是符合整体设计的**合法发现**（对应 AgentFuzz Approach.md 的依赖注入断链观察），不强行造桥。

### 5. 产出物
- `src/ql/get_handler_to_sink.ql`；`design/hermes-agent/handler-sink-chain/handler-sink-chains.csv`；
- `design/hermes-agent/handler-sink-chain/handler-sink-coverage.md`：按 9 个当前 JSON 汇总，每条给 CONNECTED（witness 链+深度）
  / NOT-CONNECTED（根因），并标注哪些是同进程桥接、哪些是跨进程边界；
- 更新 `design/hermes-agent/README.md` 增「步骤 3」段。

## 关键文件
- **新增** `src/ql/get_handler_to_sink.ql`。
- **复用不改** `src/ql/call/call.qll`、`src/ql/call/sinks_af.qll`、`src/ql/util/util.qll`、`src/ql/get_callchain_and_location.ql`。
- **仅在出现同进程断桥时才改** `getServiceHandle()`（`src/ql/call/call.qll`）/ `getDepthLimit()`（`src/ql/util/util.qll`）。
- **DB** 复用 `/root/codeql-home/dbs/hermes-xclaw-af-db`。

## 验证（end-to-end）
1. 查询编译可运行、CSV 非空。
2. `handler-sink-coverage.md` 按当前 9 个 JSON 给出 CONNECTED + 见证链（`print_callchain` 的完整 hop 串 + 深度），
   或 NOT-CONNECTED + 根因（深度不足/多态未桥/跨进程）。
3. 抽样人工核对 2 条见证链：`_handle_terminal→…→subprocess.Popen`（确认经 env 服务句柄桥）、
   `_skill_view_with_bump→…→read_text`（确认同文件链），逐 hop 比对 xclaw 树源码。

---

# 步骤 4：寻找候选 gate（检查点定位 (A) 守卫提取 + (B) 候选识别）

## Context（为什么做这件事）
步骤 1–3 已得到 handler→sink 的 call chain。设计文档「检查点（Gate）定位方法」分三步：
**(A) 守卫提取（控制依赖/支配）→ (B) gate 候选识别 → (C) Source 污点确认**。本步只做 **(A)+(B)**
——在 call chain 的每个祖先函数里，找**支配 sink-ward 调用**的守卫条件，抽出其中的校验调用 = gate
**候选**。(C) 同源污点确认 + §不一致面 `t→g`/`t→sinkArg` 变换抽取留作步骤 5。

关键认知（已核实）：gate **不在 call chain 上**，而是 sink 之前的**兄弟分支**（early-return 守卫）。
两种形态都已在 GT 见到、且都被「支配」覆盖：
- `if _is_blocked_device(path): return …`（read_file_tool）——校验调用直接在条件里；
- `_guard = check_execute_code_guard(code, env_type); if not _guard["approved"]: return …`（execute_code）
  ——校验调用结果**赋值后再判**（其 def 流入支配条件）。

## Ground truth（`groundtruth/new-vuls/` 9 JSON 的 `d5_gate_points`，共 **151** 个）
- **56 个 `kind="function"`**：校验函数**定义**（`def _is_blocked_device` / `def check_execute_code_guard`
  / `def is_safe_url` / `def validate_within_dir` / `def _skill_lookup_path_error` …）。
- **95 个 `kind="adhoc"`**：gate **调用/条件点**（`if _is_blocked_device(path):` / `_guard = check_...(...)`
  / `lookup_error = _skill_lookup_path_error(name)` …）。
- 41 个 `existed_pre_patch=False`（修复新增）——用 post-fix benchmark DB 验证。
- 散落在 `tools/approval.py` `tools/url_safety.py` `tools/path_security.py` `agent/file_safety.py`
  以及 `gateway/platforms/*`、`plugins/platforms/*`（跨组件 gate）。

## 已确认可复用
- **`existworks/AgentFuzz/ql/get_if.ql`** 的控制依赖草图（`TestBlock` + 反向 `edges*`）——但它用
  「前驱可达」不是严格支配，**升级为 `ConditionBlock.controls(controlledBB, _)`**（CodeQL Python 内建）。
- 步骤 3 链机制：`is_tool_handler` / `r_calls` / `find_mid` / `calls_cn`（取 mid→next 的下沉调用点）/
  `is_sink_af`（sink 集合）/ `print_callchain`。
- **DB** 复用 `/root/codeql-home/dbs/hermes-xclaw-af-db`（HEAD，含修复后 gate）。

## Gate特殊示例：
gate是_foreground_background_guidance，判断是在 if guidance。
```python
        # background sessions, not foreground shell hacks.
        if not background:
            guidance = _foreground_background_guidance(command)
            if guidance:
                return json.dumps({
                    "output": "",
                    "exit_code": -1,
                    "error": guidance,
                    "status": "error",
                }, ensure_ascii=False)
```

## 实施步骤
我觉得gate静态识别可以相对保守一点，先把可能的候选都找出来，然后再使用llm来做进一步的验证和分类。下面是具体的实施步骤：

### 1. 新增 `src/ql/get_gates.ql`（候选 = (A)+(B)，不含 (C)）
对每条 handler→sink 链（`is_tool_handler` → `r_calls` → `is_sink_af`）上的每个函数 `F`（由 `find_mid`
枚举）+ 其「通往 sink 的下沉调用 `cs`」（`calls_cn(F, next, cs)`；当 `F` = sink 所在函数时 `cs` = sink 本身）：
- **(A) 支配**：`exists(ConditionBlock cb | cb.getScope() = F.getFunction() and cb.controls(cs.getBasicBlock(), _))`
  ——cb 守卫 cs（sink 落在「未 return」那一支）。
- **(B) 候选抽取**：gate 候选校验调用 `vc`（`CallNode`），满足其一：
  - `vc` 直接在 cb 的测试里（`vc` 是 `cb.getLastNode()`/测试表达式的子节点）——`if check(x):`；
  - `vc` 的结果经一次赋值流入 cb 的测试（def→use 到测试变量）——`x = check(); if x:`。
- 输出：`(handler, sink file:line, F 函数, gate 条件 callsite=adhoc gate, vc 解析到的被调函数=function gate, file:line)`。

### 2. 跑 → `design/hermes-agent/gate/gate-candidates.csv`
```bash
bin/codeql query run --database=/root/codeql-home/dbs/hermes-xclaw-af-db \
  --additional-packs=src/ql -o /tmp/gates.bqrs src/ql/get_gates.ql
bin/codeql bqrs decode --format=csv /tmp/gates.bqrs > design/hermes-agent/gate/gate-candidates.csv
```

### 3. 比对 151 个 d5_gate_points → `gate-candidate-coverage.md`
匹配口径同前（忽略行号）：`adhoc` 按 (file + 条件 callsite/evidence) 匹配候选的 gate 条件点；
`function` 按候选 vc 解析到的被调函数名/def 匹配。逐条 COVERED / NOT-COVERED + 原因。

预判（待实证）——**支配法天然覆盖「控制依赖型守卫」**：`if check():` / `x=check(); if x:` 形态的
adhoc 条件 + 其校验函数（`_is_blocked_device`/`check_execute_code_guard`/`is_safe_url`/`validate_within_dir`/
`_skill_lookup_path_error`/`get_read_block_error` 等）应大多命中。**支配法不覆盖**的 GT（明确列为已知限制，
留给步骤 5 的变换/污点分析或跨组件桥）：
- **数据结构型 gate**：`DANGEROUS_PATTERNS` 列表 @approval.py:367（不是条件，是 denylist 数据）；
- **变换型 gate**：Slack 控制字符转义、Matrix `_markdown_to_html`/`_sanitize_*`（是对数据的净化变换，
  不是支配 sink 的条件）——这正是 §不一致面 `t→g` 变换该抽的节点；
- **跨组件 gate**：`gateway/platforms/matrix.py`、`slack.py`、`plugins/.../mattermost` 里的 gate 支配的是
  网关/插件 sink，需在 `delivery_bridge` 接通的跨组件链上找（与步骤 3 #13 同源）。

### 4. 产出物
- `src/ql/get_gates.ql`；`design/hermes-agent/gate/gate-candidates.csv`；
- `design/hermes-agent/gate/gate-candidate-coverage.md`（151 行覆盖表 + 三类未覆盖归因）；
- 更新 `design/hermes-agent/README.md` 增「步骤 4」段。

## 关键文件
- **新增** `src/ql/get_gates.ql`（`import call.call` + `call.sinks_af`；升级 `get_if.ql` 思路为 `ConditionBlock.controls`）。
- **复用不改** `src/ql/call/call.qll`、`src/ql/call/sinks_af.qll`、`src/ql/util/util.qll`。
- **DB** 复用 `/root/codeql-home/dbs/hermes-xclaw-af-db`。

## 验证（end-to-end）
1. 查询编译可运行、CSV 非空。
2. `gate-candidate-coverage.md` 覆盖 151 个 d5_gate_points：给出命中数 + 三类未覆盖（数据结构/变换/跨组件）归因。
3. 抽样人工核对 3 条候选：read_file `if _is_blocked_device(path)`→`_is_blocked_device`、
   execute_code `if not _guard…`←`check_execute_code_guard`、skill_view `if lookup_error`←`_skill_lookup_path_error`，
   确认每条都「支配各自 sink-ward 调用」且抽出了正确的校验函数。

## 下一步（步骤 5，本步不做）
(C) Source 同源污点确认（`t→*g ∧ t→*sinkArg`，用 `d5_param_extraction` 做 Source 锚点）+ §不一致面把
`t→g` 与 `t→sinkArg` 两条数据流路径抽出，喂 LLM 判「覆盖域 < 能力域」。

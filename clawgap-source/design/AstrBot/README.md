# AstrBot 4.25.2 Pipeline Adaptation

AstrBot 是通用 Python benchmark pipeline 的第二个非 Hermes adapter。分析对象固定为：

- source root：`benchmark/python/AstrBot`
- release：`4.25.2`
- revision：`0e973bd4d483d18e1672c4dfa2eb7aae31bc1f83`
- benchmark state：以该 revision 为基础，显式回退 write/read root separation 补丁，用于受影响态回归
- CodeQL DB：`codeql-db/AstrBot-db`
- output：`output/AstrBot`
- raw GT：`design/AstrBot/groundtruth/new-vuls`
- revision-pinned oracle：`design/AstrBot/astrbot-4.25.2-acceptance.json`

四阶段命令是：

```bash
python -m src.pipeline --project AstrBot infer-gates
python -m src.pipeline --project AstrBot infer-call-chains
python design/AstrBot/call-chain/debug/script/count_detected_call_chains.py
python -m src.pipeline --project AstrBot infer-gate-semantics
python -m src.pipeline --project AstrBot infer-call-chain-semantics
```

`all` 按上述顺序运行。静态 acceptance 不依赖在线 LLM，只重建 stage 1/2；stage 3 使用
`DEEPSEEK_API_KEY` 环境变量，credential 不进入源码、命令、manifest 或报告。

## 1. Handler root 与 tool name

adapter 把 concrete `FunctionTool` subclass 的 `call(...)` 作为 root，不把 `FunctionTool.call`、
`FunctionToolExecutor.execute` 或 agent tool-loop dispatch 当 root。AstrBot 的 model-controlled source 是
concrete handler 中除 `self`、`cls`、`context` 外的形参；参数顺序按源码列号稳定输出。

已审计的 class-to-tool-name 映射在 `ProjectModel.qll` 的 `astrClassToolName`。GT 相关 root 是：

| Tool name | Concrete root | Current location |
|---|---|---|
| `astrbot_file_read_tool` | `FileReadTool.call` | `astrbot/core/tools/computer_tools/fs.py:245` |
| `astrbot_file_write_tool` | `FileWriteTool.call` | `astrbot/core/tools/computer_tools/fs.py:313` |
| `astrbot_file_edit_tool` | `FileEditTool.call` | `astrbot/core/tools/computer_tools/fs.py:388` |
| `astrbot_execute_shell` | `ExecuteShellTool.call` | `astrbot/core/tools/computer_tools/shell.py:84` |
| `astrbot_execute_ipython` | `PythonTool.call` | `astrbot/core/tools/computer_tools/python.py:84` |
| `astrbot_execute_python` | `LocalPythonTool.call` | `astrbot/core/tools/computer_tools/python.py:124` |

未在静态表中的 concrete subclass 仍以 class name 形成可审计 fallback name；动态 MCP tool name 保留为
`mcp-dynamic`，不猜运行时注册实例。

## 2. Project-specific call/taint edges

AstrBot 有两类普通 Python call graph 无法稳定恢复的运行时边：

1. `sb.fs/shell/python.<method>(...)`：`ComputerBooter` 注入的 component handle 分别连接到
   `LocalFileSystemComponent`、`LocalShellComponent`、`LocalPythonComponent` 的同名方法。具名或位置实参
   继续映射到 concrete method parameter。
2. `asyncio.to_thread(callback, ...)` / imported `to_thread(callback, ...)`：显式 callback 参数跳过第 0 个
   callable argument 后映射；nested `_run` 没有显式参数，因此把 lexical owner parameter 映射到闭包内
   同名 capture use。

同模块存在大量同名 `_run`。CodeQL 的通用 `FunctionInvocation`/`module_calls` points-to 会把它们合并，
例如把 `LocalShellComponent.exec` 错连到 filesystem `_run`。adapter 只允许 nested `_run` 的 lexical owner
调用它，并由 `astrToThreadCallbackEdge` 补回精确边。fixture 同时断言正确 owner edge 与不出现 unrelated
callback edge，避免以过连通换 recall。

## 3. Sink 与 terminal capability constraint

共享 `is_sink_af` 继续覆盖 process/file/network primitives。AstrBot 额外声明共享 catalog 未稳定表达的 read
形状：

- `read_local_text_range_sync` 的 `open(path, ...)`；
- `_read_local_file_bytes` 的 `to_thread(Path(path).read_bytes)`。

GT 当前 6 个唯一文件 sink 是：

| Capability | Current sink points |
|---|---|
| file read | `file_read_utils.py:217`, `:277`, `:289`, `:299` |
| file write | `booters/local.py:264`, `:280` |

每个 concrete sink point 在 `sink-constraints.csv` 中必须恰有一行。`Path.open`、direct/threaded
`Path.read_bytes` 映射到对应 capability card；`write_file._run` 的 `open(abs_path, mode, ...)` 使用 enclosing
function 解析动态 mode 为 `file-write`，不会因为 mode 不是 literal 而误标为 read。constraint 是 terminal
capability ceiling，不进入 `gates[]`。

## 4. Gate profiles

GT 路径 policy 的当前执行顺序为：

```text
handler path
  -> _normalize_rw_path
  -> _resolve_tool_path(path, ...)                 # transform callsite fs.py:176
  -> _is_path_within_allowed_roots(normalized_path) # dominance callsite fs.py:181
  -> file sink
```

`_resolve_tool_path` 是 project-scoped known transform，definition 在 `fs.py:135`，gate identity 绑定 callsite
`fs.py:176`。`_is_path_within_allowed_roots` 是 `_normalize_rw_path` 内的 nested returning-policy gate；detector
输出 child callsite `fs.py:181`，但 chain owner 保持 `_normalize_rw_path`，避免虚构 helper→sink 的正向边。
两者都必须对 GT read/write/edit chains 输出 `confirmed` 并按 176→181 保序。

`needs-review` 仍保留在 raw candidate CSV，但不能进入 semantic catalog 或 `chain-gates.csv`。没有 eligible
gate 的 process chain仍必须保留，并在 stage 4 形成 `gates: []` 加一个 `sink_constraint`。

## 5. Ground-truth rebase

raw GT 有两个 report，oracle 必须全部表示：

- `Advisory-GHSA-3jx4-q2m7-r496-WorkspaceHardlinkAlias`：在当前 revision 仍按 pathname containment
  授权，缺失 filesystem object/inode identity validation；要求 read 的 4 个 sink 与 write 的 1 个 sink
  全部有 handler→sink chain，且不得伪造 `hardlink`/`inode`/`samefile` gate。
- `Add_admin_permission_checks_for_Python_and_Shell_execution-PathMismatch`：benchmark 已显式回退 write/read
  root separation；restricted member 的 write/edit 再次复用包含 plugin Skills 的 `_read_allowed_roots`。因此
  oracle 将其标为 `affected`，要求 write/edit current chains、现有 path gates 与缺失的 write-policy separation。

GT gate definition anchor 与 callsite-bound detector identity 不是同一个坐标：oracle 用当前 callsite 176/181
做检测断言，并把旧 revision 行号单列为 stale source anchors，不用模糊行号匹配掩盖版本差异。

生成 canonical coverage：

```bash
python design/AstrBot/call-chain/debug/script/render_gt_coverage.py \
  --oracle design/AstrBot/astrbot-4.25.2-acceptance.json \
  --ground-truth design/AstrBot/groundtruth/new-vuls \
  --source-root benchmark/python/AstrBot \
  --pipeline-output output/AstrBot \
  --out-dir design/AstrBot/call-chain/debug
```

生成器在 Markdown 开头写完整命令，并把 source-report、sink-chain、detected-gate、expected-missing、
current-policy、stale-source-anchor 和 zero-gate-chain 分行输出。不能手改生成 CSV/Markdown。

## 6. Regression gates

快速 fixture/unit：

```bash
bin/codeql test run --additional-packs=src/ql -- src/ql/tests/astrbot_project_model
python design/AstrBot/call-chain/debug/script/test_render_gt_coverage.py
python -m unittest src.pipeline.tests.test_pipeline
```

固定 DB 上重新生成 stage 1/2 并执行 oracle：

```bash
python scripts/test_astrbot_gt_coverage.py
```

`python scripts/test_ql.py` 串行运行 Python/JavaScript QL fixtures、九项目 baseline/GT renderer tests，编译
两个 production query pack，再执行 Hermes monotonic D5 baseline 和八个 adapter 的 fixed-DB GT acceptance。
共享 TypeScript pack 的项目包括 OpenClaw、NanoClaw 与 LobsterAI。`.claude` QL-dirty Stop hook 同样串行执行
九项目 full-DB regression；任一失败都保留 marker。

新增后续 Python benchmark 时复用相同步骤：先固定 source/revision/DB，定义 concrete root/name/source，补最窄
dynamic edge 与 sink extension，添加 positive+negative CodeQL fixture，再把 raw GT rebase 成 revision-pinned
oracle；只在临时输出通过后发布 canonical artifacts。

## 7. Handler-entry 与 sink 独立报告

AstrBot 在各自的 `debug/scripts/` 中提供 project-owned launcher；launcher 固定 explicit revision、DB/GT/output
path，再调用 Hermes 的 deterministic processor。生成报告因此记录 AstrBot launcher，而不是直接记录 Hermes
processor 的长参数命令。当前 handler
inventory 共 27 行，raw GT 4 条 entry（3 个 distinct tool）全部命中 concrete `FunctionTool.call`；sink
inventory 共 369 个 callsite、31 个 label，raw GT 7 条 sink 全部有当前 DB evidence。

```bash
python design/AstrBot/handler-entry/debug/scripts/generate_handler_entry_data.py

python design/AstrBot/sink/debug/scripts/generate_sink_data.py
```

三个 composite raw sink name 同时描述 `builtins.open` 与 owner/`f.write`；override 将 capability boundary
明确固定为当前行的 `open(path, ...)`，每条报告均标记 `explicit-revision-override`。PathMismatch 的 benchmark
状态由 revision-bound oracle 标记为 `affected`；write/edit 对 plugin Skills 的 read-root policy reuse 是缺陷证据。

共享门禁 `python scripts/test_ql.py` 现顺序运行 Python 与 TypeScript fixtures/production packs，并在既有 adapter
之后执行 OpenClaw、NanoClaw 的 fixed-revision acceptance；同一 DB 不并发访问。
## Shared gate regression

The repository QL gate now also validates the revision-pinned zero-gate audit schema and witness
coverage. AstrBot keeps its existing approved `_resolve_tool_path` transform and existing filter;
the cross-project generalization does not promote generic rewrites by name.

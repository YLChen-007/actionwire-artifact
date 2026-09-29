# CowAgent 2.0.8 Benchmark Adapter

本目录管辖 `chatgpt-on-wechat`（现 CowAgent）在通用 Python benchmark pipeline 中的项目映射与 acceptance
oracle。分析源码固定为 `benchmark/python/chatgpt-on-wechat`，release 2.0.8 revision
`55aaf60a57ea6e9f4b8a54797572d98f65e88d2f`，输出为 `output/chatgpt-on-wechat`。

本次适配的完整总结、通用/项目专用边界，以及后续 Python benchmark 的逐步接入清单见
[`ADAPTATION_SUMMARY.md`](ADAPTATION_SUMMARY.md)。

CodeQL root 仅接受 concrete `BaseTool` subclass 的 `execute(self,args)`；抽象 `BaseTool.execute`、统一
`execute_tool`/`_execute_tool` dispatcher、非 BaseTool infrastructure operation 均不是 root。adapter 另建模
BrowserTool `_ACTION_MAP`、BrowserTool→BrowserService method 和 `_submit(callback, ...)` 三类窄边，并排除
`.agentfuzz-main-venv`、cache、site-packages，但不排除真实 `channel/web`。

四阶段命令：

```bash
python -m src.pipeline --project chatgpt-on-wechat infer-gates
python -m src.pipeline --project chatgpt-on-wechat infer-call-chains
python design/chatgpt-on-wechat/call-chain/debug/script/count_detected_call_chains.py
python -m src.pipeline --project chatgpt-on-wechat infer-gate-semantics
python -m src.pipeline --project chatgpt-on-wechat infer-call-chain-semantics
```

静态 acceptance oracle 位于 `groundtruth/cowagent-2.0.8-acceptance.json`，按当前源码重定位六个漏洞维度和七个
distinct sink points，并把两个等价 Vision SSRF report 去重。轻量静态 GT regression 只重建 stage 1/2 并运行
oracle renderer，完整命令为：

```bash
python scripts/test_chatgpt_on_wechat_gt_coverage.py
```

该命令把 pipeline 和报告产物全部写入临时目录，不覆盖 canonical `output/chatgpt-on-wechat` 或 `debug/*.csv/md`。
它要求七个 current sink points 都存在对应 handler→sink chain、每个 sink point 恰有一个 constraint、五个
oracle-declared existing gate anchor 全部挂接，并保持四个 expected-missing control 不被伪造。新增非 GT
chain/gate 不会导致失败。只检查现有 canonical static output 时可运行：

```bash
python scripts/test_chatgpt_on_wechat_gt_coverage.py \
  --pipeline-output output/chatgpt-on-wechat
```

`python scripts/test_ql.py` 的完整模式和 Claude QL-dirty Stop hook 都依次执行 Hermes D5 baseline，以及
CowAgent、AstrBot、QwenPaw、nanobot、poco-agent、OpenClaw、NanoClaw、LobsterAI regression。九个项目共享
project-model adapter preflight 和
生产查询编译门禁；`--unit-only`
只执行 Python/JavaScript fixture、comparator 和 renderer failure-path tests。

较完整的 D5 call-chain 覆盖报告同时读取 raw JSON、oracle、
结构链、`chain-gates.csv`、gate semantics 和 terminal `sink_constraint`；覆盖报告只能由以下命令生成，不能手改
CSV/Markdown：

```bash
python design/chatgpt-on-wechat/call-chain/debug/script/render_d5_chain_coverage.py
```

生成器写出 `d5-chain-coverage.csv`、`d5-chain-coverage-items.csv`、`d5-chain-coverage-debug.csv` 和
`d5-chain-coverage.md`。Markdown 开头保留完整仓库根目录生成命令；ground-truth symlink 仍以仓库内相对入口显示。

匹配规则沿用 Hermes 报告的 provenance 口径：raw 位置与当前 evidence 一致时才是 exact；否则只能以同文件
symbol、source owner、near-location semantic 或 `nested-in-gate` 证据重定位。`existed_pre_patch=false` 不进入
当前 gate recall，expected-missing 使用完整 gate semantic profile 检查，不能靠空的 forbidden-name 集合通过；
transform GT 只能由 eligible transform candidate 覆盖。报告分别呈现 duplicate reports、stale anchors、
handler/sink chain、constraint cardinality、ordered gates、semantic status 和完整 matcher trace。危险 live exploit 和
prompt-entry reachability 不在本 acceptance 范围。

轻量 oracle CSV/Markdown 由以下命令生成，其输出用于审计 regression contract，但 full regression 默认在临时
目录生成：

```bash
python design/chatgpt-on-wechat/call-chain/debug/script/render_gt_coverage.py
```

## Handler-entry 与 sink 独立报告

本项目在各自的 `debug/scripts/` 中提供 project-owned launcher；launcher 固定 project title、explicit revision、
DB/GT/output path，再调用 Hermes 的 deterministic processor。生成报告因此只需记录本项目 launcher，不直接暴露
跨项目的长参数命令。
handler inventory 共 14 行，raw GT 的 7 条 entry（5 个 distinct tool）全部命中 concrete
`BaseTool.execute`；sink inventory 共 348 个 callsite、15 个 label，raw GT 9 条 sink 全部有当前 DB evidence。

```bash
python design/chatgpt-on-wechat/handler-entry/debug/scripts/generate_handler_entry_data.py

python design/chatgpt-on-wechat/sink/debug/scripts/generate_sink_data.py
```

两个 historical Bash `subprocess.Popen` raw entry 在 2.0.8 已变为 `subprocess.run`；override 文件只做
revision-pinned API rebase，并在每条 coverage row 中保留理由。七个 unique current GT sink point 的完整性仍由
call-chain oracle 强制，不能用这里较宽的 raw method-name coverage 替代。

共享门禁 `python scripts/test_ql.py` 现顺序运行 Python fixtures/production pack、共享 TypeScript pack，及包括
OpenClaw、NanoClaw 在内的 revision-pinned adapters；同一 DB 的任务不并发执行。
## Zero-gate audit

The shared QL regression now includes the cross-project zero-gate audit tests. This adapter adds
the exact `agent/tools/read/read.py::Read._resolve_path` transform signature, restricted to its
`Read.execute` callsite and the `open`-bound path flow. Same-named Edit/Write helpers and
compatibility/environment syntax rewrites remain excluded or review-only. The originally-zero
filter cell still requires per-canonical-witness `confirmed-zero` records at the pinned revision.

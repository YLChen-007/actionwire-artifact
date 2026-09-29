/**
 * @id clawgap/hermes-gates
 * @name hermes 支配型 gate（(A) 控制支配 ∧ (B) 校验调用 ∧ (C) 同源污点穿过）
 * @description gate-fte-design §2：在 handler→sink call chain 的每个函数里找**支配 sink-ward 调用**的守卫条件
 *              (A)（`ConditionBlock.controls`），抽其中/流入的校验调用 vc = 候选 (B)，再要求该候选被**同源污点
 *              穿过** (C)：存在 Source 参数 t（≈ d5_param_extraction，取 on-chain 函数形参），t →* vc 的被检查
 *              实参 g，且 t →* sink 实参 sinkArg（同源）。(C) 用**无 sanitizer** 的 TaintTracking::Global（§1）。
 *              按 §1.1 分级、不静默丢：taint_verdict=confirmed 表示严格支配 gate 的 (C) 成立；needs-review 表示
 *              (A)(B) 成立但污点未连通（未建模的容器/跨组件步，如 env 服务句柄分发）。taint_verdict=branch-confirmed
 *              表示非全局支配、但 gate 所在分支到 sink-ward 调用可达，且 gate 检查值与 sinkArg 同源。
 *              下游取 confirmed/branch-confirmed 即真 gate，branch-confirmed 语义弱于严格 confirmed。
 *              (A) 含**透明化**（§1.1 例外）三类：`if not force:` 硬编码旁路 `[bypass:force]`、`if x: vc(x)` 被校验参数
 *              存在守卫 `[opt-guard:x]`、`for x in xs: if bad(x): return` 简单迭代器 loop-aggregate `[loop:x]`——它们本身
 *              不算 gate 但被当透明，让内层真 gate（`_check_all_guards`/`_validate_workdir`/web_extract secret-block）浮出。
 *              验证 DB：/root/codeql-home/dbs/hermes-xclaw-af-db。
 * @kind table
 * @tags clawgap
 */

import python
import call.call
import call.sinks_af
import gate.GateShapes
import util.util
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

// call chain 上的函数（handler 可达 + 到达某 is_sink_af sink）——由 find_mid 精确给出链上每个 mid。
predicate onChainMid(FunctionObject f, CallNode sink) {
  exists(FunctionObject h, int d, int k |
    is_tool_handler(h) and
    is_sink_af(sink) and
    isIncludeLocation2(sink.getLocation()) and
    r_calls(h, sink, d) and
    find_mid(h, sink, f, d, k)
  )
}

// F 内「通往 sink 的下沉调用 cs」：F 直接包住 sink 时 cs=sink；否则 cs 是 F→下一个链上函数的调用点。
predicate sinkwardCall(FunctionObject f, CallNode cs, CallNode sink) {
  onChainMid(f, sink) and
  (
    cs = sink and sink.getScope() = f.getFunction()
    or
    exists(FunctionObject next | onChainMid(next, sink) and calls_cn(f, next, cs))
  )
}

// ===== (A′) 硬编码旁路开关透明化（§1.1 例外 / bypass surface）=====
// `if not force:` 这类**策略开关/配置门**查的是配置或标志、非污点值，本身不算 gate（§1.1 例外）；但它
// **不该挡住被它包住的内层真 gate**（如 terminal 的 `_check_all_guards(command)`）。这里维护一张**硬编码
// 旁路开关名表**，把命中的外层条件当「透明」——支配判定 (A) 忽略它，让内层数据-检查点浮出。首版仅列
// force（terminal 审批 `if not force:` 旁路：762f7e97/6a320e8b/fd335a4e）；后续可增补 approval_mode / _allow_private_urls 等。
predicate bypassFlagName(string s) { s = "force" }

predicate isBypassCondition(ConditionBlock outer, string flag) {
  bypassFlagName(flag) and
  exists(Name n | n.getId() = flag and n.getAFlowNode().getBasicBlock() = outer)
}

// **被校验参数的存在守卫**：外层测试是**裸 Name `x`**（`if workdir:`）或 `not x`（无 call/比较/下标），且该 `x`
// **正是内层校验调用 vc 的实参**（`if workdir: err=_validate_workdir(workdir); if err: return`）。语义：可选参数在场
// 才校验——`x` falsy 时跳过校验，但该参数此时**也未被使用**，故 vc 仍是覆盖 `x` 的**完整 gate**，不该被存在守卫埋掉。
// 关键约束「x 是 vc 的实参」把透明化**限定到「守卫的正是被校验的那个值」**，避免退化成「任意 `if x:` 都透明」而爆炸。
predicate isPresenceGuardOfArg(ConditionBlock outer, CallNode vc, string name) {
  not isBypassCondition(outer, _) and
  exists(Variable v, Expr test |
    test = outer.getLastNode().getNode() and
    (
      test.(Name).getVariable() = v
      or
      test.(UnaryExpr).getOp() instanceof Not and test.(UnaryExpr).getOperand().(Name).getVariable() = v
    ) and
    name = v.getId() and
    exists(Name argUse | argUse = vc.getAnArg().getNode() and argUse.getVariable() = v)
  )
}

// cb 守住了一个阻断出口（早退 return / raise）——确保被透明化后浮出的是真挡路 gate，不是取值分支。
predicate guardsBlockingExit(ConditionBlock cb) {
  exists(ControlFlowNode fn |
    cb.controls(fn.getBasicBlock(), _) and
    (fn.getNode() instanceof Return or fn.getNode() instanceof Raise)
  )
}

// 短路 or 链守卫 `if A or B or …: return`——**没有单一 ConditionBlock 支配 return**（return 从任一 operand-true
// 都可达，每个 operand 的块都不独占），故上面按块的 guardsBlockingExit(cb) 会漏（实测 web_extract 的四路 or 即 Q4=NO）。
// 改在 **If AST 层**判：cb 是某 If 测试的子表达式、且该 If 的 then-body（getStmt，不含 else）**直接**含 Return/Raise。
predicate ifThenBlocksExit(ConditionBlock cb) {
  exists(If ifs, Stmt exit |
    ifs.getTest().getASubExpression*() = cb.getLastNode().getNode() and
    exit = ifs.getStmt(_) and
    (exit instanceof Return or exit instanceof Raise)
  )
}

// ===== (A″) 简单 for 迭代器透明化（loop-aggregate 守卫）=====
// `for x in xs: if bad(x): return` —— 守卫在**逐项循环体内**、sink 在**循环之后**（`provider.extract(safe_urls)`）。
// 纯基本块支配抓不到：for 的「迭代耗尽」出边直达 sink、旁路该条件，故 `cb.controls(sink,_)=NO`（实测
// web_extract：diag_web_extract.ql P2=NO，同块 in-loop append P3=YES）。但语义上「逐项都过了守卫、任一失败即 return
// 退出，才能正常走出循环到 sink」== 该守卫覆盖到 sink。故把**简单迭代器**（单 Name 目标 `for x in …`）当透明。
// 收紧（仿 opt-guard「x 是 vc 实参」，避免退化成「任意 for 内 if 都透明」而爆炸）：**vc 的实参就是循环变量 x**——
// 守的正是被迭代项；再叠加既有 guardsBlockingExit（必须早退，天然排除只 append 不 return 的 filter 型循环）。
predicate isLoopGuardBeforeSink(ConditionBlock cb, CallNode vc, CallNode cs, string itervar) {
  exists(For loop, Variable v |
    loop.getScope() = cb.getScope() and
    loop.getTarget().(Name).getVariable() = v and // 简单迭代器：单 Name 目标（`for a,b in` 的 Tuple 目标不算）
    itervar = v.getId() and
    // 守卫 cb 在循环体内（其被测节点的 AST 祖先含该 for）
    cb.getLastNode().getNode().getParentNode+() = loop and
    // 收紧：vc 的实参就是循环变量（守的正是被迭代项）
    exists(Name u | u = vc.getAnArg().getNode() and u.getVariable() = v) and
    // sink-ward 调用 cs 在该循环**之外**、同作用域（循环后的 sink）
    cs.getScope() = loop.getScope() and
    not cs.getNode().getParentNode+() = loop
  )
}

// 透明分支 (A′)(A″) 专用：gate 块 cb 必须能在**前向控制流**里到达 sink-ward 调用 cs——否则 cb 在 cs
// **之后**执行，根本管不到它。透明化只解除「cb 不严格支配 cs」这一条（`not cb.controls(cs,_)`），但那是**负**
// 约束，对「cb 在 cs 后」和「cb 在 cs 前但被可选外层守卫包住」**一视同仁**——会把 sink 后面的无关早退 gate 错配上来
// （实测 skill_view：collision-scan 循环里的 `read_text`@1065 被文件读分支里 `if has_traversal(file_path):`@1197
// 的 opt-guard 错配，1197 在 1065 之后、另一分支，实为无关）。加此**正**向可达约束即排除。严格支配 (A) 天然满足
// （支配 ⟹ 可达），故只加在 (A′)(A″) 上。
predicate gateBlockReachesSink(ConditionBlock cb, CallNode cs) { cb.getASuccessor+() = cs.getBasicBlock() }

// ===== (B3) 无调用的 inline early-exit gate =====
// `if not repo or not pr_number: return` 的 gate 是整个条件，而不是给 repo/pr_number 生产值的
// `dict.get`。只纳入：条件内无调用、then 直接 return/raise、条件块在 CFG 上能前向到 sink-ward call。
predicate inlineEarlyExitShape(
  FunctionObject f, CallNode cs, CallNode sink, If guard, Expr test
) {
  sinkwardCall(f, cs, sink) and
  guard.getScope() = f.getFunction() and
  callFreeEarlyExitCondition(guard, test) and
  exists(ConditionBlock cb |
    cb.getScope() = f.getFunction() and
    cb.getLastNode().getNode() = test.getASubExpression*() and
    gateBlockReachesSink(cb, cs)
  )
}

// inline 条件中真正被读取的原子 Name。至少一个这样的值必须与 sinkArg 同源；完整条件仍作为
// 一个复合 gate 输出，由 Python slicer 从 source location 恢复所有 operand 和短路顺序。
predicate inlineGateArgNode(If guard, DataFlow::Node g) {
  exists(FunctionObject f, CallNode cs, CallNode sink, Expr test, Name checked |
    inlineEarlyExitShape(f, cs, sink, guard, test) and
    checked = test.getASubExpression*() and
    g.asCfgNode() = checked.getAFlowNode()
  )
}

// (A) 支配 cs 的条件块 cb（含 A′ 旁路透明化）+ (B) cb 里/流入 cb 的校验调用 vc。
// 注：支配判定**内联**在此（不抽成带自由 cs 的独立谓词）——sinkwardCall 先把 cs 约束到少量 sink-ward
// 调用、cb.getScope 把 cb 约束到 f 内条件块，controls / not controls 只在这些已绑定对上算，避免物化
// 「全部 cb × 全部 cs」的支配关系（曾导致 600s 超时）。
predicate gateCandidate(
  FunctionObject f, CallNode cs, CallNode sink, ConditionBlock cb, CallNode vc, string kind
) {
  sinkwardCall(f, cs, sink) and
  cb.getScope() = f.getFunction() and
  vc != cs and
  not is_sink_af(vc) and
  exists(string base |
    gateCallShape(cb, vc, base) and
    (
      // (A) 严格支配
      cb.controls(cs.getBasicBlock(), _) and kind = base
      or
      // (A′) 透明守卫：cb 被一个「透明外层守卫」outer 包住、且 cb 守着阻断出口时，把 outer 当透明——让内层真
      // gate 浮出。两类：① 硬编码旁路 flag `force` → `[bypass:<flag>]`；② `if <x>:` 存在守卫**且 x 是 vc 的实参**
      // → `[opt-guard:<x>]`（`if workdir: _validate_workdir(workdir)`）。tag 区分二者。
      exists(ConditionBlock outer, string tag |
        outer.controls(cb, _) and
        not cb.controls(cs.getBasicBlock(), _) and
        gateBlockReachesSink(cb, cs) and
        guardsBlockingExit(cb) and
        (
          exists(string flag | isBypassCondition(outer, flag) and tag = "bypass:" + flag)
          or
          exists(string name | isPresenceGuardOfArg(outer, vc, name) and tag = "opt-guard:" + name)
        ) and
        kind = base + " [" + tag + "]"
      )
      or
      // (A″) 简单 for 迭代器透明化：cb 是循环体内早退守卫、sink 在循环外——for 出边旁路 cb，纯支配漏；
      // 语义上逐项都过守卫才走出循环 → 认定支配。tag `[loop:<itervar>]`。
      exists(string itervar |
        not cb.controls(cs.getBasicBlock(), _) and
        gateBlockReachesSink(cb, cs) and
        (guardsBlockingExit(cb) or ifThenBlocksExit(cb)) and
        isLoopGuardBeforeSink(cb, vc, cs, itervar) and
        kind = base + " [loop:" + itervar + "]"
      )
    )
  )
}

// 分支局部 same-origin gate：cb 不严格支配所有到 cs 的路径，但 cb 自身能前向到达 cs，且守的是早退出口。
// 典型：`if ":" in name: namespace,bare=parse_qualified_name(name); if not is_valid_namespace(namespace): return`
// 对 fall-through sink，`is_valid_namespace(namespace)` 只覆盖冒号分支，故输出 branch-confirmed，而不削弱 confirmed。
predicate branchLocalGateCandidate(
  FunctionObject f, CallNode cs, CallNode sink, ConditionBlock cb, CallNode vc, string kind
) {
  sinkwardCall(f, cs, sink) and
  cb.getScope() = f.getFunction() and
  vc != cs and
  not is_sink_af(vc) and
  not gateCandidate(f, cs, sink, cb, vc, _) and
  not cb.controls(cs.getBasicBlock(), _) and
  gateBlockReachesSink(cb, cs) and
  (guardsBlockingExit(cb) or ifThenBlocksExit(cb)) and
  exists(string base |
    gateCallShape(cb, vc, base) and
    kind = base + " [branch-local]"
  )
}

// ===== (C) 同源污点穿过（gate-fte-design §1.1 / §2）=====

// Source（§1）：只允许模型面对的工具 handler 形参作为 t。普通 on-chain helper 形参不是
// handler-rooted source；它必须由真正的 handler 参数经全局 dataflow/显式 dispatch bridge 到达。
predicate isParamSource(DataFlow::Node n) {
  exists(FunctionObject h |
    is_tool_handler(h) and
    n.(DataFlow::ParameterNode).getScope() = h.getFunction() and
    isIncludeLocation2(n.getLocation())
  )
}

// 校验调用 vc 的被检查值 g（同源要判 t →* g）。函数实参与方法接收者都算被检查值：
// `is_valid_namespace(namespace)` 查参数；`skill_md.exists()` / `path.is_dir()` 查接收者。
predicate checkedGateNode(CallNode vc, DataFlow::Node g) {
  g.asCfgNode() = vc.getAnArg()
  or
  g.asCfgNode() = vc.getFunction().(AttrNode).getObject()
}

// 候选校验调用 vc 的被检查值 g。限定 vc 为 strict/branch 候选，缩小污点 sink 集。
predicate gateArgNode(CallNode vc, DataFlow::Node g) {
  (
    exists(FunctionObject f, CallNode cs, CallNode sink, ConditionBlock cb, string kind |
    gateCandidate(f, cs, sink, cb, vc, kind)
    )
    or
    exists(FunctionObject f, CallNode cs, CallNode sink, ConditionBlock cb, string kind |
      branchLocalGateCandidate(f, cs, sink, cb, vc, kind)
    )
  ) and
  checkedGateNode(vc, g)
}

/** Checked value for an adapter-declared child gate inside a returning policy helper. */
predicate projectNestedGateArgNode(CallNode gateCall, DataFlow::Node g) {
  projectNestedGateHelper(_, gateCall, _) and checkedGateNode(gateCall, g)
}

// sink 安全敏感值 sinkArg（HTTP 只取 URL；同源要判 t →* sinkArg）。
predicate sinkArgNode(CallNode sink, DataFlow::Node s) {
  isIncludeLocation2(sink.getLocation()) and
  sinkSensitiveNode(sink, s)
}

// 调用结果派生自输入值的窄模型：parser/normalizer/registry lookup 常把 tainted key/name 变成后续检查或 sink 值。
// 与 pathStringStep 一起保持无 sanitizer 语义；列表/元组解包目标也显式连上，覆盖
// `namespace, bare = parse_qualified_name(name)`。
predicate derivedReturnFunctionName(string name) {
  name = [
    "parse_qualified_name", "_parse_frontmatter", "split", "rsplit", "partition", "rpartition",
    "urlparse", "urlsplit", "find_plugin_skill"
  ]
}

predicate derivedValueStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(CallNode c |
    derivedReturnFunctionName(calleeName(c)) and
    (
      pred.asCfgNode() = c.getAnArg()
      or
      pred.asCfgNode() = c.getFunction().(AttrNode).getObject()
    ) and
    (
      succ.asCfgNode() = c
      or
      exists(Assign a, Expr target |
        a.getValue() = c.getNode() and
        unpackTargetElement(a.getATarget(), target) and
        succ.asCfgNode() = target.getAFlowNode()
      )
    )
  )
}

// 附加污点步（§1.1「复用桥 / 派生检查」）：gate 查 pre-resolve 串、sink 用 post-resolve 路径，默认模型不穿透
// pathlib/os.path 构造与常见字符串规范化，这里补上（无 sanitizer、保留整条路径），让路径穿越型 gate 的同源成立。
predicate pathStringStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(CallNode c | succ.asCfgNode() = c |
    // 属性调用：os.path.join/expanduser/…；x.resolve()/joinpath(y)/with_name(y)/strip()/lower()/replace()…
    c.getFunction().(AttrNode).getName() =
      [
        "join", "expanduser", "abspath", "realpath", "normpath", "normcase", "dirname", "basename",
        "resolve", "absolute", "joinpath", "with_name", "with_suffix", "strip", "lstrip", "rstrip",
        "lower", "upper", "replace", "format", "encode", "decode"
      ] and
    (
      pred.asCfgNode() = c.getAnArg()
      or
      pred.asCfgNode() = c.getFunction().(AttrNode).getObject() // 接收者 x（x.resolve() 等返回 x 的变体）
    )
    or
    // 构造器式：Path(x) / PurePath(x) / str(x) / os.fspath(x)
    c.getFunction().(NameNode).getId() = ["Path", "PurePath", "str", "fspath"] and
    pred.asCfgNode() = c.getAnArg()
  )
  or
  // `pred / y` 或 `x / pred` —— Path.__truediv__ 当作路径 join
  exists(BinaryExprNode b |
    b.getOp() instanceof Div and succ.asCfgNode() = b and pred.asCfgNode() = b.getAnOperand()
  )
}

// `skill_view(name, file_path)` first selects SKILL.md through the source-derived `name`, then
// parses policy frontmatter from that selected file before the linked-file sink. Standard value
// taint does not treat a path receiver as a source for the bytes/text returned by read_text(), but
// D5 selection provenance does: changing `name` changes which policy document is read. Keep this
// implicit selection edge limited to skill_view's two in-function reads.
predicate selectedSkillFileContentStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(CallNode read |
    read.getLocation().getFile().getRelativePath() = "tools/skills_tool.py" and
    read.getScope().(Function).getName() = "skill_view" and
    calleeName(read) = "read_text" and
    pred.asCfgNode() = read.getFunction().(AttrNode).getObject() and
    succ.asCfgNode() = read
  )
}

// Frontmatter's optional `name` overrides the selected path basename:
// `resolved_name = parsed_frontmatter.get("name", skill_md.parent.name)`.
predicate selectedSkillResolvedNameCall(CallNode getCall) {
  exists(AttrNode attr, Name receiver |
    getCall.getLocation().getFile().getRelativePath() = "tools/skills_tool.py" and
    getCall.getScope().(Function).getName() = "skill_view" and
    attr = getCall.getFunction() and attr.getName() = "get" and
    receiver = attr.getObject().getNode() and receiver.getId() = "parsed_frontmatter"
  )
}

// Model only this audited receiver→result edge instead of globally treating every dict.get as a
// derived-value transform. The projection itself is not a policy decision and is suppressed from
// direct gate output below; only the downstream disabled-skill check is a gate.
predicate selectedSkillResolvedNameStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(CallNode getCall, AttrNode attr |
    selectedSkillResolvedNameCall(getCall) and
    attr = getCall.getFunction() and
    pred.asCfgNode() = attr.getObject() and
    succ.asCfgNode() = getCall
  )
}

// QwenPaw 在 concrete tool handler 之前用 ToolGuardMixin._decide_guard_action 拦截 raw
// tool_call.input。这里是项目绑定的 dispatch bridge：具体 tool handler 的模型参数 field 与
// tool_input 属于同一份 model invocation。禁止把任意 helper 参数泛化为 source。
predicate qwenToolGuardDispatchStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(FunctionObject handler, FunctionObject guard, Name toolInput |
    is_tool_handler(handler) and
    handler.getFunction().getLocation().getFile().getRelativePath().matches(
      "src/qwenpaw/agents/tools/%"
    ) and
    pred.(DataFlow::ParameterNode).getScope() = handler.getFunction() and
    guard.getName() = "_decide_guard_action" and
    guard.getFunction().getLocation().getFile().getRelativePath() =
      "src/qwenpaw/agents/tool_guard_mixin.py" and
    toolInput.getId() = "tool_input" and
    toolInput.getScope() = guard.getFunction() and
    succ.asCfgNode() = toolInput.getAFlowNode()
  )
}

// ===== 卡点2：把调用图的 CHA/服务句柄桥「注入」污点（§1.1「复用上述桥」）=====
// CodeQL 污点用的是**库内建**的 type-tracking 调用图（`resolveCall`），解析不到运行期注入的服务句柄
// （`env.execute` / `file_ops.read_file`）——正是 `call.qll` 手写 `cha_calls`/`delivery_bridge` 兜底的那道边。
// 库不接受外部调用图，只能把桥**当附加流步注入**：对每条桥接调用 (cn→callee)，补 arg→param 边（含 self 偏移
// 与 keyword 对应），让污点像走桥一样进 callee 形参、再在体内正常流到真 sink（Popen/run/…）。
predicate bridgedCall(CallNode cn, FunctionObject callee) {
  exists(FunctionObject caller |
    cha_calls(caller, callee, cn) or delivery_bridge(caller, callee, cn) or
    project_bridge(caller, callee, cn) and
    not astrToThreadCallbackEdge(caller, callee, cn)
  )
}

// 方法首参名为 self 时，调用实参 i 对应形参 i+1（call 的 getArg 不含 receiver）；否则 0 偏移。
int selfOffset(FunctionObject callee) {
  callee.getFunction().getArgName(0) = "self" and result = 1
  or
  not callee.getFunction().getArgName(0) = "self" and result = 0
}

predicate bridgeTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(CallNode cn, FunctionObject callee | bridgedCall(cn, callee) |
    // 位置实参 i → callee 形参 i+selfOffset
    exists(int i |
      pred.asCfgNode() = cn.getArg(i) and
      succ.(DataFlow::ParameterNode).getParameter() = callee.getFunction().getArg(i + selfOffset(callee))
    )
    or
    // keyword 实参 name → 同名形参
    exists(string name, Parameter p |
      pred.asCfgNode() = cn.getArgByName(name) and
      p = callee.getFunction().getArgByName(name) and
      succ.(DataFlow::ParameterNode).getParameter() = p
    )
  )
}

// 无 sanitizer 的全局污点（§1 保留整条路径）：Source 形参 → {gate 被检查实参 g} ∪ {sinkArg}，+ 路径/字符串附加步 + CHA 桥步。
module GateTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { isParamSource(n) }

  predicate isSink(DataFlow::Node n) {
    gateArgNode(_, n) or inlineGateArgNode(_, n) or projectNestedGateArgNode(_, n) or
    sinkArgNode(_, n)
  }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    pathStringStep(a, b) or derivedValueStep(a, b) or selectedSkillFileContentStep(a, b) or
    selectedSkillResolvedNameStep(a, b) or bridgeTaintStep(a, b) or
    projectBridgeTaintStep(a, b) or qwenToolGuardDispatchStep(a, b)
  }
}

module GateTaint = TaintTracking::Global<GateTaintConfig>;

// (C) 同源：存在同一 Source 形参 t，t →* g（vc 的被检查实参）且 t →* sinkArg。
predicate sameOriginTaint(CallNode vc, CallNode sink) {
  exists(DataFlow::Node t, DataFlow::Node g | sameOriginTaintWitness(vc, sink, t, g))
}

// 保留 LLM gate-semantics 切片所需的精确 witness：同一个 Source 参数 t 与被检查表达式 g。
// 原 coverage 输出只留 gate_fn/file/line，无法可靠回答「具体检查哪个值」；此 witness 让下游可按
// checked expression + callsite 建稳定 gate/value ID，而不是按裸变量名或第一个实参猜。
predicate sameOriginTaintWitness(
  CallNode vc, CallNode sink, DataFlow::Node t, DataFlow::Node g
) {
  isParamSource(t) and
  gateArgNode(vc, g) and
  exists(DataFlow::Node s |
    sinkArgNode(sink, s) and
    GateTaint::flow(t, g) and
    GateTaint::flow(t, s)
  )
}

predicate sameOriginInlineWitness(
  If guard, CallNode sink, DataFlow::Node t, DataFlow::Node g
) {
  isParamSource(t) and
  inlineGateArgNode(guard, g) and
  exists(DataFlow::Node s |
    sinkArgNode(sink, s) and
    GateTaint::flow(t, g) and
    GateTaint::flow(t, s)
  )
}

predicate directGateResult(
  string gateFn, string gateFile, int gateLine, int gateColumn, string gateCallExpr,
  string checkedExpr, string checkedFile, int checkedLine, int checkedColumn,
  string sourceParam, string conditionExpr, string kind, string verdict, string inFunc,
  string sinkLabel, string sinkFile, int sinkLine
) {
  exists(
    FunctionObject f, CallNode cs, CallNode sink, ConditionBlock cb, CallNode vc,
    DataFlow::Node t, DataFlow::Node g, Expr checked
  |
    isIncludeLocation2(vc.getLocation()) and
    not selectedSkillResolvedNameCall(vc) and
    (
      gateCandidate(f, cs, sink, cb, vc, kind) and
      (
        sameOriginTaintWitness(vc, sink, t, g) and
        checked = g.asExpr() and
        sourceParam = t.(DataFlow::ParameterNode).getParameter().(Name).getId() and
        verdict = "confirmed"
        or
        not sameOriginTaint(vc, sink) and
        gateArgNode(vc, g) and
        checked = g.asExpr() and
        sourceParam = "" and
        verdict = "needs-review"
      )
      or
      branchLocalGateCandidate(f, cs, sink, cb, vc, kind) and
      sameOriginTaintWitness(vc, sink, t, g) and
      checked = g.asExpr() and
      sourceParam = t.(DataFlow::ParameterNode).getParameter().(Name).getId() and
      verdict = "branch-confirmed"
    ) and
    gateFn = calleeName(vc) and
    gateFile = vc.getLocation().getFile().getRelativePath() and
    gateLine = vc.getLocation().getStartLine() and
    gateColumn = vc.getLocation().getStartColumn() and
    gateCallExpr = vc.getNode().toString() and
    checkedExpr = checked.toString() and
    checkedFile = checked.getLocation().getFile().getRelativePath() and
    checkedLine = checked.getLocation().getStartLine() and
    checkedColumn = checked.getLocation().getStartColumn() and
    conditionExpr = cb.getLastNode().getNode().toString() and
    inFunc = f.getName() and
    sinkLabel = calleeName(sink) and
    sinkFile = sink.getLocation().getFile().getRelativePath() and
    sinkLine = sink.getLocation().getStartLine()
  )
}

predicate inlineGateResult(
  string gateFn, string gateFile, int gateLine, int gateColumn, string gateCallExpr,
  string checkedExpr, string checkedFile, int checkedLine, int checkedColumn,
  string sourceParam, string conditionExpr, string kind, string verdict, string inFunc,
  string sinkLabel, string sinkFile, int sinkLine
) {
  exists(
    FunctionObject f, CallNode cs, CallNode sink, If guard, Expr test,
    DataFlow::Node source, DataFlow::Node checked
  |
    inlineEarlyExitShape(f, cs, sink, guard, test) and
    sameOriginInlineWitness(guard, sink, source, checked) and
    isIncludeLocation2(test.getLocation()) and
    gateFn = "inline-condition" and
    gateFile = test.getLocation().getFile().getRelativePath() and
    gateLine = test.getLocation().getStartLine() and
    gateColumn = test.getLocation().getStartColumn() and
    // CodeQL Python AST toString() often returns BoolOp/UnaryExpr. Empty hints make the
    // source-backed slicer recover the exact expression from this location instead.
    gateCallExpr = "" and
    checkedExpr = "" and
    checkedFile = gateFile and
    checkedLine = gateLine and
    checkedColumn = gateColumn and
    sourceParam = source.(DataFlow::ParameterNode).getParameter().(Name).getId() and
    conditionExpr = "" and
    kind = "inline-condition" and
    verdict = "confirmed" and
    inFunc = f.getName() and
    sinkLabel = calleeName(sink) and
    sinkFile = sink.getLocation().getFile().getRelativePath() and
    sinkLine = sink.getLocation().getStartLine()
  )
}

// Audited child gates inside skill_view policy helpers. Their parent call is the actual
// sink-dominating checkpoint in skill_view; emit the child source location while retaining
// `in_func=skill_view`, so chain attachment remains based on the on-chain owner rather than
// requiring the side-check helper to be a terminal call-chain hop.
predicate nestedSkillGateResult(
  string gateFn, string gateFile, int gateLine, int gateColumn, string gateCallExpr,
  string checkedExpr, string checkedFile, int checkedLine, int checkedColumn,
  string sourceParam, string conditionExpr, string kind, string verdict, string inFunc,
  string sinkLabel, string sinkFile, int sinkLine
) {
  exists(
    FunctionObject f, FunctionObject helper, CallNode cs, CallNode sink, ConditionBlock cb,
    CallNode parentCall, DataFlow::Node source, DataFlow::Node parentChecked
  |
    f.getName() = "skill_view" and
    f.getFunction().getLocation().getFile().getRelativePath() = "tools/skills_tool.py" and
    gateCandidate(f, cs, sink, cb, parentCall, _) and
    sameOriginTaint(parentCall, sink) and
    (
      calleeName(parentCall) = "skill_matches_platform" and
      helper.getName() = "skill_matches_platform" and
      helper.getFunction().getLocation().getFile().getRelativePath() = "agent/skill_utils.py" and
      exists(CallNode child |
        child.getScope() = helper.getFunction() and
        calleeName(child) = "startswith" and
        isIncludeLocation2(child.getLocation()) and
        exists(AttrNode childAttr, Expr receiver |
          childAttr = child.getFunction() and
          receiver = childAttr.getObject().getNode() and
          checkedExpr = receiver.toString() and
          checkedFile = receiver.getLocation().getFile().getRelativePath() and
          checkedLine = receiver.getLocation().getStartLine() and
          checkedColumn = receiver.getLocation().getStartColumn()
        ) and
        gateFn = calleeName(child) and
        gateLine = child.getLocation().getStartLine() and
        gateColumn = child.getLocation().getStartColumn() and
        gateCallExpr = child.getNode().toString() and
        conditionExpr = child.getNode().toString() and
        kind = "nested-call [parent:skill_matches_platform]"
      )
      or
      calleeName(parentCall) = "_is_skill_disabled" and
      helper.getName() = "_is_skill_disabled" and
      helper.getFunction().getLocation().getFile().getRelativePath() =
        "tools/skills_tool.py" and
      exists(Compare membership, Expr left, Expr right, In op |
        membership.getScope() = helper.getFunction() and
        membership.compares(left, op, right) and
        left.(Name).getId() = "name" and
        isIncludeLocation2(membership.getLocation()) and
        checkedExpr = left.toString() and
        checkedFile = left.getLocation().getFile().getRelativePath() and
        checkedLine = left.getLocation().getStartLine() and
        checkedColumn = left.getLocation().getStartColumn() and
        gateFn = helper.getName() and
        gateLine = membership.getLocation().getStartLine() and
        gateColumn = membership.getLocation().getStartColumn() and
        gateCallExpr = membership.toString() and
        conditionExpr = membership.toString() and
        (
          right.(Name).getId() = "platform_disabled" and
          kind = "nested-membership [parent:_is_skill_disabled; platform]"
          or
          exists(CallNode disabledGet, AttrNode disabledAttr, Name skillsCfg |
            right = disabledGet.getNode() and
            disabledAttr = disabledGet.getFunction() and disabledAttr.getName() = "get" and
            skillsCfg = disabledAttr.getObject().getNode() and skillsCfg.getId() = "skills_cfg" and
            kind = "nested-membership [parent:_is_skill_disabled; global]"
          )
        )
      )
    ) and
    sameOriginTaintWitness(parentCall, sink, source, parentChecked) and
    sourceParam = source.(DataFlow::ParameterNode).getParameter().(Name).getId() and
    gateFile = helper.getFunction().getLocation().getFile().getRelativePath() and
    verdict = "confirmed" and
    inFunc = f.getName() and
    sinkLabel = calleeName(sink) and
    sinkFile = sink.getLocation().getFile().getRelativePath() and
    sinkLine = sink.getLocation().getStartLine()
  )
}

/**
 * Adapter-declared child gates whose helper returns an approved value to an on-chain caller.
 * The child source location is emitted, while `in_func` stays bound to the caller so chain
 * attachment does not invent a forward call from the returning helper to the terminal sink.
 */
predicate nestedProjectGateResult(
  string gateFn, string gateFile, int gateLine, int gateColumn, string gateCallExpr,
  string checkedExpr, string checkedFile, int checkedLine, int checkedColumn,
  string sourceParam, string conditionExpr, string kind, string verdict, string inFunc,
  string sinkLabel, string sinkFile, int sinkLine
) {
  exists(
    FunctionObject f, FunctionObject helper, CallNode parentCall, CallNode gateCall,
    CallNode sink, DataFlow::Node source, DataFlow::Node checked, DataFlow::Node sinkArg
  |
    onChainMid(f, sink) and
    calls_cn(f, helper, parentCall) and
    projectNestedGateHelper(helper, gateCall, kind) and
    isIncludeLocation2(gateCall.getLocation()) and
    source.(DataFlow::ParameterNode).getScope() = f.getFunction() and
    isParamSource(source) and
    projectNestedGateArgNode(gateCall, checked) and
    sinkArgNode(sink, sinkArg) and
    GateTaint::flow(source, checked) and
    GateTaint::flow(source, sinkArg) and
    gateFn = calleeName(gateCall) and
    gateFile = gateCall.getLocation().getFile().getRelativePath() and
    gateLine = gateCall.getLocation().getStartLine() and
    gateColumn = gateCall.getLocation().getStartColumn() and
    gateCallExpr = gateCall.getNode().toString() and
    checkedExpr = checked.asExpr().toString() and
    checkedFile = checked.getLocation().getFile().getRelativePath() and
    checkedLine = checked.getLocation().getStartLine() and
    checkedColumn = checked.getLocation().getStartColumn() and
    sourceParam = source.(DataFlow::ParameterNode).getParameter().(Name).getId() and
    conditionExpr = gateCall.getNode().toString() and
    verdict = "confirmed" and
    inFunc = f.getName() and
    sinkLabel = calleeName(sink) and
    sinkFile = sink.getLocation().getFile().getRelativePath() and
    sinkLine = sink.getLocation().getStartLine()
  )
}

/**
 * Adapter-declared policy gates that run before concrete handler dispatch.
 * These rows retain the concrete handler as their chain owner while the slicer
 * resolves the actual enclosing function from the gate callsite.
 */
predicate preHandlerGateResult(
  string gateFn, string gateFile, int gateLine, int gateColumn, string gateCallExpr,
  string checkedExpr, string checkedFile, int checkedLine, int checkedColumn,
  string sourceParam, string conditionExpr, string kind, string verdict, string inFunc,
  string sinkLabel, string sinkFile, int sinkLine
) {
  exists(
    FunctionObject handler, CallNode gateCall, ControlFlowNode checked, CallNode sink
  |
    onChainMid(handler, sink) and
    projectPreHandlerGate(handler, gateCall, checked, kind) and
    isIncludeLocation2(gateCall.getLocation()) and
    gateFn = calleeName(gateCall) and
    gateFile = gateCall.getLocation().getFile().getRelativePath() and
    gateLine = gateCall.getLocation().getStartLine() and
    gateColumn = gateCall.getLocation().getStartColumn() and
    gateCallExpr = gateCall.getNode().toString() and
    checkedExpr = checked.getNode().toString() and
    checkedFile = checked.getLocation().getFile().getRelativePath() and
    checkedLine = checked.getLocation().getStartLine() and
    checkedColumn = checked.getLocation().getStartColumn() and
    sourceParam = "tool_input" and
    conditionExpr = gateCall.getNode().toString() and
    verdict = "confirmed" and
    inFunc = handler.getName() and
    sinkLabel = calleeName(sink) and
    sinkFile = sink.getLocation().getFile().getRelativePath() and
    sinkLine = sink.getLocation().getStartLine()
  )
}

from
  string gateFn, string gateFile, int gateLine, int gateColumn, string gateCallExpr,
  string checkedExpr, string checkedFile, int checkedLine, int checkedColumn,
  string sourceParam, string conditionExpr, string kind, string verdict, string inFunc,
  string sinkLabel, string sinkFile, int sinkLine
where
  directGateResult(
    gateFn, gateFile, gateLine, gateColumn, gateCallExpr, checkedExpr, checkedFile,
    checkedLine, checkedColumn, sourceParam, conditionExpr, kind, verdict, inFunc,
    sinkLabel, sinkFile, sinkLine
  )
  or
  inlineGateResult(
    gateFn, gateFile, gateLine, gateColumn, gateCallExpr, checkedExpr, checkedFile,
    checkedLine, checkedColumn, sourceParam, conditionExpr, kind, verdict, inFunc,
    sinkLabel, sinkFile, sinkLine
  )
  or
  nestedSkillGateResult(
    gateFn, gateFile, gateLine, gateColumn, gateCallExpr, checkedExpr, checkedFile,
    checkedLine, checkedColumn, sourceParam, conditionExpr, kind, verdict, inFunc,
    sinkLabel, sinkFile, sinkLine
  )
  or
  nestedProjectGateResult(
    gateFn, gateFile, gateLine, gateColumn, gateCallExpr, checkedExpr, checkedFile,
    checkedLine, checkedColumn, sourceParam, conditionExpr, kind, verdict, inFunc,
    sinkLabel, sinkFile, sinkLine
  )
  or
  preHandlerGateResult(
    gateFn, gateFile, gateLine, gateColumn, gateCallExpr, checkedExpr, checkedFile,
    checkedLine, checkedColumn, sourceParam, conditionExpr, kind, verdict, inFunc,
    sinkLabel, sinkFile, sinkLine
  )
select gateFn as gate_fn, gateFile as gate_file, gateLine as gate_line,
  gateColumn as gate_column, gateCallExpr as gate_call_expr, checkedExpr as checked_expr,
  checkedFile as checked_file, checkedLine as checked_line, checkedColumn as checked_column,
  sourceParam as source_param, conditionExpr as condition_expr, kind as guard_kind,
  verdict as taint_verdict, inFunc as in_func, sinkLabel as sink_label,
  sinkFile as sink_file, sinkLine as sink_line

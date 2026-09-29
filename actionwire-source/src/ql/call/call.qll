/**
 * clawgap call-chain library (hermes 适配版，基于 AgentFuzz ql/call/call.qll)
 *
 * 与 AgentFuzz 的三处关键差异（见 clawgap/design/hermes-agent/call-chain/call_chain_hermes-design.md）：
 *   1. Source 锚定「工具入口」：仅当函数是 registry.register(handler=...) 注册的 handler
 *      （具名或 lambda 包裹）且在 depth 内到达 sink 才算 Source（对标 goclaw 从 Tool.Execute 出发）。
 *   2. 调用图 = AgentFuzz 原始边（FunctionInvocation/method/direct/module/add）+ 类型约束的
 *      cha_calls，用于穿透 hermes 的跨类多态分发。实测：纯 AgentFuzz 图 recall 不足
 *      （terminal/read_file/write_file 断在 env.execute），故启用 cha_calls；但「按名全连通」
 *      会爆炸（每个 handler 都到达所有 sink），故 cha_calls 做了双重类型约束——
 *      (A) self.m() 仅连 caller 类层次内的 override；(B) 服务句柄桥（receiver 名为 env/file_ops/…）。
 *      详见下方 cha_calls 注释。
 *   3. is_sink 在移植 AgentFuzz 全部 sink 的基础上，新增 hermes 原生文件 sink（Path 类），
 *      并按 Cmd/Path/Network/Other 分类（sink_category）。
 */

import python
import util.util
import project.ProjectModel
import semmle.python.dataflow.new.DataFlow

// ---------------------------------------------------------------------------
// Source = 工具 handler（root）且可达 sink
// ---------------------------------------------------------------------------
class Source extends PyFunctionObject {
  int depth;
  CallNode callee;

  Source() {
    is_tool_handler(this) and
    depth = [1 .. 8] and
    r_calls(this, callee, depth) and
    is_sink(callee) and
    isIncludeLocation2(this.getFunction().getLocation())
  }

  int getDepth() { result = depth }

  CallNode getCallee() { result = callee }

  string getToolHandler() { result = toolHandlerName(this) }

  string getSinkCategory() { result = sink_category(callee) }

  string getSinkLocation() { result = get_sink_location(callee) }

  FunctionObject getAMid() {
    exists(FunctionObject mid, int k | find_mid(this, callee, mid, depth, k) | result = mid)
  }

  int getMidDepth(FunctionObject mid) {
    exists(int k | find_mid(this, callee, mid, depth, k) | result = k)
  }

  string getPathStr() {
    result =
      depth + "#" +
        concat(FunctionObject mid, int k |
          find_mid(this, callee, mid, depth, k)
        |
          mid.getQualifiedName() + "@" + mid.getFunction().getLocation().getFile().getBaseName(),
          "->" order by k
        ) + "->" + get_sink_location(callee)
  }
}

// ---------------------------------------------------------------------------
// 工具入口识别：registry.register(name=..., handler=<func>, ...)
// 把 handler 关键字实参解析回同文件中定义的具名函数。
// 工厂/lambda handler（_make_handler / handler=lambda ...）不解析，留作后续。
// ---------------------------------------------------------------------------
predicate is_tool_handler(FunctionObject f) {
  // 形态 1：handler=<具名函数>（如 handler=_handle_terminal）
  exists(CallNode reg |
    is_register_call(reg) and
    reg.getArgByName("handler").(NameNode).getId() = f.getName() and
    reg.getLocation().getFile() = f.getFunction().getLocation().getFile()
  )
  or
  // 形态 2：handler=lambda args, **kw: realfunc(...)（如 execute_code / web_search_tool /
  // web_extract_tool / delegate_task）——把 lambda 体内调用的具名函数当作 root。
  exists(CallNode reg, Lambda lam, CallNode inner |
    is_register_call(reg) and
    reg.getArgByName("handler").getNode() = lam and
    inner.getScope() = lam.getInnerScope() and
    inner.getFunction().(NameNode).getId() = f.getName() and
    reg.getLocation().getFile() = f.getFunction().getLocation().getFile()
  )
  or
  projectToolHandler(f)
}

string toolHandlerName(FunctionObject f) {
  projectToolName(f) = result
  or
  is_tool_handler(f) and not projectToolHandler(f) and result = f.getName()
}

predicate is_register_call(CallNode reg) {
  reg.getFunction().(AttrNode).getNode().getName() = "register" and
  reg.getFunction().(AttrNode).getObject().getNode().toString() = "registry"
}

// ---------------------------------------------------------------------------
// 调用图（移植 AgentFuzz + 新增 cha_calls）
// ---------------------------------------------------------------------------
predicate calls(FunctionObject caller, FunctionObject callee) {
  caller != callee and
  (
    exists(FunctionInvocation fi | fi.getCaller().getFunction() = caller |
      fi.getFunction() = callee and
      not projectRejectFunctionInvocation(caller, callee)
    )
    or
    method_calls(caller, callee, _)
    or
    direct_calls(caller, callee, _)
    or
    module_calls(caller, callee, _)
    or
    add_calls(caller, callee, _)
    or
    // CHA 边（类型约束版，见文件末 cha_calls 注释）。AgentFuzz 原始图对 hermes 多态
    // 分发 recall 不足（terminal/read_file/write_file 断在 env.execute），故启用。
    cha_calls(caller, callee, _)
    or
    // 出站投递桥（hermes 专用 hardcode，见 delivery_bridge）：接上 send_message 工具到网关/插件
    // 平台 adapter 发送原语的运行期依赖注入边（Discord-Mention 跨组件）。
    delivery_bridge(caller, callee, _)
    or
    // import alias 桥：terminal_tool 将 check_all_command_guards 重命名为
    // _check_all_guards_impl，内建 points-to 在当前 DB 中未恢复该跨模块调用边。
    approval_alias_bridge(caller, callee, _)
    or
    project_bridge(caller, callee, _)
  )
}

predicate project_bridge(FunctionObject caller, FunctionObject callee, CallNode cn) {
  projectAdditionalCallEdge(caller, callee, cn)
}

/** Model-controlled argument flow over poco's injected instance-method calls. */
predicate pocoInjectedClientArgumentStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(FunctionObject caller, FunctionObject callee, CallNode cn |
    pocoInjectedClientEdge(caller, callee, cn) and
    (
      exists(int i |
        pred.asCfgNode() = cn.getArg(i) and
        succ.(DataFlow::ParameterNode).getParameter() = callee.getFunction().getArg(i + 1)
      )
      or
      exists(string name, Parameter p |
        pred.asCfgNode() = cn.getArgByName(name) and
        p = callee.getFunction().getArgByName(name) and
        succ.(DataFlow::ParameterNode).getParameter() = p
      )
    )
  )
}

/** Argument flow for dynamic callbacks whose call syntax has an explicit self/callback offset. */
predicate projectBridgeTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(FunctionObject caller, FunctionObject callee, CallNode cn |
    project_bridge(caller, callee, cn) and
    (
      cowActionMapEdge(caller, callee, cn) and
      pred.asCfgNode() = cn.getArg(1) and
      succ.(DataFlow::ParameterNode).getParameter() = callee.getFunction().getArg(1)
      or
      cowSubmitCallbackEdge(caller, callee, cn) and
      exists(int i |
        pred.asCfgNode() = cn.getArg(i + 1) and
        succ.(DataFlow::ParameterNode).getParameter() = callee.getFunction().getArg(i + 1)
      )
      or
      astrToThreadCallbackEdge(caller, callee, cn) and
      not astrNestedFunction(caller, callee) and
      (
        exists(int i |
          pred.asCfgNode() = cn.getArg(i + 1) and
          succ.(DataFlow::ParameterNode).getParameter() = callee.getFunction().getArg(i)
        )
        or
        exists(string name, Parameter p |
          pred.asCfgNode() = cn.getArgByName(name) and
          p = callee.getFunction().getArgByName(name) and
          succ.(DataFlow::ParameterNode).getParameter() = p
        )
      )
      or
      astrToThreadCallbackEdge(caller, callee, cn) and
      exists(Parameter p, NameNode captured |
        astrClosureCapture(caller, callee, p, captured) and
        pred.(DataFlow::ParameterNode).getParameter() = p and
        succ.asCfgNode() = captured
      )
      or
      qwenToThreadCallbackEdge(caller, callee, cn) and
      exists(int i |
        pred.asCfgNode() = cn.getArg(i + 1) and
        succ.(DataFlow::ParameterNode).getParameter() = callee.getFunction().getArg(i)
      )
    )
  )
  or
  pocoInjectedClientArgumentStep(pred, succ)
  or
  pocoContainerValueStep(pred.asCfgNode(), succ.asCfgNode())
}

predicate call_node(FunctionObject caller, CallNode cn) {
  isIncludeLocation2(caller.getFunction().getLocation()) and
  caller.getFunction().getBody().getAnItem().getAChildNode+().getAFlowNode() = cn and
  not exists(Function inner | caller.getFunction().getBody().getAnItem().getAChildNode+() = inner |
    inner.getBody().getAnItem().getAChildNode+().getAFlowNode() = cn
  )
}

predicate definition_node(Function caller, DefinitionNode dn) {
  isIncludeLocation2(caller.getLocation()) and
  caller.getBody().getAnItem().getAChildNode+().getAFlowNode() = dn and
  not exists(Function inner | caller.getBody().getAnItem().getAChildNode+() = inner |
    inner.getBody().getAnItem().getAChildNode+().getAFlowNode() = dn
  )
}

predicate method_calls(FunctionObject caller, FunctionObject callee, CallNode cn) {
  call_node(caller, cn) and
  exists(Class c | c.getAMethod() = caller.getFunction() and c.getAMethod() = callee.getFunction()) and
  exists(AttrNode an, NameNode nn |
    cn.getAChild() = an and an.getAChild() = nn and nn.getId() = "self"
  |
    an.getName() = callee.getName()
  )
}

predicate direct_calls(FunctionObject caller, FunctionObject callee, CallNode cn) {
  call_node(caller, cn) and
  (callee.isBuiltin() or caller.getFunction().getEnclosingScope() = callee.getFunction().getEnclosingScope()) and
  exists(NameNode nn | cn.getAChild() = nn | nn.getId() = callee.getName())
}

predicate add_calls(FunctionObject caller, FunctionObject callee, CallNode cn) {
  call_node(caller, cn) and
  callee.getName() = "_sys_execute" and
  cn.getFunction().(AttrNode).getNode().getName() = "Process" and
  cn.getArgByName("target").(NameNode).getId() = callee.getName()
}

// ---------------------------------------------------------------------------
// 审批函数 import-alias 桥（hermes 专用 hardcode）。
//
// tools/terminal_tool.py:
//   from tools.approval import check_all_command_guards as _check_all_guards_impl
//   def _check_all_guards(...):
//       return _check_all_guards_impl(...)
//
// direct_calls 要求 call 名与 callee 名相等且通常位于同一作用域，当前 CodeQL DB 的
// FunctionInvocation 也没有恢复这条跨模块 alias 边。这里同时约束 caller/call/callee
// 名称和两端文件，避免把其他同名 helper 连接到审批策略函数。
predicate approval_alias_bridge(FunctionObject caller, FunctionObject callee, CallNode cn) {
  call_node(caller, cn) and
  isIncludeLocation2(callee.getFunction().getLocation()) and
  caller.getName() = "_check_all_guards" and
  caller.getFunction().getLocation().getFile().getRelativePath() = "tools/terminal_tool.py" and
  cn.getFunction().(NameNode).getId() = "_check_all_guards_impl" and
  callee.getName() = "check_all_command_guards" and
  callee.getFunction().getLocation().getFile().getRelativePath() = "tools/approval.py"
}

// ---------------------------------------------------------------------------
// 出站投递桥（hermes 专用 hardcode，对标 add_calls / 设计文档「手动 seed 依赖注入这条边」）。
//
// 背景：send_message 工具（d5 handler = send_message_tool）发往「网关/插件平台 adapter 的发送
// 原语」的这条边，在静态图里**断开**——属运行期依赖注入：
//   tools/send_message_tool.py:_send_via_adapter
//     (1) adapter = runner.adapters.get(platform);  await adapter.send(chat_id=, content=, metadata=)
//         → adapter 是运行期从 runner 注册表取得的对象，静态不知其类，连不到具体 *Adapter.send。
//     (2) await entry.standalone_sender_fn(...)
//         → standalone_sender_fn 是插件在 gateway/platform_registry.py 注册的 Optional[Callable]，
//           静态是个字段，连不到具体 _standalone_send。
// 这两条边接上后，下游在 adapter 类内部即为普通过程内调用，可达 Discord-Mention 的三个 d5 sink：
//   SlackAdapter.send → self._get_client(...).chat_postMessage(...)            (gateway/platforms/slack.py)
//   MattermostAdapter.send → self._api_post("posts", ...)                      (plugins/.../mattermost/adapter.py)
//   _standalone_send → session.post(f"{base_url}/api/v4/posts", ...)           (同上)
//
// 约束（避免过连通）：仅当 call 点 receiver 名 = "adapter" 且被调方法名 = "send" 且被调方法所在
// 类名以 "Adapter" 结尾时建 (1) 边；(2) 边要求 call 点属性名 = "standalone_sender_fn" 且被调函数
// 名 = "_standalone_send"。两端均需 in-scope。
predicate delivery_bridge(FunctionObject caller, FunctionObject callee, CallNode cn) {
  call_node(caller, cn) and
  isIncludeLocation2(callee.getFunction().getLocation()) and
  (
    // (1) adapter.send(...) → 任一 `*Adapter` 类的 send 方法（runner.adapters.get 运行期分发）
    cn.getFunction().(AttrNode).getNode().getName() = "send" and
    cn.getFunction().(AttrNode).getObject().(NameNode).getId() = "adapter" and
    callee.getFunction().getName() = "send" and
    exists(Class c |
      c.getAMethod() = callee.getFunction() and c.getName().matches("%Adapter")
    )
    or
    // (2) <x>.standalone_sender_fn(...) → 插件注册的 _standalone_send（Optional[Callable] 注入）
    cn.getFunction().(AttrNode).getNode().getName() = "standalone_sender_fn" and
    callee.getFunction().getName() = "_standalone_send"
  )
}

predicate module_calls(FunctionObject caller, FunctionObject callee, CallNode cn) {
  call_node(caller, cn) and
  not projectRejectFunctionInvocation(caller, callee) and
  exists(Class c |
    c.getAMethod() = caller.getFunction() and
    c.getEnclosingModule() = callee.getFunction().getEnclosingModule()
  ) and
  exists(NameNode nn | cn.getAChild() = nn | nn.getId() = callee.getName())
}

// CHA 风格边（**recall 兜底，当前未接入** calls()/calls_cn()）。
// 历史教训：最初版「obj.m() 连到任意同名方法」无类型约束 → 全程序过连通（每个 handler
// 都"到达"几乎所有 sink）。因此本版做了**类型约束**，仅保留安全且高价值的一种：
//   self.m() 只连到 caller 所在**类层次**内（子类 override / 父类）名为 m 的方法——
//   精确覆盖 BaseEnvironment.execute 内 self._run_bash() → LocalEnvironment._run_bash 这种
//   「调用定义在子类」的多态，且不爆炸。
// 启用方式：把上面 calls()/calls_cn() 注释处接回 `cha_calls(caller, callee, _ / cn)`。
// 变量分发（如 env.execute()，env 非 self）仍交给 FunctionInvocation 内建 points-to；
// 若仍不足，可再补 points-to 版本（obj 指向实例类型的方法）。
predicate cha_calls(FunctionObject caller, FunctionObject callee, CallNode cn) {
  caller != callee and
  call_node(caller, cn) and
  isIncludeLocation2(callee.getFunction().getLocation()) and
  exists(AttrNode a, string m |
    a = cn.getFunction() and
    m = a.getNode().getName() and
    callee.getFunction().getName() = m
  |
    // (A) self.m() 分发到 caller 类层次内的 override（覆盖 self._run_bash()）
    (
      a.getObject().(NameNode).getId() = "self" and
      exists(ClassValue callerCls, ClassValue calleeCls |
        callerCls.getScope().getAMethod() = caller.getFunction() and
        calleeCls.getScope().getAMethod() = callee.getFunction() and
        (
          calleeCls = callerCls or
          calleeCls.getASuperType() = callerCls or
          callerCls.getASuperType() = calleeCls
        )
      )
    )
    or
    // (B) 服务句柄分发桥（hermes 专用定向桥，对标 AgentFuzz 的 add_calls 硬编码桥）：
    //     形如 `env.m()` / `self.env.m()` / `file_ops.m()` 的调用连到「任意类中名为 m
    //     的方法」。关键约束在 **receiver 名**（service-handle 白名单，见 getServiceHandle），
    //     而非 callee——既穿透 env.execute()（BaseEnvironment 层次）和 file_ops.write_file()
    //     （ShellFileOperations），又因 receiver 名很具体（env/file_ops/…）而不会像「任意
    //     X.execute() 都连 BaseEnvironment.execute」那样全连通爆炸。
    (
      (
        a.getObject().(NameNode).getId() = getServiceHandle()
        or
        a.getObject().(AttrNode).getNode().getName() = getServiceHandle()
      ) and
      exists(ClassValue c | c.getScope().getAMethod() = callee.getFunction())
    )
  )
}

// hermes 工具层获取并调用的「服务对象」句柄名（受工厂/缓存影响，points-to 解析不到，
// 故用名字定向桥接）。新增 sink 工具时若发现新的服务句柄名，在此补充即可。
string getServiceHandle() {
  result = ["env", "environment", "_env", "file_ops", "_file_ops"]
}

// 仅在「in-scope × in-scope」上做递归，把图从全程序收缩到核心代码（~900 函数），
// 大幅降低 CHA 增强后的图规模与磁盘 spill。sink 基例 call_node 已要求 caller in-scope。
predicate inscope_calls(FunctionObject caller, FunctionObject callee) {
  calls(caller, callee) and
  isIncludeLocation2(caller.getFunction().getLocation()) and
  isIncludeLocation2(callee.getFunction().getLocation())
}

predicate r_calls(FunctionObject caller, CallNode callee, int depth) {
  depth = 1 and call_node(caller, callee)
  or
  depth = getDepthLimit() and
  exists(FunctionObject mid | inscope_calls(caller, mid) | r_calls(mid, callee, depth - 1))
}

predicate r_functionobject_calls(FunctionObject caller, FunctionObject callee, int depth) {
  depth = 1 and inscope_calls(caller, callee)
  or
  depth = getDepthLimit() and
  exists(FunctionObject mid | inscope_calls(caller, mid) | r_functionobject_calls(mid, callee, depth - 1))
}

bindingset[depth]
predicate find_mid(FunctionObject caller, CallNode callee, FunctionObject mid, int depth, int k) {
  depth >= 1 and (k = 0 and mid = caller)
  or
  k > 0 and k < depth and r_functionobject_calls(caller, mid, k) and r_calls(mid, callee, depth - k)
}

string getlocStr(Location loc) {
  result =
    loc.getFile().getAbsolutePath() + "$$" + loc.getStartLine().toString() + ":" +
      loc.getStartColumn().toString() + "$$" + loc.getEndLine().toString() + ":" +
      loc.getEndColumn().toString()
}

string get_sink_location(CallNode callee) {
  if not exists(AttrNode cn | cn = callee.getFunction().(AttrNode) | 1 = 1)
  then result = callee.getFunction().getNode().toString() + "@" + getlocStr(callee.getLocation())
  else
    if exists(ControlFlowNode cn | cn = callee.getFunction().(AttrNode).getObject() | 1 = 1)
    then
      result =
        callee.getFunction().(AttrNode).getObject().getNode().toString() + "." +
          callee.getFunction().(AttrNode).getNode().getName() + "@" + getlocStr(callee.getLocation())
    else
      result =
        callee.getFunction().(AttrNode).getNode().getName() + "@" + getlocStr(callee.getLocation())
}

bindingset[depth]
string print_callchain(FunctionObject caller, CallNode callee, int depth) {
  result =
    depth + "#" +
      concat(FunctionObject mid, int k |
        find_mid(caller, callee, mid, depth, k)
      |
        mid.getQualifiedName() + "@" + mid.getFunction().getLocation().getFile().getBaseName(),
        "->" order by k
      ) + "->" + get_sink_location(callee)
}

string print_function(CallNode cn) {
  exists(AttrNode fan | first_attrnode(cn.getFunction(), fan) |
    result =
      fan.getObject().(NameNode).getId() + "." +
        concat(AttrNode an | an = cn.getFunction().getAChild*() |
          an.getName(), "." order by an.getLocation().getEndColumn()
        )
  )
}

predicate first_attrnode(ControlFlowNode cfn, AttrNode an) {
  an = cfn.getAChild*() and
  an.getLocation().getEndColumn() =
    rank[1](int i, AttrNode x | x = cfn.getAChild*() and i = x.getLocation().getEndColumn() | i)
}

predicate calls_cn(FunctionObject caller, FunctionObject callee, CallNode cn) {
  caller != callee and
  (
    method_calls(caller, callee, cn)
    or
    direct_calls(caller, callee, cn)
    or
    module_calls(caller, callee, cn)
    or
    add_calls(caller, callee, cn)
    or
    cha_calls(caller, callee, cn)
    or
    delivery_bridge(caller, callee, cn)
    or
    approval_alias_bridge(caller, callee, cn)
    or
    project_bridge(caller, callee, cn)
  )
}

predicate calls_fi(FunctionObject caller, FunctionObject callee, FunctionInvocation fi) {
  caller != callee and
  (
    fi.getCaller().getFunction() = caller and fi.getFunction() = callee and
    not projectRejectFunctionInvocation(caller, callee)
  )
}

// ---------------------------------------------------------------------------
// Sink 定义（移植 AgentFuzz is_sink + 新增 hermes 文件 sink），按类别拆分
// ---------------------------------------------------------------------------

// Cmd：shell 命令执行
predicate is_cmd_sink(CallNode cn) {
  (
    cn.getFunction().(AttrNode).getNode().getName() = "submit" and
    cn.getArg(0).(AttrNode).getNode().getName() = "run" and
    cn.getArg(0).(AttrNode).getNode().getObject().toString() = "subprocess"
  )
  or
  (
    cn.getFunction().(AttrNode).getNode().getName() = "Popen" and
    cn.getFunction().(AttrNode).getObject().getNode().toString() = "subprocess"
  )
  or
  (
    cn.getFunction().(AttrNode).getNode().getName() = "run" and
    cn.getFunction().(AttrNode).getObject().getNode().toString() = "subprocess"
  )
  or
  (
    cn.getFunction().(AttrNode).getNode().getName() = "system" and
    cn.getFunction().(AttrNode).getObject().getNode().toString() = "os"
  )
  or
  (
    cn.getFunction().(AttrNode).getNode().getName() = "run" and
    exists(DefinitionNode dn |
      definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn)
    |
      dn.getNode().toString() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
      dn.getValue().(CallNode).getNode().getFunc().toString() = "ShellTool"
    )
  )
  or
  (
    cn.getFunction().(AttrNode).getNode().getName() = "run" and
    exists(DefinitionNode dn |
      definition_node(cn.getFunction().(AttrNode).getNode().getScope*().(Function), dn)
    |
      dn.getNode().toString() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
      dn.getValue().(CallNode).getNode().getFunc().toString() = "PythonREPL"
    )
  )
  or
  (
    cn.getFunction().(AttrNode).getNode().getName() = "run_cell" and
    exists(DefinitionNode dn |
      definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn)
    |
      dn.getNode().toString() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
      dn.getValue().(CallNode).getNode().getFunc().toString() = "get_ipython"
    )
  )
}

// Network：HTTP / 爬虫 / 远程加载
predicate is_net_sink(CallNode cn) {
  (
    cn.getFunction().(AttrNode).getNode().getName() in ["request", "get"] and
    (
      exists(With wi, CallNode cn2, NameNode nn |
        wi.getScope() = cn.getScope() and
        nn = wi.getAChildNode().getAFlowNode() and
        cn2 = wi.getAChildNode().getAFlowNode()
      |
        nn.getId() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
        cn2.getFunction().(AttrNode).getNode().getName() in ["AsyncClient", "ClientSession", "Session"]
      )
      or
      exists(DefinitionNode dn |
        definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn)
      |
        dn.getNode().toString() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
        dn.getValue().(CallNode).getFunction().(AttrNode).getNode().getName() in
          ["AsyncClient", "ClientSession", "Session"]
      )
    )
  )
  or
  (
    cn.getFunction().(AttrNode).getNode().getName() in ["arun"] and
    (
      exists(With wi, CallNode cn2, NameNode nn |
        wi.getScope() = cn.getScope() and
        nn = wi.getAChildNode().getAFlowNode() and
        cn2 = wi.getAChildNode().getAFlowNode()
      |
        nn.getId() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
        cn2.getFunction().getNode().toString() in ["AsyncWebCrawler"]
      )
      or
      exists(DefinitionNode dn |
        definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn)
      |
        dn.getNode().toString() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
        dn.getValue().(CallNode).getFunction().getNode().toString() in ["AsyncWebCrawler"]
      )
    )
  )
  or
  (
    cn.getFunction().(AttrNode).getNode().getName() in ["get", "post", "request"] and
    cn.getFunction().(AttrNode).getObject().getNode().toString() = "requests"
  )
  or
  (
    exists(ParameterDefinition pd, AttrNode an | pd.getScope() = cn.getScope() and pd.getAnnotation() = an |
      cn.getFunction().(AttrNode).getNode().getName() = "request" and
      pd.getName() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
      an.getNode().getName().matches("%Client") and
      an.getObject().getNode().toString() = "httpx"
    )
  )
  or
  (
    cn.getFunction().(AttrNode).getNode().getName() = "load" and
    exists(DefinitionNode dn |
      definition_node(cn.getFunction().(AttrNode).getNode().getScope*().(Function), dn)
    |
      dn.getNode().toString() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
      dn.getValue().(CallNode).getNode().getFunc().toString() in ["AsyncHtmlLoader", "WebBaseLoader"]
    )
  )
}

// Other：eval/exec/SQL/模板/VCS
predicate is_other_sink(CallNode cn) {
  cn.getFunction().(AttrNode).getNode().getName() = "execute_code"
  or
  cn.getFunction().(NameNode).getNode().toString() = "eval"
  or
  cn.getFunction().(NameNode).getNode().toString() = "exec"
  or
  (
    cn.getFunction().(AttrNode).getNode().getName() = "execute" and
    exists(DefinitionNode dn |
      definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn)
    |
      dn.getNode().toString() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
      print_function(dn.getValue().(CallNode)).matches("%.cursor")
    )
  )
  or
  (
    cn.getFunction().(AttrNode).getNode().getName() in ["run", "invoke"] and
    exists(DefinitionNode dn |
      definition_node(cn.getFunction().(AttrNode).getNode().getScope().(Function), dn)
    |
      dn.getNode().toString() = cn.getFunction().(AttrNode).getObject().getNode().toString() and
      dn.getValue().(CallNode).getFunction().(AttrNode).getNode().getName() = "from_llm" and
      dn.getValue().(CallNode).getFunction().(AttrNode).getObject().getNode().toString() in
        ["SQLDatabaseChain", "SQLDatabaseSequentialChain"]
    )
  )
  or
  print_function(cn).matches("%session.execute")
  or
  print_function(cn).matches("connection.execute")
  or
  print_function(cn).matches("jinja.from_string")
  or
  cn.getFunction().getNode().toString() = "GitLoader"
}

// Path（hermes 新增）：文件读写 / 文件系统改动
predicate is_path_sink(CallNode cn) {
  cn.getFunction().(NameNode).getNode().toString() = "open"
  or
  cn.getFunction().(AttrNode).getNode().getName() in
    ["read_text", "write_text", "read_bytes", "write_bytes"]
  or
  (
    cn.getFunction().(AttrNode).getNode().getName() in
      ["remove", "unlink", "rename", "replace", "mkdir", "makedirs", "rmdir"] and
    cn.getFunction().(AttrNode).getObject().getNode().toString() = "os"
  )
}

predicate is_sink(CallNode cn) {
  is_cmd_sink(cn) or is_net_sink(cn) or is_path_sink(cn) or is_other_sink(cn)
}

// sink 分类（用于输出归类）。极少数 sink 可能命中多类（如 run），后处理按优先级去重。
string sink_category(CallNode cn) {
  is_cmd_sink(cn) and result = "Cmd"
  or
  is_net_sink(cn) and result = "Network"
  or
  is_path_sink(cn) and result = "Path"
  or
  is_other_sink(cn) and result = "Other"
}

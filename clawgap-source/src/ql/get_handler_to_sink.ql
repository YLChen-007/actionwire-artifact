/**
 * @id clawgap/hermes-handler-to-sink
 * @name hermes 工具 handler 入口 → sink 的 call chain 连通性
 * @description 步骤 3：验证「工具 handler 入口（is_tool_handler，步骤 1）」到「工具执行 sink
 *              （is_sink_af，步骤 2 迁移自 AgentFuzz）」是否落在同一条调用链上。
 *              复用 clawgap call.qll 的 CHA 增强调用图（r_calls / calls(含 cha_calls + 服务句柄桥) /
 *              print_callchain）。镜像 get_callchain_and_location.ql，仅把 sink 谓词换成 is_sink_af。
 *              结果再要求当前 handler 的非 self/cls 形参能污点到达 sink 实参或接收者；纯调用可达、但
 *              sink 值不来自 handler 输入的配置/环境读取链不作为有效 handler→sink 链输出。另对
 *              `write(tainted_content)` 后由 `subprocess.Popen(..., same_path)` 执行同一文件的落盘执行
 *              语义建立窄桥，避免只看 Popen 路径值而漏掉文件内容型代码执行。
 *              验证 DB：codeql-db/hermes-agent-db（benchmark/python/hermes-agent 源树）。
 * @kind table
 * @tags clawgap
 */

import python
import call.call
import call.sinks_af
import util.util
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

// A callable passed to asyncio.to_thread has no direct method CallNode. Preserve the semantic
// method name so this query stays label-compatible with get_sinks.ql.
predicate isThreadedCallableSink(CallNode cn, string method) {
  cn.getFunction().(AttrNode).getNode().getName() = "to_thread" and
  cn.getArg(0).(AttrNode).getNode().getName() = method
  or
  projectThreadedCallableSink(cn, method, _)
}

// sink 调用点简短标签：属性调用取 `obj.method`，裸名调用取 `name`（与 get_sinks.ql 一致）。
string sinkLabel(CallNode cn) {
  isThreadedCallableSink(cn, result)
  or
  not exists(string method | isThreadedCallableSink(cn, method)) and
  exists(AttrNode a | a = cn.getFunction() |
    result = a.getObject().getNode().toString() + "." + a.getNode().getName()
  )
  or
  not exists(string method | isThreadedCallableSink(cn, method)) and
  not cn.getFunction() instanceof AttrNode and
  result = cn.getFunction().getNode().toString()
}

// 被执行 sink 的安全敏感值：HTTP 只取 URL，审计过的 RPC 取 payload，其余保留实参/接收者。
predicate sinkArgNode(CallNode sink, DataFlow::Node s) {
  isIncludeLocation2(sink.getLocation()) and
  sinkSensitiveNode(sink, s)
}

// 当前 handler 的 LLM 可控入口。self/cls 是对象接收者，不代表用户输入，避免把对象状态误作 source。
predicate handlerParamSource(FunctionObject handler, DataFlow::Node n) {
  is_tool_handler(handler) and
  isIncludeLocation2(handler.getFunction().getLocation()) and
  n.(DataFlow::ParameterNode).getScope() = handler.getFunction() and
  (
    projectHandlerSourceParameter(
      handler, n.(DataFlow::ParameterNode).getParameter()
    )
    or
    not projectToolHandler(handler) and
    not n.(DataFlow::ParameterNode).getParameter().(Name).getId() = ["self", "cls"]
  )
}

predicate anyHandlerParamSource(DataFlow::Node n) {
  exists(FunctionObject handler | handlerParamSource(handler, n))
}

string calleeName(CallNode c) {
  result = c.getFunction().(NameNode).getId()
  or
  result = c.getFunction().(AttrNode).getName()
}

// 与 get_gates.ql 保持一致：parser/normalizer/lookup 常把 handler 输入变成后续 sink 值。
predicate derivedReturnFunctionName(string name) {
  name = [
    "parse_qualified_name", "split", "rsplit", "partition", "rpartition",
    "urlparse", "urlsplit", "find_plugin_skill"
  ]
}

predicate unpackTargetElement(Expr target, Expr elem) {
  elem = target.(Tuple).getAnElt()
  or
  elem = target.(List).getAnElt()
  or
  exists(Expr child |
    (
      child = target.(Tuple).getAnElt()
      or
      child = target.(List).getAnElt()
    ) and
    unpackTargetElement(child, elem)
  )
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

predicate pathStringStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(CallNode c | succ.asCfgNode() = c |
    c.getFunction().(AttrNode).getName() =
      [
        "join", "expanduser", "abspath", "realpath", "normpath", "normcase", "dirname", "basename",
        "resolve", "absolute", "joinpath", "with_name", "with_suffix", "strip", "lstrip", "rstrip",
        "lower", "upper", "replace", "format", "encode", "decode"
      ] and
    (
      pred.asCfgNode() = c.getAnArg()
      or
      pred.asCfgNode() = c.getFunction().(AttrNode).getObject()
    )
    or
    c.getFunction().(NameNode).getId() = ["Path", "PurePath", "str", "fspath"] and
    pred.asCfgNode() = c.getAnArg()
  )
  or
  exists(BinaryExprNode b |
    b.getOp() instanceof Div and succ.asCfgNode() = b and pred.asCfgNode() = b.getAnOperand()
  )
}

predicate bridgedCall(CallNode cn, FunctionObject callee) {
  exists(FunctionObject caller |
    cha_calls(caller, callee, cn) or delivery_bridge(caller, callee, cn) or
    project_bridge(caller, callee, cn) and
    not astrToThreadCallbackEdge(caller, callee, cn)
  )
}

int selfOffset(FunctionObject callee) {
  callee.getFunction().getArgName(0) = "self" and result = 1
  or
  not callee.getFunction().getArgName(0) = "self" and result = 0
}

predicate bridgeTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(CallNode cn, FunctionObject callee | bridgedCall(cn, callee) |
    exists(int i |
      pred.asCfgNode() = cn.getArg(i) and
      succ.(DataFlow::ParameterNode).getParameter() = callee.getFunction().getArg(i + selfOffset(callee))
    )
    or
    exists(string name, Parameter p |
      pred.asCfgNode() = cn.getArgByName(name) and
      p = callee.getFunction().getArgByName(name) and
      succ.(DataFlow::ParameterNode).getParameter() = p
    )
  )
}

module HandlerSinkTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { anyHandlerParamSource(n) }

  predicate isSink(DataFlow::Node n) { sinkArgNode(_, n) }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    pathStringStep(a, b) or derivedValueStep(a, b) or bridgeTaintStep(a, b) or
    projectBridgeTaintStep(a, b)
  }
}

string handlerSourceParameters(FunctionObject handler) {
  result = strictconcat(Parameter p |
    (
      projectToolHandler(handler) and projectHandlerSourceParameter(handler, p)
      or
      not projectToolHandler(handler) and
      p = handler.getFunction().getArg(_) and
      not p.(Name).getId() = ["self", "cls"]
    )
  | p.(Name).getId(), ";" order by p.getLocation().getStartColumn())
}

string controlledSinkArguments(FunctionObject handler, CallNode sink) {
  result = strictconcat(DataFlow::Node sinkArg |
    sinkArgNode(sink, sinkArg) and
    exists(DataFlow::Node source |
      handlerParamSource(handler, source) and
      HandlerSinkTaint::flow(source, sinkArg)
    )
  | sinkArg.asCfgNode().getNode().toString(), ";")
  or
  handlerParamTaintsExecutedFile(handler, sink) and result = "written-file-content"
}

module HandlerSinkTaint = TaintTracking::Global<HandlerSinkTaintConfig>;

// `execute_code` 一类 sink 的攻击者输入不是 Popen 的路径字符串，而是先写入该路径的文件内容：
//
//   with open(join(tmpdir, "script.py"), "w") as f: f.write(code)
//   script_path = join(tmpdir, "script.py")
//   subprocess.Popen([python, script_path])
//
// 普通 source→sinkArg 污点只能看到 `script_path`（它不由 code 派生），因此需要把「写入内容」与
// 「执行同一路径」连接起来。为控制误报，此桥同时要求：
//   1. write 内容在 handler 内局部数据流自 handler 参数；
//   2. write receiver 是同一 `with open(..., write-mode) as handle` 的 handle；
//   3. Popen 与 write 在同一 handler，且其路径变量定义和 open 路径共享同一非空文件名 literal。
predicate handlerParamTaintsExecutedFile(FunctionObject handler, CallNode sink) {
  sink.getScope() = handler.getFunction() and
  sink.getFunction().(AttrNode).getNode().getName() = "Popen" and
  sink.getFunction().(AttrNode).getObject().getNode().toString() = "subprocess" and
  exists(
    DataFlow::Node source, DataFlow::Node writtenContent, CallNode writeCall,
    With wi, CallNode openCall, NameNode handle, Expr openPath,
    StringLiteral openFileName, StringLiteral executedFileName,
    NameNode executedPathUse, DefinitionNode executedPathDef
  |
    handlerParamSource(handler, source) and
    writtenContent.asCfgNode() = writeCall.getArg(0) and
    DataFlow::localFlow(source, writtenContent) and

    writeCall.getScope() = handler.getFunction() and
    writeCall.getFunction().(AttrNode).getNode().getName() = "write" and
    writeCall.getNode().getParentNode+() = wi and

    wi.getScope() = handler.getFunction() and
    openCall = wi.getAChildNode().getAFlowNode() and
    openCall.getFunction().(NameNode).getId() = "open" and
    openCall.getArg(1).getNode().(StringLiteral).getText().matches("%w%") and
    handle = wi.getAChildNode().getAFlowNode() and
    handle.getId() = writeCall.getFunction().(AttrNode).getObject().getNode().toString() and

    openPath = openCall.getArg(0).getNode() and
    openFileName.getParentNode*() = openPath and
    openFileName.getText() != "" and

    executedPathUse.getNode().getParentNode*() = sink.getAnArg().getNode() and
    definition_node(handler.getFunction(), executedPathDef) and
    executedPathDef.getNode().toString() = executedPathUse.getId() and
    executedFileName.getParentNode*() = executedPathDef.getValue().getNode() and
    executedFileName.getText() = openFileName.getText()
  )
}

predicate handlerParamTaintsSink(FunctionObject handler, CallNode sink) {
  exists(DataFlow::Node source, DataFlow::Node sinkArg |
    handlerParamSource(handler, source) and
    sinkArgNode(sink, sinkArg) and
    HandlerSinkTaint::flow(source, sinkArg)
  )
  or
  handlerParamTaintsExecutedFile(handler, sink)
}

// 用自由变量 (handler, depth, sink) 一体绑定，避免类字段多值导致列间笛卡尔积。
from FunctionObject handler, int d, CallNode sink
where
  is_tool_handler(handler) and
  isIncludeLocation2(handler.getFunction().getLocation()) and
  d = [1 .. 8] and
  r_calls(handler, sink, d) and
  is_sink_af(sink) and
  handlerParamTaintsSink(handler, sink)
select handler.getName() as handler_func,
  handler.getFunction().getLocation().getFile().getRelativePath() as handler_file,
  handler.getFunction().getLocation().getStartLine() as handler_line, d as depth,
  sinkLabel(sink) as sink_label, sink.getLocation().getFile().getRelativePath() as sink_file,
  sink.getLocation().getStartLine() as sink_line, print_callchain(handler, sink, d) as call_chain,
  activeProjectId() as project_id, toolHandlerName(handler) as tool_name,
  handler.getQualifiedName() as handler_qualified_name,
  handlerSourceParameters(handler) as source_parameter,
  sink.getLocation().getStartColumn() as sink_column,
  controlledSinkArguments(handler, sink) as sink_argument

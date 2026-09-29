/**
 * @id clawgap/hermes-gate-transform
 * @name hermes transform 型 gate（同源输入经过变换后到达 sink / guard）
 * @description gate-fte-design §4：检测两类 transform gate。sink-transform 要求同一 handler Source
 *              污点到达变换输入，且变换输出继续到达 is_sink_af 的实参/接收者；guard-normalizer
 *              要求变换输出进入安全检查，同时同一 Source 仍到达 sink。已审计的标准 API / Hermes
 *              自定义签名输出 confirmed；泛化的 str.replace / re.sub 只输出 needs-review，不能仅凭
 *              字符串改写自动认定安全 gate。显式纳入 send_message_tool 根以覆盖当前 DB 注册漂移下的
 *              Matrix / Slack 发送路径，并复用 CHA / delivery_bridge 的 arg→param 污点桥。
 * @kind table
 * @tags clawgap
 */

import python
import call.call
import call.sinks_af
import util.util
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

string calleeName(CallNode c) {
  result = c.getFunction().(NameNode).getId()
  or
  result = c.getFunction().(AttrNode).getName()
}

string sinkLabel(CallNode c) {
  exists(AttrNode a | a = c.getFunction() |
    result = a.getObject().getNode().toString() + "." + a.getName()
  )
  or
  not c.getFunction() instanceof AttrNode and
  result = c.getFunction().getNode().toString()
}

predicate transformRoot(FunctionObject f) {
  is_tool_handler(f)
  or
  // send_message registration is absent in the current DB snapshot, but it is the d5 root for Matrix/Slack GT.
  f.getName() = "send_message_tool" and
  f.getFunction().getLocation().getFile().getRelativePath() = "tools/send_message_tool.py"
}

predicate rootParamSource(FunctionObject root, DataFlow::Node n) {
  transformRoot(root) and
  isIncludeLocation2(root.getFunction().getLocation()) and
  n.(DataFlow::ParameterNode).getScope() = root.getFunction() and
  not n.(DataFlow::ParameterNode).getParameter().(Name).getId() = ["self", "cls"]
}

predicate anyRootParamSource(DataFlow::Node n) {
  exists(FunctionObject root | rootParamSource(root, n))
}

predicate transformSink(CallNode sink) {
  is_sink_af(sink)
  or
  calleeName(sink) = ["send_message_event", "chat_postMessage", "_api_post"]
  or
  calleeName(sink) = "put" and
  sink.getFunction().(AttrNode).getObject().getNode().toString() = "session"
}

predicate sinkArgNode(CallNode sink, DataFlow::Node n) {
  transformSink(sink) and
  isIncludeLocation2(sink.getLocation()) and
  (
    n.asCfgNode() = sink.getAnArg()
    or
    n.asCfgNode() = sink.getFunction().(AttrNode).getObject()
  )
}

predicate unpackTargetElement(Expr target, Expr elem) {
  elem = target.(Tuple).getAnElt()
  or
  elem = target.(List).getAnElt()
  or
  exists(Expr child |
    (child = target.(Tuple).getAnElt() or child = target.(List).getAnElt()) and
    unpackTargetElement(child, elem)
  )
}

predicate knownTransformFunction(FunctionObject f, string signature, string role) {
  exists(string path, string name |
    f.getFunction().getLocation().getFile().getRelativePath() = path and
    f.getName() = name and
    (
      path = "gateway/platforms/matrix.py" and
      name = [
        "_pre_sanitize_matrix_markdown", "_sanitize_matrix_html", "_sanitize_link_url",
        "_markdown_to_html_fallback"
      ]
      or
      path = "gateway/platforms/slack.py" and name = "format_message"
      or
      path = "tools/terminal_tool.py" and name = ["_transform_sudo_command", "_strip_quotes"]
      or
      path = "tools/environments/base.py" and name = "_wrap_command"
      or
      path = "tools/file_operations.py" and
      name = ["_escape_shell_arg", "normalize_read_pagination", "_expand_path"]
      or
      path = "tools/approval.py" and name = "_normalize_command_for_detection"
      or
      path = "tools/url_safety.py" and name = "normalize_url_for_request"
      or
      path = "tools/browser_camofox.py" and name = "_rewrite_loopback_url_for_camofox"
    ) and
    signature = path + "::" + name and
    (
      name = ["_strip_quotes", "_normalize_command_for_detection"] and role = "guard-normalizer"
      or
      not name = ["_strip_quotes", "_normalize_command_for_detection"] and role = "sink-transform"
    )
  )
}

predicate resolvedKnownTransformCall(
  CallNode c, FunctionObject target, string signature, string role
) {
  knownTransformFunction(target, signature, role) and
  exists(FunctionObject caller | calls_cn(caller, target, c))
}

// Conservative fallback for direct-name calls that type tracking does not resolve. The signature table remains exact.
predicate fallbackKnownTransformCall(
  CallNode c, FunctionObject target, string signature, string role
) {
  knownTransformFunction(target, signature, role) and
  calleeName(c) = target.getName() and
  (
    target.getName() != "format_message"
    or
    c.getLocation().getFile().getRelativePath() = [
      "gateway/platforms/slack.py", "tools/send_message_tool.py"
    ]
  )
}

predicate knownTransformCall(CallNode c, FunctionObject target, string signature, string role) {
  resolvedKnownTransformCall(c, target, signature, role)
  or
  fallbackKnownTransformCall(c, target, signature, role)
}

predicate matrixPipelineFunction(FunctionObject f) {
  f.getFunction().getLocation().getFile().getRelativePath() = "gateway/platforms/matrix.py" and
  f.getName() = ["_markdown_to_html", "_build_text_message_content"]
}

predicate trackedTransformOrPipelineCall(CallNode c, FunctionObject target) {
  knownTransformCall(c, target, _, _) and
  target.getFunction().getLocation().getFile().getRelativePath() = "gateway/platforms/matrix.py"
  or
  matrixPipelineFunction(target) and
  (
    exists(FunctionObject caller | calls_cn(caller, target, c))
    or
    calleeName(c) = target.getName() and
    c.getLocation().getFile().getRelativePath() = "gateway/platforms/matrix.py"
  )
}

predicate standardTransformCall(CallNode c, string signature, string role) {
  role = "sink-transform" and
  (
    c.getFunction().(NameNode).getId() = "_html_escape" and signature = "html.escape"
    or
    exists(AttrNode a |
      a = c.getFunction() and
      a.getName() = "escape" and
      a.getObject().getNode().toString() = ["html", "markupsafe"] and
      signature = a.getObject().getNode().toString() + ".escape"
    )
    or
    exists(AttrNode a |
      a = c.getFunction() and
      a.getName() = "quote" and
      a.getObject().getNode().toString() = "shlex" and
      signature = "shlex.quote"
    )
  )
}

predicate genericPrimitiveCall(CallNode c, string primitive, string role) {
  role = "sink-transform" and
  (
    c.getFunction().(AttrNode).getName() = "replace" and primitive = "str.replace"
    or
    calleeName(c) = "sub" and primitive = "regex.sub"
  )
}

predicate transformInputNode(CallNode c, DataFlow::Node n) {
  exists(FunctionObject target, string signature, string role |
    knownTransformCall(c, target, signature, role) and n.asCfgNode() = c.getAnArg()
  )
  or
  standardTransformCall(c, _, _) and n.asCfgNode() = c.getAnArg()
  or
  c.getFunction().(AttrNode).getName() = "replace" and
  n.asCfgNode() = c.getFunction().(AttrNode).getObject()
  or
  // re.sub(pattern, repl, value) and compiled_pattern.sub(repl, value).
  calleeName(c) = "sub" and n.asCfgNode() = [c.getArg(1), c.getArg(2)]
}

predicate transformOutputNode(CallNode c, DataFlow::Node n) {
  n.asCfgNode() = c
  or
  exists(Assign a, Expr target |
    a.getValue() = c.getNode() and
    unpackTargetElement(a.getATarget(), target) and
    n.asCfgNode() = target.getAFlowNode()
  )
}

predicate checkUseNode(DataFlow::Node n) {
  exists(CallNode c |
    calleeName(c) = [
      "search", "match", "fullmatch", "startswith", "endswith", "find", "contains",
      "is_dangerous_command", "detect_dangerous_command", "detect_hardline_command"
    ] and
    (
      n.asCfgNode() = c.getAnArg()
      or
      n.asCfgNode() = c.getFunction().(AttrNode).getObject()
    )
  )
}

predicate bridgedCall(CallNode c, FunctionObject callee) {
  exists(FunctionObject caller |
    cha_calls(caller, callee, c) or delivery_bridge(caller, callee, c)
  )
}

int selfOffset(FunctionObject callee) {
  callee.getFunction().getArgName(0) = "self" and result = 1
  or
  not callee.getFunction().getArgName(0) = "self" and result = 0
}

predicate bridgeTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(CallNode c, FunctionObject callee | bridgedCall(c, callee) |
    exists(int i |
      pred.asCfgNode() = c.getArg(i) and
      succ.(DataFlow::ParameterNode).getParameter() = callee.getFunction().getArg(i + selfOffset(callee))
    )
    or
    exists(string name, Parameter p |
      pred.asCfgNode() = c.getArgByName(name) and
      p = callee.getFunction().getArg(_) and
      p.(Name).getId() = name and
      succ.(DataFlow::ParameterNode).getParameter() = p
    )
  )
}

predicate pathStringStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(CallNode c | succ.asCfgNode() = c |
    c.getFunction().(AttrNode).getName() = [
      "join", "expanduser", "abspath", "realpath", "normpath", "normcase", "dirname",
      "basename", "resolve", "absolute", "joinpath", "with_name", "with_suffix", "strip",
      "lstrip", "rstrip", "lower", "upper", "format", "encode", "decode"
    ] and
    (pred.asCfgNode() = c.getAnArg() or pred.asCfgNode() = c.getFunction().(AttrNode).getObject())
    or
    c.getFunction().(NameNode).getId() = ["Path", "PurePath", "str", "fspath"] and
    pred.asCfgNode() = c.getAnArg()
  )
  or
  exists(BinaryExprNode b |
    b.getOp() instanceof Div and succ.asCfgNode() = b and pred.asCfgNode() = b.getAnOperand()
  )
}

predicate transformUnpackStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(CallNode c, Assign a, Expr target |
    (knownTransformCall(c, _, _, _) or standardTransformCall(c, _, _)) and
    pred.asCfgNode() = c and
    a.getValue() = c.getNode() and
    unpackTargetElement(a.getATarget(), target) and
    succ.asCfgNode() = target.getAFlowNode()
  )
}

// Markdown converter results are string transforms even though the third-party library has no useful flow summary.
predicate transformPipelineStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(CallNode c |
    calleeName(c) = ["convert", "urlunsplit"] and
    pred.asCfgNode() = c.getAnArg() and succ.asCfgNode() = c
  )
}

// calls_cn includes Hermes's CHA and delivery bridges, but those synthetic edges do not carry
// return values. Keep the return summary limited to audited transforms and the two Matrix helpers
// that package transformed HTML for send_message_event.
predicate trackedReturnStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(CallNode c, FunctionObject callee, Return ret |
    trackedTransformOrPipelineCall(c, callee) and
    ret.getScope() = callee.getFunction() and
    pred.asCfgNode() = ret.getValue().getAFlowNode() and
    succ.asCfgNode() = c
  )
}

// Assignment into a returned payload dictionary is a content-flow step. The standard Python
// model handles dictionary literals, but not this mutation pattern reliably across a synthetic
// method-return edge.
predicate returnedDictPayloadStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(Assign a, Subscript target, Return ret, Name payload |
    a.getLocation().getFile().getRelativePath() = "gateway/platforms/matrix.py" and
    a.getATarget() = target and
    target.getObject() = payload and
    ret.getScope() = a.getScope() and
    ret.getValue().(Name).getId() = payload.getId() and
    pred.asCfgNode() = a.getValue().getAFlowNode() and
    succ.asCfgNode() = ret.getValue().getAFlowNode()
  )
}

// re.sub passes a match object to its replacement callback. This is needed for
// _sanitize_link_url(m.group(2)); group() then derives the captured URL from that match object.
predicate matrixRegexCallbackStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(CallNode sub, Lambda callback |
    sub.getLocation().getFile().getRelativePath() = "gateway/platforms/matrix.py" and
    sub.getScope().(Function).getName() = "_markdown_to_html_fallback" and
    calleeName(sub) = "sub" and
    sub.getArg(1) = callback.getAFlowNode() and
    pred.asCfgNode() = sub.getArg(2) and
    succ.(DataFlow::ParameterNode).getParameter() = callback.getInnerScope().getArg(0)
  )
  or
  exists(CallNode group |
    group.getLocation().getFile().getRelativePath() = "gateway/platforms/matrix.py" and
    group.getScope().(Function).getName() = "lambda" and
    calleeName(group) = "group" and
    pred.asCfgNode() = group.getFunction().(AttrNode).getObject() and
    succ.asCfgNode() = group
  )
}

// The fallback protects sanitized link HTML in a side list and restores it later. Model that
// audited callback/container behavior as parent-transform ownership instead of treating all
// regex callbacks as sanitizers.
predicate matrixNestedTransformStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(
    CallNode child, FunctionObject childTarget, CallNode parentCall, FunctionObject parentTarget
  |
    knownTransformCall(child, childTarget, _, _) and
    childTarget.getName() = "_sanitize_link_url" and
    knownTransformFunction(parentTarget, _, _) and
    parentTarget.getName() = "_markdown_to_html_fallback" and
    child.getScope().getEnclosingScope() = parentTarget.getFunction() and
    trackedTransformOrPipelineCall(parentCall, parentTarget) and
    pred.asCfgNode() = child and
    succ.asCfgNode() = parentCall
  )
}

module TransformFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    anyRootParamSource(n) or transformOutputNode(_, n)
  }

  predicate isSink(DataFlow::Node n) {
    transformInputNode(_, n) or sinkArgNode(_, n) or checkUseNode(n)
  }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    pathStringStep(a, b) or bridgeTaintStep(a, b) or transformUnpackStep(a, b) or
    transformPipelineStep(a, b) or trackedReturnStep(a, b) or returnedDictPayloadStep(a, b) or
    matrixRegexCallbackStep(a, b) or matrixNestedTransformStep(a, b)
  }
}

module TransformFlow = TaintTracking::Global<TransformFlowConfig>;

predicate sameOriginSinkTransform(
  FunctionObject root, CallNode transform, CallNode sink
) {
  exists(DataFlow::Node source, DataFlow::Node input, DataFlow::Node output, DataFlow::Node sinkArg |
    rootParamSource(root, source) and
    transformInputNode(transform, input) and
    transformOutputNode(transform, output) and
    sinkArgNode(sink, sinkArg) and
    TransformFlow::flow(source, input) and
    TransformFlow::flow(output, sinkArg)
  )
}

predicate sameOriginGuardNormalizer(
  FunctionObject root, CallNode transform, CallNode sink
) {
  exists(
    DataFlow::Node source, DataFlow::Node input, DataFlow::Node output, DataFlow::Node check,
    DataFlow::Node sinkArg
  |
    rootParamSource(root, source) and
    transformInputNode(transform, input) and
    transformOutputNode(transform, output) and
    checkUseNode(check) and
    sinkArgNode(sink, sinkArg) and
    TransformFlow::flow(source, input) and
    TransformFlow::flow(output, check) and
    TransformFlow::flow(source, sinkArg)
  )
}

predicate transformResult(
  FunctionObject root, CallNode transform, CallNode sink, string transformFn, string transformFile,
  int transformLine, string role, string primitive, string verdict
) {
  exists(FunctionObject target, string signature |
    knownTransformCall(transform, target, signature, role) and
    transformFn = target.getName() and
    transformFile = target.getFunction().getLocation().getFile().getRelativePath() and
    transformLine = target.getFunction().getLocation().getStartLine() and
    primitive = "custom-signature:" + signature and
    verdict = "confirmed" and
    (
      role = "sink-transform" and sameOriginSinkTransform(root, transform, sink)
      or
      role = "guard-normalizer" and sameOriginGuardNormalizer(root, transform, sink)
    )
  )
  or
  exists(string signature |
    standardTransformCall(transform, signature, role) and
    transformFn = calleeName(transform) and
    transformFile = transform.getLocation().getFile().getRelativePath() and
    transformLine = transform.getLocation().getStartLine() and
    primitive = signature and
    verdict = "confirmed" and
    sameOriginSinkTransform(root, transform, sink)
  )
  or
  exists(string generic |
    genericPrimitiveCall(transform, generic, role) and
    transformFn = calleeName(transform) and
    transformFile = transform.getLocation().getFile().getRelativePath() and
    transformLine = transform.getLocation().getStartLine() and
    primitive = generic and
    verdict = "needs-review" and
    sameOriginSinkTransform(root, transform, sink)
  )
}


string inputLegStatus(FunctionObject root, CallNode transform) {
  result = "input-flow" and
  exists(DataFlow::Node source, DataFlow::Node input |
    rootParamSource(root, source) and transformInputNode(transform, input) and
    TransformFlow::flow(source, input)
  )
  or
  result = "NO-input-flow" and
  not exists(DataFlow::Node source, DataFlow::Node input |
    rootParamSource(root, source) and transformInputNode(transform, input) and
    TransformFlow::flow(source, input)
  )
}

string outputLegStatus(CallNode transform) {
  result = "output-flow" and
  exists(CallNode sink, DataFlow::Node output, DataFlow::Node sinkArg |
    transformOutputNode(transform, output) and sinkArgNode(sink, sinkArg) and
    TransformFlow::flow(output, sinkArg)
  )
  or
  result = "NO-output-flow" and
  not exists(CallNode sink, DataFlow::Node output, DataFlow::Node sinkArg |
    transformOutputNode(transform, output) and sinkArgNode(sink, sinkArg) and
    TransformFlow::flow(output, sinkArg)
  )
}

from FunctionObject root, CallNode transform, FunctionObject target, string signature, string role
where
  knownTransformCall(transform, target, signature, role) and
  target.getName() = ["_sanitize_link_url", "_markdown_to_html_fallback"]
select root.getName() as handler_root, target.getName() as transform_fn,
  transform.getLocation().getFile().getRelativePath() as call_file,
  transform.getLocation().getStartLine() as call_line,
  inputLegStatus(root, transform) as input_leg,
  outputLegStatus(transform) as output_leg

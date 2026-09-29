/** Shared Python conditional collection-admission detector. */

import python
import call.call
import call.sinks_af
import project.ProjectModel
import util.util
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

string filterCalleeName(CallNode c) {
  result = c.getFunction().(NameNode).getId()
  or
  result = c.getFunction().(AttrNode).getName()
}

private predicate controlledCollAdmit(
  ConditionBlock cb, DataFlow::Node checked, DataFlow::Node collAfter
) {
  exists(DataFlow::MethodCallNode mc |
    mc.getMethodName() = ["append", "add", "extend", "insert"] and
    cb.controls(mc.asCfgNode().getBasicBlock(), _) and
    TaintTracking::localTaint(checked, mc.getArg(_)) and
    collAfter.(DataFlow::PostUpdateNode).getPreUpdateNode() = mc.getObject()
  )
  or
  exists(Subscript subT, Assign a |
    a.getATarget() = subT and
    cb.controls(subT.getAFlowNode().getBasicBlock(), _) and
    (
      TaintTracking::localTaint(checked, DataFlow::exprNode(subT.getIndex()))
      or TaintTracking::localTaint(checked, DataFlow::exprNode(a.getValue()))
    ) and
    collAfter.(DataFlow::PostUpdateNode).getPreUpdateNode().asExpr() = subT.getObject()
  )
}

/** Preserve the accepted pre-generalization same-variable admission baseline. */
private predicate legacySameVariableAdmission(
  ConditionBlock cb, DataFlow::Node checked, DataFlow::Node collAfter
) {
  exists(DataFlow::MethodCallNode mc |
    mc.getMethodName() = ["append", "add", "extend", "insert"] and
    cb.controls(mc.asCfgNode().getBasicBlock(), _) and
    checked.asExpr().(Name).getVariable() = mc.getArg(_).asExpr().(Name).getVariable() and
    collAfter.(DataFlow::PostUpdateNode).getPreUpdateNode() = mc.getObject()
  )
  or
  exists(Subscript subT, Assign a |
    a.getATarget() = subT and
    cb.controls(subT.getAFlowNode().getBasicBlock(), _) and
    (
      checked.asExpr().(Name).getVariable() = subT.getIndex().(Name).getVariable()
      or
      checked.asExpr().(Name).getVariable() = a.getValue().(Name).getVariable()
    ) and
    collAfter.(DataFlow::PostUpdateNode).getPreUpdateNode().asExpr() = subT.getObject()
  )
}

private predicate legacyGateInTest(
  ConditionBlock cb, CallNode gateCall, Variable checkedVariable
) {
  exists(If ifs |
    ifs.getTest().getAFlowNode() = cb.getLastNode() and
    gateCall.getNode() = ifs.getTest().getASubExpression*() and
    gateCall.getNode().(Call).getAnArg().(Name).getVariable() = checkedVariable
  )
}

/** Exact compatibility shape from the pre-generalization detector. */
private predicate legacyFilterAdmission(
  ConditionBlock cb, CallNode gateCall, DataFlow::Node checked,
  DataFlow::Node collAfter
) {
  exists(Variable checkedVariable |
    legacySameVariableAdmission(cb, checked, collAfter) and
    checked.asExpr().(Name).getVariable() = checkedVariable and
    legacyGateInTest(cb, gateCall, checkedVariable)
  ) and
  not (
    isHermesProject() and
    gateCall.getLocation().getFile().getRelativePath() = "tools/browser_tool.py" and
    gateCall.getLocation().getStartLine() = 639
  )
}

private predicate rejectingContinue(If ifs, For loop) {
  ifs.getParent() = loop.getBody() and
  exists(Continue cont | cont.getParent() = ifs.getBody())
}

private predicate conditionBlockInIf(ConditionBlock cb, If ifs) {
  cb.getLastNode().getNode() = ifs.getTest().getASubExpression*()
}

private predicate postRejectCollAdmit(
  ConditionBlock cb, DataFlow::Node checked, DataFlow::Node collAfter
) {
  exists(If ifs, For loop, DataFlow::MethodCallNode mc |
    conditionBlockInIf(cb, ifs) and
    rejectingContinue(ifs, loop) and
    mc.getMethodName() = ["append", "add", "extend", "insert"] and
    mc.getScope() = loop.getScope() and
    mc.asCfgNode().getNode().getParentNode+() = loop and
    mc.getLocation().getStartLine() > ifs.getLocation().getEndLine() and
    TaintTracking::localTaint(checked, mc.getArg(_)) and
    collAfter.(DataFlow::PostUpdateNode).getPreUpdateNode() = mc.getObject()
  )
}

private predicate collAdmit(
  ConditionBlock cb, DataFlow::Node checked, DataFlow::Node collAfter
) {
  controlledCollAdmit(cb, checked, collAfter)
  or postRejectCollAdmit(cb, checked, collAfter)
}

private predicate gateInTest(
  ConditionBlock cb, CallNode gateCall, DataFlow::Node checked
) {
  exists(If ifs |
    conditionBlockInIf(cb, ifs) and
    gateCall.getNode() = cb.getLastNode().getNode().(Expr).getASubExpression*() and
    (
      checked.asCfgNode() = gateCall.getAnArg()
      or checked.asCfgNode() = gateCall.getFunction().(AttrNode).getObject()
    )
  )
}

private predicate filterSinkArgNode(CallNode sink, DataFlow::Node n) {
  sinkSensitiveNode(sink, n)
}

private module FilterConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { collAdmit(_, _, n) }

  predicate isSink(DataFlow::Node n) { filterSinkArgNode(_, n) }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    projectBridgeTaintStep(pred, succ)
  }
}

private module FilterFlow = TaintTracking::Global<FilterConfig>;

private predicate admittedCollectionFlowsToNode(
  DataFlow::Node collAfter, DataFlow::Node node
) {
  FilterFlow::flow(collAfter, node)
}

private predicate filterRootSource(DataFlow::Node source) {
  exists(FunctionObject root, Parameter parameter |
    projectToolHandler(root) and projectHandlerSourceParameter(root, parameter) and
    source.(DataFlow::ParameterNode).getScope() = root.getFunction() and
    source.(DataFlow::ParameterNode).getParameter() = parameter
  )
}

private module FilterOriginConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { filterRootSource(n) }

  predicate isSink(DataFlow::Node n) {
    exists(ConditionBlock cb, CallNode gate, DataFlow::Node collAfter |
      collAdmit(cb, n, collAfter) and gateInTest(cb, gate, n)
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    projectBridgeTaintStep(pred, succ)
  }
}

private module FilterOriginFlow = TaintTracking::Global<FilterOriginConfig>;

/**
 * Revision-pinned bridges for source flows that the bounded Python call graph does not resolve.
 * QwenPaw uses dynamic archive/search dispatch; Hermes passes the tool-controlled process
 * environment through its environment abstraction before these admission points.
 */
private predicate auditedProjectFilterOrigin(CallNode gateCall) {
  isQwenPawProject() and
  (
    gateCall.getLocation().getFile().getRelativePath() =
      "src/qwenpaw/agents/tools/file_search.py" and
    gateCall.getLocation().getStartLine() = 308 and filterCalleeName(gateCall) = "_is_text_file"
    or
    gateCall.getLocation().getFile().getRelativePath() =
      "src/qwenpaw/agents/skill_system/pool_service.py" and
    gateCall.getLocation().getStartLine() = 301 and filterCalleeName(gateCall) = "import_skill_dir"
  )
  or
  isHermesProject() and
  gateCall.getLocation().getFile().getRelativePath() = "tools/environments/local.py" and
  gateCall.getLocation().getStartLine() = [156, 162, 232] and
  filterCalleeName(gateCall) = "startswith"
}

predicate filterAdmissionCandidate(
  ConditionBlock cb, CallNode gateCall, DataFlow::Node checked,
  DataFlow::Node collAfter
) {
  collAdmit(cb, checked, collAfter) and
  gateInTest(cb, gateCall, checked) and
  not is_sink_af(gateCall)
}

private predicate filterGateHasRootOrigin(CallNode gateCall, DataFlow::Node checked) {
  exists(DataFlow::Node source |
    filterRootSource(source) and FilterOriginFlow::flow(source, checked)
  )
  or auditedProjectFilterOrigin(gateCall)
}

private predicate admittedCollectionReachesSink(
  DataFlow::Node collAfter, CallNode sink, DataFlow::Node sinkArg
) {
  filterSinkArgNode(sink, sinkArg) and
  admittedCollectionFlowsToNode(collAfter, sinkArg)
}

/** Location-independent core used by fixtures whose absolute paths contain `/tests/`. */
predicate filterGateCoreResult(
  ConditionBlock cb, CallNode gateCall, DataFlow::Node checked,
  DataFlow::Node collAfter, CallNode sink, DataFlow::Node sinkArg
) {
  filterAdmissionCandidate(cb, gateCall, checked, collAfter) and
  (
    legacyFilterAdmission(cb, gateCall, checked, collAfter)
    or filterGateHasRootOrigin(gateCall, checked)
  ) and
  admittedCollectionReachesSink(collAfter, sink, sinkArg)
}

predicate filterGateResult(
  ConditionBlock cb, CallNode gateCall, DataFlow::Node checked,
  DataFlow::Node collAfter, CallNode sink, DataFlow::Node sinkArg
) {
  filterGateCoreResult(cb, gateCall, checked, collAfter, sink, sinkArg) and
  isIncludeLocation2(gateCall.getLocation()) and
  isIncludeLocation2(sink.getLocation())
}

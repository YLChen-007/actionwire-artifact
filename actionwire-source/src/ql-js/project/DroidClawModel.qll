/** DroidClaw 1.0.0 LLM-selected local action and skill model. */

import javascript

predicate dcIsProject() {
  exists(Function decision, Function dispatch, Function adb |
    decision.getName() = "getDecisionStreaming" and
    decision.getFile().getRelativePath() = "src/kernel.ts" and
    dispatch.getName() = "executeAction" and
    dispatch.getFile().getRelativePath() = "src/actions.ts" and
    adb.getName() = "runAdbCommand" and adb.getFile() = dispatch.getFile()
  )
}

bindingset[path]
predicate dcIsCoreSourcePath(string path) {
  path.matches("src/%.ts") and
  not path.matches("%.test.ts") and not path.matches("%.spec.ts")
}

predicate dcIsCoreLocation(Location loc) {
  dcIsCoreSourcePath(loc.getFile().getRelativePath())
}

private predicate dcParameterProperty(Expr expr, string parameterName, string propertyName) {
  exists(PropAccess access |
    expr.getUnderlyingValue() = access and access.getPropertyName() = propertyName and
    access.getBase().getUnderlyingValue().(Identifier).getName() = parameterName
  )
}

/** The audited direct-action dispatcher switches specifically on `action.action`. */
private predicate dcActionDispatcher(Function dispatch, SwitchStmt switchStmt) {
  dispatch.getName() = "executeAction" and
  dispatch.getFile().getRelativePath() = "src/actions.ts" and
  dispatch.getNumParameter() = 1 and dispatch.getParameter(0).getName() = "action" and
  switchStmt.getContainer() = dispatch and
  dcParameterProperty(switchStmt.getExpr(), "action", "action")
}

/** The audited skill dispatcher derives its key from `decision.skill ?? decision.action`. */
private predicate dcSkillDispatcher(Function dispatch, SwitchStmt switchStmt) {
  dispatch.getName() = "executeSkill" and
  dispatch.getFile().getRelativePath() = "src/skills.ts" and
  dispatch.getNumParameter() = 2 and dispatch.getParameter(0).getName() = "decision" and
  dispatch.getParameter(1).getName() = "elements" and switchStmt.getContainer() = dispatch and
  switchStmt.getExpr().getUnderlyingValue().(Identifier).getName() = "skill" and
  exists(VariableDeclarator declaration, NullishCoalescingExpr fallback |
    declaration.getEnclosingFunction() = dispatch and
    declaration.getBindingPattern().(Identifier).getName() = "skill" and
    declaration.getInit().getUnderlyingValue() = fallback and
    dcParameterProperty(fallback.getLeftOperand(), "decision", "skill") and
    dcParameterProperty(fallback.getRightOperand(), "decision", "action")
  )
}

/** A literal case must directly return a resolved local function from the audited dispatcher. */
private predicate dcLiteralDispatchCase(
  Function dispatch, Function handler, DataFlow::CallNode handlerCall, string toolName,
  string dispatchKind
) {
  exists(SwitchStmt switchStmt, Case caseStmt, ReturnStmt returned |
    (
      dcActionDispatcher(dispatch, switchStmt) and dispatchKind = "action"
      or
      dcSkillDispatcher(dispatch, switchStmt) and dispatchKind = "skill"
    ) and
    caseStmt = switchStmt.getACase() and not caseStmt.isDefault() and
    toolName = caseStmt.getExpr().getStringValue() and returned = caseStmt.getABodyStmt() and
    returned.getExpr().getUnderlyingValue() = handlerCall.asExpr() and
    handlerCall.getContainer() = dispatch and handlerCall.getACallee() = handler and
    handler.getFile() = dispatch.getFile() and dcIsCoreLocation(handler.getLocation())
  )
}

predicate dcToolHandler(Function handler, string toolName, string model) {
  dcIsProject() and
  exists(Function dispatch, DataFlow::CallNode handlerCall, string dispatchKind,
    string dispatcherParameter |
    dcLiteralDispatchCase(dispatch, handler, handlerCall, toolName, dispatchKind) and
    dispatcherParameter = dispatch.getParameter(0).getName() and
    dispatcherParameter = ["action", "decision"] and handlerCall.getNumArgument() > 0 and
    handlerCall.getArgument(0).asExpr().getUnderlyingValue().(Identifier).getName() =
      dispatcherParameter and
    handler.getNumParameter() > 0 and handler.getParameter(0).getName() = dispatcherParameter and
    model = "literal-" + dispatchKind + "-case:" + toolName
  )
}

predicate dcHandlerSource(Function handler, DataFlow::Node source, string parameterName) {
  dcIsProject() and
  exists(Function dispatch, DataFlow::CallNode handlerCall, string toolName,
    string dispatchKind, string dispatcherParameter |
    dcLiteralDispatchCase(
      dispatch, handler, handlerCall, toolName, dispatchKind
    ) and
    dispatcherParameter = dispatch.getParameter(0).getName() and
    dispatcherParameter = ["action", "decision"] and handlerCall.getNumArgument() > 0 and
    handlerCall.getArgument(0).asExpr().getUnderlyingValue().(Identifier).getName() =
      dispatcherParameter and
    handler.getNumParameter() > 0 and handler.getParameter(0).getName() = dispatcherParameter and
    source = DataFlow::parameterNode(handler.getParameter(0)) and
    parameterName = dispatcherParameter
  )
}

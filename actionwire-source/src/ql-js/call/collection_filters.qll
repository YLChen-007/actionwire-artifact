/** Cross-project TypeScript conditional collection-admission shapes and flow proof. */

import javascript
import project.ProjectModel
import call.call
import call.sinks_af

private predicate rejectingBranch(IfStmt guard) {
  exists(ReturnStmt rejection | rejection.getParent*() = guard.getThen())
  or exists(ThrowStmt rejection | rejection.getParent*() = guard.getThen())
  or exists(ContinueStmt rejection | rejection.getParent*() = guard.getThen())
}

private predicate sameOriginAdmission(
  DataFlow::Node checked, DataFlow::CallNode admission
) {
  localTaint(checked, admission.getAnArgument())
  or
  exists(VarRef checkedRef, VarRef admittedRef |
    checkedRef.flow() = checked and checkedRef.getVariable() = admittedRef.getVariable() and
    admittedRef.getParent*() = admission.getAnArgument().asExpr()
  )
}

predicate collectionAdmissionShape(
  DataFlow::CallNode gate, DataFlow::Node checked, DataFlow::CallNode admission,
  string conditionExpr, string mode
) {
  exists(IfStmt guard |
    gate.asExpr().getParent*() = guard.getCondition() and
    (checked = gate.getAnArgument() or checked = gate.getReceiver()) and
    admission.getCalleeName() = ["push", "add", "set"] and
    sameOriginAdmission(checked, admission) and
    (
      admission.asExpr().getParent+() = guard.getThen() and mode = "guarded-admission"
      or
      rejectingBranch(guard) and admission.getContainer() = gate.getContainer() and
      admission.getLocation().getStartLine() > guard.getLocation().getEndLine() and
      guard.getCondition().getBasicBlock().(ReachableBasicBlock).dominates(
        admission.getBasicBlock()
      ) and mode = "reject-then-admit"
    ) and
    conditionExpr = guard.getCondition().toString()
  )
}

predicate arrayFilterShape(
  DataFlow::CallNode filter, DataFlow::Node checked, string conditionExpr
) {
  filter.getCalleeName() = "filter" and checked = filter.getReceiver() and
  exists(Function callback |
    filter.getArgument(0).asExpr().getUnderlyingValue() = callback and
    conditionExpr = callback.getBody().toString()
  )
}

predicate genericProjectFilterRow(
  Function handler, DataFlow::Node source, DataFlow::CallNode sink,
  DataFlow::Node sinkArg, DataFlow::CallNode gate, DataFlow::Node checked,
  Function owner, int chainDepth, int gateDepth, string path,
  string conditionExpr
) {
  projectToolHandler(handler, _, _) and handlerSource(handler, source, _) and
  isCoreLocation(gate.getLocation()) and isCoreLocation(sink.getLocation()) and
  controlledSinkArgument(sink, sinkArg, _) and
  taintReachesSink(handler, source, sink, sinkArg, chainDepth) and
  reachesSink(handler, sink, chainDepth, path) and gate.getContainer() = owner and
  (
    exists(DataFlow::CallNode admission, Function sinkOwner, int remainingDepth, string mode |
      collectionAdmissionShape(gate, checked, admission, conditionExpr, mode) and
      sourceReachesFunctionNode(handler, source, owner, checked, gateDepth) and
      dominatesSinkPath(gate, owner, sink) and
      sink.getContainer() = sinkOwner and
      sourceReachesFunctionNode(
        owner, admission.getReceiver(), sinkOwner, sinkArg, remainingDepth
      )
    )
    or
    arrayFilterShape(gate, checked, conditionExpr) and
    sourceReachesFunctionNode(handler, source, owner, checked, gateDepth) and
    dominatesSinkPath(gate, owner, sink) and
    exists(Function sinkOwner, int remainingDepth |
      sink.getContainer() = sinkOwner and
      sourceReachesFunctionNode(owner, gate, sinkOwner, sinkArg, remainingDepth)
    )
  )
}

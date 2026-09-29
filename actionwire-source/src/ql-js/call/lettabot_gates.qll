/** Revision-pinned LettaBot dominance gates on exact handler-to-sink chains. */

import javascript
import project.ProjectModel
import call.call
import call.sinks_af

/** Exact semantic sink identity selected for one source-bearing LettaBot handler. */
private predicate lettaBotHandlerSink(string toolName, DataFlow::CallNode sink) {
  toolName = "Bash" and sinkCanonicalId(sink) = "LB-CODE-BASH"
  or
  toolName = "Read" and sinkCanonicalId(sink) = "LB-CODE-READ"
  or
  toolName = "Edit" and sinkCanonicalId(sink) = "LB-CODE-EDIT"
  or
  toolName = "Write" and sinkCanonicalId(sink) = "LB-CODE-WRITE"
  or
  toolName = "Glob" and sinkCanonicalId(sink) = "LB-CODE-GLOB"
  or
  toolName = "Grep" and sinkCanonicalId(sink) = "LB-CODE-GREP"
  or
  toolName = "Task" and sinkCanonicalId(sink) = "LB-CODE-TASK"
  or
  toolName = "manage_todo" and sinkCanonicalId(sink) = "LB-TODO-STORE-WRITE"
}

/**
 * Bind gates to the same revision-pinned handler/source/sink path used by the call-chain query.
 * The separate call-chain query proves facet taint. Repeating that global taint closure here made
 * the dominance query needlessly recompute the complete project relation for every gate candidate.
 */
private predicate lettaBotChain(
  Function handler, DataFlow::Node source, DataFlow::CallNode sink,
  string toolName, string sourceName
) {
  isLettaBotProject() and lettaBotToolHandler(handler, toolName, _) and
  handlerSource(handler, source, sourceName) and lettaBotHandlerSink(toolName, sink) and
  exists(DataFlow::Node sinkArg, int chainDepth, string path |
    controlledSinkArgument(sink, sinkArg, _) and
    reachesSink(handler, sink, chainDepth, path)
  )
}

private predicate conditionMentions(Expr condition, string name) {
  exists(Identifier identifier |
    identifier.getName() = name and identifier.getParent*() = condition
  )
}

private predicate blockingIf(IfStmt guard, string guardKind) {
  exists(ThrowStmt rejection |
    rejection.getParent*() = guard.getThen() and guardKind = "inline-early-throw"
  )
  or
  exists(ReturnStmt rejection |
    rejection.getParent*() = guard.getThen() and guardKind = "inline-early-return"
  )
}

/** Direct required-field checks shared by the seven pinned Letta Code handlers. */
private predicate requiredParameterGate(
  Function handler, DataFlow::Node source, DataFlow::CallNode sink,
  DataFlow::CallNode gate, DataFlow::Node checked, string toolName,
  string guardKind, string verdict, string conditionExpr
) {
  toolName = ["Bash", "Read", "Edit", "Write", "Glob", "Grep", "Task"] and
  gate.getContainer() = handler and gate.getCalleeName() = "validateRequiredParams" and
  gate.getNumArgument() = 3 and checked = gate.getArgument(0) and
  checked.toString() = "args" and
  sourceReachesFunctionNode(handler, source, handler, checked, 0) and
  (
    toolName != "Task" and dominatesSinkPath(gate, handler, sink) and
    guardKind = "call-dominates" and verdict = "confirmed"
    or
    toolName = "Task" and guardKind = "decision-return-branch" and
    verdict = "branch-confirmed"
  ) and
  conditionExpr = gate.asExpr().toString()
}

/** Call-shaped validation gates specific to one LettaBot capability path. */
private predicate capabilityCallGate(
  Function handler, DataFlow::Node source, DataFlow::CallNode sink,
  DataFlow::CallNode gate, DataFlow::Node checked, string toolName,
  string guardKind, string verdict, string conditionExpr, Function owner
) {
  gate.getContainer() = owner and
  (
    toolName = "Read" and owner = handler and gate.getCalleeName() = "isBinaryFile" and
    sink.getCalleeName() = "readFile" and checked = gate.getArgument(0) and
    checked.toString() = "resolvedPath" and
    exists(IfStmt guard |
      gate.asExpr().getParent*() = guard.getCondition() and
      blockingIf(guard, guardKind) and conditionExpr = guard.getCondition().toString()
    ) and
    verdict = "confirmed"
    or
    toolName = "Task" and owner = handler and gate.getCalleeName() = "has" and
    gate.getReceiver().toString() = "VALID_DEPLOY_TYPES" and
    checked = gate.getArgument(0) and checked.toString() = "subagent_type" and
    sourceReachesFunctionNode(handler, source, owner, checked, 0) and
    exists(IfStmt guard |
      gate.asExpr().getParent*() = guard.getCondition() and
      conditionExpr = guard.getCondition().toString()
    ) and guardKind = "decision-return-branch" and verdict = "branch-confirmed"
    or
    toolName = "manage_todo" and owner = handler and
    gate.getCalleeName() = "readStringParam" and gate.getNumArgument() = 3 and
    checked = gate.getArgument(0) and checked.toString() = "params" and
    gate.getArgument(1).mayHaveStringValue("action") and
    sourceReachesFunctionNode(handler, source, owner, checked, 0) and
    dominatesSinkPath(gate, owner, sink) and guardKind = "call-dominates" and
    verdict = "confirmed" and conditionExpr = gate.asExpr().toString()
    or
    toolName = "manage_todo" and owner.getName() = [
      "completeTodo", "reopenTodo", "removeTodo", "snoozeTodo"
    ] and gate.getCalleeName() = "findTodoIndex" and checked = gate.getArgument(1) and
    checked.toString() = "id" and
    sourceReachesFunctionNode(handler, source, owner, checked, 1) and
    dominatesSinkPath(gate, owner, sink) and guardKind = "call-dominates" and
    verdict = "confirmed" and conditionExpr = gate.asExpr().toString()
    or
    toolName = "manage_todo" and owner.getName() = "snoozeTodo" and
    gate.getCalleeName() = "parseDateOrThrow" and checked = gate.getArgument(0) and
    checked.toString() = "until" and
    (
      sourceReachesFunctionNode(handler, source, owner, checked, 1)
      or
      exists(DataFlow::CallNode mutation |
        mutation.getContainer() = handler and mutation.getCalleeName() = "snoozeTodo" and
        mutation.getNumArgument() = 3 and mutation.getArgument(2).toString() = "until"
      )
    ) and
    guardKind = "decision-return-branch" and verdict = "branch-confirmed" and
    conditionExpr = gate.asExpr().toString()
  )
}

/** Call-free value rejection with an audited blocking branch. */
private predicate capabilityInlineGate(
  Function handler, Expr gateExpr, DataFlow::Node checked,
  string toolName, string gateName, string guardKind, string verdict, string conditionExpr,
  Function owner
) {
  exists(IfStmt guard |
    guard.getContainer() = owner and gateExpr = guard.getCondition() and
    checked = guard.getCondition().flow() and conditionExpr = gateExpr.toString() and
    blockingIf(guard, guardKind) and verdict = "confirmed" and
    (
      toolName = "Glob" and owner = handler and conditionMentions(gateExpr, "pattern") and
      not conditionMentions(gateExpr, "searchPath") and gateName = "validateNonemptyPattern"
      or
      toolName = "Edit" and owner = handler and
      conditionMentions(gateExpr, ["old_string", "new_string", "expected_replacements", "occurrences"]) and
      not conditionMentions(gateExpr, ["unescapedOccurrences", "firstIndex", "index"]) and
      (
        conditionMentions(gateExpr, "old_string") and
        not conditionMentions(gateExpr, ["new_string", "expected_replacements", "occurrences"]) and
        gateName = "validateOldStringNonempty"
        or
        conditionMentions(gateExpr, "old_string") and conditionMentions(gateExpr, "new_string") and
        gateName = "validateReplacementChanges"
        or
        conditionMentions(gateExpr, "expected_replacements") and
        conditionMentions(gateExpr, "occurrences") and
        gateName = "validateExpectedReplacementCount"
        or
        conditionMentions(gateExpr, "expected_replacements") and
        not conditionMentions(gateExpr, "occurrences") and
        gateName = "validateExpectedReplacementRange"
        or
        conditionMentions(gateExpr, "occurrences") and
        not conditionMentions(gateExpr, "expected_replacements") and
        gateName = "validateOccurrenceMatch"
      )
      or
      toolName = "Task" and owner = handler and
      conditionMentions(gateExpr, "subagent_type") and conditionMentions(gateExpr, "allConfigs") and
      gateName = "validateConfiguredSubagentType"
      or
      toolName = "manage_todo" and owner.getName() = "addTodo" and
      conditionMentions(gateExpr, "text") and gateName = "validateNonemptyTodoText"
    )
  )
}

predicate lettaBotGateRow(
  Function handler, DataFlow::CallNode sink, Expr gateExpr, DataFlow::Node checked,
  string gateName, string sourceName, string guardKind, string verdict,
  string ownerName, string conditionExpr
) {
  exists(DataFlow::Node source, string toolName |
    lettaBotChain(handler, source, sink, toolName, sourceName) and
    (
      exists(DataFlow::CallNode gate |
        requiredParameterGate(
          handler, source, sink, gate, checked, toolName, guardKind, verdict,
          conditionExpr
        ) and gateExpr = gate.asExpr() and gateName = gate.getCalleeName() and
        ownerName = handler.getName()
      )
      or
      exists(DataFlow::CallNode gate, Function owner |
        capabilityCallGate(
          handler, source, sink, gate, checked, toolName, guardKind, verdict,
          conditionExpr, owner
        ) and gateExpr = gate.asExpr() and gateName = gate.getCalleeName() and
        ownerName = owner.getName()
      )
      or
      exists(Function owner |
        capabilityInlineGate(
          handler, gateExpr, checked, toolName, gateName, guardKind, verdict,
          conditionExpr, owner
        ) and ownerName = owner.getName()
      )
    )
  )
}

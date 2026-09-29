/** Source-influenced rejecting conditions on DroidClaw semantic-action paths. */

import javascript
import project.ProjectModel
import call.call
import call.sinks_af
import call.droidclaw_common

private predicate conditionMentions(Expr condition, string name) {
  exists(Identifier identifier |
    identifier.getName() = name and identifier.getParent*() = condition
  )
}

private predicate rejectingIf(IfStmt guard) {
  exists(ReturnStmt rejection | rejection.getParent*() = guard.getThen())
  or
  exists(ThrowStmt rejection | rejection.getParent*() = guard.getThen())
}

private predicate directSourceCondition(
  Function handler, DataFlow::Node source, IfStmt guard, string toolName
) {
  exists(Expr witness |
    witness.getParent*() = guard.getCondition() and
    sourceReachesFunctionNode(handler, source, handler, witness.flow(), 0)
  ) and
  (
    toolName = "type" and conditionMentions(guard.getCondition(), "text")
    or
    toolName = "clipboard_set" and conditionMentions(guard.getCondition(), "text")
    or
    toolName = "open_url" and conditionMentions(guard.getCondition(), "url")
    or
    toolName = "switch_app" and conditionMentions(guard.getCondition(), "pkg")
    or
    toolName = "keyevent" and conditionMentions(guard.getCondition(), "code")
    or
    toolName = "find_and_tap" and conditionMentions(guard.getCondition(), "query")
    or
    toolName = "compose_email" and conditionMentions(guard.getCondition(), "emailAddress")
    or
    toolName = "pull_file" and conditionMentions(guard.getCondition(), "devicePath")
    or
    toolName = "push_file" and conditionMentions(guard.getCondition(), "source") and
    conditionMentions(guard.getCondition(), "dest")
    or
    toolName = "shell" and conditionMentions(guard.getCondition(), "cmd")
  )
}

/** A source-fed validation/selection call initializes the local rejected by the guard. */
private predicate sourceFedProducerCondition(
  Function handler, DataFlow::Node source, IfStmt guard, string toolName
) {
  exists(VariableDeclarator declaration, Variable variable, VarRef use,
    DataFlow::CallNode producer, DataFlow::Node producerInput |
    declaration.getContainer() = handler and declaration.getInit() = producer.asExpr() and
    variable = declaration.getBindingPattern().getAVariable() and
    use.getVariable() = variable and use.getParent*() = guard.getCondition() and
    producerInput = producer.getAnArgument() and
    sourceReachesFunctionNode(handler, source, handler, producerInput, 0) and
    (
      toolName = ["tap", "longpress"] and producer.getCalleeName() = "validateCoordinates" and
      conditionMentions(guard.getCondition(), "coords")
      or
      toolName = "find_and_tap" and producer.getCalleeName() = "findMatch" and
      conditionMentions(guard.getCondition(), "best")
    )
  )
}

/** A source-derived allowlist lookup initializes the local rejected by the guard. */
private predicate sourceFedIndexCondition(
  Function handler, DataFlow::Node source, IfStmt guard, string toolName
) {
  toolName = "open_settings" and conditionMentions(guard.getCondition(), "intentAction") and
  exists(IndexExpr lookup, VariableDeclarator declaration, Variable variable, VarRef use |
    lookup.getContainer() = handler and
    sourceReachesFunctionNode(handler, source, handler, lookup.getIndex().flow(), 0) and
    declaration.getContainer() = handler and declaration.getInit() = lookup and
    variable = declaration.getBindingPattern().getAVariable() and
    use.getVariable() = variable and use.getParent*() = guard.getCondition()
  )
}

/** The model query controls a filtered collection whose emptiness rejects the effect. */
private predicate sourceFedCollectionCondition(
  Function handler, DataFlow::Node source, IfStmt guard, string toolName
) {
  toolName = "copy_visible_text" and
  conditionMentions(guard.getCondition(), "textElements") and
  exists(DataFlow::CallNode filter, Expr witness |
    filter.getContainer() = handler and filter.getCalleeName() = "filter" and
    filter.getLocation().getStartLine() < guard.getLocation().getStartLine() and
    witness.getParent*() = filter.asExpr() and
    sourceReachesFunctionNode(handler, source, handler, witness.flow(), 0)
  )
}

predicate droidClawGateRow(
  Function handler, DataFlow::CallNode sink, Expr gateExpr, DataFlow::Node checked,
  string gateName, string sourceName, string guardKind, string verdict,
  string ownerName, string conditionExpr
) {
  exists(DataFlow::Node source, DataFlow::Node sinkArg, string toolName,
    int chainDepth, string path, IfStmt guard |
    droidClawSemanticChain(
      handler, source, sink, sinkArg, toolName, sourceName, chainDepth, path
    ) and
    guard.getContainer() = handler and rejectingIf(guard) and
    guard.getLocation().getStartLine() < sink.getLocation().getStartLine() and
    guard.getCondition().getBasicBlock().(ReachableBasicBlock).dominates(sink.getBasicBlock()) and
    (
      directSourceCondition(handler, source, guard, toolName)
      or
      sourceFedProducerCondition(handler, source, guard, toolName)
      or
      sourceFedIndexCondition(handler, source, guard, toolName)
      or
      sourceFedCollectionCondition(handler, source, guard, toolName)
    ) and
    gateExpr = guard.getCondition() and checked = guard.getCondition().flow() and
    gateName = "inlineCondition" and guardKind = "inline-early-return" and
    (
      toolName = "copy_visible_text" and verdict = "branch-confirmed"
      or
      toolName != "copy_visible_text" and verdict = "confirmed"
    ) and
    ownerName = handler.getName() and conditionExpr = guard.getCondition().toString()
  )
}

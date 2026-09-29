/**
 * Reusable structural shapes for predicate-style gate detection.
 *
 * Keep these predicates independent of Hermes handler/sink discovery so they can be
 * exercised against small CodeQL test fixtures. `get_gates.ql` adds call-chain,
 * dominance, and same-origin taint requirements around these shapes.
 */

import python

/** Name of the function or method invoked by `call`. */
string calleeName(CallNode call) {
  result = call.getFunction().(NameNode).getId()
  or
  result = call.getFunction().(AttrNode).getName()
}

/** Any scalar target nested in a tuple/list assignment target. */
predicate unpackTargetElement(Expr target, Expr element) {
  element = target.(Tuple).getAnElt()
  or
  element = target.(List).getAnElt()
  or
  exists(Expr child |
    (
      child = target.(Tuple).getAnElt()
      or
      child = target.(List).getAnElt()
    ) and
    unpackTargetElement(child, element)
  )
}

/**
 * A call that directly supplies a condition's truth value.
 *
 * Nested producers are excluded: in `Path(value).is_file()` the gate-shaped call is
 * `is_file`, and in `has_binary_extension(resolve(value))` it is
 * `has_binary_extension`.
 */
private predicate isOutermostConditionCall(ConditionBlock condition, CallNode call) {
  call.getNode() = condition.getLastNode().getNode().(Expr).getASubExpression*() and
  not exists(CallNode outer |
    outer != call and
    outer.getNode() = condition.getLastNode().getNode().(Expr).getASubExpression*() and
    call.getNode().getParentNode+() = outer.getNode()
  )
}

/** A tested SSA use that is not merely an input or receiver of another call. */
private predicate isDirectTestedResultUse(ConditionBlock condition, Name use) {
  use = condition.getLastNode().getNode().(Expr).getASubExpression*() and
  not exists(CallNode outer | use.getParentNode+() = outer.getNode())
}

/**
 * Mapping lookups derive values; a later call-free truthiness condition is the gate.
 * This list is deliberately narrow so assigned validator results remain detectable.
 */
private predicate isMappingProjectionProducer(CallNode call) {
  calleeName(call) = ["get", "setdefault"] and call.getFunction() instanceof AttrNode
}

/**
 * A validation call used directly by a condition, or assigned and then tested through
 * the same SSA definition.
 */
predicate gateCallShape(ConditionBlock condition, CallNode call, string shape) {
  (
    isOutermostConditionCall(condition, call) and
    shape = "in-condition"
  )
  or
  (
    exists(Assign assignment, EssaVariable variable, Expr assignedTarget |
      assignment.getValue() = call.getNode() and
      not isMappingProjectionProducer(call) and
      (
        assignedTarget = assignment.getATarget()
        or
        unpackTargetElement(assignment.getATarget(), assignedTarget)
      ) and
      variable.getDefinition().(EssaNodeDefinition).getDefiningNode() =
        assignedTarget.getAFlowNode() and
      exists(Name use |
        use.getAFlowNode() = variable.getASourceUse() and
        isDirectTestedResultUse(condition, use)
      )
    ) and
    shape = "assign-then-branch"
  )
}

/**
 * A complete call-free condition whose true branch exits immediately.
 *
 * The production query additionally proves that the condition precedes and controls a
 * sink-ward call. Keeping this AST boundary separate prevents upstream `dict.get`
 * projections from becoming gates.
 */
predicate callFreeEarlyExitCondition(If guard, Expr test) {
  test = guard.getTest() and
  not exists(CallNode nested | nested.getNode() = test.getASubExpression*()) and
  exists(Stmt exit |
    exit = guard.getStmt(_) and (exit instanceof Return or exit instanceof Raise)
  )
}

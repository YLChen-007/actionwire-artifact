/** Query-controlled target/content filters on DroidClaw semantic-action paths. */

import javascript
import project.ProjectModel
import call.call
import call.sinks_af
import call.droidclaw_common

private predicate decisionQueryWitness(
  Function handler, DataFlow::Node source, DataFlow::CallNode filter, DataFlow::Node checked
) {
  source = DataFlow::parameterNode(handler.getParameter(0)) and
  exists(VariableDeclarator declaration, Variable variable, VarRef reference, PropAccess access |
    declaration.getContainer() = handler and
    variable = declaration.getBindingPattern().getAVariable() and variable.getName() = "query" and
    reference.getVariable() = variable and reference.getParent*() = filter.asExpr() and
    access.getPropertyName() = "query" and access.getParent*() = declaration.getInit() and
    access.getBase().getUnderlyingValue().(Identifier).getName() =
      handler.getParameter(0).getName() and
    checked = reference.flow()
  )
}

private predicate parameterQueryWitness(
  Function owner, DataFlow::CallNode filter, DataFlow::Node checked
) {
  exists(VarRef reference |
    owner.getNumParameter() = 2 and owner.getParameter(1).getName() = "queryLower" and
    reference.getVariable() = owner.getParameter(1).getABindingVarRef().getVariable() and
    reference.getParent*() = filter.asExpr() and checked = reference.flow()
  )
}

/** The findMatch query argument is derived from decision.query through queryLower. */
private predicate findMatchQueryEdge(
  Function handler, DataFlow::Node source, DataFlow::CallNode edge
) {
  source = DataFlow::parameterNode(handler.getParameter(0)) and
  edge.getContainer() = handler and edge.getCalleeName() = "findMatch" and
  exists(VariableDeclarator queryDeclaration, Variable queryVariable,
    VariableDeclarator lowerDeclaration, Variable lowerVariable, PropAccess access,
    VarRef queryUse, VarRef lowerUse |
    queryDeclaration.getContainer() = handler and
    queryVariable = queryDeclaration.getBindingPattern().getAVariable() and
    queryVariable.getName() = "query" and access.getPropertyName() = "query" and
    access.getParent*() = queryDeclaration.getInit() and
    access.getBase().getUnderlyingValue().(Identifier).getName() =
      handler.getParameter(0).getName() and
    lowerDeclaration.getContainer() = handler and
    lowerVariable = lowerDeclaration.getBindingPattern().getAVariable() and
    lowerVariable.getName() = "queryLower" and queryUse.getVariable() = queryVariable and
    queryUse.getParent*() = lowerDeclaration.getInit() and lowerUse.getVariable() = lowerVariable and
    lowerUse.getParent*() = edge.getArgument(1).asExpr()
  )
}

predicate droidClawFilterRow(
  Function handler, DataFlow::Node source, DataFlow::CallNode sink,
  DataFlow::Node sinkArg, DataFlow::CallNode gate, DataFlow::Node checked,
  Function owner, int chainDepth, int gateDepth, string path, string conditionExpr
) {
  exists(string toolName, string sourceName |
    droidClawSemanticChain(
      handler, source, sink, sinkArg, toolName, sourceName, chainDepth, path
    ) and gate.getCalleeName() = "filter" and
    (
      toolName = "copy_visible_text" and owner = handler and gate.getContainer() = owner and
      decisionQueryWitness(handler, source, gate, checked) and gateDepth = 0 and
      conditionExpr = "el.text.toLowerCase().includes(query)"
      or
      toolName = "find_and_tap" and owner.getName() = "findMatch" and
      owner.getFile() = handler.getFile() and gate.getContainer() = owner and
      parameterQueryWitness(owner, gate, checked) and
      exists(DataFlow::CallNode edge |
        findMatchQueryEdge(handler, source, edge)
      ) and gateDepth = 1 and
      conditionExpr = "el.text.toLowerCase().includes(queryLower)"
    )
  )
}

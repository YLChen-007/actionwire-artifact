/** Security-relevant source-to-effect transforms on DroidClaw semantic-action paths. */

import javascript
import project.ProjectModel
import call.call
import call.sinks_af
import call.droidclaw_common

private predicate declaredTransform(
  Function handler, DataFlow::CallNode transform, string variableName, Variable variable
) {
  exists(VariableDeclarator declaration |
    declaration.getContainer() = handler and
    variable = declaration.getBindingPattern().getAVariable() and
    variable.getName() = variableName and
    declaration.getInit() = transform.asExpr()
  )
}

/** Bind a transform input to a local initialized from the model-decision parameter. */
private predicate sourcePropertyIdentifier(
  Function handler, DataFlow::Node source, DataFlow::CallNode transform,
  string variableName, string propertyName, DataFlow::Node input
) {
  source = DataFlow::parameterNode(handler.getParameter(0)) and
  exists(VariableDeclarator declaration, Variable variable, PropAccess access, VarRef reference |
    declaration.getContainer() = handler and
    variable = declaration.getBindingPattern().getAVariable() and
    variable.getName() = variableName and access.getPropertyName() = propertyName and
    access.getParent*() = declaration.getInit() and
    access.getBase().getUnderlyingValue().(Identifier).getName() =
      handler.getParameter(0).getName() and
    reference.getVariable() = variable and reference.getParent*() = transform.asExpr() and
    input = reference.flow()
  )
}

private predicate sinkUsesVariable(DataFlow::CallNode sink, Variable variable) {
  exists(VarRef reference |
    reference.getVariable() = variable and reference.getParent*() = sink.asExpr()
  )
}

/** basename extraction feeds the localPath interpolated into the pull effect. */
private predicate basenameFeedsPullSink(
  Function handler, DataFlow::CallNode transform, DataFlow::CallNode sink
) {
  exists(VariableDeclarator filenameDeclaration, Variable filename,
    VariableDeclarator localPathDeclaration, Variable localPath, VarRef filenameUse |
    filenameDeclaration.getContainer() = handler and
    filename = filenameDeclaration.getBindingPattern().getAVariable() and
    filename.getName() = "filename" and
    transform.asExpr().getParent*() = filenameDeclaration.getInit() and
    localPathDeclaration.getContainer() = handler and
    localPath = localPathDeclaration.getBindingPattern().getAVariable() and
    localPath.getName() = "localPath" and filenameUse.getVariable() = filename and
    filenameUse.getParent*() = localPathDeclaration.getInit() and sinkUsesVariable(sink, localPath)
  )
}

private predicate securityTransform(
  Function handler, DataFlow::Node source, DataFlow::CallNode sink,
  DataFlow::CallNode transform, DataFlow::Node input, string toolName
) {
  exists(Variable transformed |
    toolName = "type" and transform.getContainer() = handler and
    transform.getCalleeName() = "replaceAll" and
    declaredTransform(handler, transform, "escapedText", transformed) and
    sourcePropertyIdentifier(handler, source, transform, "text", "text", input) and
    sinkUsesVariable(sink, transformed)
  )
  or
  exists(Variable transformed |
    toolName = "clipboard_set" and transform.getContainer() = handler and
    transform.getCalleeName() = "replaceAll" and
    declaredTransform(handler, transform, "escaped", transformed) and
    sourcePropertyIdentifier(handler, source, transform, "text", "text", input) and
    sinkUsesVariable(sink, transformed)
  )
  or
  toolName = "pull_file" and transform.getContainer() = handler and
  transform.getCalleeName() = "pop" and
  sourcePropertyIdentifier(handler, source, transform, "devicePath", "path", input) and
  basenameFeedsPullSink(handler, transform, sink)
}

predicate droidClawTransformRow(
  Function handler, DataFlow::Node source, DataFlow::CallNode sink,
  DataFlow::Node sinkArg, DataFlow::CallNode transform, DataFlow::Node input,
  string sourceName, string role, string verdict, Function owner,
  int chainDepth, int transformDepth, int remainingDepth, string path,
  string reportedOwner
) {
  exists(string toolName |
    droidClawSemanticChain(
      handler, source, sink, sinkArg, toolName, sourceName, chainDepth, path
    ) and securityTransform(handler, source, sink, transform, input, toolName) and
    owner = handler and transformDepth = 0 and remainingDepth = 0 and
    role = "sink-transform" and verdict = "confirmed" and
    reportedOwner = handler.getName()
  )
}

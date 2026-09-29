/** TinyClaw v0.0.20 external-agent adapter boundary model. */

import javascript

predicate tcIsProject() {
  exists(Function invokeAgent, Function register, Function runCommand |
    invokeAgent.getName() = "invokeAgent" and
    invokeAgent.getFile().getRelativePath() = "packages/core/src/invoke.ts" and
    register.getName() = "register" and
    register.getFile().getRelativePath() = "packages/core/src/adapters/index.ts" and
    runCommand.getName() = "runCommand" and
    runCommand.getFile().getRelativePath() = "packages/core/src/invoke.ts"
  )
}

bindingset[path]
predicate tcIsCoreSourcePath(string path) {
  path.matches("packages/core/src/%.ts") and
  not path.matches("%.test.ts") and not path.matches("%.spec.ts")
}

predicate tcIsCoreLocation(Location loc) {
  tcIsCoreSourcePath(loc.getFile().getRelativePath())
}

private predicate tcRegisteredAdapter(ObjectExpr adapter, string bindingName) {
  exists(VariableDeclarator declaration, DataFlow::CallNode registration, Identifier registered |
    declaration.getInit().getUnderlyingValue() = adapter and
    declaration.getBindingPattern().(Identifier).getName() = bindingName and
    registration.getCalleeName() = "register" and
    registration.getLocation().getFile().getRelativePath() =
      "packages/core/src/adapters/index.ts" and
    registered = registration.getArgument(0).asExpr() and registered.getName() = bindingName
  )
}

private predicate tcAdapterIdentity(string bindingName, string toolName) {
  bindingName = "claudeAdapter" and toolName = "claude-cli"
  or
  bindingName = "codexAdapter" and toolName = "codex-cli"
  or
  bindingName = "opencodeAdapter" and toolName = "opencode-cli"
}

predicate tcToolHandler(Function handler, string toolName, string model) {
  tcIsProject() and tcIsCoreLocation(handler.getLocation()) and
  exists(ObjectExpr adapter, Property invokeProperty, string bindingName |
    tcRegisteredAdapter(adapter, bindingName) and tcAdapterIdentity(bindingName, toolName) and
    invokeProperty = adapter.getPropertyByName("invoke") and
    invokeProperty.getInit().getUnderlyingValue() = handler and handler.getName() = "invoke" and
    model = "registered-external-agent-adapter:" + bindingName
  )
}

predicate tcHandlerSource(Function handler, DataFlow::Node source, string parameterName) {
  tcToolHandler(handler, _, _) and handler.getNumParameter() = 1 and
  source = DataFlow::parameterNode(handler.getParameter(0)) and
  parameterName = handler.getParameter(0).getName() and parameterName = ["opts", "options"]
}

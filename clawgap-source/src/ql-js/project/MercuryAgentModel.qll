/** Mercury Agent v1.1.12 registered capability-tool model. */

import javascript

predicate maIsProject() {
  exists(Function registerAll, Function getTools, Function createRunCommand |
    registerAll.getName() = "registerAll" and
    registerAll.getFile().getRelativePath() = "src/capabilities/registry.ts" and
    getTools.getName() = "getTools" and getTools.getFile() = registerAll.getFile() and
    createRunCommand.getName() = "createRunCommandTool" and
    createRunCommand.getFile().getRelativePath() = "src/capabilities/shell/run-command.ts"
  )
}

bindingset[path]
predicate maIsCoreSourcePath(string path) {
  path.matches("src/%.ts") and
  not path.matches("%.test.ts") and not path.matches("%.spec.ts")
}

predicate maIsCoreLocation(Location loc) {
  maIsCoreSourcePath(loc.getFile().getRelativePath())
}

/** Recover a literal registry key and the factory assigned to it. */
private predicate maRegisteredFactory(string toolName, string factoryName) {
  exists(Function registrationOwner, AssignExpr assignment, PropAccess toolProperty,
    PropAccess toolsProperty, DataFlow::CallNode factoryCall |
    registrationOwner.getName() = ["registerAll", "registerSpotifyTools"] and
    registrationOwner.getFile().getRelativePath() = "src/capabilities/registry.ts" and
    assignment.getEnclosingFunction() = registrationOwner and
    toolProperty = assignment.getLhs() and toolName = toolProperty.getPropertyName() and
    toolsProperty = toolProperty.getBase() and toolsProperty.getPropertyName() = "tools" and
    toolsProperty.getBase() instanceof ThisExpr and
    factoryCall.asExpr() = assignment.getRhs() and factoryName = factoryCall.getCalleeName() and
    factoryName.matches("create%Tool")
  )
}

predicate maToolHandler(Function handler, string toolName, string model) {
  maIsProject() and maIsCoreLocation(handler.getLocation()) and
  exists(Function factory, ObjectExpr definition, Property executeProperty, string factoryName |
    maRegisteredFactory(toolName, factoryName) and factory.getName() = factoryName and
    factory.getFile().getRelativePath().matches("src/capabilities/%.ts") and
    executeProperty = definition.getPropertyByName("execute") and
    executeProperty.getInit().getUnderlyingValue() = handler and
    handler.getEnclosingStmt().getContainer() = factory and handler.getName() = "execute" and
    model = "capability-registry:" + factoryName
  )
}

predicate maHandlerSource(Function handler, DataFlow::Node source, string parameterName) {
  maToolHandler(handler, _, _) and handler.getNumParameter() >= 1 and
  source = DataFlow::parameterNode(handler.getParameter(0)) and parameterName = "args"
}

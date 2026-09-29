/** LettaBot v0.2.0 local and pinned Letta Code tool model. */

import javascript

predicate lbIsProject() {
  exists(Function options, Function factory |
    options.getName() = "baseSessionOptions" and
    options.getFile().getRelativePath() = "src/core/session-manager.ts" and
    factory.getName() = "createManageTodoTool" and
    factory.getFile().getRelativePath() = "src/tools/todo.ts" and
    exists(DataFlow::CallNode registration |
      registration.getContainer() = options and registration.getCalleeName() = factory.getName()
    )
  )
}

bindingset[path]
predicate lbIsCoreSourcePath(string path) {
  path.matches("src/%.ts") and
  not path.matches("%.test.ts") and not path.matches("%.spec.ts") and
  not path.matches("src/test/%") and not path.matches("src/setup/%") and
  not path.matches("src/skills/%")
  or
  path = "vendor-source/letta-code-v0.19.5/src/tools/toolDefinitions.ts"
  or
  path = "vendor-source/letta-code-v0.19.5/src/tools/impl/validation.ts"
  or
  path = "vendor-source/letta-code-sdk-v0.1.14/src/tool-helpers.ts"
  or
  path = [
    "vendor-source/letta-code-v0.19.5/src/tools/impl/Bash.ts",
    "vendor-source/letta-code-v0.19.5/src/tools/impl/Read.ts",
    "vendor-source/letta-code-v0.19.5/src/tools/impl/Edit.ts",
    "vendor-source/letta-code-v0.19.5/src/tools/impl/Write.ts",
    "vendor-source/letta-code-v0.19.5/src/tools/impl/Glob.ts",
    "vendor-source/letta-code-v0.19.5/src/tools/impl/Grep.ts",
    "vendor-source/letta-code-v0.19.5/src/tools/impl/Task.ts"
  ]
}

predicate lbIsCoreLocation(Location loc) {
  lbIsCoreSourcePath(loc.getFile().getRelativePath())
}

private predicate lbLocalToolHandler(Function handler, string toolName, string model) {
  lbIsProject() and handler.getName() = "execute" and
  handler.getFile().getRelativePath() = "src/tools/todo.ts" and
  exists(Function factory, ObjectExpr definition, Property executeProperty |
    factory.getName() = "createManageTodoTool" and factory.getFile() = handler.getFile() and
    handler.getEnclosingStmt().getContainer() = factory and
    executeProperty = definition.getPropertyByName("execute") and
    executeProperty.getInit().getUnderlyingValue() = handler and
    toolName = definition.getPropertyByName("name").getInit().getStringValue() and
    toolName = "manage_todo" and model = "session-registered-local-tool"
  )
}

/** The repository-declared fallback list of tools implemented by Letta Code SDK. */
private predicate lbHasDefaultSdkAllowlist() {
  exists(DataFlow::CallNode parse, DataFlow::CallNode ensure |
    parse.getLocation().getFile().getRelativePath() = "src/main.ts" and
    parse.getCalleeName() = "parseCsvList" and ensure.getCalleeName() = "ensureRequiredTools" and
    parse.asExpr().getParent*() = ensure.getArgument(0).asExpr() and
    parse.getArgument(0).mayHaveStringValue(
      "Bash,Read,Edit,Write,Glob,Grep,Task,web_search,conversation_search"
    )
  )
}

/** Exact registry key, implementation symbol, file, and source signature for one pinned CLI tool. */
private predicate lbVendoredToolIdentity(
  string toolName, string implementationName, string implementationPath
) {
  toolName = "Bash" and implementationName = "bash" and
  implementationPath = "vendor-source/letta-code-v0.19.5/src/tools/impl/Bash.ts"
  or
  toolName = "Read" and implementationName = "read" and
  implementationPath = "vendor-source/letta-code-v0.19.5/src/tools/impl/Read.ts"
  or
  toolName = "Edit" and implementationName = "edit" and
  implementationPath = "vendor-source/letta-code-v0.19.5/src/tools/impl/Edit.ts"
  or
  toolName = "Write" and implementationName = "write" and
  implementationPath = "vendor-source/letta-code-v0.19.5/src/tools/impl/Write.ts"
  or
  toolName = "Glob" and implementationName = "glob" and
  implementationPath = "vendor-source/letta-code-v0.19.5/src/tools/impl/Glob.ts"
  or
  toolName = "Grep" and implementationName = "grep" and
  implementationPath = "vendor-source/letta-code-v0.19.5/src/tools/impl/Grep.ts"
  or
  toolName = "Task" and implementationName = "task" and
  implementationPath = "vendor-source/letta-code-v0.19.5/src/tools/impl/Task.ts"
}

/** The exact v0.19.5 toolDefinitions object is exported as TOOL_DEFINITIONS. */
private predicate lbHasVendoredToolRegistry(ObjectExpr registry) {
  exists(VariableDeclarator local, VariableDeclarator exported, Identifier forwarded |
    local.getFile().getRelativePath() =
      "vendor-source/letta-code-v0.19.5/src/tools/toolDefinitions.ts" and
    local.getBindingPattern().(Identifier).getName() = "toolDefinitions" and
    local.getInit().getUnderlyingValue() = registry and
    exported.getFile() = local.getFile() and
    exported.getBindingPattern().(Identifier).getName() = "TOOL_DEFINITIONS" and
    forwarded = exported.getInit().getUnderlyingValue() and forwarded.getName() = "toolDefinitions"
  )
}

/** A default allowlisted name resolves to its real pinned Letta Code implementation. */
private predicate lbVendoredToolHandler(Function handler, string toolName, string model) {
  lbIsProject() and lbHasDefaultSdkAllowlist() and
  exists(ObjectExpr registry, ObjectExpr definition, Property toolProperty, Property implProperty,
    Identifier implementation, string implementationName, string implementationPath |
    lbVendoredToolIdentity(toolName, implementationName, implementationPath) and
    handler.getName() = implementationName and handler.getFile().getRelativePath() = implementationPath and
    handler.getNumParameter() = 1 and handler.getParameter(0).getName() = "args" and
    lbHasVendoredToolRegistry(registry) and toolProperty = registry.getPropertyByName(toolName) and
    definition = toolProperty.getInit().getUnderlyingValue() and
    implProperty = definition.getPropertyByName("impl") and
    implementation = implProperty.getInit().getUnderlyingValue() and
    implementation.getName() = implementationName and
    model = "allowed-vendored-letta-code-tool:0.19.5"
  )
}

/**
 * Anchor SDK-owned default tools at the session option that forwards allowedTools.
 * This is an explicit cross-component entry boundary, not a synthetic local execute body.
 */
predicate lbToolBoundary(
  Function handler, string toolName, string model
) {
  lbIsProject() and lbHasDefaultSdkAllowlist() and
  handler.getName() = "baseSessionOptions" and
  handler.getFile().getRelativePath() = "src/core/session-manager.ts" and
  exists(Property allowedTools, PropAccess forwarded, PropAccess config,
    DataFlow::CallNode localRegistration |
    allowedTools.getName() = "allowedTools" and
    allowedTools.getInit().getEnclosingFunction() = handler and
    forwarded = allowedTools.getInit() and forwarded.getPropertyName() = "allowedTools" and
    config = forwarded.getBase() and config.getPropertyName() = "config" and
    config.getBase() instanceof ThisExpr and
    localRegistration.getContainer() = handler and
    localRegistration.getCalleeName() = "createManageTodoTool"
  ) and
  toolName = [
    "Bash", "Read", "Edit", "Write", "Glob", "Grep", "Task", "web_search",
    "conversation_search"
  ] and
  model = "sdk-default-tool-boundary"
}

predicate lbToolHandler(Function handler, string toolName, string model) {
  lbLocalToolHandler(handler, toolName, model)
  or
  lbVendoredToolHandler(handler, toolName, model)
}

predicate lbHandlerSource(Function handler, DataFlow::Node source, string parameterName) {
  lbLocalToolHandler(handler, "manage_todo", _) and handler.getNumParameter() >= 2 and
  source = DataFlow::parameterNode(handler.getParameter(1)) and
  parameterName = handler.getParameter(1).getName() and parameterName = "args"
  or
  lbVendoredToolHandler(handler, _, _) and source = DataFlow::parameterNode(handler.getParameter(0)) and
  parameterName = handler.getParameter(0).getName() and parameterName = "args"
}

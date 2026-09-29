/** NanoClaw v2.1.11 TypeScript project and registered MCP-tool model. */

import javascript

predicate ncIsProject() {
  exists(Function register, Function start, Function delivery |
    register.getName() = "registerTools" and
    register.getFile().getRelativePath() = "container/agent-runner/src/mcp-tools/server.ts" and
    start.getName() = "startMcpServer" and
    start.getFile().getRelativePath() = "container/agent-runner/src/mcp-tools/server.ts" and
    delivery.getName() = "createChannelDeliveryAdapter" and
    delivery.getFile().getRelativePath() = "src/channels/channel-registry.ts"
  )
}

bindingset[path]
predicate ncIsCoreSourcePath(string path) {
  path.matches("container/agent-runner/src/%.ts") and
  not path.matches("%.test.ts") and not path.matches("%.spec.ts")
  or
  path.matches("src/%.ts") and
  not path.matches("%.test.ts") and not path.matches("%.spec.ts")
}

predicate ncIsCoreLocation(Location loc) {
  ncIsCoreSourcePath(loc.getFile().getRelativePath())
}

private predicate ncHandlerProperty(Function handler, ObjectExpr definition) {
  exists(Property property |
    property = definition.getPropertyByName("handler") and
    property.getInit().getUnderlyingValue() = handler
  )
}

private predicate ncRegisteredDefinition(ObjectExpr definition, string bindingName) {
  exists(VariableDeclarator declaration, DataFlow::CallNode registration, ArrayExpr tools,
    Identifier registered |
    declaration.getInit().getUnderlyingValue() = definition and
    declaration.getBindingPattern().(Identifier).getName() = bindingName and
    registration.getCalleeName() = "registerTools" and
    registration.getLocation().getFile() = declaration.getFile() and
    tools = registration.getArgument(0).asExpr() and
    registered = tools.getAnElement() and registered.getName() = bindingName
  )
}

predicate ncToolHandler(Function handler, string toolName, string model) {
  ncIsProject() and ncIsCoreLocation(handler.getLocation()) and
  handler.getFile().getRelativePath().matches("container/agent-runner/src/mcp-tools/%.ts") and
  exists(ObjectExpr definition, ObjectExpr tool, string bindingName |
    ncHandlerProperty(handler, definition) and
    tool = definition.getPropertyByName("tool").getInit().getUnderlyingValue() and
    toolName = tool.getPropertyByName("name").getInit().getStringValue() and
    ncRegisteredDefinition(definition, bindingName) and
    model = "registered-mcp-object:" + bindingName
  )
}

/** Gets the concrete `ClaudeProvider.query` method that forwards allowed tools to the SDK. */
private predicate ncClaudeProviderQuery(Function anchor) {
  anchor.getFile().getRelativePath() =
    "container/agent-runner/src/providers/claude.ts" and
  exists(MethodDefinition method, DataFlow::CallNode sdkCall |
    method.getBody() = anchor and method.getName() = "query" and
    method.getDeclaringClass().getName() = "ClaudeProvider" and
    sdkCall.getContainer() = anchor and sdkCall.getCalleeName() = "sdkQuery"
  )
}

/** Gets the literal allowlist and proves that the same binding is spread into SDK options. */
private predicate ncForwardedSdkAllowlist(
  Function anchor, ArrayExpr allowlist, ArrayExpr allowedTools
) {
  exists(VariableDeclarator declaration, VarRef declared, SpreadElement spread,
    VarRef forwarded, DataFlow::CallNode sdkCall, ObjectExpr sdkArgument, ObjectExpr options |
    ncClaudeProviderQuery(anchor) and
    declaration.getFile().getRelativePath() =
      "container/agent-runner/src/providers/claude.ts" and
    declared = declaration.getBindingPattern() and declared.getName() = "TOOL_ALLOWLIST" and
    allowlist = declaration.getInit() and
    sdkCall.getContainer() = anchor and sdkCall.getCalleeName() = "sdkQuery" and
    sdkArgument = sdkCall.getArgument(0).asExpr() and
    options = sdkArgument.getPropertyByName("options").getInit() and
    allowedTools = options.getPropertyByName("allowedTools").getInit() and
    spread = allowedTools.getAnElement() and forwarded = spread.getOperand() and
    forwarded.getVariable() = declared.getVariable()
  )
}

/** The runtime MCP map must contain a built-in server plus external config entries. */
private predicate ncHasExternalMcpPopulation() {
  exists(Function main, VariableDeclarator configDeclaration,
    VariableDeclarator serversDeclaration, Variable configVariable, Variable serversVariable,
    Variable nameVariable, Variable serverConfigVariable,
    ObjectExpr initialServers, DataFlow::CallNode loadConfig, ForOfStmt loop,
    InvokeExpr entries, PropAccess configuredServers, AssignExpr assignment, IndexExpr target,
    VarRef targetBase, VarRef targetIndex, VarRef assignedValue |
    main.getName() = "main" and
    main.getFile().getRelativePath() = "container/agent-runner/src/index.ts" and
    configVariable = configDeclaration.getBindingPattern().getAVariable() and
    configVariable.getName() = "config" and loadConfig.asExpr() = configDeclaration.getInit() and
    loadConfig.getCalleeName() = "loadConfig" and loadConfig.getContainer() = main and
    serversVariable = serversDeclaration.getBindingPattern().getAVariable() and
    serversVariable.getName() = "mcpServers" and initialServers = serversDeclaration.getInit() and
    initialServers.getPropertyByName("nanoclaw").getName() = "nanoclaw" and
    loop.getContainer() = main and entries = loop.getIterationDomain() and
    entries.getCalleeName() = "entries" and
    entries.getCallee().(PropAccess).getBase().(GlobalVarAccess).getName() = "Object" and
    configuredServers = entries.getArgument(0) and
    configuredServers.getPropertyName() = "mcpServers" and
    configuredServers.getBase().(VarRef).getVariable() = configVariable and
    nameVariable = loop.getAnIterationVariable() and nameVariable.getName() = "name" and
    serverConfigVariable = loop.getAnIterationVariable() and
    serverConfigVariable.getName() = "serverConfig" and
    assignment.getEnclosingFunction() = main and target = assignment.getTarget() and
    targetBase = target.getBase() and targetBase.getVariable() = serversVariable and
    targetIndex = target.getIndex() and targetIndex.getVariable() = nameVariable and
    assignedValue = assignment.getRhs() and
    assignedValue.getVariable() = serverConfigVariable
  )
}

/** Proves the exact `Object.keys(this.mcpServers).map(mcpAllowPattern)` forwarding shape. */
private predicate ncForwardsDynamicMcpNamespace(Function anchor, ArrayExpr allowedTools) {
  exists(SpreadElement spread, InvokeExpr mapCall, InvokeExpr keysCall, PropAccess receiver,
    VarRef mapper, Function helper, ReturnStmt returned, TemplateLiteral pattern,
    TemplateElement prefix, TemplateElement suffix |
    ncHasExternalMcpPopulation() and
    spread = allowedTools.getAnElement() and mapCall = spread.getOperand() and
    mapCall.getCalleeName() = "map" and keysCall = mapCall.getCallee().(PropAccess).getBase() and
    keysCall.getCalleeName() = "keys" and
    keysCall.getCallee().(PropAccess).getBase().(GlobalVarAccess).getName() = "Object" and
    receiver = keysCall.getArgument(0) and receiver.getPropertyName() = "mcpServers" and
    receiver.getBase() instanceof ThisExpr and
    mapper = mapCall.getArgument(0) and mapper.getName() = "mcpAllowPattern" and
    helper.getVariable() = mapper.getVariable() and helper.getFile() = anchor.getFile() and
    helper.getNumParameter() = 1 and helper.getParameter(0).getName() = "serverName" and
    returned.getContainer() = helper and pattern = returned.getExpr() and
    prefix = pattern.getElement(0) and prefix.getValue() = "mcp__" and
    suffix = pattern.getElement(pattern.getNumElement() - 1) and suffix.getValue() = "__*"
  )
}

/**
 * Gets SDK/runtime-owned tool namespaces exposed by the pinned NanoClaw source.
 * These inventory boundaries deliberately have no local handler source.
 */
predicate ncToolBoundary(Function anchor, string toolName, string model) {
  ncIsProject() and
  exists(ArrayExpr allowlist, ArrayExpr allowedTools, Expr literal |
    ncForwardedSdkAllowlist(anchor, allowlist, allowedTools) and
    literal = allowlist.getAnElement() and toolName = literal.getStringValue() and
    model = "sdk-default-tool-boundary"
  )
  or
  ncIsProject() and
  exists(ArrayExpr allowlist, ArrayExpr allowedTools |
    ncForwardedSdkAllowlist(anchor, allowlist, allowedTools) and
    ncForwardsDynamicMcpNamespace(anchor, allowedTools) and
    toolName = "mcp__<configured-server>__*" and
    model = "dynamic-external-mcp-namespace-boundary"
  )
}

predicate ncHandlerSource(Function handler, DataFlow::Node source, string parameterName) {
  ncToolHandler(handler, _, _) and handler.getNumParameter() = 1 and
  source = DataFlow::parameterNode(handler.getParameter(0)) and
  parameterName = handler.getParameter(0).getName() and parameterName = "args"
}

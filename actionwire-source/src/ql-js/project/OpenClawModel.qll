/** OpenClaw v2026.2.1 TypeScript project and tool-handler model. */

import javascript

predicate ocIsProject() {
  exists(Function coding, Function core |
    coding.getName() = "createOpenClawCodingTools" and
    coding.getFile().getRelativePath() = "src/agents/pi-tools.ts" and
    core.getName() = "createOpenClawTools" and
    core.getFile().getRelativePath() = "src/agents/openclaw-tools.ts"
  ) and
  not exists(Function forkFactory |
    forkFactory.getName() = "createOpenClawTools" and
    forkFactory.getFile().getRelativePath() = "src/agents/clawdbot-tools.ts"
  )
}

bindingset[path]
predicate ocIsCoreSourcePath(string path) {
  (
    path.matches("src/%.ts")
    or
    // The bundled browser implementation is a model-facing tool, not an arbitrary
    // dynamically discovered channel/plugin extension. v2026.2.1 has no such files;
    // this path is exercised only by revision-bound sources and the synthetic fixture.
    path.matches("extensions/browser/src/%.ts")
  ) and
  not path.matches("%.test.ts") and
  not path.matches("%.spec.ts") and
  not path.matches("src/%/test-helpers/%") and
  not path.matches("src/channels/plugins/agent-tools/%") and
  not path.matches("src/plugins/%")
}

predicate ocIsCoreLocation(Location loc) {
  ocIsCoreSourcePath(loc.getFile().getRelativePath())
}

predicate ocFamilyDirectToolFactory(Function factory, boolean includeSubagents) {
  includeSubagents = [true, false] and
  factory.getName() = [
    "createExecTool", "createProcessTool", "createApplyPatchTool",
    "createAgentsListTool", "createBrowserTool", "createCanvasTool", "createCronTool",
    "createGatewayTool", "createImageTool", "createMemorySearchTool", "createMemoryGetTool",
    "createMessageTool", "createNodesTool", "createSessionStatusTool",
    "createSessionsHistoryTool", "createSessionsListTool", "createSessionsSendTool",
    "createSessionsSpawnTool", "createTtsTool", "createWebFetchTool", "createWebSearchTool"
  ] and
  ocIsCoreLocation(factory.getLocation())
  or
  includeSubagents = true and factory.getName() = "createSubagentsTool" and
  ocIsCoreLocation(factory.getLocation())
}

predicate ocFamilyExecuteProperty(Function execute, ObjectExpr object) {
  exists(Property property |
    property = object.getPropertyByName("execute") and
    property.getInit().getUnderlyingValue() = execute
  )
}

predicate ocFamilyLiteralToolObject(
  Function execute, Function factory, ObjectExpr object, string toolName,
  boolean includeSubagents
) {
  ocFamilyDirectToolFactory(factory, includeSubagents) and
  ocFamilyExecuteProperty(execute, object) and
  execute.getEnclosingStmt().getContainer() = factory and
  toolName = object.getPropertyByName("name").getInit().getStringValue()
}

/** Generic wrappers are instantiated only for the listed assembled core tools. */
private predicate ocWrappedToolHandler(Function execute, string toolName, string model) {
  execute.getName() = "execute" and
  execute.getFile().getRelativePath() = "src/agents/pi-tools.read.ts" and
  (
    execute.getEnclosingStmt().getContainer().(Function).getName() = "wrapToolParamNormalization" and
    toolName = ["write", "edit"] and model = "normalization-wrapper"
    or
    execute.getEnclosingStmt().getContainer().(Function).getName() = "wrapSandboxPathGuard" and
    toolName = ["read", "write", "edit"] and model = "sandbox-path-wrapper"
    or
    execute.getEnclosingStmt().getContainer().(Function).getName() = "createOpenClawReadTool" and
    toolName = "read" and model = "read-wrapper"
  )
}

predicate ocToolHandler(Function execute, string toolName, string model) {
  ocIsProject() and
  exists(Function factory, ObjectExpr object |
    ocFamilyLiteralToolObject(execute, factory, object, toolName, false) and
    model = "literal-object:" + factory.getName()
  )
  or
  ocIsProject() and ocWrappedToolHandler(execute, toolName, model)
}

predicate ocHandlerSource(Function handler, DataFlow::Node source, string parameterName) {
  ocToolHandler(handler, _, _) and
  source = DataFlow::parameterNode(handler.getParameter(1)) and
  parameterName = handler.getParameter(1).getName() and
  parameterName = ["args", "params"]
}

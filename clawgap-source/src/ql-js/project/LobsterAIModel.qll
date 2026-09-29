/** LobsterAI 2026.6.10 local tools plus its pinned OpenClaw v2026.4.14 browser runtime. */

import javascript

private string browserToolPath() {
  result =
    "vendor-source/openclaw-v2026.4.14/extensions/browser/src/browser-tool.ts"
}

private string browserRegistrationPath() {
  result =
    "vendor-source/openclaw-v2026.4.14/extensions/browser/plugin-registration.ts"
}

private predicate lobsterAILocalToolSpec(string path, string toolName, string model) {
  path = "openclaw-extensions/ask-user-question/index.ts" and
  toolName = "AskUserQuestion" and model = "registered-lobsterai-ask-user-tool"
  or
  path = "openclaw-extensions/lobster-media-generation/index.ts" and
  toolName = ["lobsterai_image_generate", "lobsterai_video_generate"] and
  model = "registered-lobsterai-media-tool"
}

predicate laiIsProject() {
  exists(Function normalize, Function buildConfig, Function registerPlugin |
    normalize.getName() = "normalizeBrowserWebAccessConfig" and
    normalize.getFile().getRelativePath() = "src/shared/browserWebAccess/constants.ts" and
    buildConfig.getName() = "buildBrowserConfig" and
    buildConfig.getFile().getRelativePath() = "src/main/libs/openclawConfigSync.ts" and
    registerPlugin.getName() = "registerBrowserPlugin" and
    registerPlugin.getFile().getRelativePath() = browserRegistrationPath()
  )
}

bindingset[path]
predicate laiIsCoreSourcePath(string path) {
  path.matches("src/%.ts") and
  not path.matches("%.test.ts") and not path.matches("%.spec.ts")
  or
  path.matches("src/%.tsx") and
  not path.matches("%.test.tsx") and not path.matches("%.spec.tsx")
  or
  lobsterAILocalToolSpec(path, _, _)
  or
  path.matches("vendor-source/openclaw-v2026.4.14/extensions/browser/%.ts") and
  not path.matches("%.test.ts") and not path.matches("%.spec.ts") and
  not path.matches("%test-harness.ts") and not path.matches("%.snapshot.ts")
  or
  path = "vendor-source/openclaw-v2026.4.14/src/infra/net/ssrf.ts"
}

predicate laiIsCoreLocation(Location loc) {
  laiIsCoreSourcePath(loc.getFile().getRelativePath())
}

private predicate registeredBrowserFactory() {
  exists(Function registerPlugin, DataFlow::CallNode registration,
    DataFlow::CallNode create |
    registerPlugin.getName() = "registerBrowserPlugin" and
    registerPlugin.getFile().getRelativePath() = browserRegistrationPath() and
    registration.getContainer() = registerPlugin and
    registration.getCalleeName() = "registerTool" and
    create.getCalleeName() = "createBrowserTool" and
    create.getLocation().getFile().getRelativePath() = browserRegistrationPath() and
    create.asExpr().getParent+() = registration.getArgument(0).asExpr()
  )
}

/**
 * A LobsterAI-owned extension tool must be the literal object returned by the
 * factory passed to `api.registerTool(...)`. Restricting both the checked-in
 * extension path and exact tool name excludes legacy dynamic MCP wrappers,
 * user plugins, OpenClaw core tools, and same-shape decoys.
 */
private predicate registeredLobsterAILocalTool(
  Function execute, string toolName, string model
) {
  exists(string path, DataFlow::CallNode registration, Function factory,
    ObjectExpr definition, Property executeProperty |
    lobsterAILocalToolSpec(path, toolName, model) and
    execute.getFile().getRelativePath() = path and
    registration.getLocation().getFile() = execute.getFile() and
    registration.getCalleeName() = "registerTool" and
    registration.getArgument(0).asExpr().getUnderlyingValue() = factory and
    execute.getEnclosingStmt().getContainer() = factory and
    executeProperty = definition.getPropertyByName("execute") and
    executeProperty.getInit().getUnderlyingValue() = execute and
    definition.getPropertyByName("name").getInit().getStringValue() = toolName
  )
}

predicate laiToolHandler(Function execute, string toolName, string model) {
  laiIsProject() and registeredBrowserFactory() and
  execute.getFile().getRelativePath() = browserToolPath() and
  exists(Function factory, ObjectExpr definition, Property property |
    factory.getName() = "createBrowserTool" and factory.getFile() = execute.getFile() and
    execute.getEnclosingStmt().getContainer() = factory and
    property = definition.getPropertyByName("execute") and
    property.getInit().getUnderlyingValue() = execute and
    toolName = definition.getPropertyByName("name").getInit().getStringValue() and
    toolName = "browser" and model = "registered-openclaw-browser-tool"
  )
  or
  laiIsProject() and registeredLobsterAILocalTool(execute, toolName, model)
}

predicate laiHandlerSource(Function handler, DataFlow::Node source, string parameterName) {
  laiToolHandler(handler, _, _) and handler.getNumParameter() >= 2 and
  source = DataFlow::parameterNode(handler.getParameter(1)) and
  parameterName = handler.getParameter(1).getName() and parameterName = ["args", "params"]
}

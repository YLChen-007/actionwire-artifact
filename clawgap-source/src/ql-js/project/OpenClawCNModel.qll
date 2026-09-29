/** OpenClaw-CN v0.2.1 fork identity and OpenClaw-family tool-handler model. */

import javascript
import project.OpenClawModel

predicate occnIsProject() {
  exists(Function coding, Function currentCore, Function legacyCore |
    coding.getName() = "createOpenClawCodingTools" and
    coding.getFile().getRelativePath() = "src/agents/pi-tools.ts" and
    currentCore.getName() = "createOpenClawTools" and
    currentCore.getFile().getRelativePath() = "src/agents/openclaw-tools.ts" and
    legacyCore.getName() = "createOpenClawTools" and
    legacyCore.getFile().getRelativePath() = "src/agents/clawdbot-tools.ts"
  )
}

bindingset[path]
predicate occnIsCoreSourcePath(string path) {
  (
    path.matches("src/%.ts") and
    not path.matches("src/plugins/%") and
    not path.matches("src/channels/plugins/agent-tools/%") and
    not path.matches("src/%/test-helpers/%")
    or
    path = ["extensions/feishu/src/outbound.ts", "extensions/feishu/src/media.ts"]
  ) and
  not path.matches("%.test.ts") and not path.matches("%.spec.ts")
}

predicate occnIsCoreLocation(Location loc) {
  occnIsCoreSourcePath(loc.getFile().getRelativePath())
}

private predicate occnWrappedToolHandler(Function execute, string toolName, string model) {
  execute.getName() = "execute" and
  execute.getFile().getRelativePath() = "src/agents/pi-tools.read.ts" and
  (
    execute.getEnclosingStmt().getContainer().(Function).getName() = "wrapToolParamNormalization" and
    toolName = ["write", "edit"] and model = "normalization-wrapper"
    or
    execute.getEnclosingStmt().getContainer().(Function).getName() = "wrapSandboxPathGuard" and
    toolName = ["read", "write", "edit"] and model = "sandbox-path-wrapper"
    or
    execute.getEnclosingStmt().getContainer().(Function).getName() = "createClawdbotReadTool" and
    toolName = "read" and model = "clawdbot-read-wrapper"
  )
}

predicate occnToolHandler(Function execute, string toolName, string model) {
  occnIsProject() and
  exists(Function factory, ObjectExpr object |
    ocFamilyLiteralToolObject(execute, factory, object, toolName, true) and
    model = "literal-object:" + factory.getName()
  )
  or
  occnIsProject() and occnWrappedToolHandler(execute, toolName, model)
}

predicate occnHandlerSource(Function handler, DataFlow::Node source, string parameterName) {
  occnToolHandler(handler, _, _) and handler.getNumParameter() > 1 and
  source = DataFlow::parameterNode(handler.getParameter(1)) and
  parameterName = handler.getParameter(1).getName() and
  parameterName = ["args", "params"]
}

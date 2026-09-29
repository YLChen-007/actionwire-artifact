/** CodeG v0.15.9 TypeScript ACP-agent entry and Rust boundary model. */

import javascript

private predicate cgAgentAllowlist(ArrayExpr allowlist) {
  exists(VariableDeclarator declaration |
    declaration.getBindingPattern().(Identifier).getName() = "ALL_AGENT_TYPES" and
    declaration.getInit().getUnderlyingValue() = allowlist and
    strictcount(allowlist.getAnElement()) = 7
  )
}

private predicate cgRegisteredAgentType(string agentType) {
  exists(ArrayExpr allowlist, Expr literal |
    cgAgentAllowlist(allowlist) and literal = allowlist.getAnElement() and
    agentType = literal.getStringValue()
  )
}

private predicate cgAcpPromptShape(
  Function handler, DataFlow::CallNode boundary, ObjectExpr payload
) {
  handler.getName() = "acpPrompt" and handler.getNumParameter() = 5 and
  handler.getParameter(0).getName() = "connectionId" and
  handler.getParameter(1).getName() = "blocks" and
  handler.getParameter(2).getName() = "folderId" and
  handler.getParameter(3).getName() = "conversationId" and
  handler.getParameter(4).getName() = "clientMessageId" and
  boundary.getContainer() = handler and boundary.getCalleeName() = "call" and
  exists(CallExpr transportCall |
    boundary.getReceiver().asExpr() = transportCall and transportCall.getNumArgument() = 0 and
    transportCall.getCallee().getUnderlyingValue().(Identifier).getName() = "getTransport"
  ) and
  boundary.getArgument(0).getStringValue() = "acp_prompt" and
  payload = boundary.getArgument(1).asExpr() and
  payload.getPropertyByName("blocks").getInit().getUnderlyingValue().(Identifier).getName() =
    "blocks"
}

predicate cgIsProject() {
  exists(Function handler, DataFlow::CallNode boundary, ObjectExpr payload |
    cgAcpPromptShape(handler, boundary, payload) and cgIsCoreLocation(handler.getLocation()) and
    cgRegisteredAgentType("claude_code") and cgRegisteredAgentType("codex") and
    cgRegisteredAgentType("open_code") and cgRegisteredAgentType("gemini") and
    cgRegisteredAgentType("open_claw") and cgRegisteredAgentType("cline") and
    cgRegisteredAgentType("hermes")
  )
}

bindingset[path]
predicate cgIsCoreSourcePath(string path) {
  path.matches("src/%.ts") and
  not path.matches("%.test.ts") and not path.matches("%.spec.ts") and
  not path.matches("src/test/%") and not path.matches("src/test-setup.ts")
  or
  path.matches("src/%.tsx") and
  not path.matches("%.test.tsx") and not path.matches("%.spec.tsx")
}

predicate cgIsCoreLocation(Location loc) {
  cgIsCoreSourcePath(loc.getFile().getRelativePath())
}

predicate cgToolHandler(Function handler, string toolName, string model) {
  cgIsProject() and cgIsCoreLocation(handler.getLocation()) and cgRegisteredAgentType(toolName) and
  exists(DataFlow::CallNode boundary, ObjectExpr payload |
    cgAcpPromptShape(handler, boundary, payload)
  ) and
  model = "registered-external-acp-agent-adapter"
}

predicate cgHandlerSource(Function handler, DataFlow::Node source, string parameterName) {
  cgToolHandler(handler, _, _) and source = DataFlow::parameterNode(handler.getParameter(1)) and
  parameterName = handler.getParameter(1).getName() and parameterName = "blocks"
}

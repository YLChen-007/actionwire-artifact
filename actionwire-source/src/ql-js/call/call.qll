/** OpenClaw TypeScript call graph with narrow wrapper/callback bridges. */

import javascript
import project.ProjectModel
import call.sinks_af

predicate directCallEdge(Function caller, Function callee, DataFlow::CallNode call) {
  call.getContainer() = caller and call.getACallee(1) = callee and
  isCoreLocation(caller.getLocation()) and isCoreLocation(callee.getLocation())
}

/** Resolution fallback for audited local/imported bridges missed by getACallee(). */
private predicate strictNamedBridge(Function caller, Function callee, DataFlow::CallNode call) {
  call.getContainer() = caller and call.getCalleeName() = callee.getName() and
  (
    call.getCalleeName() = "runExecProcess" and
    caller.getFile().getRelativePath() = "src/agents/bash-tools.exec.ts" and
    callee.getFile().getRelativePath() = "src/agents/bash-tools.exec.ts"
    or
    call.getCalleeName() = "spawnWithFallback" and
    caller.getFile().getRelativePath() = "src/agents/bash-tools.exec.ts" and
    callee.getFile().getRelativePath() = "src/process/spawn-utils.ts"
    or
    call.getCalleeName() = "spawnAndWaitForSpawn" and
    caller.getFile().getRelativePath() = "src/process/spawn-utils.ts" and
    callee.getFile().getRelativePath() = "src/process/spawn-utils.ts"
    or
    call.getCalleeName() = "applyPatch" and
    caller.getFile().getRelativePath() = "src/agents/apply-patch.ts" and
    callee.getFile().getRelativePath() = "src/agents/apply-patch.ts"
    or
    call.getCalleeName() = ["runWebFetch", "fetchWithRedirects"] and
    caller.getFile().getRelativePath() = "src/agents/tools/web-fetch.ts" and
    callee.getFile().getRelativePath() = "src/agents/tools/web-fetch.ts"
    or
    call.getCalleeName() = ["runWebSearch", "runPerplexitySearch"] and
    caller.getFile().getRelativePath() = "src/agents/tools/web-search.ts" and
    callee.getFile().getRelativePath() = "src/agents/tools/web-search.ts"
    or
    call.getCalleeName() = "loadWebMedia" and
    caller.getFile().getRelativePath() = "src/agents/tools/image-tool.ts" and
    callee.getFile().getRelativePath() = "src/web/media.ts"
    or
    call.getCalleeName() = "loadWebMediaInternal" and
    caller.getFile().getRelativePath() = "src/web/media.ts" and
    callee.getFile().getRelativePath() = "src/web/media.ts"
    or
    call.getCalleeName() = "fetchRemoteMedia" and
    caller.getFile().getRelativePath() = "src/web/media.ts" and
    callee.getFile().getRelativePath() = "src/media/fetch.ts"
    or
    call.getCalleeName() = "readErrorBodySnippet" and
    caller.getFile().getRelativePath() = "src/media/fetch.ts" and
    callee.getFile().getRelativePath() = "src/media/fetch.ts"
    or
    call.getCalleeName() = "runCommand" and
    caller.getFile().getRelativePath() = "src/node-host/runner.ts" and
    callee.getFile().getRelativePath() = "src/node-host/runner.ts"
    or
    call.getCalleeName() = [
      "evaluateShellAllowlist", "evaluateExecAllowlist", "requiresExecApproval"
    ] and
    caller.getFile().getRelativePath() = [
      "src/agents/bash-tools.exec.ts", "src/node-host/runner.ts"
    ] and
    callee.getFile().getRelativePath() = "src/infra/exec-approvals.ts"
    or
    call.getCalleeName() = [
      "evaluateExecAllowlist", "evaluateSegments", "isSafeBinUsage"
    ] and
    caller.getFile().getRelativePath() = "src/infra/exec-approvals.ts" and
    callee.getFile().getRelativePath() = "src/infra/exec-approvals.ts"
    or
    // OpenClaw witnesses for two revision-incompatible reports, exercised together
    // only by the synthetic fixture. Exact path/function constraints keep the bridges
    // dormant in v2026.2.1, which lacks the matching calls.
    isOpenClawProject() and
    caller.getFile().getRelativePath() = "src/agents/tools/message-tool.ts" and
    call.getCalleeName() = "readLocalFileSafely" and
    callee.getName() = "readLocalFileSafely" and
    callee.getFile().getRelativePath() = "src/infra/fs-safe.ts"
    or
    isOpenClawProject() and
    caller.getFile().getRelativePath() = "src/infra/fs-safe.ts" and
    caller.getName() = "readLocalFileSafely" and call.getCalleeName() = "openLocalFileSafely" and
    callee.getName() = "openLocalFileSafely" and
    callee.getFile().getRelativePath() = "src/infra/fs-safe.ts"
    or
    isOpenClawProject() and
    caller.getFile().getRelativePath() = "extensions/browser/src/browser-tool.ts" and
    call.getCalleeName() = "browserAct" and callee.getName() = "browserAct" and
    callee.getFile().getRelativePath() =
      "extensions/browser/src/browser/client-actions-core.ts"
    or
    isOpenClawProject() and
    caller.getFile().getRelativePath() =
      "extensions/browser/src/browser/client-actions-core.ts" and
    call.getCalleeName() = "runActRoute" and callee.getName() = "runActRoute" and
    callee.getFile().getRelativePath() =
      "extensions/browser/src/browser/routes/agent.act.ts"
    or
    isOpenClawProject() and
    caller.getFile().getRelativePath() =
      "extensions/browser/src/browser/routes/agent.act.ts" and
    call.getCalleeName() = "evaluateWithChromeMcp" and
    callee.getName() = "evaluateWithChromeMcp" and
    callee.getFile().getRelativePath() = "extensions/browser/src/browser/chrome-mcp.ts"
    or
    isOpenClawProject() and
    caller.getFile().getRelativePath() = "extensions/browser/src/browser/chrome-mcp.ts" and
    caller.getName() = "evaluateWithChromeMcp" and call.getCalleeName() = "callTool" and
    callee.getName() = "callTool" and
    callee.getFile().getRelativePath() = "extensions/browser/src/browser/chrome-mcp.ts"
  )
}

/** Audited logical edge across gateway RPC serialization and node-host event delivery. */
private predicate nodeInvokeRpcEdge(Function caller, Function callee, DataFlow::CallNode call) {
  call.getContainer() = caller and call.getCalleeName() = "callGatewayTool" and
  call.getArgument(0).mayHaveStringValue("node.invoke") and
  (
    (openClawToolHandler(caller, "exec", _) or openClawCNToolHandler(caller, "exec", _))
    or
    (openClawToolHandler(caller, "nodes", _) or openClawCNToolHandler(caller, "nodes", _)) and
    call.getArgument(2).asExpr().(ObjectExpr).getPropertyByName("command").getInit().getStringValue() =
      "system.run"
  ) and
  callee.getName() = "handleInvoke" and
  callee.getFile().getRelativePath() = "src/node-host/runner.ts"
}

/** Captured argv enters the Promise executor that owns runner.ts's concrete spawn. */
private predicate runnerPromiseCallbackEdge(
  Function caller, Function callee, DataFlow::CallNode call
) {
  caller.getName() = "runCommand" and
  caller.getFile().getRelativePath() = "src/node-host/runner.ts" and
  callee.getEnclosingStmt().getContainer() = caller and call.getContainer() = callee and
  call.getCalleeName() = "spawn" and
  call.getLocation().getFile().getRelativePath() = "src/node-host/runner.ts"
}

/** A call is admitted only when it is in the continuing arm of the audited literal route. */
bindingset[checkedField, literal]
private predicate nanoClawLiteralRoute(
  DataFlow::CallNode call, string checkedField, string literal
) {
  exists(IfStmt guard, PropAccess access, Literal value |
    call.asExpr().getParent+() = guard.getThen() and
    access.getParent*() = guard.getCondition() and
    access.getBase().(Identifier).getName() = "msg" and
    access.getPropertyName() = checkedField and
    value.getParent*() = guard.getCondition() and value.getValue() = literal
  )
}

/** Container messages are consumed from outbound.db before host delivery. */
private predicate nanoClawMessagesOutBridgeShape() {
  exists(Function poll, Function drain, Function deliver, DataFlow::CallNode drainCall,
    DataFlow::CallNode readDue, DataFlow::CallNode deliverCall |
    poll.getName() = "deliverSessionMessages" and
    poll.getFile().getRelativePath() = "src/delivery.ts" and
    drain.getName() = "drainSession" and
    drain.getFile().getRelativePath() = "src/delivery.ts" and
    deliver.getName() = "deliverMessage" and
    deliver.getFile().getRelativePath() = "src/delivery.ts" and
    drainCall.getContainer() = poll and drainCall.getCalleeName() = "drainSession" and
    readDue.getContainer() = drain and readDue.getCalleeName() = "getDueOutboundMessages" and
    deliverCall.getContainer() = drain and deliverCall.getCalleeName() = "deliverMessage" and
    deliverCall.getArgument(0).asExpr().(Identifier).getName() = "msg"
  )
}

/** The host installs the concrete channel-registry bridge used by ChannelDeliveryAdapter. */
private predicate nanoClawDeliveryAdapterBoundary() {
  exists(DataFlow::CallNode install, DataFlow::CallNode create |
    install.getCalleeName() = "setDeliveryAdapter" and
    install.getLocation().getFile().getRelativePath() = "src/index.ts" and
    create = install.getArgument(0) and create.getCalleeName() = "createChannelDeliveryAdapter" and
    exists(Function factory |
      factory.getName() = "createChannelDeliveryAdapter" and
      factory.getFile().getRelativePath() = "src/channels/channel-registry.ts"
    )
  )
}

/** NanoClaw callback edges, tied to literal registration sites. */
private predicate nanoClawRegistryEdge(
  Function caller, Function callee, DataFlow::CallNode call
) {
  isNanoClawProject() and call.getContainer() = caller and
  (
    caller.getName() = "handleSystemAction" and
    caller.getFile().getRelativePath() = "src/delivery.ts" and
    call.getCalleeName() = "registered" and
    callee.getName() = "handleAddMcpServer" and
    callee.getFile().getRelativePath() = "src/modules/self-mod/request.ts" and
    exists(DataFlow::CallNode registration |
      registration.getCalleeName() = "registerDeliveryAction" and
      registration.getLocation().getFile().getRelativePath() = "src/modules/self-mod/index.ts" and
      registration.getArgument(0).mayHaveStringValue("add_mcp_server") and
      registration.getArgument(1).asExpr().(Identifier).getName() = "handleAddMcpServer"
    )
    or
    caller.getName() = "handleRegisteredApproval" and
    caller.getFile().getRelativePath() = "src/modules/approvals/response-handler.ts" and
    call.getCalleeName() = "handler" and
    callee.getName() = "applyAddMcpServer" and
    callee.getFile().getRelativePath() = "src/modules/self-mod/apply.ts" and
    exists(DataFlow::CallNode registration |
      registration.getCalleeName() = "registerApprovalHandler" and
      registration.getLocation().getFile().getRelativePath() = "src/modules/self-mod/index.ts" and
      registration.getArgument(0).mayHaveStringValue("add_mcp_server") and
      registration.getArgument(1).asExpr().(Identifier).getName() = "applyAddMcpServer"
    )
  )
}

/** Audited local/dynamic calls used on NanoClaw GT paths. */
private predicate nanoClawStrictEdge(
  Function caller, Function callee, DataFlow::CallNode call
) {
  isNanoClawProject() and call.getContainer() = caller and
  call.getCalleeName() = callee.getName() and
  (
    caller.getName() = "deliverMessage" and caller.getFile().getRelativePath() = "src/delivery.ts" and
    callee.getName() = "handleSystemAction" and callee.getFile().getRelativePath() = "src/delivery.ts"
    and nanoClawLiteralRoute(call, "kind", "system")
    or
    caller.getName() = "deliverMessage" and caller.getFile().getRelativePath() = "src/delivery.ts" and
    callee.getName() = "routeAgentMessage" and
    callee.getFile().getRelativePath() = "src/modules/agent-to-agent/agent-route.ts" and
    nanoClawLiteralRoute(call, "channel_type", "agent")
    or
    caller.getName() = "routeAgentMessage" and
    caller.getFile().getRelativePath() = "src/modules/agent-to-agent/agent-route.ts" and
    callee.getName() = "forwardFileAttachments" and
    callee.getFile().getRelativePath() = "src/modules/agent-to-agent/agent-route.ts" and
    call.getArgument(0).asExpr().(Identifier).getName() = "msg"
    or
    caller.getName() = "forwardFileAttachments" and
    caller.getFile().getRelativePath() = "src/modules/agent-to-agent/agent-route.ts" and
    callee.getName() = "forwardAttachedFiles" and
    callee.getFile().getRelativePath() = "src/modules/agent-to-agent/agent-route.ts" and
    exists(Property filenames |
      filenames = call.getArgument(0).asExpr().(ObjectExpr).getPropertyByName("filenames")
    )
    or
    caller.getName() = "handleAddMcpServer" and
    caller.getFile().getRelativePath() = "src/modules/self-mod/request.ts" and
    callee.getName() = "requestApproval" and
    callee.getFile().getRelativePath() = "src/modules/approvals/primitive.ts" and
    call.getArgument(0).asExpr().(ObjectExpr).getPropertyByName("action").getInit().mayHaveStringValue(
      "add_mcp_server"
    )
    or
    caller.getName() = "requestApproval" and
    caller.getFile().getRelativePath() = "src/modules/approvals/primitive.ts" and
    callee.getName() = "createPendingApproval" and
    callee.getFile().getRelativePath() = "src/db/sessions.ts" and
    exists(Property action, Property payload |
      action = call.getArgument(0).asExpr().(ObjectExpr).getPropertyByName("action") and
      payload = call.getArgument(0).asExpr().(ObjectExpr).getPropertyByName("payload")
    )
    or
    caller.getName() = "applyAddMcpServer" and
    caller.getFile().getRelativePath() = "src/modules/self-mod/apply.ts" and
    callee.getName() = "updateContainerConfigJson" and
    callee.getFile().getRelativePath() = "src/db/container-configs.ts" and
    call.getArgument(1).mayHaveStringValue("mcp_servers")
  )
}

/** Audited TinyClaw adapter-to-invoker calls. */
private predicate tinyClawStrictEdge(
  Function caller, Function callee, DataFlow::CallNode call
) {
  isTinyClawProject() and tinyClawToolHandler(caller, _, _) and
  call.getContainer() = caller and call.getCalleeName() = ["runCommand", "runCommandStreaming"] and
  callee.getName() = call.getCalleeName() and
  callee.getFile().getRelativePath() = "packages/core/src/invoke.ts"
}

/** Mercury dependency-injection and sub-agent lifecycle edges on GT paths. */
private predicate mercuryAgentStrictEdge(
  Function caller, Function callee, DataFlow::CallNode call
) {
  isMercuryAgentProject() and call.getContainer() = caller and
  (
    mercuryAgentToolHandler(caller, "install_skill", _) and
    call.getCalleeName() = "saveSkill" and call.getReceiver().toString() = "skillLoader" and
    callee.getName() = "saveSkill" and callee.getFile().getRelativePath() = "src/skills/loader.ts"
    or
    mercuryAgentToolHandler(caller, "run_command", _) and
    call.getCalleeName() = "executeCommand" and
    callee.getName() = "executeCommand" and callee.getNumParameter() = 3 and
    callee.getParameter(0).getName() = "command" and
    callee.getParameter(1).getName() = "cwd" and
    callee.getParameter(2).getName() = "timeoutMs"
    or
    mercuryAgentToolHandler(caller, "github_api", _) and
    call.getCalleeName() = "githubRequest" and
    callee.getName() = "githubRequest" and callee.getNumParameter() = 2 and
    callee.getParameter(0).getName() = "path" and
    callee.getParameter(1).getName() = "options"
    or
    mercuryAgentToolHandler(caller, "delegate_task", _) and
    call.getCalleeName() = "spawn" and call.getReceiver().toString() = "supervisor" and
    callee.getName() = "spawn" and callee.getFile().getRelativePath() = "src/core/supervisor.ts"
    or
    caller.getName() = "spawn" and caller.getFile().getRelativePath() = "src/core/supervisor.ts" and
    call.getCalleeName() = "startAgentInBackground" and
    callee.getName() = "startAgentInBackground" and callee.getFile() = caller.getFile()
    or
    caller.getName() = "startAgentInBackground" and
    caller.getFile().getRelativePath() = "src/core/supervisor.ts" and
    call.getCalleeName() = "run" and call.getReceiver().toString() = "subAgent" and
    callee.getName() = "run" and callee.getFile().getRelativePath() = "src/core/sub-agent.ts"
    or
    mercuryAgentToolHandler(caller, "run_command", _) and
    call.getCalleeName() = "checkShellCommand" and call.getReceiver().toString() = "permissions" and
    callee.getName() = "checkShellCommand" and
    callee.getFile().getRelativePath() = "src/capabilities/permissions.ts"
    or
    mercuryAgentToolHandler(caller, ["read_file", "write_file", "create_file", "edit_file"], _) and
    call.getCalleeName() = "checkFsAccess" and call.getReceiver().toString() = "permissions" and
    callee.getName() = "checkFsAccess" and
    callee.getFile().getRelativePath() = "src/capabilities/permissions.ts"
  )
}

/** Registered manage_todo dispatch into its audited local store mutators. */
private predicate lettaBotStrictEdge(
  Function caller, Function callee, DataFlow::CallNode call
) {
  isLettaBotProject() and call.getContainer() = caller and
  (
    lettaBotToolHandler(caller, "manage_todo", _) and
    call.getCalleeName() = [
      "addTodo", "completeTodo", "reopenTodo", "removeTodo", "snoozeTodo"
    ] and callee.getName() = call.getCalleeName() and callee.getNumParameter() >= 2 and
    callee.getParameter(0).getName() = "agentKey"
    or
    caller.getName() = [
      "addTodo", "completeTodo", "reopenTodo", "removeTodo", "snoozeTodo"
    ] and caller.getNumParameter() >= 2 and caller.getParameter(0).getName() = "agentKey" and
    call.getCalleeName() = "saveStore" and callee.getName() = "saveStore" and
    callee.getNumParameter() = 2 and callee.getParameter(0).getName() = "path" and
    callee.getParameter(1).getName() = "store"
  )
}

predicate projectCallEdge(Function caller, Function callee, DataFlow::CallNode call) {
  directCallEdge(caller, callee, call)
  or
  strictNamedBridge(caller, callee, call)
  or
  nodeInvokeRpcEdge(caller, callee, call)
  or
  nanoClawRegistryEdge(caller, callee, call)
  or
  nanoClawStrictEdge(caller, callee, call)
  or
  tinyClawStrictEdge(caller, callee, call)
  or
  mercuryAgentStrictEdge(caller, callee, call)
  or
  lettaBotStrictEdge(caller, callee, call)
  or
  call.getContainer() = caller and isCoreLocation(call.getLocation()) and
  exists(DataFlow::FunctionNode callback |
    callback = call.getCallback(_) and callback.getFunction() = callee and
    isCoreLocation(callee.getLocation())
  )
}

/** Explicit paths for the one anonymous callback admitted by the project model. */
private predicate runnerPromiseSinkPath(
  Function root, DataFlow::CallNode sink, int depth, string path
) {
  depth = 2 and
  exists(Function callback |
    runnerPromiseCallbackEdge(root, callback, sink) and
    path = root.getName() + "@" + root.getFile().getBaseName() + "->" +
      "<runner-promise-callback>@" + callback.getFile().getBaseName() + "->" +
      sinkLabel(sink) + "@" + sink.getLocation().getFile().getBaseName()
  )
  or
  depth = 3 and
  exists(Function runCommand, Function callback, DataFlow::CallNode firstEdge |
    projectCallEdge(root, runCommand, firstEdge) and
    runnerPromiseCallbackEdge(runCommand, callback, sink) and
    path = root.getName() + "@" + root.getFile().getBaseName() + "->" +
      runCommand.getName() + "@" + runCommand.getFile().getBaseName() + "->" +
      "<runner-promise-callback>@" + callback.getFile().getBaseName() + "->" +
      sinkLabel(sink) + "@" + sink.getLocation().getFile().getBaseName()
  )
  or
  depth = 4 and
  exists(Function handleInvoke, Function runCommand, Function callback,
    DataFlow::CallNode firstEdge, DataFlow::CallNode secondEdge |
    projectCallEdge(root, handleInvoke, firstEdge) and
    projectCallEdge(handleInvoke, runCommand, secondEdge) and
    runnerPromiseCallbackEdge(runCommand, callback, sink) and
    path = root.getName() + "@" + root.getFile().getBaseName() + "->" +
      handleInvoke.getName() + "@" + handleInvoke.getFile().getBaseName() + "->" +
      runCommand.getName() + "@" + runCommand.getFile().getBaseName() + "->" +
      "<runner-promise-callback>@" + callback.getFile().getBaseName() + "->" +
      sinkLabel(sink) + "@" + sink.getLocation().getFile().getBaseName()
  )
}

private predicate nanoClawOutboundSource(
  Function root, DataFlow::Node source, DataFlow::CallNode outbound, string toolName
) {
  nanoClawToolHandler(root, toolName, _) and handlerSource(root, source, "args") and
  outbound.getContainer() = root and outbound.getCalleeName() = "writeMessageOut" and
  outbound.getLocation().getFile().getRelativePath() = root.getFile().getRelativePath() and
  exists(ObjectExpr payload, Property content |
    payload = outbound.getArgument(0).asExpr() and content = payload.getPropertyByName("content") and
    localTaint(source, content.getInit().flow()) and
    (
      toolName = "send_file" and
      payload.getPropertyByName("kind").getInit().mayHaveStringValue("chat") and
      exists(DataFlow::CallNode stringify, ObjectExpr contentPayload |
        stringify = content.getInit().flow() and stringify.getCalleeName() = "stringify" and
        contentPayload = stringify.getArgument(0).asExpr() and
        localTaint(
          source, contentPayload.getPropertyByName("files").getInit().flow()
        )
      )
      or
      toolName = "add_mcp_server" and
      payload.getPropertyByName("kind").getInit().mayHaveStringValue("system") and
      exists(DataFlow::CallNode stringify, ObjectExpr actionPayload |
        stringify = content.getInit().flow() and stringify.getCalleeName() = "stringify" and
        actionPayload = stringify.getArgument(0).asExpr() and
        actionPayload.getPropertyByName("action").getInit().mayHaveStringValue("add_mcp_server") and
        localTaint(
          source, actionPayload.getPropertyByName("command").getInit().flow()
        )
      )
    )
  )
}

/** Every A2A hop is backed by the audited route, payload position, and DB hand-off. */
private predicate nanoClawA2ABridgeShape() {
  nanoClawMessagesOutBridgeShape() and
  exists(Function deliver, Function route, Function attachments, Function copy,
    DataFlow::CallNode routeCall, DataFlow::CallNode attachmentsCall,
    DataFlow::CallNode copyCall |
    nanoClawStrictEdge(deliver, route, routeCall) and
    nanoClawStrictEdge(route, attachments, attachmentsCall) and
    nanoClawStrictEdge(attachments, copy, copyCall)
  )
}

/** The literal delivery action reaches requestApproval and its persistence primitive. */
private predicate nanoClawApprovalRequestBridgeShape() {
  nanoClawMessagesOutBridgeShape() and nanoClawDeliveryAdapterBoundary() and
  exists(Function systemAction, Function requestHandler, Function approval,
    Function persist, DataFlow::CallNode registryCall, DataFlow::CallNode approvalCall,
    DataFlow::CallNode persistCall |
    nanoClawRegistryEdge(systemAction, requestHandler, registryCall) and
    nanoClawStrictEdge(requestHandler, approval, approvalCall) and
    nanoClawStrictEdge(approval, persist, persistCall)
  )
}

/** Approval replay is admitted only through the literal handler registry and mcp_servers update. */
private predicate nanoClawApprovalApplyBridgeShape() {
  nanoClawApprovalRequestBridgeShape() and
  exists(Function response, Function apply, Function update, DataFlow::CallNode handlerCall,
    DataFlow::CallNode updateCall |
    nanoClawRegistryEdge(response, apply, handlerCall) and
    nanoClawStrictEdge(apply, update, updateCall)
  )
}

/**
 * LobsterAI ships the browser tool and control server in a separate runtime bundle.
 * Admit only the literal POST /tabs/open route and the persistent-Playwright branch.
 */
private predicate lobsterAIBrowserBridgeShape() {
  isLobsterAIProject() and
  exists(DataFlow::CallNode routeRegistration, DataFlow::CallNode routeOpen,
    DataFlow::CallNode routeGate, Function navigationGuard,
    DataFlow::CallNode resolvePolicyCall, Function resolvePolicy,
    DataFlow::CallNode policyChecksCall, Function policyChecks,
    DataFlow::CallNode skipChecksCall, Function skipChecks,
    DataFlow::CallNode privateNetworkPolicyCall,
    Function openTabFunction, DataFlow::CallNode createPageCall,
    Function createPageFunction, DataFlow::CallNode guardedGotoCall,
    Function guardedGotoFunction, DataFlow::CallNode concreteGoto |
    routeRegistration.getCalleeName() = "post" and
    routeRegistration.getArgument(0).mayHaveStringValue("/tabs/open") and
    routeRegistration.getLocation().getFile().getRelativePath() =
      "vendor-source/openclaw-v2026.4.14/extensions/browser/src/browser/routes/tabs.ts" and
    routeOpen.getCalleeName() = "openTab" and routeOpen.getArgument(0).toString() = "url" and
    routeOpen.getLocation().getFile() = routeRegistration.getLocation().getFile() and
    routeGate.getCalleeName() = "assertBrowserNavigationAllowed" and
    routeGate.getLocation().getFile() = routeRegistration.getLocation().getFile() and
    navigationGuard.getName() = "assertBrowserNavigationAllowed" and
    navigationGuard.getFile().getRelativePath() =
      "vendor-source/openclaw-v2026.4.14/extensions/browser/src/browser/navigation-guard.ts" and
    resolvePolicyCall.getContainer() = navigationGuard and
    resolvePolicyCall.getCalleeName() = "resolvePinnedHostnameWithPolicy" and
    resolvePolicy.getName() = "resolvePinnedHostnameWithPolicy" and
    resolvePolicy.getFile().getRelativePath() =
      "vendor-source/openclaw-v2026.4.14/src/infra/net/ssrf.ts" and
    policyChecksCall.getContainer() = resolvePolicy and
    policyChecksCall.getCalleeName() = "resolveHostnamePolicyChecks" and
    policyChecks.getName() = "resolveHostnamePolicyChecks" and
    policyChecks.getFile() = resolvePolicy.getFile() and
    skipChecksCall.getContainer() = policyChecks and
    skipChecksCall.getCalleeName() = "shouldSkipPrivateNetworkChecks" and
    skipChecks.getName() = "shouldSkipPrivateNetworkChecks" and
    skipChecks.getFile() = resolvePolicy.getFile() and
    privateNetworkPolicyCall.getContainer() = skipChecks and
    privateNetworkPolicyCall.getCalleeName() = "isPrivateNetworkAllowedByPolicy" and
    openTabFunction.getName() = "openTab" and
    openTabFunction.getFile().getRelativePath() =
      "vendor-source/openclaw-v2026.4.14/extensions/browser/src/browser/server-context.tab-ops.ts" and
    createPageCall.getContainer() = openTabFunction and
    createPageCall.getCalleeName() = "createPageViaPlaywright" and
    createPageCall.getArgument(0).asExpr().(ObjectExpr).getPropertyByName("url").getInit().toString() =
      "url" and
    createPageFunction.getName() = "createPageViaPlaywright" and
    createPageFunction.getFile().getRelativePath() =
      "vendor-source/openclaw-v2026.4.14/extensions/browser/src/browser/pw-session.ts" and
    guardedGotoCall.getContainer() = createPageFunction and
    guardedGotoCall.getCalleeName() = "gotoPageWithNavigationGuard" and
    guardedGotoCall.getArgument(0).asExpr().(ObjectExpr).getPropertyByName("url").getInit().toString() =
      "targetUrl" and
    guardedGotoFunction.getName() = "gotoPageWithNavigationGuard" and
    guardedGotoFunction.getFile() = createPageFunction.getFile() and
    concreteGoto.getContainer() = guardedGotoFunction and
    sinkCanonicalId(concreteGoto) = "LA-BROWSER-PAGE-GOTO"
  )
}

private predicate lobsterAIClientBoundary(
  Function root, DataFlow::Node source, DataFlow::CallNode boundary
) {
  lobsterAIToolHandler(root, "browser", _) and handlerSource(root, source, _) and
  boundary.getContainer() = root and boundary.getCalleeName() = "browserOpenTab" and
  boundary.getReceiver().toString() = "browserToolDeps" and
  boundary.getLocation().getFile().getRelativePath() =
    "vendor-source/openclaw-v2026.4.14/extensions/browser/src/browser-tool.ts" and
  localTaint(source, boundary.getArgument(1))
}

/** One explicit structural witness across the bundled loopback control-server boundary. */
private predicate lobsterAIReachesSink(
  Function root, DataFlow::CallNode sink, int depth, string path
) {
  lobsterAIToolHandler(root, "browser", _) and lobsterAIBrowserBridgeShape() and
  sinkCanonicalId(sink) = "LA-BROWSER-PAGE-GOTO" and depth = 11 and
  path = "execute@browser-tool.ts->browserOpenTab@client.ts->" +
    "<POST /tabs/open>@tabs.ts->assertBrowserNavigationAllowed@navigation-guard.ts->" +
    "resolvePinnedHostnameWithPolicy@ssrf.ts->resolveHostnamePolicyChecks@ssrf.ts->" +
    "shouldSkipPrivateNetworkChecks@ssrf.ts->profileCtx.openTab@tabs.ts->" +
    "openTab@server-context.tab-ops.ts->createPageViaPlaywright@pw-session.ts->" +
    "gotoPageWithNavigationGuard@pw-session.ts->page.goto@pw-session.ts"
}

/** TinyClaw's spawn lives in the Promise callback owned by each core invoker. */
private predicate tinyClawReachesSink(
  Function root, DataFlow::CallNode sink, int depth, string path
) {
  tinyClawToolHandler(root, _, _) and sinkCanonicalId(sink) = "TC-EXTERNAL-AGENT-SPAWN" and
  exists(Function invoker, DataFlow::CallNode edge, Function callback |
    tinyClawStrictEdge(root, invoker, edge) and
    sink.getContainer() = callback and callback.getEnclosingStmt().getContainer() = invoker and
    depth = 2 and
    path = root.getName() + "@" + root.getFile().getBaseName() + "->" +
      invoker.getName() + "@" + invoker.getFile().getBaseName() + "->" +
      "<promise-callback>@" + callback.getFile().getBaseName() + "->" +
      sinkLabel(sink) + "@" + sink.getLocation().getFile().getBaseName()
  )
}

/** Explicit Mercury capability-exposure path across the sub-agent object boundary. */
private predicate mercuryAgentExposureReachesSink(
  Function root, DataFlow::CallNode sink, int depth, string path
) {
  mercuryAgentToolHandler(root, "delegate_task", _) and
  sinkCanonicalId(sink) = "MA-SUBAGENT-TOOL-EXPOSURE" and
  exists(Function spawn, Function start, Function run, DataFlow::CallNode spawnCall,
    DataFlow::CallNode startCall, DataFlow::CallNode runCall |
    mercuryAgentStrictEdge(root, spawn, spawnCall) and
    mercuryAgentStrictEdge(spawn, start, startCall) and
    mercuryAgentStrictEdge(start, run, runCall) and sink.getContainer() = run and depth = 4 and
    path = "execute@delegate-task.ts->spawn@supervisor.ts->" +
      "startAgentInBackground@supervisor.ts->run@sub-agent.ts->generateText.tools@sub-agent.ts"
  )
}

/** The registered run_command handler enters executeCommand's Promise-owned spawn. */
private predicate mercuryAgentCommandReachesSink(
  Function root, DataFlow::CallNode sink, int depth, string path
) {
  mercuryAgentToolHandler(root, "run_command", _) and
  sinkCanonicalId(sink) = "MA-PROCESS-SPAWN" and
  exists(Function executeCommand, Function callback, DataFlow::CallNode edge |
    mercuryAgentStrictEdge(root, executeCommand, edge) and sink.getContainer() = callback and
    callback.getEnclosingStmt().getContainer() = executeCommand and depth = 2 and
    path = "execute@run-command.ts->executeCommand@run-command.ts->" +
      "<promise-callback>@run-command.ts->child_process.spawn@run-command.ts"
  )
}

/** Explicit structural paths across NanoClaw's two SQLite hand-off boundaries. */
private predicate nanoClawReachesSink(
  Function root, DataFlow::CallNode sink, int depth, string path
) {
  (
    nanoClawA2ABridgeShape() and nanoClawToolHandler(root, "send_file", _) and
    sinkCanonicalId(sink) = "NC-FILE-COPY" and
    sink.getLocation().getFile().getRelativePath() = "src/modules/agent-to-agent/agent-route.ts" and
    depth = 5 and
    path = "handler@core.ts-><messages_out-db>@outbound.db->deliverMessage@delivery.ts->" +
      "routeAgentMessage@agent-route.ts->forwardFileAttachments@agent-route.ts->" +
      "forwardAttachedFiles@agent-route.ts->copyFileSync@agent-route.ts"
    or
    nanoClawApprovalRequestBridgeShape() and
    nanoClawToolHandler(root, "add_mcp_server", _) and
    sinkCanonicalId(sink) = ["NC-APPROVAL-PERSIST", "NC-APPROVAL-PRESENT"] and
    depth = 6 and
    path = "handler@self-mod.ts-><messages_out-db>@outbound.db->deliverMessage@delivery.ts->" +
      "handleSystemAction@delivery.ts->handleAddMcpServer@request.ts->" +
      "requestApproval@primitive.ts->" + sinkLabel(sink) + "@" +
      sink.getLocation().getFile().getBaseName()
    or
    nanoClawApprovalApplyBridgeShape() and
    nanoClawToolHandler(root, "add_mcp_server", _) and
    sinkCanonicalId(sink) = "NC-CONFIG-MUTATION" and depth = 10 and
    path = "handler@self-mod.ts-><messages_out-db>@outbound.db->deliverMessage@delivery.ts->" +
      "handleSystemAction@delivery.ts->handleAddMcpServer@request.ts->" +
      "requestApproval@primitive.ts-><pending_approvals-db>@central.db->" +
      "handleRegisteredApproval@response-handler.ts->applyAddMcpServer@apply.ts->" +
      "updateContainerConfigJson@container-configs.ts->" + sinkLabel(sink) + "@container-configs.ts"
  )
}

/** Literal HTTP/RPC routes and callback positions used by OpenClaw-CN's browser tool. */
private predicate openClawCNBrowserBridgeShape(DataFlow::CallNode sink, string routeKind) {
  isOpenClawCNProject() and
  (
    routeKind = "act" and sinkCanonicalId(sink) = [
      "OCCN-BROWSER-EVALUATE", "OCCN-BROWSER-INTERACTION"
    ] and
    exists(DataFlow::CallNode route, DataFlow::CallNode client, DataFlow::CallNode delegate |
      route.getCalleeName() = "post" and route.getArgument(0).mayHaveStringValue("/act") and
      client.getCalleeName() = "fetchBrowserJson" and
      client.getContainer().(Function).getName() = "browserAct" and
      client.getContainer().(Function).getNumParameter() = 3 and
      client.getContainer().(Function).getParameter(1).getName() = "req" and
      delegate.getCalleeName() = ["clickViaPlaywright", "evaluateViaPlaywright"] and
      delegate.getReceiver().toString() = "pw" and
      delegate.getContainer().getFile().getRelativePath() = route.getLocation().getFile().getRelativePath()
    )
    or
    routeKind = "navigate" and sinkCanonicalId(sink) = "OCCN-BROWSER-PAGE-GOTO" and
    sink.getContainer().(Function).getName() = "navigateViaPlaywright" and
    exists(DataFlow::CallNode route, DataFlow::CallNode client, DataFlow::CallNode delegate |
      route.getCalleeName() = "post" and route.getArgument(0).mayHaveStringValue("/navigate") and
      client.getCalleeName() = "fetchBrowserJson" and
      client.getContainer().(Function).getName() = "browserNavigate" and
      client.getContainer().(Function).getNumParameter() = 2 and
      client.getContainer().(Function).getParameter(1).getName() = "opts" and
      delegate.getCalleeName() = "navigateViaPlaywright" and
      delegate.getReceiver().toString() = "pw"
    )
    or
    routeKind = "open" and sinkCanonicalId(sink) = [
      "OCCN-BROWSER-CDP-CREATE-TARGET", "OCCN-BROWSER-PAGE-GOTO",
      "OCCN-BROWSER-JSON-NEW"
    ] and
    (
      sinkCanonicalId(sink) != "OCCN-BROWSER-PAGE-GOTO"
      or
      sink.getContainer().(Function).getName() = "createPageViaPlaywright"
    ) and
    exists(DataFlow::CallNode route, DataFlow::CallNode client, DataFlow::CallNode openCall,
      Function openTab |
      route.getCalleeName() = "post" and route.getArgument(0).mayHaveStringValue("/tabs/open") and
      client.getCalleeName() = "fetchBrowserJson" and
      client.getContainer().(Function).getName() = "browserOpenTab" and
      client.getContainer().(Function).getNumParameter() = 3 and
      client.getContainer().(Function).getParameter(1).getName() = "url" and
      openCall.getCalleeName() = "openTab" and openCall.getReceiver().toString() = "profileCtx" and
      openTab.getName() = "openTab" and openTab.getNumParameter() = 1 and
      openTab.getParameter(0).getName() = "url" and
      exists(DataFlow::CallNode terminal |
        terminal.getContainer() = openTab and
        terminal.getCalleeName() = ["createPageViaPlaywright", "createTargetViaCdp", "fetchJson"]
      )
    )
  )
}

/** Feishu's literal outbound adapter links the message action media field to sendMediaFeishu. */
private predicate openClawCNFeishuBridgeShape(DataFlow::CallNode sink) {
  isOpenClawCNProject() and sinkCanonicalId(sink) = "OCCN-FEISHU-MEDIA-FETCH" and
  exists(ObjectExpr outbound, Property deliveryMode, Property sendMedia, Function callback,
    Function deliveryCallback, Function deliveryFactory, DataFlow::CallNode mediaCall,
    DataFlow::CallNode deliveryCall |
    deliveryMode = outbound.getPropertyByName("deliveryMode") and
    deliveryMode.getInit().mayHaveStringValue("direct") and
    sendMedia = outbound.getPropertyByName("sendMedia") and
    callback = sendMedia.getInit().getUnderlyingValue() and mediaCall.getContainer() = callback and
    mediaCall.getCalleeName() = "sendMediaFeishu" and
    mediaCall.getArgument(0).asExpr().(ObjectExpr).getPropertyByName("mediaUrl").getInit().toString() =
      "mediaUrl" and
    deliveryCall.getCalleeName() = "sendMedia" and deliveryCall.getContainer() = deliveryCallback and
    deliveryCallback.getEnclosingStmt().getContainer() = deliveryFactory and
    deliveryFactory.getName() = "createPluginHandler" and
    deliveryCall.getArgument(0).asExpr().(ObjectExpr).getPropertyByName("mediaUrl").getInit().toString() =
      "mediaUrl"
  )
}

private string openClawCNSinkOwnerLabel(DataFlow::CallNode sink) {
  exists(Function owner | sink.getContainer() = owner and result = owner.getName())
  or
  not exists(Function owner, string name | sink.getContainer() = owner and owner.getName() = name) and
  sinkCanonicalId(sink) = "OCCN-BROWSER-CDP-CREATE-TARGET" and
  result = "createTargetViaCdp.<callback>"
}

private predicate openClawCNReachesSink(
  Function root, DataFlow::CallNode sink, int depth, string path
) {
  openClawCNToolHandler(root, "browser", _) and
  openClawCNBrowserBridgeShape(sink, "act") and depth = 5 and
  path = "execute@browser-tool.ts->browserAct@client-actions-core.ts->" +
    "<POST /act>@agent.act.ts->" + sink.getContainer().(Function).getName() + "@" +
    sink.getLocation().getFile().getBaseName() + "->" + sinkLabel(sink) + "@" +
    sink.getLocation().getFile().getBaseName()
  or
  openClawCNToolHandler(root, "browser", _) and
  openClawCNBrowserBridgeShape(sink, "navigate") and depth = 5 and
  path = "execute@browser-tool.ts->browserNavigate@client-actions-core.ts->" +
    "<POST /navigate>@agent.snapshot.ts->navigateViaPlaywright@pw-tools-core.snapshot.ts->" +
    sinkLabel(sink) + "@pw-tools-core.snapshot.ts"
  or
  openClawCNToolHandler(root, "browser", _) and
  openClawCNBrowserBridgeShape(sink, "open") and depth = 6 and
  path = "execute@browser-tool.ts->browserOpenTab@client.ts-><POST /tabs/open>@tabs.ts->" +
    "openTab@server-context.ts->" + openClawCNSinkOwnerLabel(sink) + "@" +
    sink.getLocation().getFile().getBaseName() + "->" + sinkLabel(sink) + "@" +
    sink.getLocation().getFile().getBaseName()
  or
  openClawCNToolHandler(root, "apply_patch", _) and
  sinkCanonicalId(sink) = "OCCN-APPLY-PATCH-WRITE" and depth = 3 and
  path = "execute@apply-patch.ts->applyPatch@apply-patch.ts->" +
    "resolvePatchFileOps.<callback>@apply-patch.ts->fs.writeFile:apply-patch@apply-patch.ts"
  or
  openClawCNToolHandler(root, "message", _) and openClawCNFeishuBridgeShape(sink) and depth = 8 and
  path = "execute@message-tool.ts->runMessageAction@message-action-runner.ts->" +
    "executeSendAction@outbound-send-service.ts->sendMessage@message.ts->" +
    "deliverOutboundPayloads@deliver.ts-><feishu-outbound-registry>@channel.ts->" +
    "sendMedia@outbound.ts->sendMediaFeishu@media.ts->fetch:feishu-media@media.ts"
}

predicate reachesSink(Function root, DataFlow::CallNode sink, int depth, string path) {
  runnerPromiseSinkPath(root, sink, depth, path)
  or
  nanoClawReachesSink(root, sink, depth, path)
  or
  openClawCNReachesSink(root, sink, depth, path)
  or
  lobsterAIReachesSink(root, sink, depth, path)
  or
  tinyClawReachesSink(root, sink, depth, path)
  or
  mercuryAgentExposureReachesSink(root, sink, depth, path)
  or
  mercuryAgentCommandReachesSink(root, sink, depth, path)
  or
  depth = 1 and sink.getContainer() = root and
  path = root.getName() + "@" + root.getFile().getBaseName() + "->" +
    sinkLabel(sink) + "@" + sink.getLocation().getFile().getBaseName()
  or
  depth = 2 and
  exists(Function next, DataFlow::CallNode edge |
    projectCallEdge(root, next, edge) and sink.getContainer() = next and
    path = root.getName() + "@" + root.getFile().getBaseName() + "->" +
      next.getName() + "@" + next.getFile().getBaseName() + "->" +
      sinkLabel(sink) + "@" + sink.getLocation().getFile().getBaseName()
  )
  or
  depth = 3 and
  exists(Function first, Function second, DataFlow::CallNode firstEdge,
    DataFlow::CallNode secondEdge |
    projectCallEdge(root, first, firstEdge) and
    projectCallEdge(first, second, secondEdge) and sink.getContainer() = second and
    path = root.getName() + "@" + root.getFile().getBaseName() + "->" +
      first.getName() + "@" + first.getFile().getBaseName() + "->" +
      second.getName() + "@" + second.getFile().getBaseName() + "->" +
      sinkLabel(sink) + "@" + sink.getLocation().getFile().getBaseName()
  )
  or
  depth = 4 and
  exists(Function first, Function second, Function third, DataFlow::CallNode firstEdge,
    DataFlow::CallNode secondEdge, DataFlow::CallNode thirdEdge |
    projectCallEdge(root, first, firstEdge) and
    projectCallEdge(first, second, secondEdge) and
    projectCallEdge(second, third, thirdEdge) and sink.getContainer() = third and
    path = root.getName() + "@" + root.getFile().getBaseName() + "->" +
      first.getName() + "@" + first.getFile().getBaseName() + "->" +
      second.getName() + "@" + second.getFile().getBaseName() + "->" +
      third.getName() + "@" + third.getFile().getBaseName() + "->" +
      sinkLabel(sink) + "@" + sink.getLocation().getFile().getBaseName()
  )
  or
  depth = 5 and
  exists(Function first, Function second, Function third, Function fourth,
    DataFlow::CallNode firstEdge, DataFlow::CallNode secondEdge,
    DataFlow::CallNode thirdEdge, DataFlow::CallNode fourthEdge |
    projectCallEdge(root, first, firstEdge) and
    projectCallEdge(first, second, secondEdge) and
    projectCallEdge(second, third, thirdEdge) and
    projectCallEdge(third, fourth, fourthEdge) and sink.getContainer() = fourth and
    path = root.getName() + "@" + root.getFile().getBaseName() + "->" +
      first.getName() + "@" + first.getFile().getBaseName() + "->" +
      second.getName() + "@" + second.getFile().getBaseName() + "->" +
      third.getName() + "@" + third.getFile().getBaseName() + "->" +
      fourth.getName() + "@" + fourth.getFile().getBaseName() + "->" +
      sinkLabel(sink) + "@" + sink.getLocation().getFile().getBaseName()
  )
}

predicate projectEdgeTaint(
  Function caller, Function callee, DataFlow::CallNode call,
  DataFlow::Node pred, DataFlow::Node succ
) {
  projectCallEdge(caller, callee, call) and
  exists(int i |
    pred = call.getArgument(i) and succ = DataFlow::parameterNode(callee.getParameter(i))
  )
  or
  nodeInvokeRpcEdge(caller, callee, call) and pred = call.getArgument(2) and
  succ = DataFlow::parameterNode(callee.getParameter(0))
  or
  projectCallEdge(caller, callee, call) and caller.getName() = "evaluateSegments" and
  caller.getFile().getRelativePath() = "src/infra/exec-approvals.ts" and
  call.getCalleeName() = "every" and pred = call.getReceiver() and
  succ = DataFlow::parameterNode(callee.getParameter(0))
}

predicate objectValueStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(ObjectExpr object, Property property |
    property = object.getAProperty() and pred = property.getInit().flow() and succ = object.flow()
  )
  or
  exists(ArrayExpr array |
    pred = array.getAnElement().flow() and succ = array.flow()
  )
}

predicate propertyReadStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(PropAccess access |
    pred = access.getBase().flow() and succ = access.flow()
  )
}

/** A destructured execute({ ... }) binding is derived from the complete tool input. */
private predicate mercuryHandlerBindingStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(Function handler, VarRef declared, VarRef use |
    mercuryAgentToolHandler(handler, _, _) and
    pred = DataFlow::parameterNode(handler.getParameter(0)) and
    declared = handler.getParameter(0).getABindingVarRef() and
    use.getVariable() = declared.getVariable() and use.getEnclosingFunction() = handler and
    succ = use.flow()
  )
}

/** Resolve uses of ActionDecision and ADB-command parameters on audited DroidClaw paths. */
private predicate droidClawHandlerBindingStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(Function owner, Parameter parameter, VarRef declared, VarRef use |
    (
      exists(DataFlow::Node source, string parameterName |
        droidClawToolHandler(owner, _, _) and
        handlerSource(owner, source, parameterName) and parameter = owner.getParameter(0) and
        pred = source
      )
      or
      owner.getName() = "runAdbCommand" and
      owner.getFile().getRelativePath() = "src/actions.ts" and owner.getNumParameter() = 2 and
      owner.getParameter(0).getName() = "command" and
      owner.getParameter(1).getName() = "retries" and parameter = owner.getParameter(0) and
      pred = DataFlow::parameterNode(parameter)
    ) and
    declared = parameter.getABindingVarRef() and use.getVariable() = declared.getVariable() and
    use.getEnclosingFunction() = owner and
    succ = use.flow()
  )
}

predicate derivedCallStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(DataFlow::CallNode call |
    (
      call.getCalleeName() = [
        "readStringParam", "readNumberParam", "normalizeToolParams", "resolveNodeId",
        "resolvePatchPath", "parsePatchText", "applyUpdateHunk", "String", "trim",
        "toLowerCase", "slice", "map", "filter", "join", "decodeParams"
      ]
      or
      isNanoClawProject() and
      call.getCalleeName() = [
        "stringify", "parse", "resolveRouting", "findByName", "basename", "resolve",
        "realpathSync"
      ]
      or
      isLobsterAIProject() and
      call.getCalleeName() = ["readTargetUrlParam", "readStringParam", "trim"]
      or
      isTinyClawProject() and call.getCalleeName() = ["push", "JSON.stringify"]
      or
      isMercuryAgentProject() and
      call.getCalleeName() = [
        "resolve", "join", "parse", "parseYaml", "trim", "match", "replace", "split"
      ]
      or
      isDroidClawProject() and call.getCalleeName() = ["split", "String"]
      or
      isLettaBotProject() and
      call.getCalleeName() = ["readStringParam", "trim", "toLowerCase", "stringify"]
    ) and
    (pred = call.getAnArgument() or pred = call.getReceiver()) and succ = call
  )
}

/** The selected remote URL determines the Response whose body is consumed. */
private predicate remoteResponseStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(DataFlow::CallNode call, Function fetchRemoteMedia |
    call.getCalleeName() = "fetcher" and
    call.getLocation().getFile().getRelativePath() = "src/media/fetch.ts" and
    call.getContainer() = fetchRemoteMedia and fetchRemoteMedia.getName() = "fetchRemoteMedia" and
    (
      pred = call.getArgument(0)
      or
      pred = DataFlow::parameterNode(fetchRemoteMedia.getParameter(0))
    ) and succ = call
  )
  or
  exists(Function fetchRemoteMedia, DataFlow::CallNode fetchCall,
    DataFlow::CallNode snippetCall |
    fetchRemoteMedia.getName() = "fetchRemoteMedia" and
    fetchRemoteMedia.getFile().getRelativePath() = "src/media/fetch.ts" and
    fetchCall.getContainer() = fetchRemoteMedia and fetchCall.getCalleeName() = "fetcher" and
    snippetCall.getContainer() = fetchRemoteMedia and
    snippetCall.getCalleeName() = "readErrorBodySnippet" and
    pred = DataFlow::parameterNode(fetchRemoteMedia.getParameter(0)) and
    succ = snippetCall.getArgument(0)
  )
}

/** The node system.run payload builder closes over the exec handler's params. */
private predicate capturedExecPayloadStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(Function handler, DataFlow::CallNode call, DataFlow::CallNode invoke |
    (openClawToolHandler(handler, "exec", _) or openClawCNToolHandler(handler, "exec", _)) and
    handler.getFile().getRelativePath() = "src/agents/bash-tools.exec.ts" and
    pred = DataFlow::parameterNode(handler.getParameter(1)) and
    call.getContainer() = handler and call.getCalleeName() = "buildInvokeParams" and
    invoke.getContainer() = handler and invoke.getCalleeName() = "callGatewayTool" and
    invoke.getArgument(0).mayHaveStringValue("node.invoke") and
    invoke.getArgument(2) = call and succ = call
  )
}

/** A TinyClaw adapter places options.message into argv before invoking the core spawner. */
private predicate tinyClawSpawnTaintBridge(
  Function root, DataFlow::Node source, DataFlow::CallNode sink, DataFlow::Node sinkArg
) {
  tinyClawToolHandler(root, _, _) and source = DataFlow::parameterNode(root.getParameter(0)) and
  sinkCanonicalId(sink) = "TC-EXTERNAL-AGENT-SPAWN" and sinkArg = sink.getArgument(1) and
  exists(Expr messageRead, DataFlow::CallNode argvPush, DataFlow::CallNode invokeCall,
    Function invoker, Function callback |
    (
      messageRead.(Identifier).getName() = "message"
      or
      messageRead.(PropAccess).getPropertyName() = "message" and
      messageRead.(PropAccess).getBase().(Identifier).getName() = ["opts", "options"]
    ) and
    messageRead.getEnclosingFunction() = root and argvPush.getContainer() = root and
    argvPush.getCalleeName() = "push" and messageRead.getParent*() = argvPush.asExpr() and
    tinyClawStrictEdge(root, invoker, invokeCall) and
    invokeCall.getArgument(1).asExpr().(Identifier).getName() = "args" and
    sink.getContainer() = callback and callback.getEnclosingStmt().getContainer() = invoker
  )
}

/** The delegate task triggers an unfiltered complete tool map at AI SDK dispatch. */
private predicate mercuryAgentExposureTaintBridge(
  Function root, DataFlow::Node source, DataFlow::CallNode sink, DataFlow::Node sinkArg
) {
  mercuryAgentToolHandler(root, "delegate_task", _) and
  source = DataFlow::parameterNode(root.getParameter(0)) and
  sinkCanonicalId(sink) = "MA-SUBAGENT-TOOL-EXPOSURE" and
  controlledSinkArgument(sink, sinkArg, "tool-map") and
  mercuryAgentExposureReachesSink(root, sink, 4, _)
}

/** run_command's command argument is captured by executeCommand's Promise executor. */
private predicate mercuryAgentCommandTaintBridge(
  Function root, DataFlow::Node source, DataFlow::CallNode sink, DataFlow::Node sinkArg
) {
  mercuryAgentToolHandler(root, "run_command", _) and
  source = DataFlow::parameterNode(root.getParameter(0)) and
  sinkCanonicalId(sink) = "MA-PROCESS-SPAWN" and sinkArg = sink.getArgument(0) and
  exists(Function executeCommand, Function callback, DataFlow::CallNode edge |
    mercuryAgentStrictEdge(root, executeCommand, edge) and localTaint(source, edge.getArgument(0)) and
    sink.getContainer() = callback and callback.getEnclosingStmt().getContainer() = executeCommand
  )
}

/** run_command's command argument crosses PermissionManager DI into the approval prompt. */
private predicate mercuryAgentApprovalTaintBridge(
  Function root, DataFlow::Node source, DataFlow::CallNode sink, DataFlow::Node sinkArg
) {
  mercuryAgentToolHandler(root, "run_command", _) and
  source = DataFlow::parameterNode(root.getParameter(0)) and
  sinkCanonicalId(sink) = "MA-COMMAND-APPROVAL" and sinkArg = sink.getArgument(0) and
  exists(Function checkShellCommand, DataFlow::CallNode edge |
    mercuryAgentStrictEdge(root, checkShellCommand, edge) and
    edge.getCalleeName() = "checkShellCommand" and localTaint(source, edge.getArgument(0)) and
    sink.getContainer() = checkShellCommand
  )
}

/** Parsed SKILL.md frontmatter name controls saveSkill's filesystem destination. */
private predicate mercuryAgentSkillPathTaintBridge(
  Function root, DataFlow::Node source, DataFlow::CallNode sink, DataFlow::Node sinkArg
) {
  mercuryAgentToolHandler(root, "install_skill", _) and
  source = DataFlow::parameterNode(root.getParameter(0)) and
  sinkCanonicalId(sink) = "MA-FILE-WRITE" and sinkArg = sink.getArgument(0) and
  exists(Function saveSkill, DataFlow::CallNode saveCall, DataFlow::CallNode parseCall,
    VariableDeclarator meta, PropAccess parsedName |
    mercuryAgentStrictEdge(root, saveSkill, saveCall) and sink.getContainer() = saveSkill and
    parseCall.getContainer() = root and parseCall.getCalleeName() = "parseYaml" and
    localTaint(source, parseCall.getArgument(0)) and meta.getEnclosingFunction() = root and
    meta.getBindingPattern().(Identifier).getName() = "meta" and
    meta.getInit() = parseCall.asExpr() and parsedName = saveCall.getArgument(0).asExpr() and
    parsedName.getPropertyName() = "name" and
    parsedName.getBase().(Identifier).getName() = "meta"
  )
}

/** manage_todo mutators serialize model-derived fields through saveStore. */
private predicate lettaBotTodoWriteTaintBridge(
  Function root, DataFlow::Node source, DataFlow::CallNode sink, DataFlow::Node sinkArg
) {
  lettaBotToolHandler(root, "manage_todo", _) and
  source = DataFlow::parameterNode(root.getParameter(1)) and
  sinkCanonicalId(sink) = "LB-TODO-STORE-WRITE" and sinkArg = sink.getArgument(1) and
  exists(DataFlow::CallNode mutation |
    mutation.getContainer() = root and
    mutation.getCalleeName() = ["addTodo", "completeTodo", "reopenTodo", "removeTodo", "snoozeTodo"]
  )
}

predicate localTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
  succ = pred.getASuccessor() or objectValueStep(pred, succ) or
  propertyReadStep(pred, succ) or derivedCallStep(pred, succ) or
  capturedExecPayloadStep(pred, succ) or remoteResponseStep(pred, succ) or
  mercuryHandlerBindingStep(pred, succ) or droidClawHandlerBindingStep(pred, succ)
}

/** parsePatchText expands the complete patch input into every file operation facet. */
private predicate applyPatchTaintBridge(
  Function root, DataFlow::Node source, DataFlow::CallNode sink, DataFlow::Node sinkArg
) {
  (openClawToolHandler(root, "apply_patch", _) or
    openClawCNToolHandler(root, "apply_patch", _)) and
  root.getFile().getRelativePath() = "src/agents/apply-patch.ts" and
  source = DataFlow::parameterNode(root.getParameter(1)) and
  sink.getLocation().getFile().getRelativePath() = "src/agents/apply-patch.ts" and
  controlledSinkArgument(sink, sinkArg, _) and
  (
    sink.getContainer().(Function).getName() = "applyPatch"
    or
    sinkCanonicalId(sink) = "OCCN-APPLY-PATCH-WRITE" and
    exists(Function callback, Function factory |
      sink.getContainer() = callback and callback.getEnclosingStmt().getContainer() = factory and
      factory.getName() = "resolvePatchFileOps"
    )
  )
}

predicate localTaint(DataFlow::Node source, DataFlow::Node sink) {
  source = sink or localTaintStep+(source, sink)
}

/** Taint from a handler source into a node owned by a bounded downstream function. */
predicate sourceReachesFunctionNode(
  Function root, DataFlow::Node source, Function owner, DataFlow::Node node, int depth
) {
  depth = 0 and owner = root and localTaint(source, node)
  or
  depth = 1 and
  exists(DataFlow::CallNode edge, DataFlow::Node pred, DataFlow::Node succ |
    projectEdgeTaint(root, owner, edge, pred, succ) and localTaint(source, pred) and
    localTaint(succ, node)
  )
  or
  depth = 2 and
  exists(Function first, DataFlow::CallNode firstEdge, DataFlow::CallNode secondEdge,
    DataFlow::Node firstPred, DataFlow::Node firstSucc, DataFlow::Node secondPred,
    DataFlow::Node secondSucc |
    projectEdgeTaint(root, first, firstEdge, firstPred, firstSucc) and
    projectEdgeTaint(first, owner, secondEdge, secondPred, secondSucc) and
    localTaint(source, firstPred) and localTaint(firstSucc, secondPred) and
    localTaint(secondSucc, node)
  )
  or
  depth = 3 and
  exists(Function first, Function second, DataFlow::CallNode firstEdge,
    DataFlow::CallNode secondEdge, DataFlow::CallNode thirdEdge,
    DataFlow::Node firstPred, DataFlow::Node firstSucc, DataFlow::Node secondPred,
    DataFlow::Node secondSucc, DataFlow::Node thirdPred, DataFlow::Node thirdSucc |
    projectEdgeTaint(root, first, firstEdge, firstPred, firstSucc) and
    projectEdgeTaint(first, second, secondEdge, secondPred, secondSucc) and
    projectEdgeTaint(second, owner, thirdEdge, thirdPred, thirdSucc) and
    localTaint(source, firstPred) and localTaint(firstSucc, secondPred) and
    localTaint(secondSucc, thirdPred) and localTaint(thirdSucc, node)
  )
  or
  depth = 4 and
  exists(Function first, Function second, Function third, DataFlow::CallNode firstEdge,
    DataFlow::CallNode secondEdge, DataFlow::CallNode thirdEdge,
    DataFlow::CallNode fourthEdge, DataFlow::Node firstPred, DataFlow::Node firstSucc,
    DataFlow::Node secondPred, DataFlow::Node secondSucc, DataFlow::Node thirdPred,
    DataFlow::Node thirdSucc, DataFlow::Node fourthPred, DataFlow::Node fourthSucc |
    projectEdgeTaint(root, first, firstEdge, firstPred, firstSucc) and
    projectEdgeTaint(first, second, secondEdge, secondPred, secondSucc) and
    projectEdgeTaint(second, third, thirdEdge, thirdPred, thirdSucc) and
    projectEdgeTaint(third, owner, fourthEdge, fourthPred, fourthSucc) and
    localTaint(source, firstPred) and localTaint(firstSucc, secondPred) and
    localTaint(secondSucc, thirdPred) and localTaint(thirdSucc, fourthPred) and
    localTaint(fourthSucc, node)
  )
}

/** A gate dominates the sink itself or the first downstream call leading to it. */
predicate dominatesSinkPath(DataFlow::CallNode gate, Function owner, DataFlow::CallNode sink) {
  gate.getContainer() = owner and sink.getContainer() = owner and
  gate.getBasicBlock().(ReachableBasicBlock).dominates(sink.getBasicBlock())
  or
  gate.getContainer() = owner and
  exists(Function next, DataFlow::CallNode edge, int remaining, string path |
    projectCallEdge(owner, next, edge) and reachesSink(next, sink, remaining, path) and
    gate.getBasicBlock().(ReachableBasicBlock).dominates(edge.getBasicBlock())
  )
}

/**
 * Audited policy routes whose checked object is assembled from derived decision state.
 * The generic local-flow relation does not model these boolean/property summaries.
 */
private predicate auditedPolicyDecisionInput(
  Function handler, DataFlow::CallNode gate, DataFlow::Node checked,
  Function owner, int gateDepth
) {
  gate.getCalleeName() = "requiresExecApproval" and checked = gate.getArgument(0) and
  (
    owner = handler and gate.getContainer() = owner and
    gate.getLocation().getFile().getRelativePath() = "src/agents/bash-tools.exec.ts" and
    gateDepth = 0
    or
    gate.getContainer() = owner and owner.getName() = "handleInvoke" and
    gate.getLocation().getFile().getRelativePath() = "src/node-host/runner.ts" and
    exists(DataFlow::CallNode invoke | nodeInvokeRpcEdge(handler, owner, invoke)) and
    gateDepth = 1
  )
  or
  gate.getCalleeName() = "isSafeBinUsage" and checked = gate.getArgument(0) and
  gate.getLocation().getFile().getRelativePath() = "src/infra/exec-approvals.ts" and
  gate.getLocation().getStartLine() = 986 and gate.getContainer() = owner and
  openClawToolHandler(handler, ["exec", "nodes"], _) and gateDepth = 4
}

/**
 * Policy helpers whose returned decision is checked later by their caller.
 * These are branch gates rather than unconditional dominance gates.
 */
predicate policyDecisionGateForSink(
  Function handler, DataFlow::Node source, DataFlow::CallNode sink,
  DataFlow::Node sinkArg, DataFlow::CallNode gate, DataFlow::Node checked,
  Function owner, int chainDepth, int gateDepth, string path
) {
  (openClawToolHandler(handler, ["exec", "nodes"], _) or
    openClawCNToolHandler(handler, ["exec", "nodes"], _)) and
  controlledSinkArgument(sink, sinkArg, _) and sinkCapability(sink) = "process-spawn" and
  taintReachesSink(handler, source, sink, sinkArg, chainDepth) and
  reachesSink(handler, sink, chainDepth, path) and gate.getContainer() = owner and
  gate.getCalleeName() = [
    "evaluateShellAllowlist", "evaluateExecAllowlist", "evaluateSegments", "isSafeBinUsage",
    "requiresExecApproval"
  ] and
  gate.getLocation().getFile().getRelativePath() = [
    "src/agents/bash-tools.exec.ts", "src/node-host/runner.ts", "src/infra/exec-approvals.ts"
  ] and
  (checked = gate.getAnArgument() or checked = gate.getReceiver()) and
  (
    sourceReachesFunctionNode(handler, source, owner, checked, gateDepth) and
    not dominatesSinkPath(gate, owner, sink)
    or
    auditedPolicyDecisionInput(handler, gate, checked, owner, gateDepth)
  )
}

/** Audited end-to-end taint proof for node.invoke system.run into runner spawn. */
private predicate runnerSpawnTaintBridge(
  Function root, DataFlow::Node source, DataFlow::CallNode sink, DataFlow::Node sinkArg
) {
  exists(Function handleInvoke, Function runCommand, Function callback,
    DataFlow::CallNode invoke, DataFlow::CallNode runCall |
    nodeInvokeRpcEdge(root, handleInvoke, invoke) and
    localTaint(source, invoke.getArgument(2)) and
    strictNamedBridge(handleInvoke, runCommand, runCall) and
    localTaint(
      DataFlow::parameterNode(handleInvoke.getParameter(0)), runCall.getAnArgument()
    ) and
    runnerPromiseCallbackEdge(runCommand, callback, sink) and
    controlledSinkArgument(sink, sinkArg, _)
  )
}

/** Source-taint witnesses for the fork's audited RPC/callback/plugin bridges. */
private predicate openClawCNTaintBridge(
  Function root, DataFlow::Node source, DataFlow::CallNode sink, DataFlow::Node sinkArg,
  int depth
) {
  openClawCNToolHandler(root, "browser", _) and handlerSource(root, source, _) and
  controlledSinkArgument(sink, sinkArg, _) and
  (
    openClawCNBrowserBridgeShape(sink, "act") and depth = 5 and
    exists(DataFlow::CallNode boundary |
      boundary.getContainer() = root and boundary.getCalleeName() = "browserAct" and
      localTaint(source, boundary.getArgument(1))
    )
    or
    openClawCNBrowserBridgeShape(sink, "navigate") and depth = 5 and
    exists(DataFlow::CallNode boundary |
      boundary.getContainer() = root and boundary.getCalleeName() = "browserNavigate" and
      localTaint(source, boundary.getArgument(1))
    )
    or
    openClawCNBrowserBridgeShape(sink, "open") and depth = 6 and
    exists(DataFlow::CallNode boundary |
      boundary.getContainer() = root and boundary.getCalleeName() = "browserOpenTab" and
      localTaint(source, boundary.getArgument(1))
    )
  )
  or
  openClawCNToolHandler(root, "message", _) and handlerSource(root, source, _) and
  controlledSinkArgument(sink, sinkArg, "url") and openClawCNFeishuBridgeShape(sink) and
  exists(DataFlow::CallNode boundary, ObjectExpr payload |
    boundary.getContainer() = root and boundary.getCalleeName() = "runMessageAction" and
    payload = boundary.getArgument(0).asExpr() and
    localTaint(source, payload.getPropertyByName("params").getInit().flow())
  ) and depth = 8
}

predicate taintReachesSink(
  Function root, DataFlow::Node source, DataFlow::CallNode sink, DataFlow::Node sinkArg,
  int depth
) {
  exists(Function owner, int functionDepth |
    sink.getContainer() = owner and
    sourceReachesFunctionNode(root, source, owner, sinkArg, functionDepth) and
    depth = functionDepth + 1
  )
  or
  applyPatchTaintBridge(root, source, sink, sinkArg) and
  (
    openClawToolHandler(root, "apply_patch", _) and depth = 2
    or
    openClawCNToolHandler(root, "apply_patch", _) and depth = 3
  )
  or
  depth = 4 and runnerSpawnTaintBridge(root, source, sink, sinkArg)
  or
  openClawCNTaintBridge(root, source, sink, sinkArg, depth)
  or
  exists(DataFlow::CallNode outbound |
    isNanoClawProject() and nanoClawOutboundSource(root, source, outbound, _) and
    controlledSinkArgument(sink, sinkArg, _) and
    nanoClawReachesSink(root, sink, depth, _)
  )
  or
  depth = 11 and
  exists(DataFlow::CallNode boundary |
    lobsterAIClientBoundary(root, source, boundary) and
    controlledSinkArgument(sink, sinkArg, "url") and
    lobsterAIReachesSink(root, sink, depth, _)
  )
  or
  depth = 2 and tinyClawSpawnTaintBridge(root, source, sink, sinkArg)
  or
  depth = 4 and mercuryAgentExposureTaintBridge(root, source, sink, sinkArg)
  or
  depth = 2 and mercuryAgentCommandTaintBridge(root, source, sink, sinkArg)
  or
  depth = 2 and mercuryAgentApprovalTaintBridge(root, source, sink, sinkArg)
  or
  depth = 2 and mercuryAgentSkillPathTaintBridge(root, source, sink, sinkArg)
  or
  depth = 3 and lettaBotTodoWriteTaintBridge(root, source, sink, sinkArg)
}

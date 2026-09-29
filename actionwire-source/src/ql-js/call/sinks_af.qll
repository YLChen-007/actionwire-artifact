/** Project-neutral JavaScript/TypeScript dangerous sinks and controlled facets. */

import javascript
import project.ProjectModel

private predicate moduleCall(DataFlow::CallNode call, string moduleName, string member) {
  call = API::moduleImport(moduleName).getMember(member).getACall()
}

private predicate anyModuleCall(DataFlow::CallNode call, string family, string member) {
  family = "child_process" and
  moduleCall(call, ["child_process", "node:child_process"], member)
  or
  family = "fs" and moduleCall(call, ["fs", "node:fs"], member)
  or
  family = "fs.promises" and
  (
    moduleCall(call, ["fs/promises", "node:fs/promises"], member)
    or
    call = API::moduleImport(["fs", "node:fs"]).getMember("promises").getMember(member).getACall()
  )
}

bindingset[marker]
private predicate sqlTemplateContains(DataFlow::CallNode prepare, string marker) {
  exists(TemplateLiteral template, TemplateElement element |
    template = prepare.getArgument(0).asExpr() and element = template.getAnElement() and
    element.getValue().matches("%" + marker + "%")
  )
  or
  prepare.getArgument(0).mayHaveStringValue("%" + marker + "%")
}

/** The call is owned by a callback nested directly in a wrapper/factory. */
private predicate callbackOwner(DataFlow::CallNode call, Function owner) {
  exists(Function callback |
    call.getContainer() = callback and callback.getEnclosingStmt().getContainer() = owner
  )
}

/** The call occurs in a returned tool callback owned by a literal factory signature. */
private predicate callOwnedByFactory(DataFlow::CallNode call, string factoryName) {
  exists(Function callback, Function factory |
    call.getContainer() = callback and callback.getEnclosingStmt().getContainer() = factory and
    factory.getName() = factoryName
  )
}

private predicate externalCliSpawnShape(DataFlow::CallNode call) {
  anyModuleCall(call, "child_process", "spawn") and
  exists(Function invoker |
    callbackOwner(call, invoker) and
    (
      invoker.getName() = "runCommand" and invoker.getNumParameter() = 4 and
      invoker.getParameter(0).getName() = "command" and
      invoker.getParameter(1).getName() = "args" and
      invoker.getParameter(2).getName() = "cwd" and
      invoker.getParameter(3).getName() = "envOverrides"
      or
      invoker.getName() = "runCommandStreaming" and invoker.getNumParameter() = 6 and
      invoker.getParameter(0).getName() = "command" and
      invoker.getParameter(1).getName() = "args" and
      invoker.getParameter(2).getName() = "onLine" and
      invoker.getParameter(3).getName() = "cwd" and
      invoker.getParameter(4).getName() = "envOverrides" and
      invoker.getParameter(5).getName() = "agentId"
    )
  )
}

private predicate commandExecutorSpawnShape(DataFlow::CallNode call) {
  anyModuleCall(call, "child_process", "spawn") and
  exists(Function executeCommand |
    callbackOwner(call, executeCommand) and executeCommand.getName() = "executeCommand" and
    executeCommand.getNumParameter() = 3 and
    executeCommand.getParameter(0).getName() = "command" and
    executeCommand.getParameter(1).getName() = "cwd" and
    executeCommand.getParameter(2).getName() = "timeoutMs"
  )
}

/** Mercury's command text enters the user-consent callback selected by checkShellCommand. */
private predicate mercuryCommandApprovalShape(DataFlow::CallNode call) {
  call.getCalleeName() = "askHandler" and call.getReceiver().toString() = "this" and
  exists(Function checkShellCommand |
    call.getContainer() = checkShellCommand and checkShellCommand.getName() = "checkShellCommand" and
    checkShellCommand.getNumParameter() = 1 and
    checkShellCommand.getParameter(0).getName() = "command"
  )
}

private predicate nodeHostSpawnShape(DataFlow::CallNode call) {
  call.getCalleeName() = "spawn" and
  exists(Function runCommand |
    callbackOwner(call, runCommand) and runCommand.getName() = "runCommand" and
    runCommand.getNumParameter() = 4 and runCommand.getParameter(0).getName() = "argv" and
    runCommand.getParameter(1).getName() = "cwd" and
    runCommand.getParameter(2).getName() = "env" and
    runCommand.getParameter(3).getName() = "timeoutMs"
  )
}

private predicate applyPatchWriteShape(DataFlow::CallNode call) {
  anyModuleCall(call, "fs.promises", "writeFile") and
  exists(Function factory |
    callbackOwner(call, factory) and factory.getName() = "resolvePatchFileOps" and
    factory.getNumParameter() = 1 and factory.getParameter(0).getName() = "options"
  )
}

private predicate browserJsonFetchShape(DataFlow::CallNode call) {
  call.getCalleeName() = "fetch" and
  exists(Function fetchJson, ExportNamedDeclaration exportDecl |
    call.getContainer() = fetchJson and fetchJson.getName() = "fetchJson" and
    fetchJson.getNumParameter() = 3 and fetchJson.getParameter(0).getName() = "url" and
    fetchJson.getParameter(1).getName() = "timeoutMs" and
    fetchJson.getParameter(2).getName() = "init" and exportDecl.getOperand() = fetchJson
  ) and
  call.getArgument(0).toString() = "url"
}

private predicate feishuMediaFetchShape(DataFlow::CallNode call) {
  call.getCalleeName() = "fetch" and call.getContainer().(Function).getName() = "sendMediaFeishu" and
  call.getContainer().(Function).getNumParameter() = 1 and
  call.getContainer().(Function).getParameter(0).getName() = "params" and
  call.getArgument(0).toString() = "mediaUrl"
}

private predicate capabilityFactoryCall(DataFlow::CallNode call, string factoryName) {
  callOwnedByFactory(call, factoryName)
}

/** Shared source hygiene: sink shapes apply to production code in every project. */
private predicate isProductionSinkCall(DataFlow::CallNode call) {
  exists(string path |
    path = call.getLocation().getFile().getRelativePath() and
    not path.matches("%.test.%") and not path.matches("%.spec.%") and
    not path.matches("%/tests/%") and not path.matches("tests/%") and
    not path.matches("%/node_modules/%") and not path.matches("node_modules/%") and
    not path.matches("%/dist/%") and not path.matches("dist/%")
  )
}

/** Lower-level Node calls inside pinned Letta Code handlers are semantic witnesses, not report labels. */
private predicate lettaBotVendoredPrimitiveCall(DataFlow::CallNode call) {
  isLettaBotProject() and
  (
    call.getLocation().getFile().getRelativePath() =
      "vendor-source/letta-code-v0.19.5/src/tools/impl/Bash.ts" and
    anyModuleCall(call, "child_process", [
      "spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"
    ])
    or
    call.getLocation().getFile().getRelativePath() =
      "vendor-source/letta-code-v0.19.5/src/tools/impl/Read.ts" and
    anyModuleCall(call, ["fs", "fs.promises"], [
      "readFile", "readFileSync", "open", "openSync"
    ])
    or
    call.getLocation().getFile().getRelativePath() =
      "vendor-source/letta-code-v0.19.5/src/tools/impl/Edit.ts" and
    anyModuleCall(call, ["fs", "fs.promises"], [
      "readFile", "readFileSync", "open", "openSync", "writeFile", "writeFileSync",
      "appendFile", "appendFileSync"
    ])
    or
    call.getLocation().getFile().getRelativePath() =
      "vendor-source/letta-code-v0.19.5/src/tools/impl/Write.ts" and
    anyModuleCall(call, ["fs", "fs.promises"], [
      "writeFile", "writeFileSync", "appendFile", "appendFileSync"
    ])
  )
}

/** Shared Node primitives plus strict literal RPC and external-tool boundaries. */
private predicate nodeAndBoundarySinkDefinition(
  DataFlow::CallNode call, string canonicalId, string label, string capability,
  string boundaryKind
) {
  (
  // OpenClaw exec/node command-spawn variants; duplicate reports share this canonical rule.
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/new-vuls/Advirsory-GHSA-3h2q-j2v4-6w5r.json
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/new-vuls/Advirsory-GHSA-48wf-g7cp-gr3m.json
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/new-vuls/CVE-2026-29607-variant.json
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/new-vuls/jq-env-safebins-bypass.json
  anyModuleCall(call, "child_process", [
    "spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"
  ]) and not externalCliSpawnShape(call) and not commandExecutorSpawnShape(call) and
  not nodeHostSpawnShape(call) and not lettaBotVendoredPrimitiveCall(call) and
  canonicalId = "OC-PROCESS-CHILD-PROCESS" and label = call.getCalleeName() and
  capability = "process-spawn" and boundaryKind = "in-process"
  or
  // GHSA-jq4x-98m3-ggq6: model-controlled Canvas path reaches a Node file-read primitive.
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/exist-vuls/Advisory-GHSA-jq4x-98m3-ggq6.json
  anyModuleCall(call, ["fs", "fs.promises"], ["readFile", "readFileSync", "open", "openSync"]) and
  not capabilityFactoryCall(call, ["createReadFileTool", "createEditFileTool"]) and
  not lettaBotVendoredPrimitiveCall(call) and
  not (
    call.getContainer().(Function).getName() = "loadStore" and
    call.getContainer().(Function).getNumParameter() = 1
  ) and
  canonicalId = "OC-FILE-READ" and label = call.getCalleeName() and
  capability = "file-read" and boundaryKind = "in-process"
  or
  // GHSA-qcc4-p59m-p54m: apply_patch path alias escape reaches a Node file-write primitive.
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/exist-vuls/Advisory-GHSA-qcc4-p59m-p54m.json
  anyModuleCall(call, ["fs", "fs.promises"], [
    "writeFile", "writeFileSync", "appendFile", "appendFileSync"
  ]) and not applyPatchWriteShape(call) and
  not lettaBotVendoredPrimitiveCall(call) and
  not capabilityFactoryCall(call, [
    "createCreateFileTool", "createWriteFileTool", "createEditFileTool"
  ]) and
  not (
    call.getContainer().(Function).getName() = ["saveSkill", "saveStore"] and
    call.getContainer().(Function).getNumParameter() = 2
  ) and
  canonicalId = "OC-FILE-WRITE" and label = call.getCalleeName() and
  capability = "file-write" and boundaryKind = "in-process"
  or
  // GHSA-qcc4-p59m-p54m: capability-complete delete sibling for the same apply_patch path.
  // The report's minimum d5 sink witness is writeFile; this branch covers delete hunks.
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/exist-vuls/Advisory-GHSA-qcc4-p59m-p54m.json
  anyModuleCall(call, ["fs", "fs.promises"], [
    "rm", "rmSync", "unlink", "unlinkSync", "rmdir", "rmdirSync"
  ]) and not capabilityFactoryCall(call, "createDeleteFileTool") and
  canonicalId = "OC-FILE-DELETE" and label = call.getCalleeName() and
  capability = "file-delete" and boundaryKind = "in-process"
  or
  // GHSA-56f2-hvwg-5743: model-controlled URL reaches the JavaScript fetch capability.
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/exist-vuls/Advisory-GHSA-56f2-hvwg-5743.json
  call.getCalleeName() = "fetch" and not browserJsonFetchShape(call) and
  not feishuMediaFetchShape(call) and
  not capabilityFactoryCall(call, ["createFetchUrlTool", "createInstallSkillTool"]) and
  not (
    call.getContainer().(Function).getName() = "githubRequest" and
    call.getContainer().(Function).getNumParameter() = 2
  ) and
  canonicalId = "OC-NETWORK-FETCH" and label = "fetch" and capability = "network-egress" and
  boundaryKind = "in-process"
  or
  // CVE-2026-29609 error-path variant: unbounded error-body consumption via Response.text.
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/new-vuls/CVE-2026-29609-error-path-variant.json
  call.getCalleeName() = "text" and
  call.getContainer().(Function).getName() = "readErrorBodySnippet" and
  canonicalId = "OC-RESOURCE-RESPONSE-TEXT" and label = "Response.text" and
  capability = "resource-consumption" and boundaryKind = "in-process"
  or
  // GHSA-h9g4-589h-68xv: unauthenticated browser bridge exposes tab-open navigation.
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/exist-vuls/Advisory-GHSA-h9g4-589h-68xv.json
  call.getCalleeName() = "browserOpenTab" and call.getNumArgument() = [2, 3] and
  call.getArgument(1).toString() = "targetUrl" and
  callOwnedByFactory(call, "createBrowserTool") and
  canonicalId = "OC-BROWSER-OPEN" and label = "browserOpenTab" and
  capability = "browser-navigation" and boundaryKind = "core-boundary"
  or
  // GHSA-h9g4-589h-68xv: core browser tool delegates /tabs/open to the browser component.
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/exist-vuls/Advisory-GHSA-h9g4-589h-68xv.json
  call.getCalleeName() = "proxyRequest" and call.getNumArgument() = 1 and
  callOwnedByFactory(call, "createBrowserTool") and
  call.getArgument(0).asExpr().(ObjectExpr).getPropertyByName("path").getInit().getStringValue() =
    "/tabs/open" and
  canonicalId = "OC-BROWSER-PROXY-OPEN" and label = "proxyRequest:/tabs/open" and
  capability = "browser-navigation" and boundaryKind = "rpc-boundary"
  or
  // CVE-2026-27158: message action crosses the plugin boundary to an outbound delivery sink.
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/exist-vuls/CVE-2026-27158.json
  call.getCalleeName() = "runMessageAction" and call.getNumArgument() = 1 and
  callOwnedByFactory(call, "createMessageTool") and
  canonicalId = "OC-DELIVERY-MESSAGE-ACTION" and label = "runMessageAction" and
  capability = "delivery" and boundaryKind = "plugin-boundary"
  or
  // Synthetic revision-overlay witness for the existing-session Chrome MCP path.
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/new-vuls/Advisory-GHSA-527m-976r-jf79-dataflow-wait-fn-existing-session.json
  // The production v2026.2.1 snapshot does not contain extensions/browser; the
  // dedicated qltest fixture proves the exact handler-to-RPC sink contract.
  isOpenClawProject() and call.getCalleeName() = "callTool" and
  call.getContainer().(Function).getName() = "callTool" and
  call.getLocation().getFile().getRelativePath() =
    "extensions/browser/src/browser/chrome-mcp.ts" and
  canonicalId = "OC-BROWSER-CHROME-MCP-CALL" and label = "Chrome MCP client.callTool" and
  capability = "rpc-boundary" and boundaryKind = "browser-rpc"
  or
  // CVE-2026-29610 and the exec variant use node.invoke before node-host process execution.
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/exist-vuls/CVE-2026-29610.json
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/new-vuls/CVE-2026-29607-variant.json
  call.getCalleeName() = "callGatewayTool" and
  call.getArgument(0).mayHaveStringValue("node.invoke") and
  canonicalId = "OC-RPC-NODE-INVOKE" and label = "callGatewayTool:node.invoke" and
  capability = "rpc-node-invoke" and boundaryKind = "rpc-boundary"
  or
  // GHSA-2hm8-rqrm-xfjq: tool-controlled gateway invocation reaches owner-only capabilities.
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/exist-vuls/Advisory-GHSA-2hm8-rqrm-xfjq.json
  call.getCalleeName() = "callGatewayTool" and
  call.getArgument(0).mayHaveStringValue([
    "config.get", "config.schema", "config.apply", "config.patch", "update.run",
    "cron.status", "cron.list", "cron.add", "cron.update", "cron.remove", "cron.run",
    "cron.runs", "wake"
  ]) and
  canonicalId = "OC-RPC-GATEWAY-METHOD" and
  label = "callGatewayTool:" + call.getArgument(0).getStringValue() and
  capability = "rpc-boundary" and boundaryKind = "rpc-boundary"
  or
  // External coding-tool file capability boundary used by read/write/edit wrappers.
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/exist-vuls/Advisory-GHSA-3jx4-q2m7-r496.json
  // source: /root/my-project/agent-research/clawgap/design/openclaw/groundtruth/exist-vuls/Advisory-GHSA-qcc4-p59m-p54m.json
  call.getCalleeName() = "execute" and
  call.getReceiver().asExpr().(Identifier).getName() = ["tool", "base"] and
  canonicalId = "OC-EXTERNAL-PI-TOOL" and label = call.getReceiver().toString() + ".execute" and
  exists(Function wrapper |
    call.getContainer().(Function).getEnclosingStmt().getContainer() = wrapper and
  (
      wrapper.getName() = "createOpenClawReadTool" and capability = "file-read"
    or
      wrapper.getName() = ["wrapToolParamNormalization", "wrapSandboxPathGuard"] and
      capability = "file-write"
    )
  ) and
  boundaryKind = "excluded-boundary"
  )
}

/** Shared browser/runtime shapes; legacy IDs remain stable artifact identifiers. */
private predicate browserAndRuntimeSinkDefinition(
  DataFlow::CallNode call, string canonicalId, string label, string capability,
  string boundaryKind
) {
  (
    // Playwright evaluation receives the model-selected function text in argument 1.
    call.getCalleeName() = "evaluate" and call.getReceiver().toString() = ["page", "locator"] and
    call.getContainer().(Function).getName() = "evaluateViaPlaywright" and
    call.getContainer().(Function).getNumParameter() = 1 and
    call.getContainer().(Function).getParameter(0).getName() = "opts" and
    call.getArgument(1).toString() = "fnText" and
    canonicalId = "OCCN-BROWSER-EVALUATE" and
    label = call.getReceiver().toString() + ".evaluate" and capability = "code-eval" and
    boundaryKind = "browser-runtime"
    or
    // The locator is derived from the LLM-selected snapshot ref.
    call.getCalleeName() = ["click", "dblclick"] and call.getReceiver().toString() = "locator" and
    call.getContainer().(Function).getName() = "clickViaPlaywright" and
    call.getContainer().(Function).getNumParameter() = 1 and
    call.getContainer().(Function).getParameter(0).getName() = "opts" and
    canonicalId = "OCCN-BROWSER-INTERACTION" and
    label = "locator." + call.getCalleeName() and capability = "browser-interaction" and
    boundaryKind = "browser-runtime"
    or
    // Direct browser navigation has two audited owners in the pinned fork.
    call.getCalleeName() = "goto" and call.getReceiver().toString() = "page" and
    call.getContainer().(Function).getName() = [
      "navigateViaPlaywright", "createPageViaPlaywright"
    ] and call.getContainer().(Function).getNumParameter() = 1 and
    call.getContainer().(Function).getParameter(0).getName() = "opts" and
    canonicalId = "OCCN-BROWSER-PAGE-GOTO" and label = "page.goto" and
    capability = "browser-navigation" and boundaryKind = "browser-runtime"
    or
    // CDP tab creation is constrained by both literal action and payload field.
    call.getCalleeName() = "send" and
    call.getArgument(0).mayHaveStringValue("Target.createTarget") and
    exists(ObjectExpr payload |
      payload = call.getArgument(1).asExpr() and
      payload.getPropertyByName("url").getInit().toString() = "opts.url"
    ) and
    call.getContainer().(Function).getEnclosingStmt().getContainer().(Function).getName() =
      "createTargetViaCdp" and
    canonicalId = "OCCN-BROWSER-CDP-CREATE-TARGET" and
    label = "CDP.Target.createTarget" and capability = "browser-navigation" and
    boundaryKind = "browser-rpc"
    or
    // The /json/new fallback is the URL facet entering the audited fetchJson primitive.
    browserJsonFetchShape(call) and
    canonicalId = "OCCN-BROWSER-JSON-NEW" and label = "fetch:/json/new" and
    capability = "browser-navigation" and boundaryKind = "browser-http"
    or
    // Node-host system.run terminates at the imported child_process spawn.
    nodeHostSpawnShape(call) and
    canonicalId = "OCCN-NODE-HOST-SPAWN" and label = "child_process.spawn:node-host" and
    capability = "process-spawn" and boundaryKind = "in-process"
    or
    // Gateway non-PTY execution uses an injected spawn with a typed argv/options signature.
    call.getCalleeName() = "spawnImpl" and
    call.getContainer().(Function).getName() = "spawnAndWaitForSpawn" and
    call.getContainer().(Function).getNumParameter() = 3 and
    call.getContainer().(Function).getParameter(0).getName() = "spawnImpl" and
    call.getContainer().(Function).getParameter(1).getName() = "argv" and
    call.getContainer().(Function).getParameter(2).getName() = "options" and
    canonicalId = "OCCN-GATEWAY-SPAWN" and label = "spawnImpl" and
    capability = "process-spawn" and boundaryKind = "dependency-injection"
    or
    // Dynamic @lydell/node-pty loading is accepted only in runExecProcess's PTY branch.
    call.getCalleeName() = "spawnPty" and
    call.getContainer().(Function).getName() = "runExecProcess" and
    call.getContainer().(Function).getNumParameter() = 1 and
    call.getContainer().(Function).getParameter(0).getName() = "opts" and
    call.getArgument(1).asExpr().(ArrayExpr).getAnElement().toString() = "opts.command" and
    canonicalId = "OCCN-GATEWAY-PTY-SPAWN" and label = "node-pty.spawn" and
    capability = "process-spawn" and boundaryKind = "dynamic-module"
    or
    // apply_patch resolves PatchFileOps before invoking this fs.promises callback.
    applyPatchWriteShape(call) and
    canonicalId = "OCCN-APPLY-PATCH-WRITE" and label = "fs.writeFile:apply-patch" and
    capability = "file-write" and boundaryKind = "callback"
    or
    // Feishu is the sole extension exception; a generic fetch elsewhere is not admitted.
    feishuMediaFetchShape(call) and
    canonicalId = "OCCN-FEISHU-MEDIA-FETCH" and label = "fetch:feishu-media" and
    capability = "network-egress" and boundaryKind = "plugin-extension"
  )
}

/** Shared file-copy, SQLite mutation, and approval-presentation shapes. */
private predicate persistenceAndApprovalSinkDefinition(
  DataFlow::CallNode call, string canonicalId, string label, string capability,
  string boundaryKind
) {
  (
    // CVE-2026-29611 and GHSA-qcc4-p59m-p54m: concrete Node file-copy primitive.
    // Match the imported fs API plus its source/destination arguments, independent of callsite file.
    // source: /root/my-project/agent-research/clawgap/design/nanoclaw/groundtruth/new-vuls/CVE-2026-29611-nanoclaw-send-file.json
    // source: /root/my-project/agent-research/clawgap/design/nanoclaw/groundtruth/new-vuls/Advisory-GHSA-qcc4-p59m-p54m-a2a-inbox-symlink.json
    anyModuleCall(call, "fs", "copyFileSync") and
    exists(DataFlow::Node sourcePath, DataFlow::Node destinationPath |
      sourcePath = call.getArgument(0) and destinationPath = call.getArgument(1)
    ) and
    canonicalId = "NC-FILE-COPY" and label = "copyFileSync" and
    capability = "file-copy" and boundaryKind = "in-process"
    or
    // The payload hidden from the approval question is persisted here.
    // source: /root/my-project/agent-research/clawgap/design/nanoclaw/groundtruth/new-vuls/Advisory-GHSA-6rcp-vxwf-3mfp-add-mcp-server-approval-smuggling.json
    // source: /root/my-project/agent-research/clawgap/design/nanoclaw/groundtruth/new-vuls/CVE-2026-31993-add-mcp-server-approval-smuggling.json
    call.getCalleeName() = "run" and
    call.getContainer().(Function).getName() = "createPendingApproval" and
    call.getContainer().(Function).getNumParameter() >= 1 and
    exists(DataFlow::CallNode prepare |
      prepare.getContainer() = call.getContainer() and prepare.getCalleeName() = "prepare" and
      sqlTemplateContains(prepare, "pending_approvals")
    ) and
    canonicalId = "NC-APPROVAL-PERSIST" and label = "Statement.run:pending_approvals" and
    capability = "approval-persistence" and boundaryKind = "in-process"
    or
    // Approved MCP command/argv/env are committed to the runtime config here.
    // source: /root/my-project/agent-research/clawgap/design/nanoclaw/groundtruth/new-vuls/Advisory-GHSA-6rcp-vxwf-3mfp-add-mcp-server-approval-smuggling.json
    call.getCalleeName() = "run" and
    call.getContainer().(Function).getName() = "updateContainerConfigJson" and
    call.getContainer().(Function).getNumParameter() >= 1 and
    exists(DataFlow::CallNode prepare |
      prepare.getContainer() = call.getContainer() and prepare.getCalleeName() = "prepare" and
      sqlTemplateContains(prepare, "container_configs")
    ) and
    canonicalId = "NC-CONFIG-MUTATION" and label = "Statement.run:container_configs" and
    capability = "runtime-config-mutation" and boundaryKind = "in-process"
    or
    // The concrete channel implementations live outside the trunk snapshot; stop at the
    // capability-explicit approval-card delivery boundary.
    // source: /root/my-project/agent-research/clawgap/design/nanoclaw/groundtruth/new-vuls/CVE-2026-31993-add-mcp-server-approval-smuggling.json
    call.getCalleeName() = "deliver" and
    call.getReceiver().asExpr().(Identifier).getName() = "adapter" and
    call.getContainer().(Function).getName() = "requestApproval" and
    call.getArgument(3).mayHaveStringValue("chat-sdk") and
    canonicalId = "NC-APPROVAL-PRESENT" and label = "adapter.deliver:approval-card" and
    capability = "approval-presentation" and boundaryKind = "excluded-boundary"
  )
}

/** A NanoClaw system action must have a literal host-side registry consumer. */
bindingset[action]
private predicate nanoClawRegisteredDeliveryAction(string action) {
  exists(DataFlow::CallNode registration |
    registration.getCalleeName() = "registerDeliveryAction" and
    registration.getArgument(0).mayHaveStringValue(action)
  )
}

/** NanoClaw's host installs a channel adapter that owns outbound delivery. */
private predicate nanoClawChannelDeliveryBoundary() {
  exists(Function factory |
    factory.getName() = "createChannelDeliveryAdapter" and
    factory.getFile().getRelativePath() = "src/channels/channel-registry.ts"
  )
}

/** Extract the JSON object persisted by one handler's `writeMessageOut` call. */
private predicate nanoClawOutboundPayload(
  DataFlow::CallNode call, string kind, ObjectExpr payload
) {
  call.getCalleeName() = "writeMessageOut" and call.getNumArgument() = 1 and
  exists(ObjectExpr envelope, Property content, DataFlow::CallNode stringify |
    envelope = call.getArgument(0).asExpr() and
    envelope.getPropertyByName("kind").getInit().mayHaveStringValue(kind) and
    content = envelope.getPropertyByName("content") and
    stringify = content.getInit().flow() and stringify.getCalleeName() = "stringify" and
    payload = stringify.getArgument(0).asExpr()
  )
}

/** One registered source-bearing handler and its capability-bearing local witness. */
private predicate nanoClawSemanticActionCall(
  DataFlow::CallNode call, string toolName, string canonicalId, string capability
) {
  isNanoClawProject() and
  exists(Function handler |
    nanoClawToolHandler(handler, toolName, _) and call.getContainer() = handler and
    handler.getNumParameter() = 1 and handler.getParameter(0).getName() = "args" and
    (
      toolName = "list_tasks" and call.getCalleeName() = "getInboundDb" and
      canonicalId = "NC-ACTION-LIST-TASKS" and capability = "task-read"
      or
      exists(ObjectExpr payload |
        nanoClawOutboundPayload(call, "chat", payload) and nanoClawChannelDeliveryBoundary() and
        (
          toolName = "send_message" and
          payload.getPropertyByName("text").getName() = "text" and
          not exists(payload.getPropertyByName("files")) and
          not exists(payload.getPropertyByName("operation")) and
          canonicalId = "NC-ACTION-SEND-MESSAGE" and capability = "message-delivery"
          or
          toolName = "send_file" and payload.getPropertyByName("files").getName() = "files" and
          canonicalId = "NC-ACTION-SEND-FILE" and capability = "file-delivery"
          or
          toolName = "edit_message" and
          payload.getPropertyByName("operation").getInit().mayHaveStringValue("edit") and
          canonicalId = "NC-ACTION-EDIT-MESSAGE" and capability = "message-edit"
          or
          toolName = "add_reaction" and
          payload.getPropertyByName("operation").getInit().mayHaveStringValue("reaction") and
          canonicalId = "NC-ACTION-ADD-REACTION" and capability = "message-reaction"
        )
      )
      or
      exists(ObjectExpr payload |
        nanoClawOutboundPayload(call, "chat-sdk", payload) and
        nanoClawChannelDeliveryBoundary() and
        (
          toolName = "ask_user_question" and
          payload.getPropertyByName("type").getInit().mayHaveStringValue("ask_question") and
          canonicalId = "NC-ACTION-ASK-USER-QUESTION" and capability = "interactive-question"
          or
          toolName = "send_card" and
          payload.getPropertyByName("type").getInit().mayHaveStringValue("card") and
          canonicalId = "NC-ACTION-SEND-CARD" and capability = "card-delivery"
        )
      )
      or
      exists(ObjectExpr payload, string action |
        nanoClawOutboundPayload(call, "system", payload) and
        payload.getPropertyByName("action").getInit().mayHaveStringValue(action) and
        nanoClawRegisteredDeliveryAction(action) and
        (
          toolName = "create_agent" and action = "create_agent" and
          canonicalId = "NC-ACTION-CREATE-AGENT" and capability = "agent-creation"
          or
          toolName = "schedule_task" and action = "schedule_task" and
          canonicalId = "NC-ACTION-SCHEDULE-TASK" and capability = "task-scheduling"
          or
          toolName = "cancel_task" and action = "cancel_task" and
          canonicalId = "NC-ACTION-CANCEL-TASK" and capability = "task-cancel"
          or
          toolName = "pause_task" and action = "pause_task" and
          canonicalId = "NC-ACTION-PAUSE-TASK" and capability = "task-pause"
          or
          toolName = "resume_task" and action = "resume_task" and
          canonicalId = "NC-ACTION-RESUME-TASK" and capability = "task-resume"
          or
          toolName = "update_task" and action = "update_task" and
          canonicalId = "NC-ACTION-UPDATE-TASK" and capability = "task-update"
          or
          toolName = "install_packages" and action = "install_packages" and
          canonicalId = "NC-ACTION-INSTALL-PACKAGES" and capability = "package-installation"
          or
          toolName = "add_mcp_server" and action = "add_mcp_server" and
          canonicalId = "NC-ACTION-ADD-MCP-SERVER" and capability = "mcp-server-registration"
        )
      )
    )
  )
}

/** Named semantic boundary; generic DB/message primitives stay physical witnesses only. */
private predicate nanoClawSemanticSinkDefinition(
  DataFlow::CallNode call, string canonicalId, string label, string capability,
  string boundaryKind
) {
  nanoClawSemanticActionCall(call, label, canonicalId, capability) and
  boundaryKind = "semantic-action"
}

/** Model-controlled facets advertised by each NanoClaw handler. */
private predicate nanoClawSemanticFacet(string canonicalId, string facet) {
  canonicalId = [
    "NC-ACTION-CREATE-AGENT", "NC-ACTION-SEND-MESSAGE", "NC-ACTION-SEND-FILE",
    "NC-ACTION-EDIT-MESSAGE", "NC-ACTION-ADD-REACTION", "NC-ACTION-ASK-USER-QUESTION",
    "NC-ACTION-SEND-CARD", "NC-ACTION-SCHEDULE-TASK", "NC-ACTION-LIST-TASKS",
    "NC-ACTION-CANCEL-TASK", "NC-ACTION-PAUSE-TASK", "NC-ACTION-RESUME-TASK",
    "NC-ACTION-UPDATE-TASK", "NC-ACTION-INSTALL-PACKAGES", "NC-ACTION-ADD-MCP-SERVER"
  ] and facet = "tool.action"
  or
  canonicalId = "NC-ACTION-CREATE-AGENT" and facet = ["name", "instructions"]
  or
  canonicalId = "NC-ACTION-SEND-MESSAGE" and facet = ["to", "text"]
  or
  canonicalId = "NC-ACTION-SEND-FILE" and facet = ["to", "path", "text", "filename"]
  or
  canonicalId = "NC-ACTION-EDIT-MESSAGE" and facet = ["messageId", "text"]
  or
  canonicalId = "NC-ACTION-ADD-REACTION" and facet = ["messageId", "emoji"]
  or
  canonicalId = "NC-ACTION-ASK-USER-QUESTION" and
  facet = ["title", "question", "options", "timeout"]
  or
  canonicalId = "NC-ACTION-SEND-CARD" and facet = ["card", "fallbackText"]
  or
  canonicalId = "NC-ACTION-SCHEDULE-TASK" and
  facet = ["prompt", "processAfter", "recurrence", "script"]
  or
  canonicalId = "NC-ACTION-LIST-TASKS" and facet = "status"
  or
  canonicalId = ["NC-ACTION-CANCEL-TASK", "NC-ACTION-PAUSE-TASK", "NC-ACTION-RESUME-TASK"] and
  facet = "taskId"
  or
  canonicalId = "NC-ACTION-UPDATE-TASK" and
  facet = ["taskId", "prompt", "processAfter", "recurrence", "script"]
  or
  canonicalId = "NC-ACTION-INSTALL-PACKAGES" and facet = ["apt", "npm", "reason"]
  or
  canonicalId = "NC-ACTION-ADD-MCP-SERVER" and facet = ["name", "command", "args", "env"]
}

private predicate guardedPageGotoSinkDefinition(
  DataFlow::CallNode call, string canonicalId, string label, string capability,
  string boundaryKind
) {
  // GHSA-53vx-pmqw-863c: the model-controlled URL reaches the lowest concrete
  // in-process host-browser navigation primitive in LobsterAI's pinned runtime.
  // source: design/LobsterAI/groundtruth/new-vuls/Advisory-GHSA-53vx-pmqw-863c-lobsterai-browser-ssrf-default.json
  call.getCalleeName() = "goto" and call.getReceiver().toString() = "opts.page" and
  call.getContainer().(Function).getName() = "gotoPageWithNavigationGuard" and
  canonicalId = "LA-BROWSER-PAGE-GOTO" and label = "page.goto" and
  capability = "browser-navigation" and boundaryKind = "in-process"
}

private predicate externalCliSpawnSinkDefinition(
  DataFlow::CallNode call, string canonicalId, string label, string capability,
  string boundaryKind
) {
  // TinyClaw delegates the agent runtime to one of three registered external CLI adapters.
  // Stop at the lowest in-process process-creation primitive. The Promise owner is
  // constrained by its audited signature, without binding the rule to a file.
  externalCliSpawnShape(call) and
  canonicalId = "TC-EXTERNAL-AGENT-SPAWN" and label = "spawn:external-agent-cli" and
  capability = "process-spawn" and boundaryKind = "process-boundary"
}

/** Shared capability-factory and AI SDK boundary signatures. */
private predicate capabilityRuntimeSinkDefinition(
  DataFlow::CallNode call, string canonicalId, string label, string capability,
  string boundaryKind
) {
  (
    // Duplicate shell-policy reports share the executeCommand process primitive.
    // Match its callback-owned spawn by the enclosing function signature, not a file path.
    commandExecutorSpawnShape(call) and
    canonicalId = "MA-PROCESS-SPAWN" and label = "child_process.spawn" and
    capability = "process-spawn" and boundaryKind = "in-process"
    or
    // Four approval-bypass reports terminate at the callback that would present
    // the command to the user, not at the later process-spawn impact endpoint.
    // source: /root/my-project/agent-research/clawgap/design/mercury-agent/groundtruth/new-vuls/Advisory-GHSA-7977-c43c-xpwj-wc-files0-from.json
    // source: /root/my-project/agent-research/clawgap/design/mercury-agent/groundtruth/new-vuls/Advisory-GHSA-jccr-rrw2-vc8h-echo-env.json
    // source: /root/my-project/agent-research/clawgap/design/mercury-agent/groundtruth/new-vuls/CVE-2026-28391-safe-read-redirection.json
    // source: /root/my-project/agent-research/clawgap/design/mercury-agent/groundtruth/new-vuls/CVE-2026-32010-find-exec-safe-read.json
    // sink: this.askHandler(`Run command: ${trimmed}`) at src/capabilities/permissions.ts:514
    mercuryCommandApprovalShape(call) and
    canonicalId = "MA-COMMAND-APPROVAL" and label = "askHandler" and
    capability = "user-consent" and boundaryKind = "control-flow"
    or
    // Direct registered filesystem tools: receiver identity comes from node:fs and
    // the handler identity comes from Mercury's literal capability registry.
    anyModuleCall(call, ["fs", "fs.promises"], [
      "readFile", "readFileSync", "open", "openSync"
    ]) and capabilityFactoryCall(call, ["createReadFileTool", "createEditFileTool"]) and
    canonicalId = "MA-FILE-READ" and label = call.getCalleeName() and
    capability = "file-read" and boundaryKind = "in-process"
    or
    anyModuleCall(call, ["fs", "fs.promises"], [
      "writeFile", "writeFileSync", "appendFile", "appendFileSync"
    ]) and
    (
      capabilityFactoryCall(call, [
        "createCreateFileTool", "createWriteFileTool", "createEditFileTool"
      ])
      or
      call.getContainer().(Function).getName() = "saveSkill" and
      call.getContainer().(Function).getNumParameter() = 2 and
      call.getContainer().(Function).getParameter(0).getName() = "name" and
      call.getContainer().(Function).getParameter(1).getName() = "content"
    ) and
    canonicalId = "MA-FILE-WRITE" and label = call.getCalleeName() and
    capability = "file-write" and boundaryKind = "in-process"
    or
    anyModuleCall(call, ["fs", "fs.promises"], [
      "rm", "rmSync", "unlink", "unlinkSync", "rmdir", "rmdirSync"
    ]) and capabilityFactoryCall(call, "createDeleteFileTool") and
    canonicalId = "MA-FILE-DELETE" and label = call.getCalleeName() and
    capability = "file-delete" and boundaryKind = "in-process"
    or
    call.getCalleeName() = "fetch" and
    (
      capabilityFactoryCall(call, ["createFetchUrlTool", "createInstallSkillTool"])
      or
      call.getContainer().(Function).getName() = "githubRequest" and
      call.getContainer().(Function).getNumParameter() = 2 and
      call.getContainer().(Function).getParameter(0).getName() = "path" and
      call.getContainer().(Function).getParameter(1).getName() = "options"
    ) and
    canonicalId = "MA-NETWORK-FETCH" and label = "fetch" and
    capability = "network-egress" and boundaryKind = "in-process"
    or
    // allowedTools is not applied before this complete capability map crosses into AI SDK dispatch.
    call = API::moduleImport("ai").getMember("generateText").getACall() and
    exists(ObjectExpr options, Property tools |
      options = call.getArgument(0).asExpr() and tools = options.getPropertyByName("tools") and
      tools.getInit().getUnderlyingValue().(CallExpr).getCalleeName() = "getTools"
    ) and
    canonicalId = "MA-SUBAGENT-TOOL-EXPOSURE" and label = "generateText.tools" and
    capability = "tool-capability-exposure" and boundaryKind = "sdk-boundary"
  )
}

/** The call is the one primary external effect selected for a named DroidClaw handler. */
private predicate droidClawPrimaryEffectCall(DataFlow::CallNode call, string handlerName) {
  exists(Function handler |
    call.getContainer() = handler and handlerName = handler.getName() and
    (
      handlerName = [
        "executeTap", "executeSwipe", "executeLongPress", "executeOpenUrl", "executeSwitchApp",
        "executeKeyevent", "executeOpenSettings", "executeScroll", "executePullFile",
        "executePushFile", "executeShell"
      ] and call.getCalleeName() = "runAdbCommand"
      or
      handlerName = "executeType" and call.getCalleeName() = "runAdbCommand" and
      call.getArgument(0).asExpr().(ArrayExpr).getAnElement().getStringValue() = "text"
      or
      handlerName = "executeLaunch" and call.getCalleeName() = "runAdbCommand" and
      call.getArgument(0).toString() = "args"
      or
      handlerName = "executePaste" and call.getCalleeName() = "runAdbCommand" and
      call.getArgument(0).asExpr().(ArrayExpr).getAnElement().getStringValue() = "keyevent"
      or
      handlerName = "executeScreenshot" and call.getCalleeName() = "runAdbCommand" and
      call.getArgument(0).asExpr().(ArrayExpr).getElement(0).getStringValue() = "pull"
      or
      handlerName = "executeClipboardSet" and call.getCalleeName() = "runAdbCommand"
      or
      handlerName = "copyVisibleText" and call.getCalleeName() = "safeClipboardSet"
      or
      handlerName = "findAndTap" and call.getCalleeName() = "runAdbCommand" and
      call.getArgument(0).asExpr().(ArrayExpr).getAnElement().getStringValue() = "tap"
      or
      handlerName = "composeEmail" and call.getCalleeName() = "runAdbCommand" and
      call.getArgument(0).asExpr().(ArrayExpr).getAnElement().getStringValue() =
        "android.intent.action.SENDTO"
    ) and
    (
      handlerName = [
        "executeTap", "executeType", "executeSwipe", "executeLaunch", "executePaste",
        "executeScreenshot", "executeLongPress", "executeClipboardSet", "executeOpenUrl",
        "executeSwitchApp", "executeKeyevent", "executeOpenSettings", "executeScroll",
        "executePullFile", "executePushFile", "executeShell"
      ] and handler.getNumParameter() = 1 and handler.getParameter(0).getName() = "action"
      or
      handlerName = ["copyVisibleText", "findAndTap", "composeEmail"] and
      handler.getNumParameter() = 2 and handler.getParameter(0).getName() = "decision" and
      handler.getParameter(1).getName() = "elements"
    )
  )
}

/**
 * Source-bearing DroidClaw action sinks are modeled at their named semantic boundary.
 * The generic Bun.spawnSync executor is intentionally not a sink for this benchmark.
 * source: /root/my-project/agent-research/clawgap/design/droidclaw/groundtruth/new-vuls/CVE-2026-30741-CLI-Shell-AutoApproval.json
 */
private predicate droidClawSemanticSinkDefinition(
  DataFlow::CallNode call, string canonicalId, string label, string capability,
  string boundaryKind
) {
  exists(string handlerName |
    droidClawPrimaryEffectCall(call, handlerName) and label = handlerName and
    boundaryKind = "semantic-action" and
    (
      handlerName = "executeTap" and canonicalId = "DC-ACTION-TAP" and capability = "device-tap"
      or
      handlerName = "executeType" and canonicalId = "DC-ACTION-TYPE" and
      capability = "device-text-input"
      or
      handlerName = "executeSwipe" and canonicalId = "DC-ACTION-SWIPE" and
      capability = "device-swipe"
      or
      handlerName = "executeLaunch" and canonicalId = "DC-ACTION-LAUNCH" and
      capability = "app-launch"
      or
      handlerName = "executePaste" and canonicalId = "DC-ACTION-PASTE" and
      capability = "clipboard-paste"
      or
      handlerName = "executeScreenshot" and canonicalId = "DC-ACTION-SCREENSHOT" and
      capability = "screen-capture"
      or
      handlerName = "executeLongPress" and canonicalId = "DC-ACTION-LONGPRESS" and
      capability = "device-long-press"
      or
      handlerName = "executeClipboardSet" and canonicalId = "DC-ACTION-CLIPBOARD-SET" and
      capability = "clipboard-write"
      or
      handlerName = "executeOpenUrl" and canonicalId = "DC-ACTION-OPEN-URL" and
      capability = "browser-navigation"
      or
      handlerName = "executeSwitchApp" and canonicalId = "DC-ACTION-SWITCH-APP" and
      capability = "app-launch"
      or
      handlerName = "executeKeyevent" and canonicalId = "DC-ACTION-KEYEVENT" and
      capability = "device-keyevent"
      or
      handlerName = "executeOpenSettings" and canonicalId = "DC-ACTION-OPEN-SETTINGS" and
      capability = "settings-navigation"
      or
      handlerName = "executeScroll" and canonicalId = "DC-ACTION-SCROLL" and
      capability = "device-swipe"
      or
      handlerName = "executePullFile" and canonicalId = "DC-ACTION-PULL-FILE" and
      capability = "device-file-pull"
      or
      handlerName = "executePushFile" and canonicalId = "DC-ACTION-PUSH-FILE" and
      capability = "device-file-push"
      or
      handlerName = "executeShell" and canonicalId = "DC-ACTION-SHELL" and
      capability = "adb-shell-execution"
      or
      handlerName = "copyVisibleText" and canonicalId = "DC-SKILL-COPY-VISIBLE-TEXT" and
      capability = "clipboard-write"
      or
      handlerName = "findAndTap" and canonicalId = "DC-SKILL-FIND-AND-TAP" and
      capability = "device-tap"
      or
      handlerName = "composeEmail" and canonicalId = "DC-ACTION-COMPOSE-EMAIL" and
      capability = "email-compose"
    )
  )
}

/** The complete model-controlled facet set of one semantic DroidClaw action. */
private predicate droidClawSemanticFacet(string canonicalId, string facet) {
  canonicalId = [
    "DC-ACTION-TAP", "DC-ACTION-TYPE", "DC-ACTION-SWIPE", "DC-ACTION-LAUNCH",
    "DC-ACTION-PASTE", "DC-ACTION-SCREENSHOT", "DC-ACTION-LONGPRESS",
    "DC-ACTION-CLIPBOARD-SET", "DC-ACTION-OPEN-URL", "DC-ACTION-SWITCH-APP",
    "DC-ACTION-KEYEVENT", "DC-ACTION-OPEN-SETTINGS", "DC-ACTION-SCROLL",
    "DC-ACTION-PULL-FILE", "DC-ACTION-PUSH-FILE", "DC-ACTION-SHELL"
  ] and facet = "action.action"
  or
  canonicalId = [
    "DC-SKILL-COPY-VISIBLE-TEXT", "DC-SKILL-FIND-AND-TAP", "DC-ACTION-COMPOSE-EMAIL"
  ] and
  facet = "decision.action"
  or
  canonicalId = ["DC-ACTION-TAP", "DC-ACTION-LONGPRESS", "DC-ACTION-PASTE"] and
  facet = "coordinates"
  or
  canonicalId = ["DC-ACTION-TYPE", "DC-ACTION-CLIPBOARD-SET", "DC-ACTION-COMPOSE-EMAIL"] and
  facet = "text"
  or
  canonicalId = ["DC-ACTION-SWIPE", "DC-ACTION-SCROLL"] and facet = "direction"
  or
  canonicalId = "DC-ACTION-LAUNCH" and facet = ["package", "activity", "uri", "extras"]
  or
  canonicalId = "DC-ACTION-SCREENSHOT" and facet = "filename"
  or
  canonicalId = "DC-ACTION-OPEN-URL" and facet = "url"
  or
  canonicalId = "DC-ACTION-SWITCH-APP" and facet = "package"
  or
  canonicalId = "DC-ACTION-KEYEVENT" and facet = "code"
  or
  canonicalId = "DC-ACTION-OPEN-SETTINGS" and facet = "setting"
  or
  canonicalId = "DC-ACTION-PULL-FILE" and facet = "path"
  or
  canonicalId = "DC-ACTION-PUSH-FILE" and facet = ["source", "dest"]
  or
  canonicalId = "DC-ACTION-SHELL" and facet = "command"
  or
  canonicalId = [
    "DC-SKILL-COPY-VISIBLE-TEXT", "DC-SKILL-FIND-AND-TAP", "DC-ACTION-COMPOSE-EMAIL"
  ] and
  facet = "query"
}

/** Every real execution branch selected for the seven pinned Letta Code handlers. */
private predicate lettaBotSemanticEffectCall(DataFlow::CallNode call, string toolName) {
  exists(Function handler |
    lettaBotToolHandler(handler, toolName, "allowed-vendored-letta-code-tool:0.19.5") and
    call.getContainer() = handler and
    (
      toolName = "Bash" and
      (
        call.getCalleeName() = "spawn" and call.getNumArgument() = 3 and
        call.getArgument(0).toString() = "executable"
        or
        call.getCalleeName() = "spawnCommand" and call.getNumArgument() = 2 and
        call.getArgument(0).toString() = "command"
      )
      or
      toolName = "Read" and
      (
        call.getCalleeName() = "readImageFile" and call.getArgument(0).toString() = "resolvedPath"
        or
        call.getCalleeName() = "readFile" and call.getReceiver().toString() = "fs" and
        call.getArgument(0).toString() = "resolvedPath"
      )
      or
      toolName = "Edit" and call.getCalleeName() = "writeFile" and
      call.getReceiver().toString() = "fs" and call.getArgument(0).toString() = "resolvedPath" and
      call.getArgument(1).toString() = "newContent"
      or
      toolName = "Write" and call.getCalleeName() = "writeFile" and
      call.getReceiver().toString() = "fs" and call.getArgument(0).toString() = "resolvedPath" and
      call.getArgument(1).toString() = "content"
      or
      toolName = ["Glob", "Grep"] and call.getCalleeName() = "execFileAsync" and
      call.getArgument(0).toString() = "rgPath" and call.getArgument(1).toString() = "rgArgs"
      or
      toolName = "Task" and
      (
        call.getCalleeName() = "spawnBackgroundSubagentTask" and
        call.getArgument(0).asExpr() instanceof ObjectExpr
        or
        call.getCalleeName() = "spawnSubagent" and call.getNumArgument() = 8 and
        call.getArgument(1).toString() = "prompt"
      )
    )
  )
}

/** Handler-named Letta Code semantic sinks backed by exact v0.19.5 effect calls. */
private predicate lettaBotSemanticSinkDefinition(
  DataFlow::CallNode call, string canonicalId, string label, string capability,
  string boundaryKind
) {
  exists(string toolName |
    lettaBotSemanticEffectCall(call, toolName) and label = toolName and
    boundaryKind = "semantic-action" and
    (
      toolName = "Bash" and canonicalId = "LB-CODE-BASH" and capability = "command-execution"
      or
      toolName = "Read" and canonicalId = "LB-CODE-READ" and capability = "file-read"
      or
      toolName = "Edit" and canonicalId = "LB-CODE-EDIT" and capability = "file-edit"
      or
      toolName = "Write" and canonicalId = "LB-CODE-WRITE" and capability = "file-write"
      or
      toolName = "Glob" and canonicalId = "LB-CODE-GLOB" and capability = "file-enumeration"
      or
      toolName = "Grep" and canonicalId = "LB-CODE-GREP" and capability = "content-search"
      or
      toolName = "Task" and canonicalId = "LB-CODE-TASK" and capability = "subagent-delegation"
    )
  )
}

/** Effective model-controlled fields from the pinned Letta Code tool schemas and handlers. */
private predicate lettaBotSemanticFacet(string canonicalId, string facet) {
  canonicalId = "LB-CODE-BASH" and facet = ["command", "timeout", "run_in_background"]
  or
  canonicalId = "LB-CODE-READ" and facet = ["file_path", "offset", "limit"]
  or
  canonicalId = "LB-CODE-EDIT" and
  facet = ["file_path", "old_string", "new_string", "replace_all"]
  or
  canonicalId = "LB-CODE-WRITE" and facet = ["file_path", "content"]
  or
  canonicalId = "LB-CODE-GLOB" and facet = ["pattern", "path"]
  or
  canonicalId = "LB-CODE-GREP" and
  facet = [
    "pattern", "path", "glob", "output_mode", "-B", "-A", "-C", "-n", "-i", "type",
    "head_limit", "offset", "multiline"
  ]
  or
  canonicalId = "LB-CODE-TASK" and
  facet = [
    "description", "prompt", "subagent_type", "model", "run_in_background", "agent_id",
    "conversation_id"
  ]
}

private predicate todoStoreSinkDefinition(
  DataFlow::CallNode call, string canonicalId, string label, string capability,
  string boundaryKind
) {
  (
    anyModuleCall(call, "fs", "readFileSync") and
    call.getContainer().(Function).getName() = "loadStore" and
    call.getContainer().(Function).getNumParameter() = 1 and
    call.getContainer().(Function).getParameter(0).getName() = "path" and
    canonicalId = "LB-TODO-STORE-READ" and label = "readFileSync:todo-store" and
    capability = "file-read" and boundaryKind = "in-process"
    or
    anyModuleCall(call, "fs", "writeFileSync") and
    call.getContainer().(Function).getName() = "saveStore" and
    call.getContainer().(Function).getNumParameter() = 2 and
    call.getContainer().(Function).getParameter(0).getName() = "path" and
    call.getContainer().(Function).getParameter(1).getName() = "store" and
    canonicalId = "LB-TODO-STORE-WRITE" and label = "writeFileSync:todo-store" and
    capability = "file-write" and boundaryKind = "in-process"
  )
}

private predicate acpBoundarySinkDefinition(
  DataFlow::CallNode call, string canonicalId, string label, string capability,
  string boundaryKind
) {
  call.getCalleeName() = "call" and
  exists(CallExpr transportCall |
    call.getReceiver().asExpr() = transportCall and transportCall.getNumArgument() = 0 and
    transportCall.getCallee().getUnderlyingValue().(Identifier).getName() = "getTransport"
  ) and
  call.getArgument(0).getStringValue() = "acp_prompt" and
  exists(Function handler, ObjectExpr payload, Property blocks |
    call.getContainer() = handler and
    handler.getName() = "acpPrompt" and
    handler.getNumParameter() = 5 and
    handler.getParameter(0).getName() = "connectionId" and
    handler.getParameter(1).getName() = "blocks" and
    handler.getParameter(2).getName() = "folderId" and
    handler.getParameter(3).getName() = "conversationId" and
    handler.getParameter(4).getName() = "clientMessageId" and
    payload = call.getArgument(1).asExpr() and blocks = payload.getPropertyByName("blocks") and
    blocks.getInit().getUnderlyingValue().(Identifier).getName() = "blocks"
  ) and
  canonicalId = "CG-ACP-PROMPT" and label = "getTransport.call:acp_prompt" and
  capability = "external-agent-execution" and boundaryKind = "rust-acp-boundary"
}

predicate sinkDefinition(
  DataFlow::CallNode call, string canonicalId, string label, string capability,
  string boundaryKind
) {
  isProductionSinkCall(call) and
  (
    nodeAndBoundarySinkDefinition(call, canonicalId, label, capability, boundaryKind)
    or
    browserAndRuntimeSinkDefinition(call, canonicalId, label, capability, boundaryKind)
    or
    persistenceAndApprovalSinkDefinition(call, canonicalId, label, capability, boundaryKind)
    or
    nanoClawSemanticSinkDefinition(call, canonicalId, label, capability, boundaryKind)
    or
    guardedPageGotoSinkDefinition(call, canonicalId, label, capability, boundaryKind)
    or
    externalCliSpawnSinkDefinition(call, canonicalId, label, capability, boundaryKind)
    or
    capabilityRuntimeSinkDefinition(call, canonicalId, label, capability, boundaryKind)
    or
    droidClawSemanticSinkDefinition(call, canonicalId, label, capability, boundaryKind)
    or
    lettaBotSemanticSinkDefinition(call, canonicalId, label, capability, boundaryKind)
    or
    todoStoreSinkDefinition(call, canonicalId, label, capability, boundaryKind)
    or
    acpBoundarySinkDefinition(call, canonicalId, label, capability, boundaryKind)
  )
}

predicate is_sink_af(DataFlow::CallNode call) {
  sinkDefinition(call, _, _, _, _)
}

string sinkLabel(DataFlow::CallNode call) {
  sinkDefinition(call, _, result, _, _)
}

string sinkCanonicalId(DataFlow::CallNode call) {
  sinkDefinition(call, result, _, _, _)
}

string sinkCapability(DataFlow::CallNode call) {
  sinkDefinition(call, _, _, result, _)
}

string sinkBoundaryKind(DataFlow::CallNode call) {
  sinkDefinition(call, _, _, _, result)
}

predicate controlledSinkArgument(DataFlow::CallNode call, DataFlow::Node node, string facet) {
  exists(string canonicalId, string capability |
    sinkDefinition(call, canonicalId, _, capability, _) and
  (
      canonicalId != "OC-EXTERNAL-PI-TOOL" and not canonicalId.matches("LB-CODE-%") and
      capability = "process-spawn" and node = call.getArgument(0) and facet = "command"
      or
      canonicalId != "OC-EXTERNAL-PI-TOOL" and not canonicalId.matches("LB-CODE-%") and
      capability = "process-spawn" and node = call.getArgument(1) and facet = "argv"
      or
      canonicalId != "OC-EXTERNAL-PI-TOOL" and not canonicalId.matches("LB-CODE-%") and
      capability = "process-spawn" and node = call.getArgument(2) and facet = "options"
      or
      canonicalId = "MA-COMMAND-APPROVAL" and node = call.getArgument(0) and
      facet = "command"
      or
      canonicalId != "OC-EXTERNAL-PI-TOOL" and not canonicalId.matches("LB-CODE-%") and
      capability = "file-read" and node = call.getArgument(0) and facet = "path"
      or
      canonicalId != "OC-EXTERNAL-PI-TOOL" and not canonicalId.matches("LB-CODE-%") and
      capability = "file-write" and node = call.getArgument([0, 1]) and
      (node = call.getArgument(0) and facet = "path" or node = call.getArgument(1) and facet = "content")
      or
      canonicalId != "OC-EXTERNAL-PI-TOOL" and
      capability = "file-delete" and node = call.getArgument(0) and facet = "path"
      or
      canonicalId != "OC-EXTERNAL-PI-TOOL" and
      capability = "network-egress" and node = call.getArgument([0, 1]) and
      (node = call.getArgument(0) and facet = "url" or node = call.getArgument(1) and facet = "request")
      or
      canonicalId = "OC-RESOURCE-RESPONSE-TEXT" and node = call.getReceiver() and
      facet = "response-body"
      or
      canonicalId = "OC-BROWSER-OPEN" and node = call.getArgument(1) and facet = "url"
      or
      canonicalId = "OC-BROWSER-PROXY-OPEN" and node = call.getArgument(0) and facet = "payload.url"
      or
      canonicalId = "OC-DELIVERY-MESSAGE-ACTION" and node = call.getArgument(0) and facet = "message-action"
      or
      canonicalId = "OC-BROWSER-CHROME-MCP-CALL" and
      node = call.getArgument(0).asExpr().(ObjectExpr).getPropertyByName("arguments").getInit().flow() and
      facet = "function-text"
      or
      canonicalId = "OC-RPC-NODE-INVOKE" and node = call.getArgument(2) and facet = "invoke-payload"
      or
      canonicalId = "OC-RPC-GATEWAY-METHOD" and node = call.getArgument(2) and facet = "rpc-payload"
      or
      canonicalId = "OC-EXTERNAL-PI-TOOL" and node = call.getArgument(1) and facet = "tool-params"
      or
      canonicalId = "OCCN-BROWSER-EVALUATE" and node = call.getArgument(1) and
      facet = "function-text"
      or
      canonicalId = "OCCN-BROWSER-INTERACTION" and node = call.getReceiver() and
      facet = "locator-ref"
      or
      canonicalId = "OCCN-BROWSER-PAGE-GOTO" and node = call.getArgument(0) and facet = "url"
      or
      canonicalId = "OCCN-BROWSER-CDP-CREATE-TARGET" and
      node = call.getArgument(1).asExpr().(ObjectExpr).getPropertyByName("url").getInit().flow() and
      facet = "url"
      or
      canonicalId = "OCCN-BROWSER-JSON-NEW" and node = call.getArgument(0) and facet = "url"
      or
      canonicalId = "NC-FILE-COPY" and node = call.getArgument(0) and facet = "source-path"
      or
      canonicalId = "NC-FILE-COPY" and node = call.getArgument(1) and facet = "destination-path"
      or
      canonicalId = "NC-APPROVAL-PERSIST" and node = call.getArgument(0) and
      facet = "approval-payload"
      or
      canonicalId = "NC-CONFIG-MUTATION" and node = call.getArgument(0) and
      facet = "mcp-servers"
      or
      canonicalId = "NC-APPROVAL-PRESENT" and node = call.getArgument(4) and
      facet = "approval-question"
      or
      canonicalId.matches("NC-ACTION-%") and nanoClawSemanticFacet(canonicalId, facet) and
      node = DataFlow::parameterNode(call.getContainer().(Function).getParameter(0))
      or
      canonicalId = "LA-BROWSER-PAGE-GOTO" and node = call.getArgument(0) and
      facet = "url"
      or
      canonicalId = "MA-SUBAGENT-TOOL-EXPOSURE" and
      node = call.getArgument(0).asExpr().(ObjectExpr).getPropertyByName("tools").getInit().flow() and
      facet = "tool-map"
      or
      canonicalId = "CG-ACP-PROMPT" and
      node = call.getArgument(1).asExpr().(ObjectExpr).getPropertyByName("blocks").getInit().flow() and
      facet = "prompt-blocks"
      or
      canonicalId.matches("DC-%") and droidClawSemanticFacet(canonicalId, facet) and
      node = DataFlow::parameterNode(call.getContainer().(Function).getParameter(0))
      or
      canonicalId.matches("LB-CODE-%") and lettaBotSemanticFacet(canonicalId, facet) and
      node = DataFlow::parameterNode(call.getContainer().(Function).getParameter(0))
    )
  )
}

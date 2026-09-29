/**
 * @id clawgap/typescript-gates
 * @name source-tainted TypeScript dominance gates
 * @kind table
 */

import javascript
import project.ProjectModel
import call.call
import call.sinks_af
import call.droidclaw_gates
import call.lettabot_gates

bindingset[name]
predicate policyCallName(string name) {
  name.matches("assert%") or name.matches("validate%") or name.matches("is%Allowed%") or
  name.matches("is%Safe%") or name.matches("check%") or
  name = [
    "includes", "startsWith", "endsWith", "test", "match", "has", "exists",
    "isAbsolute", "isPathInside", "isToolAllowedByPolicies", "assertSandboxPath",
    "resolvePinnedHostname", "createPinnedDispatcher", "evaluateShellAllowlist",
    "evaluateExecAllowlist", "processGatewayAllowlist", "requiresExecApproval",
    "isSafeBinUsage", "resolveExecApprovals", "resolvePatchPath"
  ]
}

predicate gateInCondition(DataFlow::CallNode gate, IfStmt guard) {
  gate.asExpr().getParent*() = guard.getCondition() and
  policyCallName(gate.getCalleeName())
}

string gateKind(DataFlow::CallNode gate) {
  exists(IfStmt guard | gateInCondition(gate, guard)) and result = "condition-dominates"
  or
  not exists(IfStmt guard | gateInCondition(gate, guard)) and result = "call-dominates"
}

string gateCondition(DataFlow::CallNode gate) {
  exists(IfStmt guard | gateInCondition(gate, guard) and result = guard.getCondition().toString())
  or
  not exists(IfStmt guard | gateInCondition(gate, guard)) and result = gate.asExpr().toString()
}

string reportedGateKind(DataFlow::CallNode gate) {
  gate.getLocation().getFile().getRelativePath() = "src/gateway/server-methods.ts" and
  gate.getCalleeName() = "authorizeGatewayMethod" and
  result = "[pre-handler] rpc-boundary-authorize"
  or
  not (
    gate.getLocation().getFile().getRelativePath() = "src/gateway/server-methods.ts" and
    gate.getCalleeName() = "authorizeGatewayMethod"
  ) and result = gateKind(gate)
}

predicate checkedGateNode(DataFlow::CallNode gate, DataFlow::Node checked) {
  checked = gate.getAnArgument() or checked = gate.getReceiver()
}

private predicate openClawGateRow(
  Function handler, DataFlow::CallNode sink, DataFlow::CallNode gate, DataFlow::Node checked,
  string sourceName, string guardKind, string verdict, string ownerName, string conditionExpr
) {
  (isOpenClawProject() or isOpenClawCNProject()) and
  exists(DataFlow::Node source, DataFlow::Node sinkArg, Function owner, int chainDepth,
    int gateDepth, string path |
    (
      handlerSource(handler, source, sourceName) and
      controlledSinkArgument(sink, sinkArg, _) and
      taintReachesSink(handler, source, sink, sinkArg, chainDepth) and
      reachesSink(handler, sink, chainDepth, path) and gate.getContainer() = owner and
      policyCallName(gate.getCalleeName()) and checkedGateNode(gate, checked) and
      sourceReachesFunctionNode(handler, source, owner, checked, gateDepth) and
      dominatesSinkPath(gate, owner, sink) and gate != sink and
      guardKind = reportedGateKind(gate) and verdict = "confirmed" and
      ownerName = owner.getName() and conditionExpr = gateCondition(gate)
      or
      handlerSource(handler, source, sourceName) and
      controlledSinkArgument(sink, sinkArg, _) and
      sinkCanonicalId(sink) = "OC-RPC-GATEWAY-METHOD" and
      taintReachesSink(handler, source, sink, sinkArg, chainDepth) and
      reachesSink(handler, sink, chainDepth, path) and
      gate.getCalleeName() = "authorizeGatewayMethod" and
      gate.getLocation().getFile().getRelativePath() = "src/gateway/server-methods.ts" and
      gate.getLocation().getStartLine() = 194 and checked = gate.getArgument(0) and
      owner = handler and gateDepth = 0 and ownerName = handler.getName() and
      guardKind = "[pre-handler] rpc-boundary-authorize" and verdict = "confirmed" and
      conditionExpr = gateCondition(gate)
      or
      handlerSource(handler, source, sourceName) and
      policyDecisionGateForSink(
        handler, source, sink, sinkArg, gate, checked, owner, chainDepth, gateDepth, path
      ) and
      guardKind = "decision-return-branch" and verdict = "branch-confirmed" and
      conditionExpr = gateCondition(gate) and
      (
        ownerName = owner.getName()
        or
        gate.getCalleeName() = "isSafeBinUsage" and
        gate.getLocation().getFile().getRelativePath() = "src/infra/exec-approvals.ts" and
        gate.getLocation().getStartLine() = 986 and ownerName = "evaluateSegments.<callback>"
      )
    )
  )
}

private predicate openClawCNInlineGate(
  string file, int line, Expr gateExpr, DataFlow::Node checked, string conditionExpr
) {
  exists(IfStmt guard |
    guard.getLocation().getFile().getRelativePath() = file and
    guard.getLocation().getStartLine() = line and gateExpr = guard.getCondition() and
    checked = guard.getCondition().flow() and conditionExpr = guard.getCondition().toString()
  )
}

private predicate openClawCNCallGate(
  string file, int line, string name, Expr gateExpr, DataFlow::Node checked,
  string conditionExpr
) {
  exists(DataFlow::CallNode call |
    call.getLocation().getFile().getRelativePath() = file and
    call.getLocation().getStartLine() = line and call.getCalleeName() = name and
    gateExpr = call.asExpr() and
    (
      checked = call.getArgument(0)
      or
      not exists(call.getArgument(0)) and checked = call.getReceiver()
    ) and conditionExpr = call.asExpr().toString()
  )
}

/** Resolve a revision-pinned local decision initializer used by an exact chain. */
private predicate openClawCNInitializerGate(
  string file, int line, string variableName, Expr gateExpr, DataFlow::Node checked,
  string conditionExpr
) {
  exists(VariableDeclarator declaration |
    declaration.getLocation().getFile().getRelativePath() = file and
    declaration.getLocation().getStartLine() = line and
    declaration.getBindingPattern().(Identifier).getName() = variableName and
    gateExpr = declaration.getInit() and checked = declaration.getInit().flow() and
    conditionExpr = declaration.getInit().toString()
  )
}

/** Constructor calls such as `new URL(rawUrl)` are not DataFlow::CallNode values. */
private predicate openClawCNNewGate(
  string file, int line, string name, Expr gateExpr, DataFlow::Node checked,
  string conditionExpr
) {
  exists(NewExpr construction |
    construction.getLocation().getFile().getRelativePath() = file and
    construction.getLocation().getStartLine() = line and
    construction.getCallee().toString() = name and gateExpr = construction and
    checked = construction.getArgument(0).flow() and conditionExpr = construction.toString()
  )
}

/** Revision-pinned, exact-chain gate catalogue for the bounded OpenClaw-CN fork model. */
private predicate openClawCNGateRow(
  Function handler, DataFlow::CallNode sink, Expr gateExpr, DataFlow::Node checked,
  string gateName, string sourceName, string guardKind, string verdict, string ownerName,
  string conditionExpr
) {
  isOpenClawCNProject() and
  exists(DataFlow::Node source, DataFlow::Node sinkArg, int chainDepth, int gateDepth,
    string path, string toolName |
    openClawCNToolHandler(handler, toolName, _) and handlerSource(handler, source, sourceName) and
    controlledSinkArgument(sink, sinkArg, _) and
    taintReachesSink(handler, source, sink, sinkArg, chainDepth) and
    reachesSink(handler, sink, chainDepth, path) and verdict = "confirmed" and
    (
      toolName = "browser" and sinkCanonicalId(sink) = [
        "OCCN-BROWSER-EVALUATE", "OCCN-BROWSER-INTERACTION"
      ] and
      (
        openClawCNInlineGate(
          "src/agents/tools/browser-tool.ts", 846, gateExpr, checked, conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "inline-early-throw"
        or
        openClawCNCallGate(
          "src/browser/routes/agent.act.ts", 39, "isActKind", gateExpr, checked,
          conditionExpr
        ) and gateName = "isActKind" and guardKind = "condition-dominates"
        or
        sinkCanonicalId(sink) = "OCCN-BROWSER-INTERACTION" and
        openClawCNInlineGate(
          "src/browser/routes/agent.act.ts", 57, gateExpr, checked, conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "inline-early-return"
        or
        sinkCanonicalId(sink) = "OCCN-BROWSER-INTERACTION" and
        openClawCNCallGate(
          "src/browser/pw-tools-core.interactions.ts", 41, "requireRef", gateExpr,
          checked, conditionExpr
        ) and gateName = "requireRef" and guardKind = "guard-normalizer"
        or
        sinkCanonicalId(sink) = "OCCN-BROWSER-INTERACTION" and
        openClawCNInlineGate(
          "src/browser/pw-session.ts", 431, gateExpr, checked, conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "helper-early-throw"
        or
        sinkCanonicalId(sink) = "OCCN-BROWSER-EVALUATE" and
        openClawCNInlineGate(
          "src/browser/routes/agent.act.ts", 255, gateExpr, checked, conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "inline-early-return"
        or
        sinkCanonicalId(sink) = "OCCN-BROWSER-EVALUATE" and
        openClawCNInlineGate(
          "src/browser/pw-tools-core.interactions.ts", 218, gateExpr, checked,
          conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "helper-early-throw"
      )
      or
      toolName = "browser" and sinkCanonicalId(sink) = "OCCN-BROWSER-PAGE-GOTO" and
      sink.getContainer().(Function).getName() = "navigateViaPlaywright" and
      (
        openClawCNCallGate(
          "src/browser/pw-tools-core.snapshot.ts", 169, "assertBrowserNavigationAllowed",
          gateExpr, checked, conditionExpr
        ) and gateName = "assertBrowserNavigationAllowed" and guardKind = "call-dominates"
        or
        openClawCNInlineGate(
          "src/browser/navigation-guard.ts", [10, 21], gateExpr, checked, conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "helper-branch"
        or
        openClawCNCallGate(
          "src/browser/navigation-guard.ts", 25, "resolvePinnedHostnameWithPolicy",
          gateExpr, checked, conditionExpr
        ) and gateName = any(DataFlow::CallNode c |
          c.asExpr() = gateExpr | c.getCalleeName()
        ) and guardKind = "helper-call"
        or
        openClawCNNewGate(
          "src/browser/navigation-guard.ts", 16, "URL", gateExpr, checked,
          conditionExpr
        ) and gateName = "URL" and guardKind = "helper-call"
        or
        openClawCNCallGate(
          "src/infra/net/ssrf.ts", [401, 406, 410, 423],
          ["matchesHostnameAllowlist", "isBlockedHostname", "isPrivateIpAddress"],
          gateExpr, checked, conditionExpr
        ) and gateName = any(DataFlow::CallNode c |
          c.asExpr() = gateExpr | c.getCalleeName()
        ) and guardKind = "policy-decision"
      )
      or
      toolName = "browser" and sinkCanonicalId(sink) = [
        "OCCN-BROWSER-CDP-CREATE-TARGET", "OCCN-BROWSER-PAGE-GOTO",
        "OCCN-BROWSER-JSON-NEW"
      ] and
      not (
        sinkCanonicalId(sink) = "OCCN-BROWSER-PAGE-GOTO" and
        sink.getContainer().(Function).getName() = "navigateViaPlaywright"
      ) and
      (
        openClawCNInlineGate(
          "src/browser/routes/tabs.ts", 34, gateExpr, checked, conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "inline-early-return"
        or
        openClawCNCallGate(
          "src/browser/server-context.ts", 153, "assertBrowserNavigationAllowed",
          gateExpr, checked, conditionExpr
        ) and gateName = "assertBrowserNavigationAllowed" and guardKind = "call-dominates"
        or
        openClawCNInlineGate(
          "src/browser/navigation-guard.ts", [10, 21], gateExpr, checked, conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "helper-branch"
        or
        openClawCNCallGate(
          "src/browser/navigation-guard.ts", 25, "resolvePinnedHostnameWithPolicy",
          gateExpr, checked, conditionExpr
        ) and gateName = any(DataFlow::CallNode c |
          c.asExpr() = gateExpr | c.getCalleeName()
        ) and guardKind = "helper-call"
        or
        openClawCNNewGate(
          "src/browser/navigation-guard.ts", 16, "URL", gateExpr, checked,
          conditionExpr
        ) and gateName = "URL" and guardKind = "helper-call"
        or
        openClawCNCallGate(
          "src/infra/net/ssrf.ts", [401, 406, 410, 423],
          ["matchesHostnameAllowlist", "isBlockedHostname", "isPrivateIpAddress"],
          gateExpr, checked, conditionExpr
        ) and gateName = any(DataFlow::CallNode c |
          c.asExpr() = gateExpr | c.getCalleeName()
        ) and guardKind = "policy-decision"
        or
        sinkCanonicalId(sink) = "OCCN-BROWSER-CDP-CREATE-TARGET" and
        openClawCNCallGate(
          "src/browser/cdp.ts", 86, "assertBrowserNavigationAllowed", gateExpr, checked,
          conditionExpr
        ) and gateName = "assertBrowserNavigationAllowed" and guardKind = "call-dominates"
        or
        sinkCanonicalId(sink) = "OCCN-BROWSER-PAGE-GOTO" and
        openClawCNCallGate(
          "src/browser/pw-session.ts", [519, 521], ["trim", "assertBrowserNavigationAllowed"],
          gateExpr, checked, conditionExpr
        ) and gateName = any(DataFlow::CallNode c |
          c.asExpr() = gateExpr | c.getCalleeName()
        ) and guardKind = "guard-normalizer"
        or
        sinkCanonicalId(sink) = "OCCN-BROWSER-JSON-NEW" and
        openClawCNCallGate(
          "src/browser/server-context.ts", [198, 210], ["encodeURIComponent", "set"],
          gateExpr, checked, conditionExpr
        ) and gateName = any(DataFlow::CallNode c |
          c.asExpr() = gateExpr | c.getCalleeName()
        ) and guardKind = "url-transform"
      )
      or
      toolName = "apply_patch" and sinkCanonicalId(sink) = "OCCN-APPLY-PATCH-WRITE" and
      (
        openClawCNInlineGate(
          "src/agents/sandbox-paths.ts", 48, gateExpr, checked, conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "helper-early-throw"
        or
        openClawCNCallGate(
          "src/agents/sandbox-paths.ts", [61, 125, 133, 145],
          ["assertNoSymlinkEscape", "isPathInside", "isNotFoundPathError", "resolve"],
          gateExpr, checked, conditionExpr
        ) and gateName = any(DataFlow::CallNode c |
          c.asExpr() = gateExpr | c.getCalleeName()
        ) and guardKind = "path-policy"
        or
        openClawCNCallGate(
          "src/infra/path-guards.ts", 25, ["startsWith", "isAbsolute"], gateExpr,
          checked, conditionExpr
        ) and gateName = any(DataFlow::CallNode c |
          c.asExpr() = gateExpr | c.getCalleeName()
        ) and guardKind = "path-policy"
      )
      or
      toolName = "message" and sinkCanonicalId(sink) = "OCCN-FEISHU-MEDIA-FETCH" and
      (
        openClawCNCallGate(
          "src/infra/outbound/message-action-runner.ts", 372, "assertMediaNotDataUrl",
          gateExpr, checked, conditionExpr
        ) and gateName = "assertMediaNotDataUrl" and guardKind = "helper-policy"
        or
        openClawCNCallGate(
          "extensions/feishu/src/media.ts", 524, "isLocalPath", gateExpr, checked,
          conditionExpr
        ) and gateName = "isLocalPath" and guardKind = "extension-branch-selector"
      )
      or
      toolName = "exec" and sinkCapability(sink) = "process-spawn" and
      (
        openClawCNInlineGate(
          "src/agents/bash-tools.exec.ts", [1016, 1240, 1378], gateExpr, checked,
          conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "decision-return-branch"
        or
        openClawCNInlineGate(
          "src/node-host/runner.ts", [1009, 1041], gateExpr, checked, conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "decision-return-branch"
        or
        openClawCNCallGate(
          "src/infra/exec-approvals.ts", [1115, 1117], ["matchAllowlist", "isSafeBinUsage"],
          gateExpr, checked, conditionExpr
        ) and gateName = any(DataFlow::CallNode c |
          c.asExpr() = gateExpr | c.getCalleeName()
        ) and guardKind = "decision-return-branch"
        or
        openClawCNInitializerGate(
          "src/infra/exec-approvals.ts", 1123, "skillAllow", gateExpr, checked,
          conditionExpr
        ) and gateName = "skillAllow" and guardKind = "allowlist-decision"
        or
        openClawCNCallGate(
          "src/agents/bash-tools.exec.ts", 1259, "resolveAllowAlwaysPatterns", gateExpr,
          checked, conditionExpr
        ) and gateName = "resolveAllowAlwaysPatterns" and guardKind = "trust-transform"
        or
        openClawCNCallGate(
          "src/infra/exec-approvals-allowlist.ts", [275, 331],
          ["has", "isShellWrapperSegment"], gateExpr, checked, conditionExpr
        ) and gateName = any(DataFlow::CallNode c |
          c.asExpr() = gateExpr | c.getCalleeName()
        ) and guardKind = "decision-return-branch"
      )
    ) and
    sourceReachesFunctionNode(
      handler, source, gateExpr.getEnclosingFunction(), checked, gateDepth
    ) and
    (
      ownerName = gateExpr.getEnclosingFunction().getName()
      or
      not exists(gateExpr.getEnclosingFunction().getName()) and ownerName = "<callback>"
    )
  )
}

/** Resolve one audited NanoClaw helper/consent call on a GT-valid chain. */
private predicate nanoClawCallGate(
  string file, int line, string name, DataFlow::CallNode gate, DataFlow::Node checked,
  string guardKind, string conditionExpr
) {
  gate.getLocation().getFile().getRelativePath() = file and
  gate.getLocation().getStartLine() = line and gate.getCalleeName() = name and
  (
    name = ["existsSync", "resolveRouting", "isSafeAttachmentName", "getAgentGroup", "requestApproval"] and
    checked = gate.getArgument(0)
    or
    name = "hasDestination" and checked = gate.getArgument(2)
    or
    name = "isPathInside" and checked = gate.getArgument(1)
  ) and
  (
    name = "requestApproval" and guardKind = "consent-gate" and
    conditionExpr = "approval required before continuing"
    or
    name != "requestApproval" and guardKind = "condition-dominates" and
    exists(IfStmt guard |
      gate.asExpr().getParent*() = guard.getCondition() and
      conditionExpr = guard.getCondition().toString()
    )
    or
    name = "resolveRouting" and guardKind = "function-result-guard" and
    conditionExpr = "'error' in routing"
  )
}

/** Resolve one audited NanoClaw inline early-return/dispatch condition. */
private predicate nanoClawInlineGate(
  string file, int line, Expr gateExpr, DataFlow::Node checked, string conditionExpr
) {
  exists(IfStmt guard |
    guard.getLocation().getFile().getRelativePath() = file and
    guard.getLocation().getStartLine() = line and
    gateExpr = guard.getCondition() and checked = guard.getCondition().flow() and
    conditionExpr = guard.getCondition().toString()
  )
}

private predicate nanoClawGateRow(
  Function handler, DataFlow::CallNode sink, Expr gateExpr, DataFlow::Node checked,
  string gateName, string sourceName, string guardKind, string verdict, string ownerName,
  string conditionExpr
) {
  isNanoClawProject() and
  exists(DataFlow::Node source, DataFlow::Node sinkArg, int chainDepth, int gateDepth,
    string path, string toolName |
    nanoClawToolHandler(handler, toolName, _) and handlerSource(handler, source, sourceName) and
    controlledSinkArgument(sink, sinkArg, _) and
    taintReachesSink(handler, source, sink, sinkArg, chainDepth) and
    reachesSink(handler, sink, chainDepth, path) and verdict = "confirmed" and
    (
      toolName = "send_file" and
      (
        // The direct copy and the A2A forwarding path share the container-side guards.
        nanoClawInlineGate(
          "container/agent-runner/src/mcp-tools/core.ts", 151, gateExpr, checked,
          conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "inline-early-return"
        or
        nanoClawCallGate(
          "container/agent-runner/src/mcp-tools/core.ts", 153, "resolveRouting",
          any(DataFlow::CallNode gate | gateExpr = gate.asExpr()), checked, guardKind,
          conditionExpr
        ) and gateName = "resolveRouting"
        or
        nanoClawCallGate(
          "container/agent-runner/src/mcp-tools/core.ts", 157, "existsSync",
          any(DataFlow::CallNode gate | gateExpr = gate.asExpr()), checked, guardKind,
          conditionExpr
        ) and gateName = "existsSync"
      )
      or
      toolName = "send_file" and
      sink.getLocation().getFile().getRelativePath() =
        "src/modules/agent-to-agent/agent-route.ts" and
      (
        nanoClawInlineGate("src/delivery.ts", 267, gateExpr, checked, conditionExpr) and
        gateName = "inlineCondition" and guardKind = "dispatch-selector"
        or
        nanoClawInlineGate(
          "src/modules/agent-to-agent/agent-route.ts", 215, gateExpr, checked,
          conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "inline-early-throw"
        or
        nanoClawCallGate(
          "src/modules/agent-to-agent/agent-route.ts", 217, "hasDestination",
          any(DataFlow::CallNode gate | gateExpr = gate.asExpr()), checked, guardKind,
          conditionExpr
        ) and gateName = "hasDestination"
        or
        nanoClawCallGate(
          "src/modules/agent-to-agent/agent-route.ts", 223, "getAgentGroup",
          any(DataFlow::CallNode gate | gateExpr = gate.asExpr()), checked, guardKind,
          conditionExpr
        ) and gateName = "getAgentGroup"
        or
        nanoClawCallGate(
          "src/modules/agent-to-agent/agent-route.ts", 104, "isSafeAttachmentName",
          any(DataFlow::CallNode gate | gateExpr = gate.asExpr()), checked, guardKind,
          conditionExpr
        ) and gateName = "isSafeAttachmentName"
        or
        nanoClawInlineGate(
          "src/modules/agent-to-agent/agent-route.ts", 115, gateExpr, checked,
          conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "inline-early-continue"
        or
        nanoClawCallGate(
          "src/modules/agent-to-agent/agent-route.ts", 130, "isPathInside",
          any(DataFlow::CallNode gate | gateExpr = gate.asExpr()), checked, guardKind,
          conditionExpr
        ) and gateName = "isPathInside"
      )
      or
      toolName = "add_mcp_server" and
      (
        nanoClawInlineGate(
          "container/agent-runner/src/mcp-tools/self-mod.ts", 100, gateExpr, checked,
          conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "inline-early-return"
        or
        nanoClawInlineGate(
          "src/modules/self-mod/request.ts", 74, gateExpr, checked, conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "inline-early-return"
        or
        nanoClawCallGate(
          "src/modules/self-mod/request.ts", 78, "requestApproval",
          any(DataFlow::CallNode gate | gateExpr = gate.asExpr()), checked, guardKind,
          conditionExpr
        ) and gateName = "requestApproval"
      )
    ) and
    sourceReachesFunctionNode(
      handler, source, gateExpr.getEnclosingFunction(), checked, gateDepth
    ) and ownerName = gateExpr.getEnclosingFunction().getName()
  )
}

/**
 * LobsterAI's SSRF control is split between app-managed policy data and the
 * bundled browser runtime. Policy-data rows are explicitly marked pre-handler;
 * runtime rows are admitted only for the one taint-valid browser chain.
 */
private predicate lobsterAIGateRow(
  Function handler, DataFlow::CallNode sink, Expr gateExpr, DataFlow::Node checked,
  string gateName, string sourceName, string guardKind, string verdict, string ownerName,
  string conditionExpr
) {
  isLobsterAIProject() and lobsterAIToolHandler(handler, "browser", _) and
  exists(DataFlow::Node source, DataFlow::Node sinkArg, int chainDepth, string path |
    handlerSource(handler, source, sourceName) and
    controlledSinkArgument(sink, sinkArg, "url") and
    taintReachesSink(handler, source, sink, sinkArg, chainDepth) and
    reachesSink(handler, sink, chainDepth, path) and verdict = "confirmed" and
    (
      exists(ObjectExpr defaults, Property networkMode |
        defaults.getLocation().getFile().getRelativePath() =
          "src/shared/browserWebAccess/constants.ts" and
        defaults.getLocation().getStartLine() = 100 and
        networkMode = defaults.getPropertyByName("networkMode") and
        gateExpr = networkMode.getInit() and checked = networkMode.getInit().flow() and
        gateName = "defaultBrowserWebAccessConfig" and
        guardKind = "[pre-handler] policy-default" and ownerName = handler.getName() and
        conditionExpr = networkMode.getInit().toString()
      )
      or
      exists(ConditionalExpr policyChoice, Function owner |
        owner.getName() = "buildBrowserConfig" and
        owner.getFile().getRelativePath() = "src/main/libs/openclawConfigSync.ts" and
        policyChoice.getEnclosingFunction() = owner and
        policyChoice.getLocation().getStartLine() = 1203 and
        gateExpr = policyChoice.getCondition() and checked = policyChoice.getCondition().flow() and
        gateName = "buildBrowserConfig" and
        guardKind = "[pre-handler] policy-serialization" and
        ownerName = handler.getName() and conditionExpr = policyChoice.getCondition().toString()
      )
      or
      exists(DataFlow::CallNode runtimeGate |
        runtimeGate.getCalleeName() = "assertBrowserNavigationAllowed" and
        runtimeGate.getLocation().getFile().getRelativePath() =
          "vendor-source/openclaw-v2026.4.14/extensions/browser/src/browser/routes/tabs.ts" and
        runtimeGate.getLocation().getStartLine() = 172 and gateExpr = runtimeGate.asExpr() and
        checked = runtimeGate.getArgument(0) and gateName = runtimeGate.getCalleeName() and
        guardKind = "condition-dominates" and ownerName = "assertBrowserNavigationAllowed" and
        conditionExpr = runtimeGate.asExpr().toString()
      )
      or
      exists(DataFlow::CallNode policyDecision |
        policyDecision.getCalleeName() = "isPrivateNetworkAllowedByPolicy" and
        policyDecision.getContainer().(Function).getName() = "shouldSkipPrivateNetworkChecks" and
        policyDecision.getLocation().getFile().getRelativePath() =
          "vendor-source/openclaw-v2026.4.14/src/infra/net/ssrf.ts" and
        policyDecision.getLocation().getStartLine() = 79 and gateExpr = policyDecision.asExpr() and
        checked = policyDecision.getArgument(0) and gateName = policyDecision.getCalleeName() and
        guardKind = "decision-return-branch" and ownerName = "shouldSkipPrivateNetworkChecks" and
        conditionExpr = policyDecision.asExpr().toString()
      )
      or
      exists(Literal promptLine |
        promptLine.getLocation().getFile().getRelativePath() =
          "src/main/libs/openclawConfigSync.ts" and
        promptLine.getLocation().getStartLine() = 271 and
        promptLine.getValue() =
          "- For every `browser` tool call, set `target=\"host\"` explicitly." and
        gateExpr = promptLine and checked = promptLine.flow() and
        gateName = "MANAGED_BROWSER_POLICY_PROMPT" and
        guardKind = "[pre-handler] prompt-policy" and ownerName = handler.getName() and
        conditionExpr = promptLine.toString()
      )
    )
  )
}

/** Resolve one inline TypeScript condition by its revision-pinned AST anchor. */
private predicate mercuryInlineGate(
  string file, int line, Expr gateExpr, DataFlow::Node checked, string conditionExpr
) {
  exists(IfStmt guard |
    guard.getLocation().getFile().getRelativePath() = file and
    guard.getLocation().getStartLine() = line and gateExpr = guard.getCondition() and
    checked = guard.getCondition().flow() and conditionExpr = guard.getCondition().toString()
  )
}

/** Resolve one audited helper/policy call without relying on a source-file sink whitelist. */
private predicate mercuryCallGate(
  string file, int line, string name, Expr gateExpr, DataFlow::Node checked,
  string conditionExpr
) {
  exists(DataFlow::CallNode call |
    call.getLocation().getFile().getRelativePath() = file and
    call.getLocation().getStartLine() = line and call.getCalleeName() = name and
    gateExpr = call.asExpr() and checked = call.getArgument(0) and
    conditionExpr = call.asExpr().toString()
  )
}

/** The complete allSegmentsSafeRead decision is a gate, not merely its nested callbacks. */
private predicate mercurySafeReadDecision(
  Expr gateExpr, DataFlow::Node checked, string conditionExpr
) {
  exists(VariableDeclarator declaration |
    declaration.getLocation().getFile().getRelativePath() =
      "src/capabilities/permissions.ts" and
    declaration.getLocation().getStartLine() = 504 and
    declaration.getBindingPattern().(Identifier).getName() = "allSegmentsSafeRead" and
    gateExpr = declaration.getInit() and checked = declaration.getInit().flow() and
    conditionExpr = declaration.getInit().toString()
  )
}

private int mercuryFsCheckLine(string toolName) {
  toolName = "read_file" and result = 15
  or toolName = "create_file" and result = 16
  or toolName = "write_file" and result = 17
  or toolName = "edit_file" and result = 18
}

private int mercuryFsDenyLine(string toolName) {
  result = mercuryFsCheckLine(toolName) + 1
}

/**
 * Audited run_command admission across checkShellCommand's DI parameter.
 * The generic local-flow library does not bind a for-of collection element to
 * its segment variable, so prove source influence at the exact formal and only
 * admit the three command-derived policy decisions selected below.
 */
private predicate mercuryCommandGateSourceAdmission(
  Function handler, DataFlow::Node source, DataFlow::CallNode sink, Expr gateExpr,
  string gateName, int gateDepth
) {
  exists(Function checkShellCommand |
    checkShellCommand = gateExpr.getEnclosingFunction() and
    checkShellCommand.getName() = "checkShellCommand" and
    checkShellCommand.getFile().getRelativePath() = "src/capabilities/permissions.ts" and
    checkShellCommand.getNumParameter() = 1 and
    checkShellCommand.getParameter(0).getName() = "command" and
    sourceReachesFunctionNode(
      handler, source, checkShellCommand,
      DataFlow::parameterNode(checkShellCommand.getParameter(0)), gateDepth
    ) and
    (
      gateName = ["matchPattern", "hasPathBeyondCwd", "allSegmentsSafeRead"]
      or
      sinkCanonicalId(sink) = "MA-PROCESS-SPAWN" and gateName = "inlineCondition" and
      gateExpr.getLocation().getStartLine() = 513
    )
  )
}

/** Source-taint-valid Mercury gate rows on the exact registered capability chain. */
private predicate mercuryAgentGateRow(
  Function handler, DataFlow::CallNode sink, Expr gateExpr, DataFlow::Node checked,
  string gateName, string sourceName, string guardKind, string verdict, string ownerName,
  string conditionExpr
) {
  isMercuryAgentProject() and
  exists(DataFlow::Node source, DataFlow::Node sinkArg, int chainDepth, int gateDepth,
    string path, string toolName |
    mercuryAgentToolHandler(handler, toolName, _) and handlerSource(handler, source, sourceName) and
    controlledSinkArgument(sink, sinkArg, _) and
    taintReachesSink(handler, source, sink, sinkArg, chainDepth) and
    reachesSink(handler, sink, chainDepth, path) and verdict = "confirmed" and
    (
      toolName = "run_command" and
      (
        sinkCanonicalId(sink) = "MA-PROCESS-SPAWN" and
        (
          mercuryCallGate(
            "src/capabilities/shell/run-command.ts", 98, "checkShellCommand", gateExpr,
            checked, conditionExpr
          ) and gateName = "checkShellCommand" and guardKind = "decision-return-branch"
          or
          mercuryInlineGate(
            "src/capabilities/shell/run-command.ts", 99, gateExpr, checked, conditionExpr
          ) and gateName = "inlineCondition" and guardKind = "inline-early-return"
          or
          mercuryInlineGate(
            "src/capabilities/permissions.ts", [459, 464, 489, 492, 513], gateExpr,
            checked, conditionExpr
          ) and gateName = "inlineCondition" and guardKind = "decision-return-branch"
          or
          mercuryCallGate(
            "src/capabilities/permissions.ts", 483, "matchPattern", gateExpr, checked,
            conditionExpr
          ) and gateName = "matchPattern" and guardKind = "decision-return-branch"
          or
          mercuryCallGate(
            "src/capabilities/permissions.ts", 491, "hasPathBeyondCwd", gateExpr, checked,
            conditionExpr
          ) and gateName = "hasPathBeyondCwd" and guardKind = "decision-return-branch"
          or
          mercurySafeReadDecision(gateExpr, checked, conditionExpr) and
          gateName = "allSegmentsSafeRead" and guardKind = "decision-return-branch"
          or
          mercuryCallGate(
            "src/capabilities/permissions.ts", 514, "askHandler", gateExpr, checked,
            conditionExpr
          ) and gateName = "askHandler" and guardKind = "decision-return-branch"
        )
        or
        sinkCanonicalId(sink) = "MA-COMMAND-APPROVAL" and
        (
          mercuryCallGate(
            "src/capabilities/permissions.ts", 483, "matchPattern", gateExpr, checked,
            conditionExpr
          ) and gateName = "matchPattern" and guardKind = "decision-return-branch"
          or
          mercuryCallGate(
            "src/capabilities/permissions.ts", 491, "hasPathBeyondCwd", gateExpr, checked,
            conditionExpr
          ) and gateName = "hasPathBeyondCwd" and guardKind = "decision-return-branch"
          or
          mercurySafeReadDecision(gateExpr, checked, conditionExpr) and
          gateName = "allSegmentsSafeRead" and guardKind = "decision-return-branch"
        )
      )
      or
      toolName = ["read_file", "create_file", "write_file", "edit_file"] and
      sinkCapability(sink) = ["file-read", "file-write"] and
      (
        mercuryCallGate(
          handler.getFile().getRelativePath(),
          mercuryFsCheckLine(toolName),
          "checkFsAccess", gateExpr, checked, conditionExpr
        ) and gateName = "checkFsAccess" and guardKind = "decision-return-branch"
        or
        mercuryInlineGate(
          handler.getFile().getRelativePath(),
          mercuryFsDenyLine(toolName),
          gateExpr, checked, conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "inline-early-return"
        or
        mercuryCallGate(
          "src/capabilities/permissions.ts", 395, "findScope", gateExpr, checked,
          conditionExpr
        ) and gateName = "findScope" and guardKind = "decision-return-branch"
        or
        mercuryCallGate(
          "src/capabilities/permissions.ts", 396, "findTempScope", gateExpr, checked,
          conditionExpr
        ) and gateName = "findTempScope" and guardKind = "decision-return-branch"
        or
        mercuryInlineGate(
          "src/capabilities/permissions.ts", [400, 406], gateExpr, checked, conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "decision-return-branch"
        or
        mercuryCallGate(
          "src/capabilities/permissions.ts", 415, "askHandler", gateExpr, checked,
          conditionExpr
        ) and gateName = "askHandler" and guardKind = "decision-return-branch"
        or
        toolName = "read_file" and
        mercuryInlineGate(
          "src/capabilities/filesystem/read-file.ts", 30, gateExpr, checked, conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "condition-dominates"
      )
      or
      toolName = "install_skill" and sinkCanonicalId(sink) = "MA-FILE-WRITE" and
      (
        mercuryCallGate(
          "src/capabilities/skills/install-skill.ts", 32, "match", gateExpr, checked,
          conditionExpr
        ) and gateName = "match" and guardKind = "condition-dominates"
        or
        mercuryInlineGate(
          "src/capabilities/skills/install-skill.ts", 39, gateExpr, checked, conditionExpr
        ) and gateName = "inlineCondition" and guardKind = "inline-early-return"
      )
    ) and
    (
      sourceReachesFunctionNode(
        handler, source, gateExpr.getEnclosingFunction(), checked, gateDepth
      )
      or
      toolName = "run_command" and
      mercuryCommandGateSourceAdmission(
        handler, source, sink, gateExpr, gateName, gateDepth
      )
    ) and ownerName = gateExpr.getEnclosingFunction().getName()
  )
}

from Function handler, DataFlow::CallNode sink, Expr gateExpr, DataFlow::Node checked,
  string gateName, string sourceName, string guardKind, string verdict, string ownerName,
  string conditionExpr
where
  exists(DataFlow::CallNode gate |
    gateExpr = gate.asExpr() and gateName = gate.getCalleeName() and
    openClawGateRow(
      handler, sink, gate, checked, sourceName, guardKind, verdict, ownerName,
      conditionExpr
    )
  )
  or
  openClawCNGateRow(
    handler, sink, gateExpr, checked, gateName, sourceName, guardKind, verdict,
    ownerName, conditionExpr
  )
  or
  nanoClawGateRow(
    handler, sink, gateExpr, checked, gateName, sourceName, guardKind, verdict, ownerName,
    conditionExpr
  )
  or
  lobsterAIGateRow(
    handler, sink, gateExpr, checked, gateName, sourceName, guardKind, verdict,
    ownerName, conditionExpr
  )
  or
  mercuryAgentGateRow(
    handler, sink, gateExpr, checked, gateName, sourceName, guardKind, verdict,
    ownerName, conditionExpr
  )
  or
  droidClawGateRow(
    handler, sink, gateExpr, checked, gateName, sourceName, guardKind, verdict,
    ownerName, conditionExpr
  )
  or
  lettaBotGateRow(
    handler, sink, gateExpr, checked, gateName, sourceName, guardKind, verdict,
    ownerName, conditionExpr
  )
select gateName as gate_fn,
  gateExpr.getLocation().getFile().getRelativePath() as gate_file,
  gateExpr.getLocation().getStartLine() as gate_line,
  gateExpr.getLocation().getStartColumn() as gate_column,
  gateExpr.toString() as gate_call_expr, checked.toString() as checked_expr,
  checked.getLocation().getFile().getRelativePath() as checked_file,
  checked.getLocation().getStartLine() as checked_line,
  checked.getLocation().getStartColumn() as checked_column,
  sourceName as source_param, conditionExpr as condition_expr,
  guardKind as guard_kind, verdict as taint_verdict,
  ownerName as in_func, sinkLabel(sink) as sink_label,
  sink.getLocation().getFile().getRelativePath() as sink_file,
  sink.getLocation().getStartLine() as sink_line,
  handler.getName() as handler_func,
  handler.getLocation().getFile().getRelativePath() as handler_file,
  toolHandlerName(handler) as tool_name

/** Project-dispatched JavaScript/TypeScript benchmark model facade. */

import javascript
import project.OpenClawModel
import project.OpenClawCNModel
import project.NanoClawModel
import project.LobsterAIModel
import project.TinyClawModel
import project.MercuryAgentModel
import project.DroidClawModel
import project.LettaBotModel
import project.CodeGModel

predicate isOpenClawProject() { ocIsProject() }

predicate isOpenClawCNProject() { occnIsProject() }

predicate isNanoClawProject() { ncIsProject() }

predicate isLobsterAIProject() { laiIsProject() }

predicate isTinyClawProject() { tcIsProject() }

predicate isMercuryAgentProject() { maIsProject() }

predicate isDroidClawProject() { dcIsProject() }

predicate isLettaBotProject() { lbIsProject() }

predicate isCodeGProject() { cgIsProject() }

bindingset[path]
predicate isCoreSourcePath(string path) {
  isOpenClawProject() and ocIsCoreSourcePath(path)
  or
  isOpenClawCNProject() and occnIsCoreSourcePath(path)
  or
  isNanoClawProject() and ncIsCoreSourcePath(path)
  or
  isLobsterAIProject() and laiIsCoreSourcePath(path)
  or
  isTinyClawProject() and tcIsCoreSourcePath(path)
  or
  isMercuryAgentProject() and maIsCoreSourcePath(path)
  or
  isDroidClawProject() and dcIsCoreSourcePath(path)
  or
  isLettaBotProject() and lbIsCoreSourcePath(path)
  or
  isCodeGProject() and cgIsCoreSourcePath(path)
}

predicate isCoreLocation(Location loc) {
  isOpenClawProject() and ocIsCoreLocation(loc)
  or
  isOpenClawCNProject() and occnIsCoreLocation(loc)
  or
  isNanoClawProject() and ncIsCoreLocation(loc)
  or
  isLobsterAIProject() and laiIsCoreLocation(loc)
  or
  isTinyClawProject() and tcIsCoreLocation(loc)
  or
  isMercuryAgentProject() and maIsCoreLocation(loc)
  or
  isDroidClawProject() and dcIsCoreLocation(loc)
  or
  isLettaBotProject() and lbIsCoreLocation(loc)
  or
  isCodeGProject() and cgIsCoreLocation(loc)
}

predicate openClawToolHandler(Function handler, string toolName, string model) {
  ocToolHandler(handler, toolName, model)
}

predicate openClawCNToolHandler(Function handler, string toolName, string model) {
  occnToolHandler(handler, toolName, model)
}

predicate nanoClawToolHandler(Function handler, string toolName, string model) {
  ncToolHandler(handler, toolName, model)
}

predicate lobsterAIToolHandler(Function handler, string toolName, string model) {
  laiToolHandler(handler, toolName, model)
}

predicate tinyClawToolHandler(Function handler, string toolName, string model) {
  tcToolHandler(handler, toolName, model)
}

predicate mercuryAgentToolHandler(Function handler, string toolName, string model) {
  maToolHandler(handler, toolName, model)
}

predicate droidClawToolHandler(Function handler, string toolName, string model) {
  dcToolHandler(handler, toolName, model)
}

predicate lettaBotToolHandler(Function handler, string toolName, string model) {
  lbToolHandler(handler, toolName, model)
}

predicate codeGToolHandler(Function handler, string toolName, string model) {
  cgToolHandler(handler, toolName, model)
}

predicate nanoClawToolBoundary(Function anchor, string toolName, string model) {
  ncToolBoundary(anchor, toolName, model)
}

predicate lettaBotToolBoundary(Function anchor, string toolName, string model) {
  lbToolBoundary(anchor, toolName, model)
}

predicate projectToolHandler(Function handler, string toolName, string model) {
  openClawToolHandler(handler, toolName, model)
  or
  openClawCNToolHandler(handler, toolName, model)
  or
  nanoClawToolHandler(handler, toolName, model)
  or
  lobsterAIToolHandler(handler, toolName, model)
  or
  tinyClawToolHandler(handler, toolName, model)
  or
  mercuryAgentToolHandler(handler, toolName, model)
  or
  droidClawToolHandler(handler, toolName, model)
  or
  lettaBotToolHandler(handler, toolName, model)
  or
  codeGToolHandler(handler, toolName, model)
}

/** External tool implementations exposed by repository-declared SDK/runtime forwarding. */
predicate projectToolBoundary(Function anchor, string toolName, string model) {
  nanoClawToolBoundary(anchor, toolName, model)
  or
  lettaBotToolBoundary(anchor, toolName, model)
}

/**
 * Inventory-only union. NanoClaw and LettaBot SDK/runtime boundaries are retained by
 * `projectToolBoundary` for exposure auditing, but are not handler entries:
 * they have no analyzed implementation or model-argument source. LettaBot's
 * seven pinned client implementations enter through `projectToolHandler` instead.
 * Call-chain roots continue to use `projectToolHandler`.
 */
predicate projectToolInventoryEntry(Function anchor, string toolName, string model) {
  projectToolHandler(anchor, toolName, model)
  or
  projectToolBoundary(anchor, toolName, model) and
  not (isNanoClawProject() or isLettaBotProject())
}

predicate handlerSource(Function handler, DataFlow::Node source, string parameterName) {
  ocHandlerSource(handler, source, parameterName)
  or
  occnHandlerSource(handler, source, parameterName)
  or
  ncHandlerSource(handler, source, parameterName)
  or
  laiHandlerSource(handler, source, parameterName)
  or
  tcHandlerSource(handler, source, parameterName)
  or
  maHandlerSource(handler, source, parameterName)
  or
  dcHandlerSource(handler, source, parameterName)
  or
  lbHandlerSource(handler, source, parameterName)
  or
  cgHandlerSource(handler, source, parameterName)
}

string activeProjectId() {
  isOpenClawProject() and result = "openclaw"
  or
  isOpenClawCNProject() and result = "openclaw-cn"
  or
  isNanoClawProject() and result = "nanoclaw"
  or
  isLobsterAIProject() and result = "LobsterAI"
  or
  isTinyClawProject() and result = "tinyclaw"
  or
  isMercuryAgentProject() and result = "mercury-agent"
  or
  isDroidClawProject() and result = "droidclaw"
  or
  isLettaBotProject() and result = "lettabot"
  or
  isCodeGProject() and result = "codeg"
}

string activeProjectAdapter() {
  isOpenClawProject() and result = "openclaw-ts"
  or
  isOpenClawCNProject() and result = "openclaw-cn-ts"
  or
  isNanoClawProject() and result = "nanoclaw-ts"
  or
  isLobsterAIProject() and result = "lobsterai-ts"
  or
  isTinyClawProject() and result = "tinyclaw-ts"
  or
  isMercuryAgentProject() and result = "mercury-agent-ts"
  or
  isDroidClawProject() and result = "droidclaw-ts"
  or
  isLettaBotProject() and result = "lettabot-ts"
  or
  isCodeGProject() and result = "codeg-ts"
}

string toolHandlerName(Function handler) {
  projectToolHandler(handler, result, _)
}

/** Exact, revision-audited transforms that may become eligible gates. */
predicate projectApprovedTransformCall(
  DataFlow::CallNode call, string role, string verdict
) {
  (isOpenClawProject() or isOpenClawCNProject()) and
  (
    call.getCalleeName() = "normalizeToolParams" and
    call.getLocation().getFile().getRelativePath() = "src/agents/pi-tools.read.ts" and
    role = "sink-transform" and verdict = "confirmed"
    or
    call.getCalleeName() = ["normalizeCronJobCreate", "normalizeCronJobPatch"] and
    call.getLocation().getFile().getRelativePath() = "src/agents/tools/cron-tool.ts" and
    role = "sink-transform" and verdict = "confirmed"
    or
    call.getCalleeName() = "resolvePatchPath" and
    call.getLocation().getFile().getRelativePath() = "src/agents/apply-patch.ts" and
    role = "guard-normalizer" and verdict = "branch-confirmed"
    or
    call.getCalleeName() = "assertSandboxPath" and
    call.getLocation().getFile().getRelativePath() = [
      "src/agents/apply-patch.ts", "src/agents/pi-tools.read.ts",
      "src/agents/tools/image-tool.ts", "src/agents/tools/message-tool.ts",
      "src/agents/bash-tools.shared.ts"
    ] and role = "guard-normalizer" and verdict = "branch-confirmed"
  )
  or
  isOpenClawProject() and call.getCalleeName() = "buildDockerExecArgs" and
  call.getLocation().getFile().getRelativePath() = "src/agents/bash-tools.exec.ts" and
  role = "command-builder" and verdict = "confirmed"
  or
  isNanoClawProject() and call.getCalleeName() = "realpathSync" and
  call.getLocation().getFile().getRelativePath() =
    "src/modules/agent-to-agent/agent-route.ts" and
  call.getLocation().getStartLine() = 122 and role = "guard-normalizer" and
  verdict = "confirmed"
  or
  isMercuryAgentProject() and call.getCalleeName() = "resolve" and
  (
    call.getLocation().getFile().getRelativePath() = [
      "src/capabilities/filesystem/read-file.ts",
      "src/capabilities/filesystem/create-file.ts",
      "src/capabilities/filesystem/write-file.ts",
      "src/capabilities/filesystem/edit-file.ts"
    ] and role = "path-normalizer"
    or
    call.getLocation().getFile().getRelativePath() = "src/capabilities/permissions.ts" and
    call.getLocation().getStartLine() = 394 and role = "policy-path-normalizer"
  ) and verdict = "confirmed"
  or
  isMercuryAgentProject() and call.getCalleeName() = "splitShellSegments" and
  call.getLocation().getFile().getRelativePath() = "src/capabilities/permissions.ts" and
  call.getLocation().getStartLine() = 476 and role = "command-segmenter" and
  verdict = "confirmed"
}

/** Generic rewrites are surfaced for review but never confirmed by their name alone. */
predicate projectReviewTransformCall(
  DataFlow::CallNode call, string role, string verdict
) {
  projectToolHandler(_, _, _) and
  call.getCalleeName() = [
    "trim", "toLowerCase", "replace", "replaceAll", "resolve", "normalize"
  ] and role = "generic-transform" and verdict = "needs-review"
}

predicate projectTransformCall(
  DataFlow::CallNode call, string role, string verdict
) {
  projectApprovedTransformCall(call, role, verdict)
  or projectReviewTransformCall(call, role, verdict)
}

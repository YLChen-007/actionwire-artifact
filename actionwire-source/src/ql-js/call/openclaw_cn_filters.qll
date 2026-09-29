/** Revision-pinned OpenClaw-CN filters whose admitted collection reaches a canonical sink. */

import javascript
import project.ProjectModel
import call.call
import call.sinks_af

/** This exact parsePatchText call admits only hunks returned by the validated hunk parser. */
private predicate openClawCNPatchParserImplementation(DataFlow::CallNode gate) {
  exists(Function parser, Function oneHunk, DataFlow::CallNode parseOne,
    DataFlow::CallNode admit, DataFlow::CallNode addHeader,
    DataFlow::CallNode deleteHeader, DataFlow::CallNode updateHeader |
    parser.getName() = "parsePatchText" and
    parser.getFile().getRelativePath() = "src/agents/apply-patch.ts" and
    gate.getCalleeName() = parser.getName() and gate.getLocation().getFile() = parser.getFile() and
    oneHunk.getName() = "parseOneHunk" and oneHunk.getFile() = parser.getFile() and
    parseOne.getContainer() = parser and parseOne.getCalleeName() = "parseOneHunk" and
    admit.getContainer() = parser and admit.getCalleeName() = "push" and
    admit.getReceiver().toString() = "hunks" and admit.getArgument(0).toString() = "hunk" and
    addHeader.getContainer() = oneHunk and addHeader.getCalleeName() = "startsWith" and
    addHeader.getReceiver().toString() = "firstLine" and
    addHeader.getArgument(0).toString() = "ADD_FILE_MARKER" and
    deleteHeader.getContainer() = oneHunk and deleteHeader.getCalleeName() = "startsWith" and
    deleteHeader.getReceiver().toString() = "firstLine" and
    deleteHeader.getArgument(0).toString() = "DELETE_FILE_MARKER" and
    updateHeader.getContainer() = oneHunk and updateHeader.getCalleeName() = "startsWith" and
    updateHeader.getReceiver().toString() = "firstLine" and
    updateHeader.getArgument(0).toString() = "UPDATE_FILE_MARKER"
  )
}

/** This exact parseEnvPairs call rejects malformed entries before dictionary admission. */
private predicate openClawCNEnvPairParserImplementation(DataFlow::CallNode gate) {
  exists(Function parser, DataFlow::CallNode delimiter, DataFlow::CallNode keyTrim,
    AssignExpr admit, IndexExpr target |
    parser.getName() = "parseEnvPairs" and
    parser.getFile().getRelativePath() = "src/cli/nodes-run.ts" and
    gate.getCalleeName() = parser.getName() and
    gate.getLocation().getFile().getRelativePath() = "src/agents/tools/nodes-tool.ts" and
    parser.getNumParameter() = 1 and parser.getParameter(0).getName() = "pairs" and
    delimiter.getContainer() = parser and delimiter.getCalleeName() = "indexOf" and
    delimiter.getArgument(0).mayHaveStringValue("=") and
    keyTrim.getContainer() = parser and keyTrim.getCalleeName() = "trim" and
    admit.getEnclosingFunction() = parser and target = admit.getTarget() and
    target.getBase().toString() = "env" and target.getIndex().toString() = "key"
  )
}

/** This exact sanitizeEnv call conditionally admits request entries into the spawned environment. */
private predicate openClawCNEnvironmentSanitizerImplementation(DataFlow::CallNode gate) {
  exists(Function sanitizer, DataFlow::CallNode entries, DataFlow::CallNode blockedKey,
    DataFlow::CallNode blockedPrefix, AssignExpr admit, IndexExpr target, ForOfStmt requestLoop |
    sanitizer.getName() = "sanitizeEnv" and
    sanitizer.getFile().getRelativePath() = "src/node-host/runner.ts" and
    gate.getCalleeName() = sanitizer.getName() and gate.getLocation().getFile() = sanitizer.getFile() and
    sanitizer.getNumParameter() = 1 and sanitizer.getParameter(0).getName() = "overrides" and
    entries.getContainer() = sanitizer and entries.getCalleeName() = "entries" and
    entries.getArgument(0).toString() = "overrides" and
    blockedKey.getContainer() = sanitizer and blockedKey.getCalleeName() = "has" and
    blockedKey.getReceiver().toString() = "blockedEnvKeys" and
    blockedPrefix.getContainer() = sanitizer and blockedPrefix.getCalleeName() = "some" and
    blockedPrefix.getReceiver().toString() = "blockedEnvPrefixes" and
    requestLoop.getContainer() = sanitizer and requestLoop.getIterationDomain() = entries.asExpr() and
    admit.getParent*() = requestLoop and
    admit.getEnclosingFunction() = sanitizer and target = admit.getTarget() and
    target.getBase().toString() = "merged" and target.getIndex().toString() = "key"
  )
}

/** The parseEnvPairs result is carried by the named runParams object into node.invoke. */
private predicate openClawCNParsedEnvironmentEntersNodeInvoke(
  DataFlow::CallNode gate, DataFlow::CallNode sink
) {
  exists(VariableDeclarator envDeclaration, Variable environment, VarRef admitted,
    VariableDeclarator paramsDeclaration, Variable runParams, ObjectExpr runParamsObject,
    Property envProperty, ObjectExpr payload, Property paramsProperty, VarRef paramsUse |
    envDeclaration.getInit() = gate.asExpr() and
    environment = envDeclaration.getBindingPattern().getAVariable() and
    environment.getName() = "env" and
    paramsDeclaration.getInit() = runParamsObject and
    runParams = paramsDeclaration.getBindingPattern().getAVariable() and
    runParams.getName() = "runParams" and
    envProperty = runParamsObject.getPropertyByName("env") and admitted = envProperty.getInit() and
    admitted.getVariable() = environment and payload = sink.getArgument(2).asExpr() and
    payload.getPropertyByName("command").getInit().mayHaveStringValue("system.run") and
    paramsProperty = payload.getPropertyByName("params") and paramsUse = paramsProperty.getInit() and
    paramsUse.getVariable() = runParams
  )
}

/** The sanitizeEnv result becomes runCommand's env and then spawn's options.env. */
private predicate openClawCNSanitizedEnvironmentEntersSpawn(
  DataFlow::CallNode gate, Function owner, DataFlow::CallNode sink
) {
  exists(VariableDeclarator declaration, Variable environment, DataFlow::Node runEnvironment,
    DataFlow::CallNode run, Function runCommand, Function callback, ObjectExpr options,
    Property envProperty, VarRef spawnedEnvironment |
    declaration.getInit() = gate.asExpr() and
    environment = declaration.getBindingPattern().getAVariable() and
    environment.getName() = "env" and run.getContainer() = owner and
    run.getCalleeName() = "runCommand" and runEnvironment = run.getArgument(2) and
    runEnvironment.asExpr().(VarRef).getVariable() = environment and
    runCommand.getName() = "runCommand" and
    runCommand.getFile().getRelativePath() = "src/node-host/runner.ts" and
    runCommand.getNumParameter() = 4 and runCommand.getParameter(2).getName() = "env" and
    sink.getContainer() = callback and callback.getEnclosingStmt().getContainer() = runCommand and
    options = sink.getArgument(2).asExpr() and envProperty = options.getPropertyByName("env") and
    spawnedEnvironment = envProperty.getInit() and
    spawnedEnvironment.getVariable() = runCommand.getParameter(2).getABindingVarRef().getVariable()
  )
}

/** Callback-owned apply-patch write reached after parsePatchText's admitted hunk iteration. */
private predicate openClawCNPatchFilterRow(
  Function handler, DataFlow::Node source, DataFlow::CallNode sink,
  DataFlow::Node sinkArg, DataFlow::CallNode gate, DataFlow::Node checked,
  Function owner, int chainDepth, int gateDepth, string path,
  string conditionExpr
) {
  openClawCNToolHandler(handler, "apply_patch", _) and handlerSource(handler, source, _) and
  openClawCNPatchParserImplementation(gate) and gate.getContainer() = owner and
  owner.getName() = "applyPatch" and
  owner.getFile().getRelativePath() = "src/agents/apply-patch.ts" and
  gate.getCalleeName() = "parsePatchText" and checked = gate.getArgument(0) and
  sourceReachesFunctionNode(handler, source, owner, checked, gateDepth) and
  sinkCanonicalId(sink) = "OCCN-APPLY-PATCH-WRITE" and
  controlledSinkArgument(sink, sinkArg, _) and
  taintReachesSink(handler, source, sink, sinkArg, chainDepth) and
  reachesSink(handler, sink, chainDepth, path) and
  conditionExpr = "parsePatchText admits only validated patch hunks"
}

private predicate openClawCNNodeEnvironmentPairFilterRow(
  Function handler, DataFlow::Node source, DataFlow::CallNode sink,
  DataFlow::Node sinkArg, DataFlow::CallNode gate, DataFlow::Node checked,
  Function owner, int chainDepth, int gateDepth, string path,
  string conditionExpr
) {
  openClawCNToolHandler(handler, "nodes", _) and handlerSource(handler, source, _) and
  owner = handler and openClawCNEnvPairParserImplementation(gate) and gate.getContainer() = owner and
  gate.getLocation().getFile().getRelativePath() = "src/agents/tools/nodes-tool.ts" and
  gate.getCalleeName() = "parseEnvPairs" and checked = gate.getArgument(0) and
  sourceReachesFunctionNode(handler, source, owner, checked, gateDepth) and
  sink.getContainer() = owner and sinkCanonicalId(sink) = "OC-RPC-NODE-INVOKE" and
  openClawCNParsedEnvironmentEntersNodeInvoke(gate, sink) and
  controlledSinkArgument(sink, sinkArg, _) and
  taintReachesSink(handler, source, sink, sinkArg, chainDepth) and
  reachesSink(handler, sink, chainDepth, path) and dominatesSinkPath(gate, owner, sink) and
  conditionExpr = "parseEnvPairs rejects malformed entries before env insertion"
}

private predicate openClawCNNodeHostEnvironmentFilterRow(
  Function handler, DataFlow::Node source, DataFlow::CallNode sink,
  DataFlow::Node sinkArg, DataFlow::CallNode gate, DataFlow::Node checked,
  Function owner, int chainDepth, int gateDepth, string path,
  string conditionExpr
) {
  openClawCNToolHandler(handler, ["exec", "nodes"], _) and handlerSource(handler, source, _) and
  openClawCNEnvironmentSanitizerImplementation(gate) and gate.getContainer() = owner and
  owner.getName() = "handleInvoke" and
  owner.getFile().getRelativePath() = "src/node-host/runner.ts" and
  gate.getCalleeName() = "sanitizeEnv" and checked = gate.getArgument(0) and
  sourceReachesFunctionNode(handler, source, owner, checked, gateDepth) and
  sinkCanonicalId(sink) = "OCCN-NODE-HOST-SPAWN" and
  openClawCNSanitizedEnvironmentEntersSpawn(gate, owner, sink) and
  controlledSinkArgument(sink, sinkArg, "options") and
  taintReachesSink(handler, source, sink, sinkArg, chainDepth) and
  reachesSink(handler, sink, chainDepth, path) and dominatesSinkPath(gate, owner, sink) and
  conditionExpr = "sanitizeEnv admits only allowed request environment entries"
}

predicate openClawCNFilterRow(
  Function handler, DataFlow::Node source, DataFlow::CallNode sink,
  DataFlow::Node sinkArg, DataFlow::CallNode gate, DataFlow::Node checked,
  Function owner, int chainDepth, int gateDepth, string path,
  string conditionExpr
) {
  isOpenClawCNProject() and
  (
    openClawCNPatchFilterRow(
      handler, source, sink, sinkArg, gate, checked, owner, chainDepth, gateDepth, path,
      conditionExpr
    )
    or
    openClawCNNodeEnvironmentPairFilterRow(
      handler, source, sink, sinkArg, gate, checked, owner, chainDepth, gateDepth, path,
      conditionExpr
    )
    or
    openClawCNNodeHostEnvironmentFilterRow(
      handler, source, sink, sinkArg, gate, checked, owner, chainDepth, gateDepth, path,
      conditionExpr
    )
  )
}

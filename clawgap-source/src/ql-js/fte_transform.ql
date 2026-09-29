/**
 * @id clawgap/typescript-gate-transform
 * @name TypeScript source-to-sink transform candidates
 * @kind table
 */

import javascript
import project.ProjectModel
import call.call
import call.sinks_af
import call.droidclaw_transforms

predicate transformCall(DataFlow::CallNode call, string role, string verdict) {
  projectTransformCall(call, role, verdict)
}

private int transformDefinitionLine(DataFlow::CallNode transform) {
  isMercuryAgentProject() and transform.getCalleeName() = "splitShellSegments" and
  transform.getLocation().getFile().getRelativePath() =
    "src/capabilities/permissions.ts" and result = 154
  or
  not (
    isMercuryAgentProject() and transform.getCalleeName() = "splitShellSegments" and
    transform.getLocation().getFile().getRelativePath() =
      "src/capabilities/permissions.ts"
  ) and result = 0
}

from Function handler, DataFlow::Node source, DataFlow::CallNode sink, DataFlow::Node sinkArg,
  DataFlow::CallNode transform, DataFlow::Node input, string sourceName, string role,
  string verdict, Function owner, int chainDepth, int transformDepth, int remainingDepth,
  string path, string reportedOwner
where
  (
    projectToolHandler(handler, _, _) and handlerSource(handler, source, sourceName) and
      controlledSinkArgument(sink, sinkArg, _) and
      taintReachesSink(handler, source, sink, sinkArg, chainDepth) and
      reachesSink(handler, sink, chainDepth, path) and
      transform.getContainer() = owner and transformCall(transform, role, verdict) and
      (input = transform.getAnArgument() or input = transform.getReceiver()) and
      sourceReachesFunctionNode(handler, source, owner, input, transformDepth) and
      dominatesSinkPath(transform, owner, sink) and
      taintReachesSink(owner, transform, sink, sinkArg, remainingDepth) and
      reportedOwner = handler.getName()
    or
      (isOpenClawProject() or isOpenClawCNProject()) and
      handlerSource(handler, source, sourceName) and
      (openClawToolHandler(handler, "exec", _) or
        openClawCNToolHandler(handler, "exec", _)) and
      controlledSinkArgument(sink, sinkArg, _) and sinkLabel(sink) = "spawnImpl" and
      taintReachesSink(handler, source, sink, sinkArg, chainDepth) and
      reachesSink(handler, sink, chainDepth, path) and chainDepth = 4 and
      transform.getCalleeName() = "buildDockerExecArgs" and
      transform.getLocation().getFile().getRelativePath() = "src/agents/bash-tools.exec.ts" and
      transform.getLocation().getStartLine() = 447 and transform.getContainer() = owner and
      input = transform.getArgument(0) and transformCall(transform, role, verdict) and
      transformDepth = 1 and remainingDepth = 3 and reportedOwner = handler.getName()
    or
    isNanoClawProject() and nanoClawToolHandler(handler, "send_file", _) and
    handlerSource(handler, source, sourceName) and
    controlledSinkArgument(sink, sinkArg, _) and sinkLabel(sink) = "copyFileSync" and
    sink.getLocation().getFile().getRelativePath() =
      "src/modules/agent-to-agent/agent-route.ts" and
    taintReachesSink(handler, source, sink, sinkArg, chainDepth) and
    reachesSink(handler, sink, chainDepth, path) and
    transform.getCalleeName() = "realpathSync" and
    transform.getLocation().getFile().getRelativePath() =
      "src/modules/agent-to-agent/agent-route.ts" and
    transform.getLocation().getStartLine() = 122 and transform.getContainer() = owner and
    owner.getName() = "forwardAttachedFiles" and input = transform.getArgument(0) and
    projectApprovedTransformCall(transform, role, verdict) and transformDepth = 5 and
    remainingDepth = 1 and reportedOwner = owner.getName()
    or
    isMercuryAgentProject() and
    mercuryAgentToolHandler(
      handler, ["read_file", "create_file", "write_file", "edit_file", "run_command"], _
    ) and
    handlerSource(handler, source, sourceName) and controlledSinkArgument(sink, sinkArg, _) and
    taintReachesSink(handler, source, sink, sinkArg, chainDepth) and
    reachesSink(handler, sink, chainDepth, path) and transform.getContainer() = owner and
    input = transform.getAnArgument() and
    sourceReachesFunctionNode(handler, source, owner, input, transformDepth) and
    (
      mercuryAgentToolHandler(
        handler, ["read_file", "create_file", "write_file", "edit_file"], _
      ) and owner = handler and transform.getCalleeName() = "resolve" and
      transform.getLocation().getStartLine() = handler.getLocation().getStartLine() + 1 and
      role = "path-normalizer"
      or
      mercuryAgentToolHandler(
        handler, ["read_file", "create_file", "write_file", "edit_file"], _
      ) and owner.getName() = "checkFsAccess" and transform.getCalleeName() = "resolve" and
      transform.getLocation().getFile().getRelativePath() =
        "src/capabilities/permissions.ts" and
      transform.getLocation().getStartLine() = 394 and role = "policy-path-normalizer"
      or
      mercuryAgentToolHandler(handler, "run_command", _) and
      owner.getName() = "checkShellCommand" and
      transform.getCalleeName() = "splitShellSegments" and
      transform.getLocation().getFile().getRelativePath() =
        "src/capabilities/permissions.ts" and
      transform.getLocation().getStartLine() = 476 and role = "command-segmenter"
    ) and projectApprovedTransformCall(transform, role, verdict) and
    remainingDepth = 0 and reportedOwner = handler.getName()
    or
    droidClawTransformRow(
      handler, source, sink, sinkArg, transform, input, sourceName, role, verdict, owner,
      chainDepth, transformDepth, remainingDepth, path, reportedOwner
    )
  )
select transform.getCalleeName() as transform_fn,
  transform.getLocation().getFile().getRelativePath() as transform_file,
  transformDefinitionLine(transform) as transform_definition_line,
  transform.getLocation().getStartLine() as transform_line,
  transform.getLocation().getFile().getRelativePath() as transform_call_file,
  transform.getLocation().getStartLine() as transform_call_line,
  transform.getLocation().getStartColumn() as transform_call_column,
  transform.asExpr().toString() as transform_call_expr, input.toString() as checked_expr,
  input.getLocation().getStartColumn() as checked_column, sourceName as source_param,
  reportedOwner as handler_func, role as transform_role, verdict as taint_verdict,
  sinkLabel(sink) as sink_label, sink.getLocation().getFile().getRelativePath() as sink_file,
  sink.getLocation().getStartLine() as sink_line

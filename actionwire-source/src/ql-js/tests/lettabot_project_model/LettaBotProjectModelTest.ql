import javascript
import project.ProjectModel
import call.call
import call.sinks_af
import call.lettabot_gates

from string kind, string name, string detail
where
  kind = "adapter" and name = activeProjectId() and detail = activeProjectAdapter()
  or
  exists(Function handler, string toolName, string model |
    projectToolInventoryEntry(handler, toolName, model) and kind = "handler" and name = toolName and
    detail = model + ":" + handler.getFile().getRelativePath()
  )
  or
  exists(Function anchor, string toolName, string model |
    projectToolBoundary(anchor, toolName, model) and kind = "boundary" and name = toolName and
    detail = model + ":" + anchor.getFile().getRelativePath()
  )
  or
  exists(Function handler, DataFlow::Node source, string parameterName |
    handlerSource(handler, source, parameterName) and kind = "source" and
    name = toolHandlerName(handler) and
    detail = parameterName + ":" + handler.getFile().getRelativePath()
  )
  or
  exists(DataFlow::CallNode sink |
    is_sink_af(sink) and kind = "sink" and name = sinkLabel(sink) and
    detail = sink.getLocation().getFile().getRelativePath() + ":" +
      sink.getLocation().getStartLine().toString()
  )
  or
  exists(Function handler, DataFlow::Node source, DataFlow::CallNode sink,
    DataFlow::Node sinkArg, int depth, string path |
    handlerSource(handler, source, _) and controlledSinkArgument(sink, sinkArg, _) and
    taintReachesSink(handler, source, sink, sinkArg, depth) and
    reachesSink(handler, sink, depth, path) and kind = "chain" and
    name = toolHandlerName(handler) and
    detail = path + ":" + sink.getLocation().getStartLine().toString()
  )
  or
  exists(Function handler, DataFlow::CallNode sink, Expr gateExpr, DataFlow::Node checked,
    string gateName, string sourceName, string guardKind, string verdict,
    string ownerName, string conditionExpr |
    lettaBotGateRow(
      handler, sink, gateExpr, checked, gateName, sourceName, guardKind, verdict,
      ownerName, conditionExpr
    ) and kind = "gate" and name = toolHandlerName(handler) and
    detail = gateName + ":" + ownerName + ":" +
      gateExpr.getLocation().getFile().getRelativePath() + ":" +
      gateExpr.getLocation().getStartLine().toString() + ":" + sinkLabel(sink)
  )
  or
  count(DataFlow::CallNode sink |
    is_sink_af(sink) and sink.getLocation().getFile().getRelativePath() = "src/cron/cli.ts"
  ) = 2 and kind = "shared-sink" and name = "non-handler-store" and
  detail = "fs-primitives-detected"
  or
  exists(DataFlow::CallNode transform, string role, string verdict |
    projectReviewTransformCall(transform, role, verdict) and
    transform.getLocation().getFile().getRelativePath() = "src/tools/todo.ts" and
    transform.getLocation().getStartLine() = 29 and
    kind = "transform-review" and name = transform.getCalleeName() and
    detail = role + ":" + verdict
  )
  or
  not exists(DataFlow::CallNode transform, string role, string verdict |
    projectApprovedTransformCall(transform, role, verdict)
  ) and kind = "negative" and name = "approved-transform" and detail = "absent"
select kind, name, detail

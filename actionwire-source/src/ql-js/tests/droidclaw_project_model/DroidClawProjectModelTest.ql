import javascript
import project.ProjectModel
import call.call
import call.sinks_af
import call.droidclaw_gates
import call.droidclaw_filters
import call.droidclaw_transforms

from string kind, string name, string detail
where
  kind = "adapter" and name = activeProjectId() and detail = activeProjectAdapter()
  or
  exists(Function handler, string toolName |
    droidClawToolHandler(handler, toolName, detail) and kind = "handler" and name = toolName
  )
  or
  exists(Function handler, DataFlow::Node source, string toolName, string parameterName |
    droidClawToolHandler(handler, toolName, _) and
    handlerSource(handler, source, parameterName) and kind = "source" and name = toolName and
    detail = parameterName
  )
  or
  exists(DataFlow::CallNode sink |
    is_sink_af(sink) and kind = "sink" and name = sinkLabel(sink) and
    detail = sink.getLocation().getFile().getRelativePath()
  )
  or
  exists(Function handler, DataFlow::Node source, DataFlow::CallNode sink,
    DataFlow::Node sinkArg, int depth, string toolName |
    droidClawToolHandler(handler, toolName, _) and toolName != "done" and
    handlerSource(handler, source, _) and
    controlledSinkArgument(sink, sinkArg, _) and
    taintReachesSink(handler, source, sink, sinkArg, depth) and reachesSink(handler, sink, depth, _) and
    kind = "chain" and name = toolName and detail = sinkLabel(sink)
  )
  or
  exists(Function handler, DataFlow::CallNode sink, Expr gateExpr, DataFlow::Node checked,
    string gateName, string sourceName, string guardKind, string verdict,
    string ownerName, string conditionExpr |
    droidClawGateRow(
      handler, sink, gateExpr, checked, gateName, sourceName, guardKind, verdict,
      ownerName, conditionExpr
    ) and kind = "gate" and name = toolHandlerName(handler) and
    detail = gateExpr.getLocation().getStartLine().toString() + ":" + sinkLabel(sink)
  )
  or
  exists(Function handler, DataFlow::Node source, DataFlow::CallNode sink,
    DataFlow::Node sinkArg, DataFlow::CallNode gate, DataFlow::Node checked,
    Function owner, int chainDepth, int gateDepth, string path, string conditionExpr |
    droidClawFilterRow(
      handler, source, sink, sinkArg, gate, checked, owner, chainDepth, gateDepth,
      path, conditionExpr
    ) and kind = "filter" and name = toolHandlerName(handler) and
    detail = gate.getLocation().getStartLine().toString() + ":" + sinkLabel(sink)
  )
  or
  exists(Function handler, DataFlow::Node source, DataFlow::CallNode sink,
    DataFlow::Node sinkArg, DataFlow::CallNode transform, DataFlow::Node input,
    string sourceName, string role, string verdict, Function owner, int chainDepth,
    int transformDepth, int remainingDepth, string path, string reportedOwner |
    droidClawTransformRow(
      handler, source, sink, sinkArg, transform, input, sourceName, role, verdict,
      owner, chainDepth, transformDepth, remainingDepth, path, reportedOwner
    ) and kind = "transform" and name = toolHandlerName(handler) and
    detail = transform.getLocation().getStartLine().toString() + ":" + sinkLabel(sink)
  )
  or
  not exists(Function handler, string toolName |
    droidClawToolHandler(handler, toolName, _) and
    toolName = [
      "back", "clear", "clipboard_get", "enter", "home", "notifications", "read_screen",
      "submit_message", "wait", "wait_for_content", "decoy", "decoy_skill", "unresolved"
    ]
  ) and kind = "negative" and name = "non-source-handlers" and detail = "absent"
  or
  not exists(Function handler, DataFlow::Node source, DataFlow::CallNode sink,
    DataFlow::Node sinkArg, int depth |
    droidClawToolHandler(handler, "done", _) and handlerSource(handler, source, _) and
    controlledSinkArgument(sink, sinkArg, _) and
    taintReachesSink(handler, source, sink, sinkArg, depth) and reachesSink(handler, sink, depth, _)
  ) and kind = "negative" and name = "done-chain" and detail = "absent"
  or
  not exists(DataFlow::CallNode sink |
    is_sink_af(sink) and sinkLabel(sink) = "Bun.spawnSync"
  ) and
  kind = "negative" and name = "bun-spawn" and detail = "absent"
select kind, name, detail

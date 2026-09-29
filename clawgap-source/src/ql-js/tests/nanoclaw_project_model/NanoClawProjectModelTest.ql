import javascript
import project.ProjectModel
import call.call
import call.sinks_af

from string kind, string name, string detail
where
  kind = "adapter" and name = activeProjectId() and detail = activeProjectAdapter()
  or
  exists(Function handler, string toolName |
    nanoClawToolHandler(handler, toolName, _) and kind = "handler" and name = toolName and
    detail = handler.getFile().getRelativePath()
  )
  or
  exists(Function anchor, string toolName, string form |
    nanoClawToolBoundary(anchor, toolName, form) and kind = "boundary" and name = toolName and
    detail = form + ":" + anchor.getFile().getRelativePath()
  )
  or
  exists(Function anchor, string toolName, string form |
    projectToolInventoryEntry(anchor, toolName, form) and kind = "inventory" and
    name = toolName and detail = form
  )
  or
  exists(DataFlow::CallNode sink |
    is_sink_af(sink) and kind = "sink" and name = sinkLabel(sink) and
    detail = sink.getLocation().getFile().getRelativePath()
  )
  or
  exists(Function handler, DataFlow::Node source, DataFlow::CallNode sink,
    DataFlow::Node sinkArg, int depth |
    handlerSource(handler, source, _) and controlledSinkArgument(sink, sinkArg, _) and
    taintReachesSink(handler, source, sink, sinkArg, depth) and reachesSink(handler, sink, depth, _) and
    kind = "chain" and name = toolHandlerName(handler) and detail = sinkLabel(sink)
  )
  or
  not exists(Function handler |
    nanoClawToolHandler(handler, ["dispatcher", "ordinary", "unregistered", "wrong_add_mcp_server"], _)
  ) and
  not exists(Function handler, DataFlow::Node source, DataFlow::CallNode sink,
    DataFlow::Node sinkArg, int depth |
    handler.getFile().getRelativePath() = [
      "container/agent-runner/src/mcp-tools/wrong-action.ts",
      "container/agent-runner/src/mcp-tools/wrong-kind.ts"
    ] and
    handlerSource(handler, source, _) and controlledSinkArgument(sink, sinkArg, _) and
    taintReachesSink(handler, source, sink, sinkArg, depth) and
    reachesSink(handler, sink, depth, _)
  ) and
  not exists(DataFlow::CallNode sink |
    is_sink_af(sink) and sink.getLocation().getFile().getRelativePath() =
      ["src/db/wrong.ts", "src/modules/approvals/wrong.ts"]
  ) and
  not exists(DataFlow::CallNode sink |
    is_sink_af(sink) and
    sink.getLocation().getFile().getRelativePath() = "src/copy-signature.ts" and
    sink.getLocation().getStartLine() = 6
  ) and
  not exists(Function boundary, string toolName, string form, DataFlow::Node source |
    projectToolBoundary(boundary, toolName, form) and
    handlerSource(boundary, source, _)
  ) and
  not exists(Function boundary, string toolName, string form |
    projectToolBoundary(boundary, toolName, form) and
    projectToolHandler(boundary, toolName, form)
  ) and
  not exists(Function boundary, string form |
    nanoClawToolBoundary(boundary, "mcp__nanoclaw__*", form)
  ) and
  not exists(Function boundary, string toolName, string form |
    nanoClawToolBoundary(boundary, toolName, form) and
    projectToolInventoryEntry(boundary, toolName, form)
  ) and
  kind = "negative" and name = "strict-registration-boundary-action-sql-kind-source-inventory" and
  detail = "absent"
select kind, name, detail

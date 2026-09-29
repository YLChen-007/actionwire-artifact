import javascript
import project.ProjectModel
import call.call
import call.sinks_af

from string kind, string name, string detail
where
  kind = "adapter" and name = activeProjectId() and detail = activeProjectAdapter()
  or
  exists(Function handler, string toolName |
    tinyClawToolHandler(handler, toolName, _) and kind = "handler" and name = toolName and
    detail = handler.getFile().getRelativePath()
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
    tinyClawToolHandler(handler, _, _) and handler.getFile().getRelativePath() =
      "packages/core/src/unrelated.ts"
  ) and
  exists(DataFlow::CallNode sink |
    sinkCanonicalId(sink) = "OC-PROCESS-CHILD-PROCESS" and
    sink.getLocation().getFile().getRelativePath() = "packages/core/src/unrelated.ts"
  ) and kind = "shared-sink" and name = "unregistered-handler" and detail = "spawn-detected"
select kind, name, detail

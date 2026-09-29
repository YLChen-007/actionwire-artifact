import javascript
import project.ProjectModel
import call.call
import call.sinks_af

from string kind, string name, string detail
where
  kind = "adapter" and name = activeProjectId() and detail = activeProjectAdapter()
  or
  exists(Function handler, string toolName |
    lobsterAIToolHandler(handler, toolName, _) and kind = "handler" and name = toolName and
    detail = handler.getFile().getRelativePath()
  )
  or
  exists(Function handler, DataFlow::Node source, string toolName, string parameterName |
    lobsterAIToolHandler(handler, toolName, _) and
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
    DataFlow::Node sinkArg, int depth |
    handlerSource(handler, source, _) and controlledSinkArgument(sink, sinkArg, _) and
    taintReachesSink(handler, source, sink, sinkArg, depth) and
    reachesSink(handler, sink, depth, _) and kind = "chain" and
    name = toolHandlerName(handler) and detail = sinkLabel(sink)
  )
  or
  not exists(Function handler |
    lobsterAIToolHandler(handler, _, _) and
    handler.getFile().getRelativePath() = "src/unrelated.ts"
  ) and kind = "negative" and name = "ordinary-execute-excluded" and detail = "absent"
  or
  not exists(Function handler |
    lobsterAIToolHandler(handler, _, _) and
    handler.getFile().getRelativePath() = "openclaw-extensions/mcp-bridge/index.ts"
  ) and kind = "negative" and name = "legacy-dynamic-mcp-excluded" and detail = "absent"
select kind, name, detail
